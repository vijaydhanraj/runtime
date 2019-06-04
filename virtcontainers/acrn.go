// Copyright (c) 2016 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

package virtcontainers

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	govmmAcrn "github.com/intel/govmm/acrn"
	"github.com/kata-containers/runtime/virtcontainers/device/config"
	"github.com/kata-containers/runtime/virtcontainers/store"
	"github.com/kata-containers/runtime/virtcontainers/types"
	"github.com/kata-containers/runtime/virtcontainers/utils"
	opentracing "github.com/opentracing/opentracing-go"
	"github.com/sirupsen/logrus"
)

// AcrnState keeps Acrn's state
type AcrnState struct {
	UUID string
}

// AcrnInfo keeps PID of the hypervisor
type AcrnInfo struct {
	PID int
}

// acrn is an Hypervisor interface implementation for the Linux ACRN hypervisor.
type acrn struct {
	id string

	store      *store.VCStore
	config     HypervisorConfig
	acrnConfig govmmAcrn.Config
	state      AcrnState
	info       AcrnInfo
	arch       acrnArch
	ctx        context.Context
}

const (
	acrnConsoleSocket      = "console.sock"
	acrnStopSandboxTimeout = 15
)

// agnostic list of kernel parameters
var acrnDefaultKernelParameters = []Param{
	{"panic", "1"},
}

func (a *acrn) kernelParameters() string {
	// get a list of arch kernel parameters
	params := a.arch.kernelParameters(a.config.Debug)

	// use default parameters
	params = append(params, acrnDefaultKernelParameters...)

	// set the maximum number of vCPUs
	params = append(params, Param{"maxcpus", fmt.Sprintf("%d", a.config.NumVCPUs)})

	// add the params specified by the provided config. As the kernel
	// honours the last parameter value set and since the config-provided
	// params are added here, they will take priority over the defaults.
	params = append(params, a.config.KernelParams...)

	paramsStr := SerializeParams(params, "=")

	return strings.Join(paramsStr, " ")
}

// Adds all capabilities supported by acrn implementation of hypervisor interface
func (a *acrn) capabilities() types.Capabilities {
	span, _ := a.trace("capabilities")
	defer span.Finish()

	return a.arch.capabilities()
}

func (a *acrn) hypervisorConfig() HypervisorConfig {
	return a.config
}

// get the ACRN binary path
func (a *acrn) acrnPath() (string, error) {
	p, err := a.config.HypervisorAssetPath()
	if err != nil {
		return "", err
	}

	if p == "" {
		p, err = a.arch.acrnPath()
		if err != nil {
			return "", err
		}
	}

	if _, err = os.Stat(p); os.IsNotExist(err) {
		return "", fmt.Errorf("ACRN path (%s) does not exist", p)
	}

	return p, nil
}

// get the ACRNCTL binary path
func (a *acrn) acrnctlPath() (string, error) {
	ctlpath, err := a.config.HypervisorCtlAssetPath()
	if err != nil {
		return "", err
	}

	if ctlpath == "" {
		ctlpath, err = a.arch.acrnctlPath()
		if err != nil {
			return "", err
		}
	}

	if _, err = os.Stat(ctlpath); os.IsNotExist(err) {
		return "", fmt.Errorf("ACRN path (%s) does not exist", ctlpath)
	}

	return ctlpath, nil
}

// Logger returns a logrus logger appropriate for logging acrn messages
func (a *acrn) Logger() *logrus.Entry {
	return virtLog.WithField("subsystem", "acrn")
}

func (a *acrn) trace(name string) (opentracing.Span, context.Context) {
	if a.ctx == nil {
		a.Logger().WithField("type", "bug").Error("trace called before context set")
		a.ctx = context.Background()
	}

	span, ctx := opentracing.StartSpanFromContext(a.ctx, name)

	span.SetTag("subsystem", "hypervisor")
	span.SetTag("type", "acrn")

	return span, ctx
}

func (a *acrn) memoryTopology() (govmmAcrn.Memory, error) {
	memMb := uint64(a.config.MemorySize)

	return a.arch.memoryTopology(memMb), nil
}

func (a *acrn) appendImage(devices []govmmAcrn.Device) ([]govmmAcrn.Device, error) {
	imagePath, err := a.config.ImageAssetPath()
	if err != nil {
		return nil, err
	}

	if imagePath != "" {
		devices, err = a.arch.appendImage(devices, imagePath)
		if err != nil {
			return nil, err
		}
	}

	return devices, nil
}

func (a *acrn) buildDevices(initrdPath string) ([]govmmAcrn.Device, error) {
	var devices []govmmAcrn.Device

	console, err := a.getSandboxConsole(a.id)
	if err != nil {
		return nil, err
	}

	// Add bridges before any other devices. This way we make sure that
	// bridge gets the first available PCI address.
	devices = a.arch.appendBridges(devices)

	//Add LPC device to the list of other devices.
	devices = a.arch.appendLPC(devices)

	devices = a.arch.appendConsole(devices, console)

	if initrdPath == "" {
		devices, err = a.appendImage(devices)
		if err != nil {
			return nil, err
		}
	}

	devices, err = a.createdummyVirtiBlkDev(devices)
	if err != nil {
		return nil, err
	}

	return devices, nil

}

// setup sets the Acrn structure up.
func (a *acrn) setup(id string, hypervisorConfig *HypervisorConfig, vcStore *store.VCStore) error {
	span, _ := a.trace("setup")
	defer span.Finish()

	err := hypervisorConfig.valid()
	if err != nil {
		return err
	}

	a.id = id
	a.store = vcStore
	a.config = *hypervisorConfig
	a.arch = newAcrnArch(a.config)

	if err = a.store.Load(store.Hypervisor, &a.state); err != nil {
		//TODO: acrn currently supports only known UUIDs
		// for security reasons.
		/*
			a.Logger().Debug("Creating UUID")
			a.state.UUID = uuid.Generate().String()
		*/
		// The path might already exist, but in case of VM templating,
		// we have to create it since the sandbox has not created it yet.
		if err = os.MkdirAll(store.SandboxRuntimeRootPath(id), store.DirMode); err != nil {
			return err
		}

		if err = a.store.Store(store.Hypervisor, a.state); err != nil {
			return err
		}
	}

	if err = a.store.Load(store.Hypervisor, &a.info); err != nil {
		a.Logger().WithField("function", "setup").WithError(err).Info("No info could be fetched")
	}

	return nil
}

func (a *acrn) createdummyVirtiBlkDev(devices []govmmAcrn.Device) ([]govmmAcrn.Device, error) {
	span, _ := a.trace("createdummyVirtiBlkDev")
	defer span.Finish()

	for driveIndex := 0; driveIndex < govmmAcrn.AcrnBlkDevPoolSz; driveIndex++ {
		/*
			// Create a temporary file as a placeholder backend for the drive
			hostURL, err := a.store.Raw("")
			if err != nil {
				return nil, err
			}

			// We get a full URL from Raw(), we need to parse it.
			u, err := url.Parse(hostURL)
			if err != nil {
				return nil, err
			}
		*/
		drive := config.BlockDrive{
			File:  "nodisk",
			Index: driveIndex,
		}

		devices = a.arch.appendBlockDevice(devices, drive)
	}

	return devices, nil
}

// createSandbox is the Hypervisor sandbox creation implementation for govmmAcrn.
func (a *acrn) createSandbox(ctx context.Context, id string, hypervisorConfig *HypervisorConfig, store *store.VCStore) error {

	// Save the tracing context
	a.ctx = ctx

	span, _ := a.trace("createSandbox")
	defer span.Finish()

	if err := a.setup(id, hypervisorConfig, store); err != nil {
		return err
	}

	memory, err := a.memoryTopology()
	if err != nil {
		return err
	}

	kernelPath, err := a.config.KernelAssetPath()
	if err != nil {
		return err
	}

	initrdPath, err := a.config.InitrdAssetPath()
	if err != nil {
		return err
	}

	kernel := govmmAcrn.Kernel{
		Path:       kernelPath,
		InitrdPath: initrdPath,
		Params:     a.kernelParameters(),
	}

	//TODO: acrn currently supports only known UUIDs
	// for security reasons.
	/*
		if a.state.UUID == "" {
			return fmt.Errorf("UUID should not be empty")
		}
	*/

	devices, err := a.buildDevices(initrdPath)
	if err != nil {
		return err
	}

	acrnPath, err := a.acrnPath()
	if err != nil {
		return err
	}

	acrnctlPath, err := a.acrnctlPath()
	if err != nil {
		return err
	}

	acrnConfig := govmmAcrn.Config{
		ACPIVirt: true,
		Path:     acrnPath,
		CtlPath:  acrnctlPath,
		Memory:   memory,
		NumCPU:   a.config.NumVCPUs,
		Devices:  devices,
		Kernel:   kernel,
		Name:     fmt.Sprintf("sandbox-%s", a.id),
	}

	a.acrnConfig = acrnConfig

	return nil
}

// startSandbox will start the Sandbox's VM.
func (a *acrn) startSandbox(timeout int) error {
	span, _ := a.trace("startSandbox")
	defer span.Finish()

	if a.config.Debug {
		params := a.arch.kernelParameters(a.config.Debug)
		strParams := SerializeParams(params, "=")
		formatted := strings.Join(strParams, " ")

		// The name of this field matches a similar one generated by
		// the runtime and allows users to identify which parameters
		// are set here, which come from the runtime and which are set
		// by the user.
		a.Logger().WithField("default-kernel-parameters", formatted).Debug()
	}

	vmPath := filepath.Join(store.RunVMStoragePath, a.id)
	err := os.MkdirAll(vmPath, store.DirMode)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			if err := os.RemoveAll(vmPath); err != nil {
				a.Logger().WithError(err).Error("Fail to clean up vm directory")
			}
		}
	}()

	var strErr string
	var PID int
	PID, strErr, err = govmmAcrn.LaunchAcrn(a.acrnConfig, virtLog.WithField("subsystem", "acrn-dm"))
	if err != nil {
		return fmt.Errorf("%s", strErr)
	}
	a.info.PID = PID

	if err = a.waitSandbox(timeout); err != nil {
		a.Logger().WithField("Acrn wait failed:", err).Debug()
		return err
	}

	//Store VMM information
	return a.store.Store(store.Hypervisor, a.info)

}

// waitSandbox will wait for the Sandbox's VM to be up and running.
func (a *acrn) waitSandbox(timeout int) error {
	span, _ := a.trace("waitSandbox")
	defer span.Finish()

	if timeout < 0 {
		return fmt.Errorf("Invalid timeout %ds", timeout)
	}

	time.Sleep(time.Duration(timeout) * time.Second)

	return nil
}

// stopSandbox will stop the Sandbox's VM.
func (a *acrn) stopSandbox() (err error) {

	span, _ := a.trace("stopSandbox")
	defer span.Finish()

	a.Logger().Infof("Stopping ACRN VM")

	defer func() {
		if err != nil {
			a.Logger().Infof("stopSandbox failed")
		} else {
			a.Logger().Infof("ACRN VM stopped")
		}
	}()

	pid := a.info.PID

	// Check if VM process is running, in case it is not, let's
	// return from here.
	if err = syscall.Kill(pid, syscall.Signal(0)); err != nil {
		a.Logger().Infof("ACRN VM already stopped")
		return nil
	}

	// Send a SIGTERM to the VM process to try to stop it properly
	if err = syscall.Kill(pid, syscall.SIGINT); err != nil {
		a.Logger().Infof("Sending SIGINT to stop ACRN VM failed")
		return err
	}

	// Wait for the VM process to terminate
	tInit := time.Now()
	for {
		if err = syscall.Kill(pid, syscall.Signal(0)); err != nil {
			a.Logger().Infof("ACRN VM stopped after sending SIGINT")
			return nil
		}

		if time.Since(tInit).Seconds() >= acrnStopSandboxTimeout {
			a.Logger().Warnf("VM still running after waiting %ds", acrnStopSandboxTimeout)
			break
		}

		// Let's avoid to run a too busy loop
		time.Sleep(time.Duration(50) * time.Millisecond)
	}

	// Let's try with a hammer now, a SIGKILL should get rid of the
	// VM process.
	return syscall.Kill(pid, syscall.SIGKILL)

}

func (a *acrn) udpateBlockDevice(drive *config.BlockDrive) error {
	var err error
	if drive.File == "" || drive.Index >= govmmAcrn.AcrnBlkDevPoolSz {
		return fmt.Errorf("Empty filepath or invalid drive index, Dive ID:%s, Drive Index:%d",
			drive.ID, drive.Index)
	}

	slot := govmmAcrn.AcrnBlkdDevSlot[drive.Index]

	//Explicitly set PCIAddr to NULL, so that VirtPath can be used
	drive.PCIAddr = ""

	args := []string{"blkrescan", a.acrnConfig.Name, fmt.Sprintf("%d,%s", slot, drive.File)}

	a.Logger().WithFields(logrus.Fields{"drive": drive}).Infof("udpateBlockDevice with acrnctl path=%s", a.config.HypervisorCtlPath)
	cmd := exec.Command(a.config.HypervisorCtlPath, args...)
	if err := cmd.Start(); err != nil {
		a.Logger().WithError(err).Error("updating Block device with newFile path")
	}

	return err
}

func (a *acrn) hotplugAddDevice(devInfo interface{}, devType deviceType) (interface{}, error) {
	span, _ := a.trace("hotplugAddDevice")
	defer span.Finish()

	switch devType {
	case blockDev:
		//The drive placeholder has to exist prior to Update
		return nil, a.udpateBlockDevice(devInfo.(*config.BlockDrive))
	default:
		a.Logger().WithFields(logrus.Fields{"devInfo": devInfo,
			"deviceType": devType}).Warn("hotplugAddDevice: unsupported device")
		return nil, fmt.Errorf("hotplugAddDevice: unsupported device: devInfo:%v, deviceType%v",
			devInfo, devType)
	}
}

func (a *acrn) hotplugRemoveDevice(devInfo interface{}, devType deviceType) (interface{}, error) {
	span, _ := a.trace("hotplugRemoveDevice")
	defer span.Finish()

	// Not supported. return success

	return nil, nil
}

func (a *acrn) pauseSandbox() error {
	span, _ := a.trace("pauseSandbox")
	defer span.Finish()

	// Not supported. return success

	return nil
}

func (a *acrn) resumeSandbox() error {
	span, _ := a.trace("resumeSandbox")
	defer span.Finish()

	// Not supported. return success

	return nil
}

// addDevice will add extra devices to Acrn command line.
func (a *acrn) addDevice(devInfo interface{}, devType deviceType) error {
	var err error
	span, _ := a.trace("addDevice")
	defer span.Finish()

	switch v := devInfo.(type) {
	case types.Volume:
		// Not supported. return success
		err = nil
	case types.Socket:
		a.acrnConfig.Devices = a.arch.appendSocket(a.acrnConfig.Devices, v)
	case kataVSOCK:
		// Not supported. return success
		err = nil
	case Endpoint:
		a.acrnConfig.Devices = a.arch.appendNetwork(a.acrnConfig.Devices, v)
	case config.BlockDrive:
		a.acrnConfig.Devices = a.arch.appendBlockDevice(a.acrnConfig.Devices, v)
	case config.VhostUserDeviceAttrs:
		// Not supported. return success
		err = nil
	case config.VFIODev:
		// Not supported. return success
		err = nil
	default:
		break
	}

	return err
}

// getSandboxConsole builds the path of the console where we can read
// logs coming from the sandbox.
func (a *acrn) getSandboxConsole(id string) (string, error) {
	span, _ := a.trace("getSandboxConsole")
	defer span.Finish()

	return utils.BuildSocketPath(store.RunVMStoragePath, id, acrnConsoleSocket)
}

func (a *acrn) saveSandbox() error {
	a.Logger().Info("save sandbox")

	// Not supported. return success

	return nil
}

func (a *acrn) disconnect() {
	span, _ := a.trace("disconnect")
	defer span.Finish()

	// Not supported. return success
}

/*TODO: Is this required for ACRN*/
func (a *acrn) getThreadIDs() (vcpuThreadIDs, error) {
	span, _ := a.trace("getThreadIDs")
	defer span.Finish()

	// Not supported. return success
	//Just allocating an empty map

	return vcpuThreadIDs{}, nil
}

func (a *acrn) resizeMemory(reqMemMB uint32, memoryBlockSizeMB uint32, probe bool) (uint32, memoryDevice, error) {
	return 0, memoryDevice{}, nil
}

func (a *acrn) resizeVCPUs(reqVCPUs uint32) (currentVCPUs uint32, newVCPUs uint32, err error) {
	return 0, 0, nil
}

func (a *acrn) cleanup() error {
	span, _ := a.trace("cleanup")
	defer span.Finish()

	return nil
}

func (a *acrn) pid() int {
	return a.info.PID
}

func (a *acrn) fromGrpc(ctx context.Context, hypervisorConfig *HypervisorConfig, store *store.VCStore, j []byte) error {
	return errors.New("acrn is not supported by VM cache")
}

func (a *acrn) toGrpc() ([]byte, error) {
	return nil, errors.New("acrn is not supported by VM cache")
}
