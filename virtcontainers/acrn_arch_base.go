// Copyright (c) 2018 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

package virtcontainers

import (
	"fmt"
	"os"

	govmmAcrn "github.com/intel/govmm/acrn"
	"github.com/kata-containers/runtime/virtcontainers/device/config"
	"github.com/kata-containers/runtime/virtcontainers/types"
)

type acrnArch interface {

	// acrnPath returns the path to the ACRN binary
	acrnPath() (string, error)

	// acrnctlPath returns the path to the ACRNCTL binary
	acrnctlPath() (string, error)

	// kernelParameters returns the kernel parameters
	// if debug is true then kernel debug parameters are included
	kernelParameters(debug bool) []Param

	//capabilities returns the capabilities supported by ACRN
	capabilities() types.Capabilities

	// memoryTopology returns the memory topology using the given amount of memoryMb and hostMemoryMb
	memoryTopology(memMb uint64) govmmAcrn.Memory

	// appendConsole appends a console to devices
	appendConsole(devices []govmmAcrn.Device, path string) []govmmAcrn.Device

	// appendImage appends an image to devices
	appendImage(devices []govmmAcrn.Device, path string) ([]govmmAcrn.Device, error)

	// appendBridges appends bridges to devices
	appendBridges(devices []govmmAcrn.Device) []govmmAcrn.Device

	// appendLPC appends LPC to devices
	// UART device emulated by the ACRN-DM is connected to the system by the LPC bus
	appendLPC(devices []govmmAcrn.Device) []govmmAcrn.Device

	// appendSocket appends a socket to devices
	appendSocket(devices []govmmAcrn.Device, socket types.Socket) []govmmAcrn.Device

	// appendNetwork appends a endpoint device to devices
	appendNetwork(devices []govmmAcrn.Device, endpoint Endpoint) []govmmAcrn.Device

	// appendBlockDevice appends a block drive to devices
	appendBlockDevice(devices []govmmAcrn.Device, drive config.BlockDrive) []govmmAcrn.Device

	// handleImagePath handles the Hypervisor Config image path
	handleImagePath(config HypervisorConfig)
}

type acrnArchBase struct {
	path                 string
	ctlpath              string
	kernelParamsNonDebug []Param
	kernelParamsDebug    []Param
	kernelParams         []Param
}

const acrnPath = "/usr/bin/acrn-dm"
const acrnctlPath = "/usr/bin/acrnctl"

// acrnKernelParamsNonDebug is a list of the default kernel
// parameters that will be used in standard (non-debug) mode.
var acrnKernelParamsNonDebug = []Param{
	{"quiet", ""},
}

// acrnKernelParamsSystemdNonDebug is a list of the default systemd related
// kernel parameters that will be used in standard (non-debug) mode.
var acrnKernelParamsSystemdNonDebug = []Param{
	{"systemd.show_status", "false"},
}

// acrnKernelParamsDebug is a list of the default kernel
// parameters that will be used in debug mode (as much boot output as
// possible).
var acrnKernelParamsDebug = []Param{
	{"debug", ""},
}

// acrnKernelParamsSystemdDebug is a list of the default systemd related kernel
// parameters that will be used in debug mode (as much boot output as
// possible).
var acrnKernelParamsSystemdDebug = []Param{
	{"systemd.show_status", "true"},
	{"systemd.log_level", "debug"},
	{"systemd.log_target", "kmsg"},
	{"printk.devkmsg", "on"},
}

var acrnKernelRootParams = []Param{
	{"root", "/dev/vda1 rw rootwait"},
}

var acrnKernelParams = []Param{
	{"tsc", "reliable"},
	{"no_timer_check", ""},
	{"nohpet", ""},
	{"console", "tty0"},
	{"console", "ttyS0"},
	{"console", "hvc0"},
	{"log_buf_len", "16M"},
	{"consoleblank", "0"},
	{"iommu", "off"},
	{"i915.avail_planes_per_pipe", "0x070F00"}, //this can also be passed via configuration.toml
	{"i915.enable_hangcheck", "0"},
	{"i915.nuclear_pageflip", "1"},
	{"i915.enable_guc_loading", "0"},
	{"i915.enable_guc_submission", "0"},
	{"i915.enable_guc", "0"},
}

// MaxAcrnVCPUs returns the maximum number of vCPUs supported
func MaxAcrnVCPUs() uint32 {
	return uint32(8)
}

func newAcrnArch(config HypervisorConfig) acrnArch {

	a := &acrnArchBase{
		path:                 acrnPath,
		ctlpath:              acrnctlPath,
		kernelParamsNonDebug: acrnKernelParamsNonDebug,
		kernelParamsDebug:    acrnKernelParamsDebug,
		kernelParams:         acrnKernelParams,
	}

	a.handleImagePath(config)
	return a
}

func (a *acrnArchBase) acrnPath() (string, error) {
	p := a.path
	return p, nil
}

func (a *acrnArchBase) acrnctlPath() (string, error) {
	ctlpath := a.ctlpath
	return ctlpath, nil
}

func (a *acrnArchBase) kernelParameters(debug bool) []Param {
	params := a.kernelParams

	if debug {
		params = append(params, a.kernelParamsDebug...)
	} else {
		params = append(params, a.kernelParamsNonDebug...)
	}

	return params
}

func (a *acrnArchBase) memoryTopology(memoryMb uint64) govmmAcrn.Memory {

	mem := fmt.Sprintf("%dM", memoryMb)
	memory := govmmAcrn.Memory{
		Size: mem,
	}

	return memory
}

func (a *acrnArchBase) capabilities() types.Capabilities {
	var caps types.Capabilities

	// For devicemapper disable support for filesystem sharing

	caps.SetFsSharingUnsupported()
	caps.SetBlockDeviceSupport()
	caps.SetBlockDeviceHotplugSupport()

	return caps
}

func (a *acrnArchBase) appendImage(devices []govmmAcrn.Device, path string) ([]govmmAcrn.Device, error) {
	imageFile, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = imageFile.Close() }()

	ImgBlkdevice := govmmAcrn.BlockDevice{
		FilePath: path,
		Index:    0xFF,
	}

	devices = append(devices, ImgBlkdevice)

	return devices, nil
}

// appendBridges appends to devices the given bridges
func (a *acrnArchBase) appendBridges(devices []govmmAcrn.Device) []govmmAcrn.Device {

	devices = append(devices,
		govmmAcrn.BridgeDevice{
			Function: 0,
			Emul:     "hostbridge",
			Config:   "",
		},
	)

	return devices
}

// appendBridges appends to devices the given bridges
func (a *acrnArchBase) appendLPC(devices []govmmAcrn.Device) []govmmAcrn.Device {

	devices = append(devices,
		govmmAcrn.LPCDevice{
			Function: 0,
			Emul:     "lpc",
		},
	)

	return devices
}

func (a *acrnArchBase) appendConsole(devices []govmmAcrn.Device, path string) []govmmAcrn.Device {

	console := govmmAcrn.ConsoleDevice{
		Name:     "console0",
		Backend:  govmmAcrn.Socket,
		PortType: govmmAcrn.ConsoleBE,
		Path:     path,
	}

	devices = append(devices, console)

	return devices
}

func (a *acrnArchBase) appendSocket(devices []govmmAcrn.Device, socket types.Socket) []govmmAcrn.Device {
	devID := socket.ID
	if len(devID) > maxDevIDSize {
		devID = devID[:maxDevIDSize]
	}

	serailsocket := govmmAcrn.ConsoleDevice{
		Name:     socket.Name,
		Backend:  govmmAcrn.Socket,
		PortType: govmmAcrn.SerialBE,
		Path:     socket.HostPath,
	}

	devices = append(devices, serailsocket)
	return devices
}

func networkModelToAcrnType(model NetInterworkingModel) govmmAcrn.NetDeviceType {
	switch model {
	case NetXConnectBridgedModel:
		return govmmAcrn.TAP
	case NetXConnectMacVtapModel:
		return govmmAcrn.MACVTAP
	//case ModelEnlightened:
	// Here the Network plugin will create a VM native interface
	// which could be MacVtap, IpVtap, SRIOV, veth-tap, vhost-user
	// In these cases we will determine the interface type here
	// and pass in the native interface through
	default:
		//TAP should work for most other cases
		return govmmAcrn.TAP
	}
}

func (a *acrnArchBase) appendNetwork(devices []govmmAcrn.Device, endpoint Endpoint) []govmmAcrn.Device {
	switch ep := endpoint.(type) {
	case *VethEndpoint, *BridgedMacvlanEndpoint, *IPVlanEndpoint:
		netPair := ep.NetworkPair()
		devices = append(devices,
			govmmAcrn.NetDevice{
				Type:       networkModelToAcrnType(netPair.NetInterworkingModel),
				IFName:     netPair.TAPIface.Name,
				MACAddress: netPair.TAPIface.HardAddr,
			},
		)
	case *MacvtapEndpoint:
		devices = append(devices,
			govmmAcrn.NetDevice{
				Type:       govmmAcrn.MACVTAP,
				IFName:     ep.Name(),
				MACAddress: ep.HardwareAddr(),
			},
		)

	}

	return devices
}

func (a *acrnArchBase) appendBlockDevice(devices []govmmAcrn.Device, drive config.BlockDrive) []govmmAcrn.Device {
	if drive.File == "" {
		return devices
	}

	devices = append(devices,
		govmmAcrn.BlockDevice{
			FilePath: drive.File,
			Index:    drive.Index,
		},
	)

	return devices
}

func (a *acrnArchBase) handleImagePath(config HypervisorConfig) {
	if config.ImagePath != "" {
		a.kernelParams = append(a.kernelParams, acrnKernelRootParams...)
		a.kernelParamsNonDebug = append(a.kernelParamsNonDebug, acrnKernelParamsSystemdNonDebug...)
		a.kernelParamsDebug = append(a.kernelParamsDebug, acrnKernelParamsSystemdDebug...)
	}
}
