/*
// Copyright contributors to the Virtual Machine Manager for Go project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

// Package acrn provides methods and types for launching and managing ACRN
// instances.  Instances can be launched with the LaunchAcrn function and
// managed thereafter via acrnctl. To manage a acrn instance after it
// has been launched you need to pass the respective acrnctl command.
// As a example to stop the VM,
// acrnctl stop VMname  For more information see the acrnctl usage document.
// https://projectacrn.github.io/latest/tools/acrn-manager/README.html#usage
package acrn

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/sirupsen/logrus"
)

var mylogger *logrus.Entry

// AcrnBlkDevPoolSz defines the number of dummy Blk
// that will be created for hot-plugging virtio-blk
// device.
var AcrnBlkDevPoolSz = 8

// AcrnBlkdDevSlot array provides translation between
// the vitio-blk device index and slot it is currently
// attached.
var AcrnBlkdDevSlot = make([]int, AcrnBlkDevPoolSz)

// Device is the acrn device interface.
type Device interface {
	Valid() bool
	AcrnParams(slot int, config *Config) []string
}

// ConsoleDeviceBackend is the character device backend for acrn
type ConsoleDeviceBackend string

const (

	// Socket creates a 2 way stream socket (TCP or Unix).
	Socket ConsoleDeviceBackend = "socket"

	// Stdio sends traffic from the guest to ACRN's standard output.
	Stdio ConsoleDeviceBackend = "console"

	// File backend only supports console output to a file (no input).
	File ConsoleDeviceBackend = "file"

	// TTY is an alias for Serial.
	TTY ConsoleDeviceBackend = "tty"

	// PTY creates a new pseudo-terminal on the host and connect to it.
	PTY ConsoleDeviceBackend = "pty"
)

// BEPortType marks the port as console port or virtio-serial port
type BEPortType int

const (
	// SerialBE marks the port as serial port
	SerialBE BEPortType = iota

	//ConsoleBE marks the port as console port (append @)
	ConsoleBE
)

// ConsoleDevice represents a acrn console device.
type ConsoleDevice struct {
	// Name of the socket
	Name string

	//Backend device used for virtio-console
	Backend ConsoleDeviceBackend

	// PortType marks the port as serial or console port (@)
	PortType BEPortType

	//Path to virtio-console backend (can be omitted for pty, tty, stdio)
	Path string
}

// Valid returns true if the CharDevice structure is valid and complete.
func (cdev ConsoleDevice) Valid() bool {

	if cdev.Backend != "tty" && cdev.Backend != "pty" &&
		cdev.Backend != "console" && cdev.Backend != "socket" &&
		cdev.Backend != "file" {
		return false
	}

	return true
}

// AcrnParams returns the acrn parameters built out of this console device.
func (cdev ConsoleDevice) AcrnParams(slot int, config *Config) []string {

	var acrnParams []string
	var deviceParams []string

	acrnParams = append(acrnParams, "-s")
	deviceParams = append(deviceParams, fmt.Sprintf("%d,virtio-console,", slot))

	if cdev.PortType == ConsoleBE {
		deviceParams = append(deviceParams, "@")
	}

	switch cdev.Backend {
	case "pty":
		deviceParams = append(deviceParams, "pty:pty_port")
	case "tty":
		deviceParams = append(deviceParams, fmt.Sprintf("tty:tty_port=%s", cdev.Path))
	case "socket":
		deviceParams = append(deviceParams, fmt.Sprintf("socket:%s=%s", cdev.Name, cdev.Path))
	case "file":
		deviceParams = append(deviceParams, fmt.Sprintf("file:file_port=%s", cdev.Path))
	case "stdio":
		deviceParams = append(deviceParams, "stdio:stdio_port")
	default:
		// do nothing. Error should be already caught
	}

	acrnParams = append(acrnParams, strings.Join(deviceParams, ""))
	return acrnParams
}

// NetDeviceType is a acrn networking device type.
type NetDeviceType string

const (
	// TAP is a TAP networking device type.
	TAP NetDeviceType = "tap"

	// MACVTAP is a macvtap networking device type.
	MACVTAP NetDeviceType = "macvtap"
)

// NetDevice represents a guest networking device
type NetDevice struct {
	// Type is the netdev type (e.g. tap).
	Type NetDeviceType

	// IfName is the interface name
	IFName string

	//MACAddress is the networking device interface MAC address
	MACAddress string
}

// AcrnNetdevParam converts to the ACRN type to string
func (netdev NetDevice) AcrnNetdevParam() []string {
	var deviceParams []string

	switch netdev.Type {
	case TAP:
		deviceParams = append(deviceParams, netdev.IFName)
		deviceParams = append(deviceParams, fmt.Sprintf(",mac=%s", netdev.MACAddress))
	case MACVTAP:
		deviceParams = append(deviceParams, netdev.IFName)
	default:
		deviceParams = append(deviceParams, netdev.IFName)

	}

	return deviceParams
}

// Valid returns true if the NetDevice structure is valid and complete.
func (netdev NetDevice) Valid() bool {
	switch netdev.Type {
	case TAP:
		return true
	case MACVTAP:
		return false
	default:
		return false
	}
}

// AcrnParams returns the acrn parameters built out of this network device.
func (netdev NetDevice) AcrnParams(slot int, config *Config) []string {
	var acrnParams []string

	acrnParams = append(acrnParams, "-s")
	acrnParams = append(acrnParams, fmt.Sprintf("%d,virtio-net,%s", slot, strings.Join(netdev.AcrnNetdevParam(), "")))

	return acrnParams
}

// BlockDevice represents a acrn block device.
type BlockDevice struct {

	// mem path to block device
	FilePath string

	//BlkIndex - Blk index corresponding to slot
	Index int
}

// Valid returns true if the BlockDevice structure is valid and complete.
func (blkdev BlockDevice) Valid() bool {
	if blkdev.FilePath == "" {
		return false
	}

	return true
}

// AcrnParams returns the acrn parameters built out of this block device.
func (blkdev BlockDevice) AcrnParams(slot int, config *Config) []string {
	var acrnParams []string

	acrnParams = append(acrnParams, "-s")
	acrnParams = append(acrnParams, fmt.Sprintf("%d,virtio-blk,%s",
		slot, blkdev.FilePath))

	// Update the global array (BlkIndex<->slot)
	// Used to identify slots for the hot-plugged virtio-blk devices
	// Index 0xFF is assigned for VM rootfs, so ignore this mapping.
	if blkdev.Index < AcrnBlkDevPoolSz {
		AcrnBlkdDevSlot[blkdev.Index] = slot
	} else {
		if blkdev.Index != 0xFF {
			mylogger.Infof("Invalid index for the virtio-blk device!\n")
		}
	}

	return acrnParams
}

// BridgeDevice represents a acrn bridge device like pci-bridge, pxb, etc.
type BridgeDevice struct {

	// Function is PCI function. Func can be from 0 to 7
	Function int

	// Emul is a string describing the type of PCI device e.g. virtio-net
	Emul string

	// Config is an optional string, depending on the device, that can be
	// used for configuration
	Config string
}

// Valid returns true if the BridgeDevice structure is valid and complete.
func (bridgeDev BridgeDevice) Valid() bool {

	if bridgeDev.Function != 0 || bridgeDev.Emul != "hostbridge" {
		return false
	}

	return true
}

// AcrnParams returns the acrn parameters built out of this bridge device.
func (bridgeDev BridgeDevice) AcrnParams(slot int, config *Config) []string {
	var acrnParams []string

	acrnParams = append(acrnParams, "-s")
	acrnParams = append(acrnParams, fmt.Sprintf("%d:%d,%s", slot,
		bridgeDev.Function, bridgeDev.Emul))

	return acrnParams
}

// LPCDevice represents a acrn LPC device
type LPCDevice struct {

	// Function is PCI function. Func can be from 0 to 7
	Function int

	// Emul is a string describing the type of PCI device e.g. virtio-net
	Emul string
}

// Valid returns true if the BridgeDevice structure is valid and complete.
func (lpcDev LPCDevice) Valid() bool {

	if lpcDev.Emul != "lpc" {
		return false
	}

	return true
}

// AcrnParams returns the acrn parameters built out of this bridge device.
func (lpcDev LPCDevice) AcrnParams(slot int, config *Config) []string {
	var acrnParams []string
	var deviceParams []string

	acrnParams = append(acrnParams, "-s")
	acrnParams = append(acrnParams, fmt.Sprintf("%d:%d,%s", slot,
		lpcDev.Function, lpcDev.Emul))

	//define UART port
	deviceParams = append(deviceParams, "-l")
	deviceParams = append(deviceParams, "com1,stdio")
	acrnParams = append(acrnParams, strings.Join(deviceParams, ""))

	return acrnParams
}

// Memory is the guest memory configuration structure.
type Memory struct {
	// Size is the amount of memory made available to the guest.
	// It should be suffixed with M or G for sizes in megabytes or
	// gigabytes respectively.
	Size string
}

// Kernel is the guest kernel configuration structure.
type Kernel struct {
	// Path is the guest kernel path on the host filesystem.
	Path string

	// InitrdPath is the guest initrd path on the host filesystem.
	InitrdPath string

	// Params is the kernel parameters string.
	Params string
}

// Config is the acrn configuration structure.
// It allows for passing custom settings and parameters to the acrn-dm API.
type Config struct {

	// Path is the acrn binary path.
	Path string

	// Path is the acrn binary path.
	CtlPath string

	// Name is the acrn guest name
	Name string

	// UUID is the acrn process UUID.
	UUID string

	// NumCPU is the number of CPUs for guest
	NumCPU uint32

	// Devices is a list of devices for acrn to create and drive.
	Devices []Device

	// Kernel is the guest kernel configuration.
	Kernel Kernel

	// Memory is the guest memory configuration.
	Memory Memory

	// ACPI virtualization support
	ACPIVirt bool

	acrnParams []string
}

func (config *Config) appendName() {
	if config.Name != "" {
		config.acrnParams = append(config.acrnParams, config.Name)
	}
}

func (config *Config) appendDevices() {
	slot := 0
	for _, d := range config.Devices {
		if d.Valid() == false {
			continue
		}

		if slot == 2 {
			slot++ /*Slot 2 is assigned for GVT-g in ACRN, so skip 2 */
		}
		config.acrnParams = append(config.acrnParams, d.AcrnParams(slot, config)...)
		slot++
	}
}

func (config *Config) appendUUID() {
	if config.UUID != "" {

		config.acrnParams = append(config.acrnParams, "-U")
		config.acrnParams = append(config.acrnParams, config.UUID)
	}
}

func (config *Config) appendACPI() {
	if config.ACPIVirt == true {

		config.acrnParams = append(config.acrnParams, "-A")
	}
}

func (config *Config) appendMemory() {
	if config.Memory.Size != "" {

		config.acrnParams = append(config.acrnParams, "-m")
		config.acrnParams = append(config.acrnParams, config.Memory.Size)
	}
}

func (config *Config) appendCPUs() {
	if config.NumCPU != 0 {

		config.acrnParams = append(config.acrnParams, "-c")
		config.acrnParams = append(config.acrnParams, fmt.Sprintf("%d", config.NumCPU))
	}

}

func (config *Config) appendKernel() {

	if config.Kernel.Path != "" {
		config.acrnParams = append(config.acrnParams, "-k")
		config.acrnParams = append(config.acrnParams, config.Kernel.Path)

		if config.Kernel.Params != "" {
			config.acrnParams = append(config.acrnParams, "-B")
			config.acrnParams = append(config.acrnParams, config.Kernel.Params)
		}
	}
}

// LaunchAcrn can be used to launch a new acrn instance.
//
// The Config parameter contains a set of acrn parameters and settings.
//
// This function writes its log output via logger parameter.
func LaunchAcrn(config Config, logger *logrus.Entry) (int, string, error) {

	mylogger = logger
	config.appendUUID()
	config.appendACPI()
	config.appendMemory()
	config.appendCPUs()
	config.appendDevices()
	config.appendKernel()
	config.appendName()

	return LaunchCustomAcrn(context.Background(), config.Path, config.acrnParams, logger)
}

// LaunchCustomAcrn can be used to launch a new acrn instance.
//
// The path parameter is used to pass the acrn executable path.
//
// params is a slice of options to pass to acrn-dm
//
// This function writes its log output via logger parameter.
func LaunchCustomAcrn(ctx context.Context, path string, params []string,
	logger *logrus.Entry) (int, string, error) {

	errStr := ""

	if path == "" {
		path = "acrn-dm"
	}

	/* #nosec */
	cmd := exec.CommandContext(ctx, path, params...)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	logger.Infof("launching %s with: %v", path, params)

	err := cmd.Start()
	if err != nil {
		logger.Errorf("Unable to launch %s: %v", path, err)
		errStr = stderr.String()
		logger.Errorf("%s", errStr)
	}
	return cmd.Process.Pid, errStr, err
}
