//go:build windows

package windowsplatform

import (
	"errors"
	"math"
	"syscall"
	"unsafe"

	"github.com/buzzmean/veliq/core/flightrecorder"
	"golang.org/x/sys/windows"
)

var resourceKernel = windows.NewLazySystemDLL("kernel32.dll")
var resourceGetIO = resourceKernel.NewProc("GetProcessIoCounters")
var resourceGetHandles = resourceKernel.NewProc("GetProcessHandleCount")
var resourceGetSystemTimes = resourceKernel.NewProc("GetSystemTimes")
var resourceGetGroupCount = resourceKernel.NewProc("GetActiveProcessorGroupCount")
var resourceGetMemory = windows.NewLazySystemDLL("psapi.dll").NewProc("GetProcessMemoryInfo")

type resourceIOCounters struct{ ReadOperations, WriteOperations, OtherOperations, ReadBytes, WriteBytes, OtherBytes uint64 }
type resourceMemoryCounters struct {
	Size                                                                                                                                      uint32
	PageFaults                                                                                                                                uint32
	PeakWorkingSet, WorkingSet, QuotaPeakPagedPool, QuotaPagedPool, QuotaPeakNonPagedPool, QuotaNonPagedPool, Pagefile, PeakPagefile, Private uintptr
}

func resourceFiletime(v windows.Filetime) uint64 {
	return uint64(v.HighDateTime)<<32 | uint64(v.LowDateTime)
}
func resourceNanoseconds(v uint64) (uint64, bool) {
	if v > math.MaxUint64/100 {
		return 0, false
	}
	return v * 100, true
}

func resourceNativeFailure(frame *flightrecorder.ResourceSample, err error) {
	frame.ErrorCode = "RESOURCE_UNAVAILABLE"
	var code syscall.Errno
	if errors.As(err, &code) {
		frame.NativeCode = uint32(code)
		if code == windows.ERROR_ACCESS_DENIED {
			frame.ErrorCode = "ACCESS_DENIED"
		}
	}
}

func readNativeResources(pid uint32) flightrecorder.ResourceSample {
	frame := flightrecorder.ResourceSample{PID: pid, Source: "WINDOWS_NATIVE", ErrorCode: "OK"}
	// No VM_READ/WRITE, suspend, terminate, token or debug privileges are requested.
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		resourceNativeFailure(&frame, err)
		return frame
	}
	defer windows.CloseHandle(h)
	var birth, exit, kernel, user windows.Filetime
	if err = windows.GetProcessTimes(h, &birth, &exit, &kernel, &user); err != nil {
		resourceNativeFailure(&frame, err)
		return frame
	}
	if resourceFiletime(exit) != 0 {
		frame.ErrorCode = "PROCESS_EXITED"
		return frame
	}
	frame.Birth = resourceFiletime(birth)
	k, u := resourceFiletime(kernel), resourceFiletime(user)
	if k <= math.MaxUint64-u {
		if n, ok := resourceNanoseconds(k + u); ok {
			frame.CPUTimeNS = n
			frame.Known |= flightrecorder.ResourceCPU
		}
	}
	var io resourceIOCounters
	if ok, _, _ := resourceGetIO.Call(uintptr(h), uintptr(unsafe.Pointer(&io))); ok != 0 {
		frame.ReadBytes = io.ReadBytes
		frame.WriteBytes = io.WriteBytes
		frame.Known |= flightrecorder.ResourceIO
	}
	mem := resourceMemoryCounters{Size: uint32(unsafe.Sizeof(resourceMemoryCounters{}))}
	if ok, _, _ := resourceGetMemory.Call(uintptr(h), uintptr(unsafe.Pointer(&mem)), uintptr(mem.Size)); ok != 0 {
		frame.WorkingSetBytes = uint64(mem.WorkingSet)
		frame.PrivateBytes = uint64(mem.Private)
		frame.Known |= flightrecorder.ResourceWorkingSet | flightrecorder.ResourcePrivate
	}
	var handles uint32
	if ok, _, _ := resourceGetHandles.Call(uintptr(h), uintptr(unsafe.Pointer(&handles))); ok != 0 {
		frame.Handles = handles
		frame.Known |= flightrecorder.ResourceHandles
	}
	var idle, systemKernel, systemUser windows.Filetime
	groups, _, _ := resourceGetGroupCount.Call()
	// GetSystemTimes covers only the caller group on multi-group machines. Do not
	// label such a subset as a measured whole-PC CPU value.
	if ok, _, _ := resourceGetSystemTimes.Call(uintptr(unsafe.Pointer(&idle)), uintptr(unsafe.Pointer(&systemKernel)), uintptr(unsafe.Pointer(&systemUser))); ok != 0 {
		var a, b, c bool
		frame.SystemIdleNS, a = resourceNanoseconds(resourceFiletime(idle))
		frame.SystemKernelNS, b = resourceNanoseconds(resourceFiletime(systemKernel))
		frame.SystemUserNS, c = resourceNanoseconds(resourceFiletime(systemUser))
		if a && b && c && groups == 1 {
			frame.Known |= flightrecorder.ResourceSystemCPU
		}
	}
	// Per-process thread count requires whole-system enumeration on supported
	// Windows APIs. Leave it explicitly unknown rather than adding that cost.
	// Detect exit during this observation without ever reopening a reused PID.
	var after, ended, ak, au windows.Filetime
	if err = windows.GetProcessTimes(h, &after, &ended, &ak, &au); err != nil {
		failed := frame
		resourceNativeFailure(&failed, err)
		return resourceFinishIdentity(frame, 0, false, failed.ErrorCode, failed.NativeCode)
	}
	return resourceFinishIdentity(frame, resourceFiletime(after), resourceFiletime(ended) != 0, "", 0)
}
