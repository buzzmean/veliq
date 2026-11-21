//go:build windows

package windowsplatform

import (
	"fmt"
	"golang.org/x/sys/windows"
	"path/filepath"
	"unsafe"
)

type ProcessDiscovery struct{}

var kernel = windows.NewLazySystemDLL("kernel32.dll")
var queryImage = kernel.NewProc("QueryFullProcessImageNameW")

func NewDiscovery() Discovery { return &ProcessDiscovery{} }
func (*ProcessDiscovery) Lookup(pid uint32) (ProcessIdentity, error) {
	handle, e := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if e != nil {
		return ProcessIdentity{}, e
	}
	defer windows.CloseHandle(handle)
	var creation, exit, kern, user windows.Filetime
	if e = windows.GetProcessTimes(handle, &creation, &exit, &kern, &user); e != nil {
		return ProcessIdentity{}, e
	}
	if exit.HighDateTime != 0 || exit.LowDateTime != 0 {
		return ProcessIdentity{}, fmt.Errorf("process has exited")
	}
	buf := make([]uint16, 32768)
	n := uint32(len(buf))
	ok, _, callErr := queryImage.Call(uintptr(handle), 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&n)))
	if ok == 0 {
		return ProcessIdentity{}, fmt.Errorf("query process image: %w", callErr)
	}
	path := windows.UTF16ToString(buf[:n])
	id := ProcessIdentity{PID: pid, Path: path, Name: filepath.Base(path), CreationTime: uint64(creation.HighDateTime)<<32 | uint64(creation.LowDateTime)}
	var basic windows.PROCESS_BASIC_INFORMATION
	if windows.NtQueryInformationProcess(handle, windows.ProcessBasicInformation, unsafe.Pointer(&basic), uint32(unsafe.Sizeof(basic)), nil) == nil && basic.InheritedFromUniqueProcessId > 0 && basic.InheritedFromUniqueProcessId <= 0xffffffff {
		parent := uint32(basic.InheritedFromUniqueProcessId)
		h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, parent)
		if err == nil {
			var c, x, k, u windows.Filetime
			if windows.GetProcessTimes(h, &c, &x, &k, &u) == nil && x.HighDateTime == 0 && x.LowDateTime == 0 {
				born := uint64(c.HighDateTime)<<32 | uint64(c.LowDateTime)
				if born <= id.CreationTime {
					id.ParentPID = parent
					id.ParentCreationTime = born
				}
			}
			windows.CloseHandle(h)
		}
	}
	return id, nil
}
func (p *ProcessDiscovery) List() ([]ProcessIdentity, error) {
	snapshot, e := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if e != nil {
		return nil, e
	}
	defer windows.CloseHandle(snapshot)
	entry := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	if e = windows.Process32First(snapshot, &entry); e != nil {
		return nil, e
	}
	out := []ProcessIdentity{}
	count := 0
	for {
		if id, e := p.Lookup(entry.ProcessID); e == nil {
			id.ParentPID = entry.ParentProcessID
			out = append(out, id)
		}
		count++
		if count >= 4096 {
			break
		}
		if windows.Process32Next(snapshot, &entry) != nil {
			break
		}
	}
	byPID := map[uint32]ProcessIdentity{}
	for _, v := range out {
		byPID[v.PID] = v
	}
	for n := range out {
		if p, ok := byPID[out[n].ParentPID]; ok && p.CreationTime <= out[n].CreationTime {
			out[n].ParentCreationTime = p.CreationTime
		}
	}
	return out, nil
}

func IsCurrent(id ProcessIdentity) bool {
	if id.PID == 0 || id.CreationTime == 0 {
		return false
	}
	h, e := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, id.PID)
	if e != nil {
		return false
	}
	defer windows.CloseHandle(h)
	var creation, exit, kernel, user windows.Filetime
	if e = windows.GetProcessTimes(h, &creation, &exit, &kernel, &user); e != nil {
		return false
	}
	return exit.HighDateTime == 0 && exit.LowDateTime == 0 && (uint64(creation.HighDateTime)<<32|uint64(creation.LowDateTime)) == id.CreationTime
}

// Parent metadata only. No PEB/memory reads, injection or signature guessing.
func (p *ProcessDiscovery) Ancestry(id ProcessIdentity) ([]ProcessIdentity, error) {
	first, err := p.Lookup(id.PID)
	if err != nil {
		return nil, err
	}
	if first.CreationTime != id.CreationTime || first.Path != id.Path {
		return nil, fmt.Errorf("process identity changed")
	}
	out := []ProcessIdentity{first}
	cur := first
	for n := 0; n < 16 && cur.ParentPID != 0; n++ {
		parent, err := p.Lookup(cur.ParentPID)
		if err != nil {
			break
		}
		if parent.CreationTime != cur.ParentCreationTime {
			break
		}
		out = append(out, parent)
		cur = parent
	}
	return out, nil
}
