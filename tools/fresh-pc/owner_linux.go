//go:build linux

package main

import (
	"os"
	"syscall"
)

func rootPrivateCA(path string) bool {
	f, e := os.Lstat(path)
	if e != nil || !f.Mode().IsRegular() || f.Mode().Perm() != 0600 {
		return false
	}
	s, ok := f.Sys().(*syscall.Stat_t)
	return ok && s.Uid == 0 && s.Gid == 0
}

// Legacy root-owned CA is read only for the explicit local upgrade proof. It is
// never copied to the PC or chmod'ed; ordinary enrollment still requires 0600.
func rootUpgradeCA(path string) bool {
	f, e := os.Lstat(path)
	if e != nil || !f.Mode().IsRegular() || (f.Mode().Perm() != 0600 && f.Mode().Perm() != 0640) {
		return false
	}
	s, ok := f.Sys().(*syscall.Stat_t)
	return ok && s.Uid == 0
}
