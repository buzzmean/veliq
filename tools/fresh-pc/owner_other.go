//go:build !linux

package main

func rootPrivateCA(string) bool { return false }
func rootUpgradeCA(string) bool { return false }
