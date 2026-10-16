//go:build !unix && !windows

package sysinfo

import (
	"os"
	"os/exec"
)

func lockFile(*os.File) error { return nil }
func unlock(*os.File)         {}

// Detach is a no-op on this platform.
func Detach(*exec.Cmd) {}

// FirewallStatus is not applicable on this platform.
func FirewallStatus(string) string { return FirewallNotApplicable }

// RestrictToOwner is a no-op on this platform.
func RestrictToOwner(string) error { return nil }
