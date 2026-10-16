//go:build unix

package sysinfo

import (
	"errors"
	"os"
	"os/exec"
	"syscall"

	"golang.org/x/sys/unix"
)

func lockFile(f *os.File) error {
	err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if errors.Is(err, unix.EWOULDBLOCK) {
		return ErrLocked
	}
	return err
}

func unlock(f *os.File) { _ = unix.Flock(int(f.Fd()), unix.LOCK_UN) }

// Detach configures cmd to outlive its parent without a terminal.
func Detach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}

// FirewallStatus reports whether the OS firewall allows inbound traffic for exe.
func FirewallStatus(string) string { return FirewallNotApplicable }
