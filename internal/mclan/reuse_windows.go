//go:build windows

package mclan

import (
	"syscall"

	"golang.org/x/sys/windows"
)

// reuseControl lets several processes (Minecraft itself, LANyard) bind the
// LAN discovery port at the same time, as Java's MulticastSocket does.
func reuseControl(_, _ string, c syscall.RawConn) error {
	var serr error
	err := c.Control(func(fd uintptr) {
		serr = windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_REUSEADDR, 1)
	})
	if err != nil {
		return err
	}
	return serr
}
