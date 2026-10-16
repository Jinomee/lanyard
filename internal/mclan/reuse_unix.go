//go:build unix

package mclan

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// reuseControl lets several processes (Minecraft itself, LANyard) bind the
// LAN discovery port at the same time, as Java's MulticastSocket does.
func reuseControl(_, _ string, c syscall.RawConn) error {
	var serr error
	err := c.Control(func(fd uintptr) {
		serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
		if serr == nil {
			// Needed for multicast port sharing on macOS/BSD; harmless on Linux.
			_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
		}
	})
	if err != nil {
		return err
	}
	return serr
}
