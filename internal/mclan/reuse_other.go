//go:build !unix && !windows

package mclan

import "syscall"

func reuseControl(_, _ string, _ syscall.RawConn) error { return nil }
