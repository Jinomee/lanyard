//go:build !linux && !windows

package netinfo

import "net/netip"

// temporaryV6 is not implemented here; the OS's preferred source comes first.
func temporaryV6() map[netip.Addr]bool { return nil }
