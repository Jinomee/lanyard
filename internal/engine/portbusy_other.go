//go:build !windows

package engine

// portBusy: elsewhere binding 127.0.0.1:port already fails when another
// program has the port, so there is nothing extra to check.
func portBusy(int) bool { return false }
