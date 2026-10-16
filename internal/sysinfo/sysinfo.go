// Package sysinfo isolates OS-specific code behind build tags: the firewall
// rule check, detached process start and the single-instance file lock.
package sysinfo

import (
	"errors"
	"os"
)

// Firewall rule states.
const (
	FirewallAllowed       = "allowed"        // an inbound allow rule exists for this program
	FirewallBlocked       = "blocked"        // an inbound block rule exists (user clicked "Cancel")
	FirewallMissing       = "missing"        // no rule: Windows will prompt on first use
	FirewallUnknown       = "unknown"        // could not determine
	FirewallNotApplicable = "not_applicable" // not Windows
)

// ErrLocked means another process holds the lock.
var ErrLocked = errors.New("sysinfo: lock held by another process")

// Lock is an exclusive, process-lifetime file lock. The OS releases it if the
// process dies, so a crashed core never blocks the next one.
type Lock struct {
	f *os.File
}

// Release unlocks and closes the lock file.
func (l *Lock) Release() error {
	if l == nil || l.f == nil {
		return nil
	}
	unlock(l.f)
	return l.f.Close()
}

// TryLock takes an exclusive lock on path without blocking.
func TryLock(path string) (*Lock, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := lockFile(f); err != nil {
		_ = f.Close()
		return nil, err
	}
	return &Lock{f: f}, nil
}
