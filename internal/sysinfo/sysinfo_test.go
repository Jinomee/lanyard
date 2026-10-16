package sysinfo

import (
	"errors"
	"path/filepath"
	"runtime"
	"testing"
)

func TestTryLock(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x.lock")
	a, err := TryLock(p)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		// flock locks are per open file description, so a second open in the
		// same process conflicts too.
		if _, err := TryLock(p); !errors.Is(err, ErrLocked) {
			t.Fatalf("second lock: %v", err)
		}
	}
	if err := a.Release(); err != nil {
		t.Fatal(err)
	}
	b, err := TryLock(p)
	if err != nil {
		t.Fatalf("relock: %v", err)
	}
	_ = b.Release()
}
