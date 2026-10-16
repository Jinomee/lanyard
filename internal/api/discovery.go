package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/jinomee/lanyard/internal/brand"
	"github.com/jinomee/lanyard/internal/engine"
	"github.com/jinomee/lanyard/internal/sysinfo"
)

// Discovery files, in the per-user config directory:
//
//	core.lock  exclusive OS lock held for the core's whole lifetime
//	core.json  {pid, addr, token, version, apiVersion}, mode 0600
//
// A client reads core.json and calls GET /v1/hello with the token. If that
// answers with a compatible apiVersion, the core is reused; otherwise the
// client starts one and waits for core.json to appear. Two cores can never
// run at once because only one can hold core.lock; a core that loses that
// race exits with ExitAlreadyRunning.
const (
	LockFile = "core.lock"
	InfoFile = "core.json"
)

// ExitAlreadyRunning is the core's exit code when another core holds the lock.
const ExitAlreadyRunning = 3

// Info is the content of core.json.
type Info struct {
	PID        int    `json:"pid"`
	Addr       string `json:"addr"`
	Token      string `json:"token"`
	Version    string `json:"version"`
	APIVersion int    `json:"apiVersion"`
}

// NewToken returns a fresh 256-bit token.
func NewToken() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}

// Claim takes the core lock in dir. It returns sysinfo.ErrLocked if another
// core is running.
func Claim(dir string) (*sysinfo.Lock, error) {
	return sysinfo.TryLock(filepath.Join(dir, LockFile))
}

// WriteInfo publishes the running core's address and token (0600).
func WriteInfo(dir string, info Info) error {
	b, err := json.Marshal(info)
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, InfoFile+".tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, InfoFile))
}

// RemoveInfo deletes core.json if it still describes pid.
func RemoveInfo(dir string, pid int) {
	p := filepath.Join(dir, InfoFile)
	if b, err := os.ReadFile(p); err == nil {
		var i Info
		if json.Unmarshal(b, &i) == nil && i.PID == pid {
			_ = os.Remove(p)
		}
	}
}

// ErrNoCore means no compatible core answered.
var ErrNoCore = errors.New("api: no running core")

// Discover connects to a running, compatible core.
func Discover(ctx context.Context, dir string) (*Client, error) {
	b, err := os.ReadFile(filepath.Join(dir, InfoFile))
	if err != nil {
		return nil, ErrNoCore
	}
	var info Info
	if err := json.Unmarshal(b, &info); err != nil || info.Addr == "" || info.Token == "" {
		return nil, ErrNoCore
	}
	c := NewClient(info.Addr, info.Token)
	ctx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()
	h, err := c.Hello(ctx)
	if err != nil {
		return nil, ErrNoCore
	}
	if h.APIVersion != engine.APIVersion || h.Product != brand.Name() {
		return nil, fmt.Errorf("%w: incompatible core %s (api %d)", ErrNoCore, h.Version, h.APIVersion)
	}
	return c, nil
}

// Ensure returns a client for the running core, starting one with start() if
// none answers, and waiting up to timeout for it to come up.
func Ensure(ctx context.Context, dir string, start func() error, timeout time.Duration) (*Client, error) {
	if c, err := Discover(ctx, dir); err == nil {
		return c, nil
	}
	if err := start(); err != nil {
		return nil, fmt.Errorf("start core: %w", err)
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if c, err := Discover(ctx, dir); err == nil {
			return c, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	return nil, ErrNoCore
}
