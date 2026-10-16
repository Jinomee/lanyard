// Package corecmd implements the core's command line: serving the control
// API, a small ctl client, and a LAN packet capture helper. Both the
// standalone lanyard-core binary and the GUI binary (with --core) use it.
package corecmd

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/jinomee/mc/internal/api"
	"github.com/jinomee/mc/internal/brand"
	"github.com/jinomee/mc/internal/config"
	"github.com/jinomee/mc/internal/engine"
	"github.com/jinomee/mc/internal/logbuf"
	"github.com/jinomee/mc/internal/mclan"
	"github.com/jinomee/mc/internal/sysinfo"
)

// Main dispatches subcommands and returns the process exit code.
func Main(args []string, stdout, stderr io.Writer) int {
	cmd := "serve"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	switch cmd {
	case "serve":
		return Serve(args, stderr)
	case "ctl":
		return Ctl(args, stdout, stderr)
	case "capture-lan":
		return CaptureLAN(args, stdout, stderr)
	case "version":
		_, _ = fmt.Fprintf(stdout, "%s %s (api %d)\n", brand.Name(), brand.Version, engine.APIVersion)
		return 0
	case "help", "-h", "--help":
		usage(stdout)
		return 0
	}
	usage(stderr)
	return 2
}

func usage(w io.Writer) {
	id := brand.ID()
	_, _ = fmt.Fprintf(w, `%s core %s

usage:
  %[3]s-core [serve] [-home DIR] [-idle 60s] [-v]   run the core (control API on 127.0.0.1)
  %[3]s-core ctl [-home DIR] METHOD PATH [JSON]       call the control API of the running core
  %[3]s-core capture-lan DIR                          save Minecraft LAN announcements as fixtures
  %[3]s-core version

The config directory defaults to the per-user config dir; %s overrides it.
`, brand.Name(), brand.Version, id, config.HomeEnv())
}

func applyHome(home string) {
	if home != "" {
		_ = os.Setenv(config.HomeEnv(), home)
	}
}

// Serve runs the core until it is told to stop, receives a signal, or (with
// -idle) has been idle that long.
func Serve(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	home := fs.String("home", "", "config directory")
	idle := fs.Duration("idle", 0, "exit after this long without API calls or sessions (0 = never)")
	verbose := fs.Bool("v", false, "also log to stderr")
	installed := fs.Bool("installed", false, "running from an installation (update downloads pick the installer)")
	noUpdates := fs.Bool("no-update-checks", false, "never check for updates")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	applyHome(*home)
	dir, err := config.Dir()
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "config dir:", err)
		return 1
	}
	lock, err := api.Claim(dir)
	if errors.Is(err, sysinfo.ErrLocked) {
		_, _ = fmt.Fprintln(stderr, "another core is already running")
		return api.ExitAlreadyRunning
	} else if err != nil {
		_, _ = fmt.Fprintln(stderr, "lock:", err)
		return 1
	}
	defer func() { _ = lock.Release() }()

	sink := logbuf.NewSink(filepath.Join(dir, "logs"))
	defer func() { _ = sink.Close() }()
	var extra io.Writer
	if *verbose {
		extra = stderr
	}
	logger := sink.Logger(extra)
	exe, _ := os.Executable()
	eng, err := engine.New(engine.Options{Dir: dir, Sink: sink, Logger: logger, Exe: exe,
		Installed: *installed, NoUpdateChecks: *noUpdates})
	if err != nil {
		logger.Error("engine", "err", err)
		_, _ = fmt.Fprintln(stderr, "engine:", err)
		return 1
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "listen:", err)
		return 1
	}
	stop := make(chan string, 1)
	token := api.NewToken()
	pid := os.Getpid()
	srv := api.NewServer(eng, token, pid, func() { stop <- "shutdown request" })
	go func() { _ = srv.Serve(ln) }()
	if err := api.WriteInfo(dir, api.Info{PID: pid, Addr: ln.Addr().String(), Token: token,
		Version: brand.Version, APIVersion: engine.APIVersion}); err != nil {
		_, _ = fmt.Fprintln(stderr, "write core.json:", err)
		return 1
	}
	logger.Info("control API listening", "addr", ln.Addr().String(), "idleExit", idle.String())

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	reason := ""
	for reason == "" {
		select {
		case s := <-sig:
			reason = "signal " + s.String()
		case r := <-stop:
			reason = r
		case <-tick.C:
			if *idle > 0 && eng.Idle(*idle) {
				reason = "idle"
			}
		}
	}
	logger.Info("core stopping", "reason", reason)
	api.RemoveInfo(dir, pid)
	eng.Close()
	_ = srv.Close()
	return 0
}

// Ctl calls the running core's API and prints the JSON response.
func Ctl(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("ctl", flag.ContinueOnError)
	fs.SetOutput(stderr)
	home := fs.String("home", "", "config directory")
	timeout := fs.Duration("timeout", 30*time.Second, "request timeout")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	applyHome(*home)
	rest := fs.Args()
	if len(rest) < 2 {
		_, _ = fmt.Fprintln(stderr, "usage: ctl METHOD PATH [JSON]")
		return 2
	}
	dir, err := config.Dir()
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	c, err := api.Discover(ctx, dir)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	var body any
	if len(rest) > 2 {
		var v any
		if err := json.Unmarshal([]byte(rest[2]), &v); err != nil {
			_, _ = fmt.Fprintln(stderr, "body:", err)
			return 2
		}
		body = v
	}
	var out []byte
	if err := c.Do(ctx, strings.ToUpper(rest[0]), rest[1], body, &out); err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	_, _ = stdout.Write(out)
	return 0
}

// CaptureLAN writes every Minecraft LAN announcement it hears to DIR, one
// .bin file per distinct payload, until interrupted.
func CaptureLAN(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		_, _ = fmt.Fprintln(stderr, "usage: capture-lan DIR")
		return 2
	}
	dir := args[0]
	if err := os.MkdirAll(dir, 0o755); err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	pc, err := mclan.ListenRaw()
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	defer func() { _ = pc.Close() }()
	_, _ = fmt.Fprintln(stdout, "listening on 224.0.2.60:4445; open a world to LAN in Minecraft (Ctrl+C to stop)")
	seen := map[string]bool{}
	buf := make([]byte, 1500)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return 0
		}
		p := string(buf[:n])
		if seen[p] {
			continue
		}
		seen[p] = true
		name := filepath.Join(dir, fmt.Sprintf("captured_%s.bin", time.Now().Format("20060102_150405")))
		if err := os.WriteFile(name, buf[:n], 0o644); err != nil { //nolint:gosec // fixture files are not secret
			_, _ = fmt.Fprintln(stderr, err)
			return 1
		}
		_, _ = fmt.Fprintf(stdout, "%s from %v: %q\n", name, from, p)
	}
}
