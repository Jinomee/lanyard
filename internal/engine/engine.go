// Package engine is the LANyard core: it owns the host and join sessions,
// diagnostics, settings and update checks. The control API (package api) is a
// thin HTTP layer over it.
package engine

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/jinomee/mc/internal/brand"
	"github.com/jinomee/mc/internal/config"
	"github.com/jinomee/mc/internal/connect"
	"github.com/jinomee/mc/internal/i18n"
	"github.com/jinomee/mc/internal/logbuf"
	"github.com/jinomee/mc/internal/portmap"
	"github.com/jinomee/mc/internal/sysinfo"
	"github.com/jinomee/mc/internal/transport"
	"github.com/jinomee/mc/internal/update"
)

// UserError is an error with a user-facing i18n key.
type UserError struct {
	Key    string            `json:"key"`
	Params map[string]string `json:"params,omitempty"`
	Detail string            `json:"detail,omitempty"`
	Status int               `json:"-"`
}

func (e *UserError) Error() string {
	if e.Detail != "" {
		return e.Key + ": " + e.Detail
	}
	return e.Key
}

func userErr(status int, key string, detail ...string) *UserError {
	e := &UserError{Key: key, Status: status}
	if len(detail) > 0 {
		e.Detail = detail[0]
	}
	return e
}

// Options configures an Engine.
type Options struct {
	Dir       string // config directory
	Sink      *logbuf.Sink
	Logger    *slog.Logger
	Exe       string // path of the running executable (firewall check)
	Installed bool   // installed via the installer (affects update download choice)
	// PortMap overrides router discovery (tests).
	PortMap portmap.Options
	// NoUpdateChecks disables automatic update checks (tests, natlab).
	NoUpdateChecks bool
	// UpdateSources overrides the update sources (tests).
	UpdateSources []update.Source
}

// Engine is the core.
type Engine struct {
	opt      Options
	settings *config.Store
	id       *transport.Identity
	log      *slog.Logger

	mu       sync.Mutex
	host     *hostSession
	join     *joinSession
	diag     DiagState
	upd      UpdateState
	firewall string
	activity time.Time

	ctx    context.Context
	cancel context.CancelFunc
}

// DiagState is the result of the standalone network test.
type DiagState struct {
	Running bool               `json:"running"`
	Report  *connect.Report    `json:"report,omitempty"`
	Outlook *connect.Diagnosis `json:"outlook,omitempty"`
}

// UpdateState is the update checker's state.
type UpdateState struct {
	Enabled    bool           `json:"enabled"`
	Configured bool           `json:"configured"` // a signing key is embedded
	Checking   bool           `json:"checking"`
	Result     *update.Result `json:"result,omitempty"`
}

// New creates the engine.
func New(opt Options) (*Engine, error) {
	st, err := config.Open(opt.Dir)
	if err != nil {
		return nil, err
	}
	id, err := transport.LoadOrCreateIdentity(filepath.Join(opt.Dir, "identity.pem"))
	if err != nil {
		return nil, err
	}
	if opt.Sink == nil {
		opt.Sink = logbuf.NewSink("")
	}
	if opt.Logger == nil {
		opt.Logger = opt.Sink.Logger(nil)
	}
	ctx, cancel := context.WithCancel(context.Background())
	e := &Engine{opt: opt, settings: st, id: id, log: opt.Logger, activity: time.Now(), ctx: ctx, cancel: cancel,
		firewall: sysinfo.FirewallNotApplicable}
	_, e.upd.Configured = update.PublicKey()
	e.upd.Enabled = st.Get().UpdateChecks && !opt.NoUpdateChecks
	e.log.Info("core started", "version", brand.Version, "os", runtime.GOOS, "arch", runtime.GOARCH,
		"fingerprint", fmtFP(id.Fingerprint()))
	go e.background()
	return e, nil
}

func fmtFP(fp [12]byte) string {
	const hexd = "0123456789abcdef"
	b := make([]byte, 0, 24)
	for _, x := range fp {
		b = append(b, hexd[x>>4], hexd[x&15])
	}
	return string(b)
}

func (e *Engine) background() {
	if runtime.GOOS == "windows" && e.opt.Exe != "" {
		fw := sysinfo.FirewallStatus(e.opt.Exe)
		e.mu.Lock()
		e.firewall = fw
		e.mu.Unlock()
		e.log.Info("firewall rule check", "status", fw)
	}
	select {
	case <-time.After(5 * time.Second):
	case <-e.ctx.Done():
		return
	}
	t := time.NewTicker(24 * time.Hour)
	defer t.Stop()
	for {
		if e.settings.Get().UpdateChecks && !e.opt.NoUpdateChecks {
			e.CheckUpdate()
		}
		select {
		case <-t.C:
		case <-e.ctx.Done():
			return
		}
	}
}

// Touch records API activity (keeps the core alive).
func (e *Engine) Touch() {
	e.mu.Lock()
	e.activity = time.Now()
	e.mu.Unlock()
}

// Idle reports whether the core has had no activity for d and no session is active.
func (e *Engine) Idle(d time.Duration) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.host != nil && e.host.active() {
		return false
	}
	if e.join != nil && e.join.active() {
		return false
	}
	return time.Since(e.activity) > d
}

// Close stops all sessions.
func (e *Engine) Close() {
	e.cancel()
	e.StopHost()
	e.StopJoin()
}

// Settings returns the current settings.
func (e *Engine) Settings() config.Settings { return e.settings.Get() }

// SetSettings validates and stores settings. Network settings apply to the next session.
func (e *Engine) SetSettings(s config.Settings) (config.Settings, error) {
	out, err := e.settings.Set(s)
	if err != nil {
		var fe *config.FieldError
		if errors.As(err, &fe) {
			return out, &UserError{Key: "settings.err." + fe.Field, Status: http.StatusBadRequest}
		}
		return out, err
	}
	e.mu.Lock()
	e.upd.Enabled = out.UpdateChecks && !e.opt.NoUpdateChecks
	e.mu.Unlock()
	e.log.Info("settings changed")
	return out, nil
}

// ResetIdentity creates a new host certificate (invalidates every old code).
func (e *Engine) ResetIdentity() error {
	e.mu.Lock()
	hosting := e.host != nil && e.host.active()
	e.mu.Unlock()
	if hosting {
		return userErr(http.StatusConflict, "err.identity.hosting")
	}
	id, err := transport.NewIdentity()
	if err != nil {
		return err
	}
	path := filepath.Join(e.opt.Dir, "identity.pem")
	if err := removeFile(path); err != nil {
		return err
	}
	if id, err = transport.LoadOrCreateIdentity(path); err != nil {
		return err
	}
	e.mu.Lock()
	e.id = id
	e.mu.Unlock()
	e.log.Info("host identity reset", "fingerprint", fmtFP(id.Fingerprint()))
	return nil
}

// lang returns the language for core-rendered text (announcement MOTDs).
func (e *Engine) lang() string {
	if l := e.settings.Get().Language; l != "" {
		return l
	}
	return i18n.Default
}

// State is everything a client shows.
type State struct {
	App struct {
		Name       string `json:"name"`
		Version    string `json:"version"`
		OS         string `json:"os"`
		APIVersion int    `json:"apiVersion"`
	} `json:"app"`
	Host        *HostState  `json:"host,omitempty"`
	Join        *JoinState  `json:"join,omitempty"`
	Diagnostics DiagState   `json:"diagnostics"`
	Update      UpdateState `json:"update"`
	Firewall    string      `json:"firewall"`
}

// APIVersion is the control API version clients check for compatibility.
const APIVersion = 1

// State returns a snapshot.
func (e *Engine) State() State {
	e.mu.Lock()
	h, j := e.host, e.join
	var s State
	s.App.Name, s.App.Version, s.App.OS, s.App.APIVersion = brand.Name(), brand.Version, runtime.GOOS, APIVersion
	s.Diagnostics = e.diag
	s.Update = e.upd
	s.Firewall = e.firewall
	e.mu.Unlock()
	if h != nil {
		hs := h.state()
		s.Host = &hs
	}
	if j != nil {
		js := j.state()
		s.Join = &js
	}
	return s
}

// RunDiagnostics starts the standalone network test.
func (e *Engine) RunDiagnostics() {
	e.mu.Lock()
	if e.diag.Running {
		e.mu.Unlock()
		return
	}
	e.diag.Running = true
	e.mu.Unlock()
	go func() {
		s := e.settings.Get()
		r := e.gatherOnce(s)
		o := connect.HostOutlook(r)
		e.mu.Lock()
		e.diag = DiagState{Report: r, Outlook: &o}
		e.mu.Unlock()
		e.log.Info("diagnostics finished", "nat", r.NATType, "mapping", r.Mapping, "filtering", r.Filtering,
			"ipv6", r.IPv6, "portmap", r.PortMap.Mapping != nil, "cgnat", r.CGNAT, "udpBlocked", r.UDPBlocked, "ms", r.ElapsedMs)
	}()
}

func (e *Engine) gatherOnce(s config.Settings) *connect.Report {
	ep4, err := transport.ListenUDP(4, 0)
	if err != nil {
		return &connect.Report{Time: time.Now(), UDPBlocked: true, NATType: connect.NATUnknown}
	}
	defer func() { _ = ep4.Close() }()
	ep6, _ := transport.ListenUDP(6, 0)
	if ep6 != nil {
		defer func() { _ = ep6.Close() }()
	}
	g := connect.Gather(e.ctx, connect.GatherOptions{
		EP4: ep4, EP6: ep6, STUNServers: s.STUNServers, PortMap: s.UPnP,
		PortMapOptions: e.portmapOptions(), ProbeFiltering: true, Timeout: 4 * time.Second,
	})
	if g.Mapping != nil {
		_ = g.Mapping.Close()
	}
	return &g.Report
}

func (e *Engine) portmapOptions() portmap.Options {
	o := e.opt.PortMap
	o.Description = brand.Name()
	return o
}

// CheckUpdate runs an update check in the background.
func (e *Engine) CheckUpdate() {
	e.mu.Lock()
	if e.upd.Checking {
		e.mu.Unlock()
		return
	}
	e.upd.Checking = true
	e.mu.Unlock()
	go func() {
		var res update.Result
		pk, ok := update.PublicKey()
		if !ok {
			res = update.Result{Checked: time.Now(), Current: brand.Version, Error: update.ErrNotConfigured.Error()}
		} else {
			srcs := e.opt.UpdateSources
			if srcs == nil {
				srcs = update.DefaultSources()
			}
			c := &update.Checker{Sources: srcs, Key: pk, Current: brand.Version, Lang: e.lang(), Installed: e.opt.Installed}
			ctx, cancel := context.WithTimeout(e.ctx, 30*time.Second)
			res = c.Check(ctx)
			cancel()
		}
		e.log.Info("update check", "latest", res.Latest, "available", res.Available, "source", res.Source,
			"error", res.Error, "attempts", res.Attempts)
		e.mu.Lock()
		e.upd.Checking = false
		e.upd.Result = &res
		e.mu.Unlock()
	}()
}

// LogLines returns recent log lines.
func (e *Engine) LogLines() []string { return e.opt.Sink.Lines() }

// ExportLogs writes a zip with logs, state and settings.
func (e *Engine) ExportLogs(w io.Writer) error {
	state, _ := json.MarshalIndent(e.State(), "", "  ")
	settings, _ := json.MarshalIndent(e.settings.Get(), "", "  ")
	readme := []byte(brand.Name() + " " + brand.Version + " diagnostic export, " + time.Now().Format(time.RFC3339) +
		"\nContains IP addresses of this computer and of peers. Nothing was sent anywhere; share it only if you choose to.\n")
	return e.opt.Sink.Export(w, map[string][]byte{"state.json": state, "settings.json": settings, "README.txt": readme})
}

// ExportLogsBytes is ExportLogs into memory.
func (e *Engine) ExportLogsBytes() ([]byte, error) {
	var b bytes.Buffer
	err := e.ExportLogs(&b)
	return b.Bytes(), err
}

func randomID() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	const hexd = "0123456789abcdef"
	out := make([]byte, 0, 12)
	for _, x := range b {
		out = append(out, hexd[x>>4], hexd[x&15])
	}
	return string(out)
}
