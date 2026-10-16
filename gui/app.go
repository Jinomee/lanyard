package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"sync"
	"time"

	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/runtime"

	"github.com/jinomee/lanyard/internal/api"
	"github.com/jinomee/lanyard/internal/brand"
	"github.com/jinomee/lanyard/internal/config"
	"github.com/jinomee/lanyard/internal/engine"
	"github.com/jinomee/lanyard/internal/i18n"
	"github.com/jinomee/lanyard/internal/joincode"
	"github.com/jinomee/lanyard/internal/sysinfo"
)

// App holds the Go side of the GUI. Every exported method is callable from
// the frontend (Wails generates TypeScript bindings).
type App struct {
	ctx  context.Context
	args []string

	ensureMu sync.Mutex // one core start at a time
	mu       sync.Mutex
	client   *api.Client
	link     string // join link/code received on the command line
	quit     confirmTexts
}

// NewApp creates the app with the process arguments.
func NewApp(args []string) *App {
	a := &App{args: args, quit: confirmTexts{Title: "Quit?", Message: "Friends will be disconnected.", Quit: "Quit", Cancel: "Cancel"}}
	a.link = linkFromArgs(args)
	return a
}

// linkFromArgs finds a lanyard:// link or a bare code in arguments.
func linkFromArgs(args []string) string {
	for _, s := range args {
		if code, _, ok := joincode.Find(s); ok {
			return code
		}
	}
	return ""
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	go a.heartbeat(ctx)
}

// heartbeat tells the core this window is still open, from Go rather than the
// page, whose timers the webview throttles while minimized. A core whose
// sessions get no client traffic for a long time assumes the GUI crashed.
func (a *App) heartbeat(ctx context.Context) {
	t := time.NewTicker(20 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		a.mu.Lock()
		c := a.client
		a.mu.Unlock()
		if c != nil {
			hctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			_, _ = c.Hello(hctx)
			cancel()
		}
	}
}

// configDir returns the per-user config directory.
func configDir() (string, error) { return config.Dir() }

// isInstalled reports whether we run from an installation (the NSIS
// installer writes uninstall.exe next to the executable).
func isInstalled() bool {
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	_, err = os.Stat(filepath.Join(filepath.Dir(exe), "uninstall.exe"))
	return err == nil
}

// startCore launches this executable as a detached background core.
func startCore() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(exe, coreFlag) //nolint:gosec // our own executable, fixed argument
	sysinfo.Detach(cmd)
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}

// core returns a client for the running core, starting one if needed. A core
// that crashed or idled out is restarted transparently.
func (a *App) core(ctx context.Context) (*api.Client, error) {
	// Overlapping calls while the core is down must not each start a core.
	a.ensureMu.Lock()
	defer a.ensureMu.Unlock()
	a.mu.Lock()
	c := a.client
	a.mu.Unlock()
	if c != nil {
		if _, err := c.Hello(ctx); err == nil {
			return c, nil
		}
	}
	dir, err := configDir()
	if err != nil {
		return nil, err
	}
	c, err = api.Ensure(ctx, dir, startCore, 15*time.Second)
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	a.client = c
	a.mu.Unlock()
	return c, nil
}

// uiError is what the frontend receives for a failed call: JSON it can parse.
func uiError(err error) error {
	var ae *api.Error
	ue := engine.UserError{Key: "gui.err.core", Detail: err.Error()}
	if errors.As(err, &ae) {
		ue = ae.UserError
	}
	b, _ := json.Marshal(ue)
	return errors.New(string(b))
}

// Call performs a control API request and returns the decoded JSON.
func (a *App) Call(method, path string, body any) (any, error) {
	ctx, cancel := context.WithTimeout(a.ctx, 30*time.Second)
	defer cancel()
	c, err := a.core(ctx)
	if err != nil {
		return nil, uiError(err)
	}
	var out any
	if err := c.Do(ctx, method, path, body, &out); err != nil {
		return nil, uiError(err)
	}
	return out, nil
}

// BrandInfo is the product identity for the frontend.
type BrandInfo struct {
	Name    string `json:"name"`
	NameZh  string `json:"nameZh"`
	ID      string `json:"id"`
	Version string `json:"version"`
	Repo    string `json:"repo"`
	OS      string `json:"os"`
}

// Brand returns the product identity.
func (a *App) Brand() BrandInfo {
	b := brand.Get()
	return BrandInfo{Name: b.Name, NameZh: b.NameZh, ID: b.ID, Version: brand.Version, Repo: b.Repo, OS: goos}
}

// Translations returns the catalog for a language ("" or "auto" = sysLang).
func (a *App) Translations(lang string) map[string]string { return i18n.Catalog(lang) }

// MatchLanguage maps a browser language tag to a catalog name.
func (a *App) MatchLanguage(tag string) string { return i18n.Match(tag) }

// ReadClipboard returns the clipboard text ("" on error).
func (a *App) ReadClipboard() string {
	s, err := runtime.ClipboardGetText(a.ctx)
	if err != nil {
		return ""
	}
	if len(s) > 8192 {
		s = s[:8192]
	}
	return s
}

// CopyText puts text on the clipboard.
func (a *App) CopyText(s string) bool {
	return runtime.ClipboardSetText(a.ctx, s) == nil
}

// TakeLink returns (once) a join code passed via lanyard:// or the command line.
func (a *App) TakeLink() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	l := a.link
	a.link = ""
	return l
}

func (a *App) secondInstance(data options.SecondInstanceData) {
	if l := linkFromArgs(data.Args); l != "" {
		a.mu.Lock()
		a.link = l
		a.mu.Unlock()
		runtime.EventsEmit(a.ctx, "link", l)
	}
	runtime.WindowUnminimise(a.ctx)
	runtime.Show(a.ctx)
}

// OpenURL opens a web page in the default browser (only http/https).
func (a *App) OpenURL(u string) {
	if strings.HasPrefix(u, "https://") || strings.HasPrefix(u, "http://") {
		runtime.BrowserOpenURL(a.ctx, u)
	}
}

// ExportLogs asks where to save the diagnostic zip and writes it.
func (a *App) ExportLogs(title string) (string, error) {
	name := fmt.Sprintf("%s-logs-%s.zip", brand.Name(), time.Now().Format("20060102-150405"))
	path, err := runtime.SaveFileDialog(a.ctx, runtime.SaveDialogOptions{
		Title: title, DefaultFilename: name,
		Filters: []runtime.FileFilter{{DisplayName: "Zip", Pattern: "*.zip"}},
	})
	if err != nil {
		return "", saveError(path, err)
	}
	if path == "" {
		return "", nil // cancelled
	}
	ctx, cancel := context.WithTimeout(a.ctx, 30*time.Second)
	defer cancel()
	c, err := a.core(ctx)
	if err != nil {
		return "", uiError(err)
	}
	var data []byte
	if err := c.Do(ctx, http.MethodGet, "/v1/logs/export", nil, &data); err != nil {
		return "", uiError(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return "", saveError(path, err)
	}
	return path, nil
}

// saveError is a local file error, worded as such (not as a core problem).
func saveError(path string, err error) error {
	msg := err.Error()
	var pe *os.PathError
	if errors.As(err, &pe) {
		msg = pe.Err.Error() // the path is shown separately
	}
	b, _ := json.Marshal(engine.UserError{Key: "gui.err.save", Params: map[string]string{"path": path, "error": msg}})
	return errors.New(string(b))
}

// OpenFirewallSettings opens the OS firewall settings (Windows only).
func (a *App) OpenFirewallSettings() { openFirewallSettings() }

// confirmTexts is set by the frontend so the quit dialog is localised.
type confirmTexts struct {
	Title, Message, Quit, Cancel string
}

// SetQuitTexts localises the "quit while playing" confirmation.
func (a *App) SetQuitTexts(title, message, quit, cancel string) {
	a.mu.Lock()
	a.quit = confirmTexts{title, message, quit, cancel}
	a.mu.Unlock()
}

// beforeClose asks for confirmation when closing would disconnect people.
func (a *App) beforeClose(ctx context.Context) bool {
	a.mu.Lock()
	c, texts := a.client, a.quit
	a.mu.Unlock()
	if c == nil {
		return false
	}
	cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	st, err := c.State(cctx)
	if err != nil {
		return false
	}
	busy := st.Host != nil && (st.Host.Status == engine.HostReady || st.Host.Status == engine.HostRefreshing) ||
		st.Join != nil && st.Join.Status == engine.JoinConnected
	if !busy {
		return false
	}
	// Enter must not disconnect everyone. Windows shows its own Yes/No
	// buttons and only understands "No" as the default.
	defBtn := texts.Cancel
	if goruntime.GOOS == "windows" {
		defBtn = "No"
	}
	res, err := runtime.MessageDialog(ctx, runtime.MessageDialogOptions{
		Type: runtime.QuestionDialog, Title: texts.Title, Message: texts.Message,
		Buttons: []string{texts.Quit, texts.Cancel}, DefaultButton: defBtn, CancelButton: texts.Cancel,
	})
	if err != nil {
		return false
	}
	return res != texts.Quit && res != "Yes" && res != "Ok"
}

// shutdown stops sessions; the core then exits by itself after its idle
// timeout unless another client (e.g. the Minecraft mod) keeps using it.
func (a *App) shutdown(ctx context.Context) {
	a.mu.Lock()
	c := a.client
	a.mu.Unlock()
	if c == nil {
		return
	}
	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	_ = c.Do(cctx, http.MethodPost, "/v1/host/stop", nil, nil)
	_ = c.Do(cctx, http.MethodPost, "/v1/join/stop", nil, nil)
}
