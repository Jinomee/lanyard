// Package update checks for new LANyard versions. It only ever notifies:
// nothing is downloaded or installed automatically, and checks can be turned
// off. A release publishes manifest.json plus a minisign signature
// (manifest.json.minisig); the manifest is trusted only if the signature
// verifies against the public key embedded at build time (pubkey.txt).
package update

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"time"

	"aead.dev/minisign"

	"github.com/jinomee/mc/internal/brand"
)

//go:embed pubkey.txt
var embeddedKey string

// PublicKeyOverride, if set via -ldflags -X, replaces pubkey.txt.
var PublicKeyOverride string

// File is one downloadable release artifact.
type File struct {
	Name   string   `json:"name"`
	OS     string   `json:"os"`
	Arch   string   `json:"arch"`
	Kind   string   `json:"kind"` // "installer", "portable", "core"
	Size   int64    `json:"size"`
	SHA256 string   `json:"sha256"`
	URLs   []string `json:"urls"` // GitHub first, then the maintainer's mirror
}

// Manifest describes a release.
type Manifest struct {
	Product  string            `json:"product"`
	Version  string            `json:"version"`
	Date     string            `json:"date"`
	NotesURL string            `json:"notesUrl"`
	Notes    map[string]string `json:"notes,omitempty"` // language → short text
	Files    []File            `json:"files"`
}

// Source is one place manifests are fetched from.
type Source struct {
	Name    string
	URL     string // manifest.json URL; the signature is URL + ".minisig"
	Timeout time.Duration
}

// DefaultSources returns GitHub Releases (3 s timeout, may be slow or blocked
// in mainland China) followed by the maintainer's own server.
func DefaultSources() []Source {
	b := brand.Get()
	srcs := []Source{{
		Name:    "github",
		URL:     "https://github.com/" + b.Repo + "/releases/latest/download/manifest.json",
		Timeout: 3 * time.Second,
	}}
	if b.UpdateServer != "" {
		srcs = append(srcs, Source{Name: "mirror", URL: strings.TrimRight(b.UpdateServer, "/") + "/manifest.json", Timeout: 10 * time.Second})
	}
	return srcs
}

// PublicKey returns the embedded update-signing key, or false if this build
// has none (development builds).
func PublicKey() (minisign.PublicKey, bool) {
	text := strings.TrimSpace(PublicKeyOverride)
	if text == "" {
		text = strings.TrimSpace(embeddedKey)
	}
	// Accept either the bare key or a minisign .pub file (comment + key).
	if i := strings.LastIndexByte(text, '\n'); i >= 0 {
		text = strings.TrimSpace(text[i+1:])
	}
	var pk minisign.PublicKey
	if text == "" || text == "UNSET" || pk.UnmarshalText([]byte(text)) != nil {
		return pk, false
	}
	return pk, true
}

// Errors (i18n keys "update.err.*").
var (
	ErrNotConfigured = errors.New("not_configured")
	ErrSignature     = errors.New("bad_signature")
	ErrManifest      = errors.New("bad_manifest")
	ErrUnreachable   = errors.New("unreachable")
)

// Verify checks sig over manifest bytes and decodes the manifest.
func Verify(pk minisign.PublicKey, manifest, sig []byte) (*Manifest, error) {
	if !minisign.Verify(pk, manifest, sig) {
		return nil, ErrSignature
	}
	var m Manifest
	if err := json.Unmarshal(manifest, &m); err != nil {
		return nil, ErrManifest
	}
	if m.Product != brand.Name() || parseVersion(m.Version) == nil {
		return nil, ErrManifest
	}
	return &m, nil
}

// Result is the outcome of a check.
type Result struct {
	Checked   time.Time `json:"checked"`
	Current   string    `json:"current"`
	Latest    string    `json:"latest,omitempty"`
	Available bool      `json:"available"`
	Source    string    `json:"source,omitempty"`
	NotesURL  string    `json:"notesUrl,omitempty"`
	Notes     string    `json:"notes,omitempty"`
	Download  *File     `json:"download,omitempty"`
	Error     string    `json:"error,omitempty"` // i18n key suffix
	Attempts  []string  `json:"attempts,omitempty"`
}

// Checker fetches and verifies manifests.
type Checker struct {
	Sources []Source
	Client  *http.Client
	Key     minisign.PublicKey
	Current string
	Lang    string
	// Installed selects the installer artifact instead of the portable exe.
	Installed bool
}

const maxManifest = 1 << 20

func (c *Checker) fetch(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", brand.Name()+"/"+brand.Version)
	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxManifest))
}

// Check tries each source in order and returns the first verified manifest's
// verdict. A source that serves a manifest with a bad signature is skipped,
// never trusted.
func (c *Checker) Check(ctx context.Context) Result {
	res := Result{Checked: time.Now(), Current: c.Current}
	if c.Client == nil {
		c.Client = &http.Client{}
	}
	var lastErr error = ErrUnreachable
	for _, s := range c.Sources {
		sctx, cancel := context.WithTimeout(ctx, s.Timeout)
		m, err := c.fromSource(sctx, s)
		cancel()
		if err != nil {
			res.Attempts = append(res.Attempts, s.Name+": "+err.Error())
			if errors.Is(err, ErrSignature) || errors.Is(err, ErrManifest) {
				lastErr = err
			}
			continue
		}
		res.Attempts = append(res.Attempts, s.Name+": ok")
		res.Source, res.Latest, res.NotesURL = s.Name, m.Version, m.NotesURL
		res.Notes = m.Notes[c.Lang]
		if res.Notes == "" {
			res.Notes = m.Notes["en"]
		}
		res.Available = Newer(m.Version, c.Current)
		if res.Available {
			res.Download = pick(m.Files, c.Installed)
		}
		return res
	}
	res.Error = lastErr.Error()
	return res
}

func (c *Checker) fromSource(ctx context.Context, s Source) (*Manifest, error) {
	body, err := c.fetch(ctx, s.URL)
	if err != nil {
		return nil, err
	}
	sig, err := c.fetch(ctx, s.URL+".minisig")
	if err != nil {
		return nil, err
	}
	return Verify(c.Key, body, sig)
}

func pick(files []File, installed bool) *File {
	want := "portable"
	if installed {
		want = "installer"
	}
	var fallback *File
	for i := range files {
		f := &files[i]
		if f.OS != runtime.GOOS || (f.Arch != runtime.GOARCH && f.Arch != "") {
			continue
		}
		if f.Kind == want {
			return f
		}
		if fallback == nil {
			fallback = f
		}
	}
	return fallback
}

// parseVersion parses "1.2.3" or "v1.2.3-rc.1" into [major minor patch pre?].
func parseVersion(v string) []int {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	core, pre, hasPre := strings.Cut(v, "-")
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return nil
	}
	out := make([]int, 4)
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil
		}
		out[i] = n
	}
	// Releases sort after pre-releases of the same version.
	out[3] = 1
	if hasPre {
		out[3] = 0
		_ = pre
	}
	return out
}

// Newer reports whether a is a newer version than b. Unparseable versions
// (e.g. development builds) are treated as 0.0.0-dev.
func Newer(a, b string) bool {
	va, vb := parseVersion(a), parseVersion(b)
	if va == nil {
		return false
	}
	if vb == nil {
		vb = []int{0, 0, 0, 0}
	}
	for i := range va {
		if va[i] != vb[i] {
			return va[i] > vb[i]
		}
	}
	return false
}
