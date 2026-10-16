// Package config holds per-user paths and settings.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/jinomee/lanyard/internal/brand"
)

// DefaultSTUNServers mixes globally operated servers with servers operated in
// mainland China, so that at least two (needed to classify the NAT) answer
// from either side of the Great Firewall. All are queried in parallel.
// The list is checked by the stun-check CI job (cmd/stuncheck); see
// docs/DECISIONS.md for the last verification.
var DefaultSTUNServers = []string{
	"stun.miwifi.com:3478",        // Xiaomi (CN), RFC 5780
	"stun.chat.bilibili.com:3478", // Bilibili (CN)
	"stun.douyucdn.cn:18000",      // Douyu (CN), RFC 5780
	"stun.cdnbye.com:3478",        // CDNBye (CN)
	"stun.cloudflare.com:3478",    // Cloudflare (global anycast)
	"stun.l.google.com:19302",     // Google (global; blocked in CN, harmless)
	"stun.nextcloud.com:3478",     // Nextcloud (EU), RFC 5780
	"stun.freeswitch.org:3478",    // FreeSWITCH (US), RFC 5780
}

// Settings are the user-editable options.
type Settings struct {
	Language        string   `json:"language"`        // "" = follow system, "en", "zh-CN"
	PlayerName      string   `json:"playerName"`      // sent to hosts you join
	STUNServers     []string `json:"stunServers"`     // host:port
	UPnP            bool     `json:"upnp"`            // ask the router for a port mapping
	UDPPort         int      `json:"udpPort"`         // host UDP port; 0 = random
	GuestPort       int      `json:"guestPort"`       // local TCP port for joined worlds; 0 = random
	ManualPort      int      `json:"manualPort"`      // Minecraft server port in manual mode
	RequireApproval bool     `json:"requireApproval"` // host approves each join
	InviteHours     int      `json:"inviteHours"`     // invite lifetime
	UpdateChecks    bool     `json:"updateChecks"`    // check for new versions
	RelayAddress    string   `json:"relayAddress"`    // v1.1 self-hosted relay; unused in v1
}

// Defaults returns the default settings.
func Defaults() Settings {
	name := "Player"
	if u, err := user.Current(); err == nil {
		n := u.Username
		if i := strings.LastIndexAny(n, `\/`); i >= 0 {
			n = n[i+1:] // DOMAIN\user on Windows
		}
		if n != "" {
			name = n
		}
	}
	return Settings{
		PlayerName:   clip(name, 32),
		STUNServers:  append([]string(nil), DefaultSTUNServers...),
		UPnP:         true,
		ManualPort:   25565,
		InviteHours:  24,
		UpdateChecks: true,
	}
}

func clip(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}

// FieldError names an invalid setting (i18n key "settings.err.<Field>").
type FieldError struct{ Field string }

func (e *FieldError) Error() string { return "invalid setting: " + e.Field }

// Validate checks and normalises settings.
func (s *Settings) Validate() error {
	s.PlayerName = strings.TrimSpace(clip(s.PlayerName, 32))
	if s.PlayerName == "" {
		return &FieldError{"playerName"}
	}
	switch s.Language {
	case "", "en", "zh-CN":
	default:
		return &FieldError{"language"}
	}
	var servers []string
	for _, x := range s.STUNServers {
		x = strings.TrimSpace(x)
		if x == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(x); err != nil {
			return &FieldError{"stunServers"}
		}
		servers = append(servers, x)
	}
	if len(servers) > 20 {
		return &FieldError{"stunServers"}
	}
	s.STUNServers = servers
	if s.UDPPort != 0 && (s.UDPPort < 1024 || s.UDPPort > 65535) {
		return &FieldError{"udpPort"}
	}
	if s.GuestPort != 0 && (s.GuestPort < 1024 || s.GuestPort > 65535) {
		return &FieldError{"guestPort"}
	}
	if s.ManualPort < 1 || s.ManualPort > 65535 {
		return &FieldError{"manualPort"}
	}
	if s.InviteHours < 1 || s.InviteHours > 24*30 {
		return &FieldError{"inviteHours"}
	}
	return nil
}

// HomeEnv overrides the config directory (tests, multiple instances).
func HomeEnv() string { return strings.ToUpper(brand.ID()) + "_HOME" }

// Dir returns the per-user configuration directory, creating it.
func Dir() (string, error) {
	d := os.Getenv(HomeEnv())
	if d == "" {
		base, err := os.UserConfigDir()
		if err != nil {
			return "", err
		}
		d = filepath.Join(base, brand.Name())
	}
	if err := os.MkdirAll(d, 0o700); err != nil {
		return "", err
	}
	return d, nil
}

// Store loads and saves settings.json.
type Store struct {
	path string
	mu   sync.Mutex
	cur  Settings
}

// Open loads settings from dir, falling back to defaults for a missing or
// unreadable file (a corrupt file is kept as settings.json.bad).
func Open(dir string) (*Store, error) {
	st := &Store{path: filepath.Join(dir, "settings.json"), cur: Defaults()}
	b, err := os.ReadFile(st.path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return st, nil
	case err != nil:
		return nil, err
	}
	s := Defaults()
	if err := json.Unmarshal(b, &s); err != nil || s.Validate() != nil {
		_ = os.Rename(st.path, st.path+".bad")
		return st, nil //nolint:nilerr // a corrupt file falls back to defaults
	}
	st.cur = s
	return st, nil
}

// Get returns a copy of the current settings.
func (st *Store) Get() Settings {
	st.mu.Lock()
	defer st.mu.Unlock()
	s := st.cur
	s.STUNServers = append([]string(nil), s.STUNServers...)
	return s
}

// Set validates and persists settings.
func (st *Store) Set(s Settings) (Settings, error) {
	if err := s.Validate(); err != nil {
		return Settings{}, err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return Settings{}, err
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	tmp := st.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return Settings{}, fmt.Errorf("save settings: %w", err)
	}
	if err := os.Rename(tmp, st.path); err != nil {
		return Settings{}, fmt.Errorf("save settings: %w", err)
	}
	st.cur = s
	return s, nil
}
