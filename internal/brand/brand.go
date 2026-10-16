// Package brand holds the product identity. Every user-visible product name,
// the URI scheme, the config-directory name and the update-server URL derive
// from brand.json, so renaming the product is a one-file change (run
// `go run ./tools/brandsync` afterwards to propagate it into gui/wails.json).
package brand

import (
	_ "embed"
	"encoding/json"
)

//go:embed brand.json
var raw []byte

// Info is the decoded brand.json.
type Info struct {
	// Name is the product name shown to users (English and default).
	Name string `json:"name"`
	// NameZh is the Simplified Chinese product name.
	NameZh string `json:"nameZh"`
	// ID is the lowercase machine identifier: config directory, URI scheme,
	// firewall rule name, ALPN prefix.
	ID string `json:"id"`
	// Repo is the GitHub "owner/name" used for release update checks.
	Repo string `json:"repo"`
	// UpdateServer is the maintainer's own update mirror (base URL, trailing slash).
	UpdateServer string `json:"updateServer"`
}

var info = mustParse(raw)

func mustParse(b []byte) Info {
	var i Info
	if err := json.Unmarshal(b, &i); err != nil {
		panic("brand: invalid brand.json: " + err.Error())
	}
	if i.Name == "" || i.ID == "" {
		panic("brand: brand.json must set name and id")
	}
	return i
}

// Version is set at build time with -ldflags "-X github.com/jinomee/mc/internal/brand.Version=1.2.3".
var Version = "0.0.0-dev"

// Get returns the brand information.
func Get() Info { return info }

// Name returns the product name.
func Name() string { return info.Name }

// ID returns the lowercase product identifier.
func ID() string { return info.ID }

// URIScheme returns the custom URI scheme used for join links.
func URIScheme() string { return info.ID }

// IsDevBuild reports whether this binary was built without a release version.
func IsDevBuild() bool { return Version == "0.0.0-dev" }
