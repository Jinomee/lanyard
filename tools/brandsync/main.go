// Command brandsync copies the product identity from internal/brand/brand.json
// into files that cannot read it at runtime (gui/wails.json, which drives the
// executable name, Windows version info and the NSIS installer, including the
// URI scheme registration). Run it after renaming the product; CI runs it
// with -check to make sure the files are in sync.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/jinomee/mc/internal/brand"
)

const wailsJSON = "gui/wails.json"

func main() {
	check := flag.Bool("check", false, "only report whether files are in sync")
	flag.Parse()
	b := brand.Get()
	orig, err := os.ReadFile(wailsJSON)
	if os.IsNotExist(err) {
		return
	}
	if err != nil {
		fail(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(orig, &cfg); err != nil {
		fail(err)
	}
	cfg["name"] = b.Name
	cfg["outputfilename"] = b.Name
	info, _ := cfg["info"].(map[string]any)
	if info == nil {
		info = map[string]any{}
	}
	info["productName"] = b.Name
	info["companyName"] = b.Name + " contributors"
	info["copyright"] = "GPL-3.0-or-later — " + b.Name + " contributors"
	info["comments"] = b.Name + " (" + b.NameZh + ")"
	info["protocols"] = []any{map[string]any{
		"scheme":      b.ID,
		"description": b.Name + " join link",
		"role":        "Viewer",
	}}
	cfg["info"] = info
	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		fail(err)
	}
	out = append(out, '\n')
	if bytes.Equal(out, orig) {
		return
	}
	if *check {
		fail(fmt.Errorf("%s is out of sync with internal/brand/brand.json; run: go run ./tools/brandsync", wailsJSON))
	}
	if err := os.WriteFile(wailsJSON, out, 0o644); err != nil { //nolint:gosec // project file, not secret
		fail(err)
	}
	fmt.Println("updated", wailsJSON)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "brandsync:", err)
	os.Exit(1)
}
