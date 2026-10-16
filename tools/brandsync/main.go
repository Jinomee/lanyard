// Command brandsync copies the product identity from internal/brand/brand.json
// into files that cannot read it at runtime: gui/wails.json, which drives the
// executable name, Windows version info and the NSIS installer, and the URI
// scheme define in the installer script. Run it after renaming the product;
// CI runs it with -check to make sure the files are in sync.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"regexp"

	"github.com/jinomee/lanyard/internal/brand"
)

const (
	wailsJSON  = "gui/wails.json"
	projectNSI = "gui/build/windows/installer/project.nsi"
)

var uriSchemeDefine = regexp.MustCompile(`(?m)^!define URI_SCHEME ".*"(\r?)$`)

func main() {
	check := flag.Bool("check", false, "only report whether files are in sync")
	version := flag.String("version", "", "also set the product version (release builds; not committed)")
	printServer := flag.Bool("print-update-server", false, "print the update mirror base URL and exit")
	flag.Parse()
	b := brand.Get()
	if *printServer {
		fmt.Println(b.UpdateServer)
		return
	}
	syncNSI(b.ID, *check)
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
	if *version != "" {
		info["productVersion"] = *version
	}
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

// syncNSI keeps the installer's URI_SCHEME define equal to the brand id.
func syncNSI(id string, check bool) {
	orig, err := os.ReadFile(projectNSI)
	if os.IsNotExist(err) {
		return
	}
	if err != nil {
		fail(err)
	}
	if !uriSchemeDefine.Match(orig) {
		fail(fmt.Errorf("%s: no `!define URI_SCHEME \"...\"` line", projectNSI))
	}
	out := uriSchemeDefine.ReplaceAll(orig, []byte(`!define URI_SCHEME "`+id+`"${1}`)) // keep a CRLF ending
	if bytes.Equal(out, orig) {
		return
	}
	if check {
		fail(fmt.Errorf("%s is out of sync with internal/brand/brand.json; run: go run ./tools/brandsync", projectNSI))
	}
	if err := os.WriteFile(projectNSI, out, 0o644); err != nil { //nolint:gosec // project file, not secret
		fail(err)
	}
	fmt.Println("updated", projectNSI)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "brandsync:", err)
	os.Exit(1)
}
