//go:build windows

package sysinfo

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// The path must never be interpreted as PowerShell, whatever quote
// characters it contains (PowerShell also treats ‘ ’ ‚ ‛ as single quotes).
func TestFirewallStatusPathIsData(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "pwned")
	for _, q := range []string{"'", "\u2018", "\u2019", "\u201a", "\u201b"} {
		exe := `C:\Users\O` + q + `Brien` + q + `;Set-Content -Path '` + marker + `' -Value 1;` + q + `\LANyard.exe`
		got := FirewallStatus(exe)
		if _, err := os.Stat(marker); err == nil {
			t.Fatalf("quote %q: the path was executed as PowerShell", q)
		}
		// On a normal Windows machine the query itself works, so "unknown"
		// would mean the script broke.
		if got != FirewallMissing {
			t.Errorf("quote %q: status = %q, want %q", q, got, FirewallMissing)
		}
	}
}

func TestRestrictToOwner(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "core.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RestrictToOwner(dir); err != nil {
		t.Fatal(err)
	}
	// Still usable by us afterwards.
	if _, err := os.ReadFile(filepath.Join(dir, "core.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "new"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if s := sd.String(); strings.Contains(s, ";;;BU)") || strings.Contains(s, ";;;WD)") || strings.Contains(s, ";;;AU)") {
		t.Fatalf("users/everyone still have access: %s", s)
	}
}
