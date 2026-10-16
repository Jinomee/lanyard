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
	// Start from a folder everyone can read, as on a non-system drive.
	open, err := windows.SecurityDescriptorFromString("D:(A;OICI;FA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	openDACL, _, _ := open.DACL()
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, openDACL, nil); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "core.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sddl(t, filepath.Join(dir, "core.json")), ";;;WD)") {
		t.Fatal("test setup: the file should start out readable by everyone")
	}
	if err := RestrictToOwner(dir); err != nil {
		t.Fatal(err)
	}
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	me := u.User.Sid.String()
	for _, p := range []string{dir, filepath.Join(dir, "core.json")} {
		s := sddl(t, p)
		if strings.Contains(s, ";;;WD)") || strings.Contains(s, ";;;BU)") || strings.Contains(s, ";;;AU)") {
			t.Errorf("%s: others still have access: %s", p, s)
		}
		if !strings.Contains(s, me) {
			t.Errorf("%s: the current user lost access: %s", p, s)
		}
	}
	// Still usable by us afterwards, including new files.
	if _, err := os.ReadFile(filepath.Join(dir, "core.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "new"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if s := sddl(t, filepath.Join(dir, "new")); strings.Contains(s, ";;;WD)") {
		t.Errorf("new file inherits access for everyone: %s", s)
	}
}

func sddl(t *testing.T, path string) string {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	return sd.String()
}
