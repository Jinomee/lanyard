//go:build windows

package sysinfo

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"syscall"
	"time"

	"golang.org/x/sys/windows"

	"github.com/jinomee/lanyard/internal/brand"
)

func lockFile(f *os.File) error {
	var ol windows.Overlapped
	err := windows.LockFileEx(windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &ol)
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		return ErrLocked
	}
	return err
}

func unlock(f *os.File) {
	var ol windows.Overlapped
	_ = windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, &ol)
}

// Detach configures cmd to run without a console window, independent of the parent.
func Detach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: windows.CREATE_NO_WINDOW | windows.CREATE_NEW_PROCESS_GROUP | windows.DETACHED_PROCESS,
	}
}

// FirewallStatus asks Windows Defender Firewall (via PowerShell's NetSecurity
// module) whether inbound rules exist for exe, including the rule the
// installer creates. Clicking "Cancel" on the Windows prompt creates *block*
// rules, which is the most common silent failure, so those are reported too.
//
// The path and rule name reach PowerShell as environment variables, never as
// script text: PowerShell treats several Unicode characters as quotes, so
// quoting a path into the script is not safe.
func FirewallStatus(exe string) string {
	script := `$ErrorActionPreference='SilentlyContinue';$exe=$env:LANYARD_FW_EXE;` +
		`$r=@(Get-NetFirewallApplicationFilter -Program $exe | Get-NetFirewallRule)` +
		// Rules named after the app count only if they are for this program
		// (or for any program), not just because of the name.
		`+@(Get-NetFirewallRule -DisplayName $env:LANYARD_FW_NAME | Where-Object {` +
		`$p=($_ | Get-NetFirewallApplicationFilter).Program;` +
		`$p -eq 'Any' -or [Environment]::ExpandEnvironmentVariables($p) -ieq $exe });` +
		`$r=@($r | Where-Object { $_.Enabled -eq 'True' -and $_.Direction -eq 'Inbound' } | Sort-Object -Property Name -Unique);` +
		`@{allow=@($r|Where-Object {$_.Action -eq 'Allow'}).Count;block=@($r|Where-Object {$_.Action -eq 'Block'}).Count}|ConvertTo-Json -Compress`
	// A hung PowerShell must not block every later check.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.Env = append(os.Environ(), "LANYARD_FW_EXE="+exe, "LANYARD_FW_NAME="+brand.Name())
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	out, err := cmd.Output()
	if err != nil {
		return FirewallUnknown
	}
	var res struct{ Allow, Block int }
	if json.Unmarshal(out, &res) != nil {
		return FirewallUnknown
	}
	switch {
	case res.Block > 0:
		return FirewallBlocked
	case res.Allow > 0:
		return FirewallAllowed
	}
	return FirewallMissing
}

// RestrictToOwner replaces dir's permissions with full control for the
// current user and SYSTEM only, inherited by everything inside. Unix modes
// mean nothing on Windows: a folder outside the user profile (LANYARD_HOME on
// another drive) would otherwise let every local user read the API token and
// the host identity key.
func RestrictToOwner(dir string) error {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;" + u.User.Sid.String() + ")(A;OICI;FA;;;SY)")
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}
