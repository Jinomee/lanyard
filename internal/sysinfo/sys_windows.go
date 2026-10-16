//go:build windows

package sysinfo

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"

	"github.com/jinomee/mc/internal/brand"
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
// module) whether inbound rules exist for exe or for the rule the installer
// creates. Clicking "Cancel" on the Windows prompt creates *block* rules,
// which is the most common silent failure, so those are reported too.
func FirewallStatus(exe string) string {
	q := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
	script := `$ErrorActionPreference='SilentlyContinue';` +
		`$r=@(Get-NetFirewallApplicationFilter -Program ` + q(exe) + ` | Get-NetFirewallRule)` +
		`+@(Get-NetFirewallRule -DisplayName ` + q(brand.Name()) + `);` +
		`$r=@($r | Where-Object { $_.Enabled -eq 'True' -and $_.Direction -eq 'Inbound' });` +
		`@{allow=@($r|Where-Object {$_.Action -eq 'Allow'}).Count;block=@($r|Where-Object {$_.Action -eq 'Block'}).Count}|ConvertTo-Json -Compress`
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
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
