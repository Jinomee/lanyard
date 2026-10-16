//go:build windows

package main

import (
	"os/exec"
	"syscall"
)

const goos = "windows"

// openFirewallSettings opens "Allow an app through Windows Firewall".
func openFirewallSettings() {
	cmd := exec.Command("control.exe", "/name", "Microsoft.WindowsFirewall", "/page", "pageConfigureApps")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_ = cmd.Start()
}
