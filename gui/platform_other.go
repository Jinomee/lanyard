//go:build !windows

package main

import "runtime"

const goos = runtime.GOOS

func openFirewallSettings() {}
