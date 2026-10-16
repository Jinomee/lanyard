package engine

import (
	"net"
	"testing"
)

func TestPortBusySeesWildcardListener(t *testing.T) {
	ln, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if !portBusy(port) {
		t.Fatal("a 0.0.0.0 listener was not noticed")
	}
	_ = ln.Close()
	if portBusy(port) {
		t.Fatal("a free port reported busy")
	}
}
