package portmap

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/huin/goupnp/soap"
)

// fakeIGD is one gateway connection service.
type fakeIGD struct {
	ext      string
	extErr   error
	addErr   map[uint16]error // per external port
	mappings map[uint16]bool
}

func (f *fakeIGD) AddPortMappingCtx(_ context.Context, _ string, port uint16, _ string, _ uint16, _ string, _ bool, _ string, _ uint32) error {
	if err := f.addErr[port]; err != nil {
		return err
	}
	if f.mappings == nil {
		f.mappings = map[uint16]bool{}
	}
	f.mappings[port] = true
	return nil
}

func (f *fakeIGD) DeletePortMappingCtx(_ context.Context, _ string, port uint16, _ string) error {
	delete(f.mappings, port)
	return nil
}

func (f *fakeIGD) GetExternalIPAddressCtx(context.Context) (string, error) { return f.ext, f.extErr }

func TestUPnPUsesTheServiceWithAPublicAddress(t *testing.T) {
	cgnat := &fakeIGD{ext: "100.64.1.2"}
	dead := &fakeIGD{extErr: soapErr(upnpActionFailed)}
	good := &fakeIGD{ext: "203.0.113.9"}
	u := &upnpMapper{clients: []igdConn{{cgnat, "192.168.1.2"}, {dead, "192.168.1.2"}, {good, "192.168.1.2"}}}
	ap, _, err := u.add(context.Background(), 40000, 40000, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if ap.String() != "203.0.113.9:40000" || !good.mappings[40000] {
		t.Fatalf("mapped %v via the wrong service", ap)
	}
	if len(cgnat.mappings)+len(dead.mappings) != 0 {
		t.Fatal("rules created on services that can't help")
	}
}

func TestUPnPAllPrivateIsCGNAT(t *testing.T) {
	u := &upnpMapper{clients: []igdConn{{&fakeIGD{ext: "10.0.0.2"}, "192.168.1.2"}}}
	if _, _, err := u.add(context.Background(), 40000, 40000, time.Hour); !errors.Is(err, ErrPrivateExternal) {
		t.Fatalf("got %v", err)
	}
}

func TestUPnPRenewNeverUsesAnotherPort(t *testing.T) {
	igd := &fakeIGD{ext: "203.0.113.9"}
	u := &upnpMapper{clients: []igdConn{{igd, "192.168.1.2"}}}
	if _, _, err := u.add(context.Background(), 40000, 40000, time.Hour); err != nil {
		t.Fatal(err)
	}
	// Someone else took the port meanwhile.
	igd.addErr = map[uint16]error{40000: soapErr(upnpConflictInMapping)}
	m := &Mapping{Protocol: "upnp", Internal: 40000, m: u}
	m.External = netipPort("203.0.113.9:40000")
	_, err := u.renew(context.Background(), 40000, 40000, time.Hour)
	if !errors.Is(err, errLost) {
		t.Fatalf("renew: %v", err)
	}
	if len(igd.mappings) != 1 {
		t.Fatalf("renewal created other rules: %v", igd.mappings)
	}
	m.lost = true
	_ = m.Close()
	if !igd.mappings[40000] {
		t.Fatal("Close deleted a rule that now belongs to another computer")
	}
}

func netipPort(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }

func soapErr(code int) error {
	f := &soap.SOAPFaultError{FaultString: "UPnPError"}
	f.Detail.UPnPError.Errorcode = code
	return f
}

// A dead service (no address) and an unrelated error must not hide the
// one service that says the router's own address is private.
func TestUPnPPrivateWinsOverNoise(t *testing.T) {
	u := &upnpMapper{clients: []igdConn{
		{&fakeIGD{ext: ""}, "192.168.1.2"},                                  // unused PPP service
		{&fakeIGD{ext: "10.0.0.2"}, "192.168.1.2"},                          // the live one, behind CGNAT
		{&fakeIGD{extErr: errors.New("connection refused")}, "192.168.1.2"}, // noise
	}}
	if _, _, err := u.add(context.Background(), 40000, 40000, time.Hour); !errors.Is(err, ErrPrivateExternal) {
		t.Fatalf("got %v", err)
	}
	// A service with no address alone is not evidence of CGNAT.
	u = &upnpMapper{clients: []igdConn{{&fakeIGD{ext: ""}, "192.168.1.2"}}}
	if _, _, err := u.add(context.Background(), 40000, 40000, time.Hour); err == nil || errors.Is(err, ErrPrivateExternal) {
		t.Fatalf("got %v", err)
	}
	// A port number containing 718 is not error 718.
	if upnpCode(errors.New("AddPortMapping 37180 failed")) == upnpConflictInMapping {
		t.Fatal("substring match")
	}
}
