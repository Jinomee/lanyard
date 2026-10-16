package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jinomee/lanyard/internal/api"
	"github.com/jinomee/lanyard/internal/brand"
	"github.com/jinomee/lanyard/internal/engine"
	"github.com/jinomee/lanyard/internal/mclan"
	"github.com/jinomee/lanyard/internal/portmap"
	"github.com/jinomee/lanyard/internal/stunx"
)

func freeUDP(t *testing.T) uint16 {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	return uint16(c.LocalAddr().(*net.UDPAddr).Port) //nolint:gosec // test
}

type node struct {
	e *engine.Engine
	c *api.Client
}

func newNode(t *testing.T, stun []string) *node {
	t.Helper()
	e, err := engine.New(engine.Options{Dir: t.TempDir(), NoUpdateChecks: true,
		PortMap: portmap.Options{NoUPnP: true, NoNATPMP: true, NoPCP: true}})
	if err != nil {
		t.Fatal(err)
	}
	s := e.Settings()
	s.STUNServers, s.UPnP, s.PlayerName = stun, false, "Tester"
	if _, err := e.SetSettings(s); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	token := api.NewToken()
	srv := api.NewServer(e, token, 1, nil)
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { e.Close(); _ = srv.Close() })
	return &node{e: e, c: api.NewClient(ln.Addr().String(), token)}
}

func (n *node) state(t *testing.T) engine.State {
	s, err := n.c.State(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func waitFor(t *testing.T, what string, timeout time.Duration, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if f() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// fakeWorld is an echo TCP server that announces itself like an "Open to LAN" world.
func fakeWorld(t *testing.T, motd string) uint16 {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(ln.Addr().(*net.TCPAddr).Port) //nolint:gosec // test
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); _ = c.Close() }()
		}
	}()
	uc, _ := net.ListenUDP("udp4", nil)
	stop := make(chan struct{})
	go func() {
		for {
			_, _ = uc.WriteToUDP(mclan.Format(motd, port), net.UDPAddrFromAddrPort(mclan.Group))
			select {
			case <-stop:
				return
			case <-time.After(300 * time.Millisecond):
			}
		}
	}()
	t.Cleanup(func() { close(stop); _ = ln.Close(); _ = uc.Close() })
	return port
}

func echo(t *testing.T, addr string) {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	msg := []byte("hello minecraft")
	if _, err := c.Write(msg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("echo through tunnel: %q %v", got, err)
	}
}

func TestAuth(t *testing.T) {
	n := newNode(t, nil)
	bad := api.NewClient(n.c.Addr(), "wrong")
	_, err := bad.Hello(context.Background())
	var ae *api.Error
	if !errors.As(err, &ae) || ae.Status != http.StatusUnauthorized {
		t.Fatalf("wrong token: %v", err)
	}
	// DNS-rebinding guard: a non-loopback Host header is refused.
	req, _ := http.NewRequest(http.MethodGet, "http://"+n.c.Addr()+"/v1/hello", nil)
	req.Host = "evil.example:80"
	req.Header.Set("Authorization", "Bearer "+n.c.Token())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("rebinding guard: %d", resp.StatusCode)
	}
	// The scheme is case-insensitive (RFC 9110) and required.
	for header, want := range map[string]int{
		"Bearer " + n.c.Token(): http.StatusOK,
		"bearer " + n.c.Token(): http.StatusOK,
		n.c.Token():             http.StatusUnauthorized,
		"Basic " + n.c.Token():  http.StatusUnauthorized,
	} {
		req, _ := http.NewRequest(http.MethodGet, "http://"+n.c.Addr()+"/v1/hello", nil)
		req.Header.Set("Authorization", header)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != want {
			t.Errorf("Authorization %.8q...: %d, want %d", header, resp.StatusCode, want)
		}
	}
}

func TestHostJoinEndToEnd(t *testing.T) {
	srv, err := stunx.NewServer(netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("127.0.0.2"), freeUDP(t), freeUDP(t))
	if err != nil {
		t.Skip(err)
	}
	defer srv.Close()
	stun := []string{srv.Addr().String(), srv.AltAddr().String()}
	host, guest := newNode(t, stun), newNode(t, stun)
	ctx := context.Background()

	worldPort := fakeWorld(t, "Steve - Test World")
	if err := host.c.StartHost(ctx, engine.ModeAuto, 0); err != nil {
		t.Fatal(err)
	}
	var code string
	waitFor(t, "host ready with detected world", 10*time.Second, func() bool {
		s := host.state(t)
		if s.Host.Status == engine.HostError {
			t.Fatalf("host error: %+v", s.Host.Error)
		}
		code = s.Host.Code
		return s.Host.Status == engine.HostReady && s.Host.Target == "127.0.0.1:"+strconv.Itoa(int(worldPort))
	})
	if p, err := guest.e.ParseCode("Join me! " + code); err != nil || p.Kind != "invite" || p.Expired {
		t.Fatalf("parse: %+v %v", p, err)
	}

	if err := guest.c.StartJoin(ctx, code); err != nil {
		t.Fatal(err)
	}
	var local string
	waitFor(t, "guest connected", 15*time.Second, func() bool {
		s := guest.state(t)
		if s.Join.Status == engine.JoinFailed {
			t.Fatalf("join failed: %+v attempts %+v", s.Join.Failure, s.Join.Attempts)
		}
		local = s.Join.LocalAddr
		return s.Join.Status == engine.JoinConnected
	})
	if s := guest.state(t); s.Join.MOTD != "Steve - Test World" || s.Join.Via == nil {
		t.Fatalf("join state %+v", s.Join)
	}
	echo(t, local)
	echo(t, local) // a second connection (like a server-list ping, then the game)
	waitFor(t, "host lists guest", 5*time.Second, func() bool { return len(host.state(t).Host.Guests) == 1 })

	// Kick → the guest sees why.
	g := host.state(t).Host.Guests[0]
	if err := host.c.Do(ctx, http.MethodPost, "/v1/host/kick", map[string]string{"id": g.ID}, nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "guest disconnected", 5*time.Second, func() bool {
		s := guest.state(t)
		return s.Join.Status == engine.JoinDisconnected && s.Join.Failure != nil &&
			s.Join.Failure.Summary.Key == "diag.disconnected.kicked"
	})

	// Revoke: the old code stops working.
	if err := host.c.Do(ctx, http.MethodPost, "/v1/host/code/new", nil, nil); err != nil {
		t.Fatal(err)
	}
	var newCode string
	waitFor(t, "new code", 10*time.Second, func() bool {
		s := host.state(t)
		newCode = s.Host.Code
		return s.Host.Status == engine.HostReady && newCode != "" && newCode != code
	})
	if err := guest.c.StartJoin(ctx, code); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "revoked code rejected", 15*time.Second, func() bool {
		s := guest.state(t)
		return s.Join.Status == engine.JoinFailed && s.Join.Failure.Summary.Key == "diag.fail.bad_secret"
	})

	// Approval: the host must click Allow.
	hs, _ := host.c.Settings(ctx)
	hs.RequireApproval = true
	if _, err := host.c.SetSettings(ctx, hs); err != nil {
		t.Fatal(err)
	}
	if err := guest.c.StartJoin(ctx, newCode); err != nil {
		t.Fatal(err)
	}
	var pendingID string
	waitFor(t, "pending approval", 15*time.Second, func() bool {
		s := host.state(t)
		if len(s.Host.Pending) == 1 {
			pendingID = s.Host.Pending[0].ID
		}
		return pendingID != "" && guest.state(t).Join.Status == engine.JoinWaitingApproval
	})
	if s := host.state(t); s.Host.Pending[0].Name != "Tester" {
		t.Fatalf("pending %+v", s.Host.Pending)
	}
	if err := host.c.Do(ctx, http.MethodPost, "/v1/host/approve", map[string]any{"id": pendingID, "allow": true}, nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "approved guest connected", 10*time.Second, func() bool {
		s := guest.state(t)
		local = s.Join.LocalAddr
		return s.Join.Status == engine.JoinConnected
	})
	echo(t, local)

	// Host stops → guest learns the host left.
	if err := host.c.Do(ctx, http.MethodPost, "/v1/host/stop", nil, nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "guest sees host stopped", 5*time.Second, func() bool {
		s := guest.state(t)
		return s.Join.Status == engine.JoinDisconnected && s.Join.Failure.Summary.Key == "diag.disconnected.host_stopped"
	})
}

func TestBadCodes(t *testing.T) {
	n := newNode(t, nil)
	ctx := context.Background()
	cases := map[string]string{
		"hello":      "err.code.not_code",
		"LY1-ABCDEF": "err.code.damaged",
	}
	for in, key := range cases {
		err := n.c.StartJoin(ctx, in)
		var ae *api.Error
		if !errors.As(err, &ae) || ae.Key != key {
			t.Errorf("%q: got %v, want %s", in, err, key)
		}
	}
	err := n.c.SubmitReply(ctx, "LY1R-0000")
	var ae *api.Error
	if !errors.As(err, &ae) || ae.Key != "err.host.not_running" {
		t.Errorf("reply without hosting: %v", err)
	}
}

func TestSettingsValidation(t *testing.T) {
	n := newNode(t, nil)
	ctx := context.Background()
	s, _ := n.c.Settings(ctx)
	s.ManualPort = 70000
	_, err := n.c.SetSettings(ctx, s)
	var ae *api.Error
	if !errors.As(err, &ae) || ae.Key != "settings.err.manualPort" {
		t.Fatalf("got %v", err)
	}
}

// fakeCore answers /v1/hello with apiVersion and records other requests.
func fakeCore(t *testing.T, dir string, apiVersion int) *[]string {
	t.Helper()
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if r.URL.Path == "/v1/hello" {
			_ = json.NewEncoder(w).Encode(api.Hello{Product: brand.Name(), Version: "x", APIVersion: apiVersion})
		}
	}))
	t.Cleanup(srv.Close)
	if err := api.WriteInfo(dir, api.Info{PID: 1, Addr: strings.TrimPrefix(srv.URL, "http://"), Token: "t", APIVersion: apiVersion}); err != nil {
		t.Fatal(err)
	}
	return &paths
}

func TestEnsureNeverStopsANewerCore(t *testing.T) {
	dir := t.TempDir()
	paths := fakeCore(t, dir, engine.APIVersion+1)
	started := false
	_, err := api.Ensure(context.Background(), dir, func() error { started = true; return nil }, time.Second)
	var ie *api.IncompatibleError
	if !errors.As(err, &ie) || started || slices.Contains(*paths, "/v1/shutdown") {
		t.Fatalf("err %v, started %v, requests %v", err, started, *paths)
	}
}

func TestEnsureStopsAnOlderCore(t *testing.T) {
	dir := t.TempDir()
	paths := fakeCore(t, dir, engine.APIVersion-1)
	started := false
	_, _ = api.Ensure(context.Background(), dir, func() error { started = true; return nil }, 200*time.Millisecond)
	if !slices.Contains(*paths, "/v1/shutdown") || !started {
		t.Fatalf("started %v, requests %v", started, *paths)
	}
}
