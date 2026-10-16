package engine

import (
	"archive/zip"
	"bytes"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/jinomee/lanyard/internal/joincode"
	"github.com/jinomee/lanyard/internal/portmap"
	"github.com/jinomee/lanyard/internal/stunx"
)

func newTestEngine(t *testing.T) *Engine {
	t.Helper()
	// A local STUN server gives the host a candidate even on machines whose
	// only addresses are unusable for joining (CI containers).
	free := func() uint16 {
		c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = c.Close() }()
		return uint16(c.LocalAddr().(*net.UDPAddr).Port) //nolint:gosec // test
	}
	srv, err := stunx.NewServer(netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("127.0.0.2"), free(), free())
	if err != nil {
		t.Skip(err)
	}
	t.Cleanup(srv.Close)
	e, err := New(Options{Dir: t.TempDir(), NoUpdateChecks: true,
		PortMap: portmap.Options{NoUPnP: true, NoNATPMP: true, NoPCP: true}})
	if err != nil {
		t.Fatal(err)
	}
	s := e.Settings()
	s.STUNServers, s.UPnP, s.UDPPort = []string{srv.Addr().String(), srv.AltAddr().String()}, false, 0
	if _, err := e.SetSettings(s); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	return e
}

func waitHost(t *testing.T, e *Engine, status string) HostState {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if s := e.State().Host; s != nil && s.Status == status {
			return *s
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("host never reached %q: %+v", status, e.State().Host)
	return HostState{}
}

func signedReply(t *testing.T, secret [joincode.SecretLen]byte) string {
	t.Helper()
	rep := &joincode.Reply{Expires: time.Now().Add(time.Minute).Truncate(time.Second),
		Candidates: []joincode.Candidate{{Kind: joincode.CandLAN, Addr: netip.MustParseAddrPort("10.0.0.1:1")}}}
	if err := rep.Sign(secret); err != nil {
		t.Fatal(err)
	}
	code, err := rep.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return code
}

func TestNewCodeRevokesImmediately(t *testing.T) {
	e := newTestEngine(t)
	if err := e.StartHost(ModeManual, 25565); err != nil {
		t.Fatal(err)
	}
	first := waitHost(t, e, HostReady)
	inv, err := joincode.DecodeInvite(first.Code)
	if err != nil {
		t.Fatal(err)
	}
	oldReply := signedReply(t, inv.Secret)

	if err := e.NewCode(); err != nil {
		t.Fatal(err)
	}
	// Right away, before the network has been re-checked: no code is shown
	// and nothing signed with the old secret is accepted.
	h := e.currentHost()
	h.mu.Lock()
	revoked := h.invite == nil && h.code == ""
	h.mu.Unlock()
	if !revoked {
		t.Fatal("old invite still valid while the new code is being prepared")
	}
	if err := e.SubmitReply(oldReply); err == nil {
		t.Fatal("reply code for the revoked invite accepted during refresh")
	}

	second := waitHost(t, e, HostReady)
	if second.Code == "" || second.Code == first.Code {
		t.Fatalf("no new code: %q", second.Code)
	}
	var ue *UserError
	if err := e.SubmitReply(oldReply); err == nil {
		t.Fatal("reply code for the revoked invite accepted")
	} else if !asUserError(err, &ue) || ue.Status != http.StatusBadRequest {
		t.Fatalf("got %v", err)
	}
}

func asUserError(err error, ue **UserError) bool {
	u, ok := err.(*UserError) //nolint:errorlint // engine returns *UserError directly
	*ue = u
	return ok
}

func TestExportLogsHasNoCodes(t *testing.T) {
	e := newTestEngine(t)
	if err := e.StartHost(ModeManual, 25565); err != nil {
		t.Fatal(err)
	}
	st := waitHost(t, e, HostReady)
	b, err := e.ExportLogsBytes()
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	payload := st.Code[len(st.Code)-12:] // any tail of the code is enough to recognise it
	for _, f := range zr.File {
		r, _ := f.Open()
		data, _ := io.ReadAll(r)
		_ = r.Close()
		if strings.Contains(string(data), payload) {
			t.Errorf("%s contains the invite code", f.Name)
		}
	}
}

func TestAbandonedSessionsEndEventually(t *testing.T) {
	e := newTestEngine(t)
	if err := e.StartHost(ModeManual, 25565); err != nil {
		t.Fatal(err)
	}
	waitHost(t, e, HostReady)
	if e.Idle(time.Minute) {
		t.Fatal("idle right after hosting started")
	}
	e.mu.Lock()
	e.activity = time.Now().Add(-AbandonedAfter(time.Minute) - time.Second)
	e.mu.Unlock()
	if !e.Idle(time.Minute) {
		t.Fatal("a host session nobody has looked at for ages keeps the core alive")
	}
}

func TestStopWhileStartingIsNotAnError(t *testing.T) {
	e := newTestEngine(t)
	if err := e.StartHost(ModeManual, 25565); err != nil {
		t.Fatal(err)
	}
	e.StopHost()
	time.Sleep(300 * time.Millisecond)
	if s := e.State().Host; s == nil || s.Status != HostStopped || s.Error != nil {
		t.Fatalf("after stop: %+v", s)
	}
}
