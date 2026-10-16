package connect

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jinomee/lanyard/internal/joincode"
	"github.com/jinomee/lanyard/internal/portmap"
	"github.com/jinomee/lanyard/internal/stunx"
	"github.com/jinomee/lanyard/internal/transport"
)

type testHost struct {
	ep  *transport.Endpoint
	inv *joincode.Invite
}

// startHost runs a minimal host that admits guests holding the secret.
func startHost(t *testing.T) *testHost {
	t.Helper()
	ep, err := transport.ListenUDP(4, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ep.Close() })
	id, err := transport.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	inv := &joincode.Invite{Expires: time.Now().Add(time.Hour), Fingerprint: id.Fingerprint()}
	copy(inv.Secret[:], "s3cr3t-key")
	ln, err := ep.Transport().Listen(transport.ServerTLS(id), transport.QUICConfig())
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			go func() {
				ctl, hello, err := transport.HostAcceptHello(context.Background(), conn, 3*time.Second)
				if err != nil {
					return
				}
				if string(hello.Secret) != string(inv.Secret[:]) {
					_ = conn.CloseWithError(transport.CodeBadSecret, "")
					return
				}
				_ = ctl.Send(transport.Msg{T: "admitted", MOTD: "world"})
			}()
		}
	}()
	return &testHost{ep: ep, inv: inv}
}

func deadAddr(t *testing.T) netip.AddrPort {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	ap := c.LocalAddr().(*net.UDPAddr).AddrPort()
	_ = c.Close()
	return ap
}

func guestEP(t *testing.T) *transport.Endpoint {
	ep, err := transport.ListenUDP(4, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ep.Close() })
	return ep
}

type attemptLog struct {
	mu sync.Mutex
	m  map[string]Attempt
}

func (l *attemptLog) add(a Attempt) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.m == nil {
		l.m = map[string]Attempt{}
	}
	l.m[a.Strategy+" "+a.Addr] = a
}

func TestJoinPicksLivePath(t *testing.T) {
	h := startHost(t)
	live := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), h.ep.Port())
	h.inv.Candidates = []joincode.Candidate{
		{Kind: joincode.CandIPv6, Addr: netip.MustParseAddrPort("[2001:db8::1]:1234")},
		{Kind: joincode.CandReflexive, Addr: deadAddr(t)},
		{Kind: joincode.CandLAN, Addr: live},
	}
	var log attemptLog
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	j, err := Join(ctx, JoinOptions{EP4: guestEP(t), Invite: h.inv, Name: "Alex", OnAttempt: log.add})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = j.Conn.CloseWithError(0, "") }()
	if j.Via.Strategy != StratLAN || j.MOTD != "world" {
		t.Fatalf("via %+v motd %q", j.Via, j.MOTD)
	}
	log.mu.Lock()
	defer log.mu.Unlock()
	if a := log.m["ipv6 [2001:db8::1]:1234"]; a.Outcome != OutNoIPv6 {
		t.Errorf("ipv6 attempt: %+v", a)
	}
	if a := log.m["lan "+live.String()]; a.Outcome != OutOK {
		t.Errorf("lan attempt: %+v", a)
	}
}

func TestJoinWrongSecret(t *testing.T) {
	h := startHost(t)
	inv := *h.inv
	inv.Secret[0] ^= 1
	inv.Candidates = []joincode.Candidate{{Kind: joincode.CandLAN, Addr: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), h.ep.Port())}}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := Join(ctx, JoinOptions{EP4: guestEP(t), Invite: &inv})
	var re *transport.RejectError
	if !errors.As(err, &re) || re.Reason != transport.ReasonBadSecret {
		t.Fatalf("got %v", err)
	}
}

func TestJoinCertMismatchStopsRetrying(t *testing.T) {
	h := startHost(t)
	inv := *h.inv
	inv.Fingerprint[0] ^= 1
	addr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), h.ep.Port())
	inv.Candidates = []joincode.Candidate{{Kind: joincode.CandLAN, Addr: addr}}
	var log attemptLog
	ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
	defer cancel()
	_, err := Join(ctx, JoinOptions{EP4: guestEP(t), Invite: &inv, OnAttempt: log.add})
	if err == nil {
		t.Fatal("expected failure")
	}
	a := log.m["lan "+addr.String()]
	if a.Outcome != OutCertMismatch || a.Tries != 1 {
		t.Fatalf("attempt %+v", a)
	}
	d := DiagnoseJoin(nil, &inv, []Attempt{a}, false)
	if d.Summary.Key != "diag.fail.cert_mismatch" {
		t.Fatalf("diagnosis %+v", d)
	}
}

// TestPeerReflexive: the invite lists only a dead address (as if the host's
// NAT allocated a different port toward us), but a punch from the host
// teaches the guest the real address.
func TestPeerReflexive(t *testing.T) {
	h := startHost(t)
	h.inv.Candidates = []joincode.Candidate{{Kind: joincode.CandReflexive, Addr: deadAddr(t)}}
	g := guestEP(t)
	session := [4]byte{1, 2, 3, 4}
	needReply := make(chan struct{})
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	go func() {
		<-needReply
		rep := &joincode.Reply{Session: session, Candidates: []joincode.Candidate{
			{Kind: joincode.CandLAN, Addr: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), g.Port())},
		}}
		HostPunch(ctx, PunchOptions{EP4: h.ep, Secret: h.inv.Secret, Reply: rep, Duration: 5 * time.Second})
	}()
	j, err := Join(ctx, JoinOptions{
		EP4: g, Invite: h.inv, Session: session, DirectTimeout: 500 * time.Millisecond,
		OnNeedReply: func() { close(needReply) },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = j.Conn.CloseWithError(0, "") }()
	if j.Via.Strategy != StratPeerRefl || j.Via.Phase != PhasePunch {
		t.Fatalf("via %+v", j.Via)
	}
}

func TestPunchWithWrongSessionIgnored(t *testing.T) {
	h := startHost(t)
	h.inv.Candidates = []joincode.Candidate{{Kind: joincode.CandReflexive, Addr: deadAddr(t)}}
	g := guestEP(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go HostPunch(ctx, PunchOptions{EP4: h.ep, Secret: h.inv.Secret, Reply: &joincode.Reply{
		Session:    [4]byte{9, 9, 9, 9},
		Candidates: []joincode.Candidate{{Kind: joincode.CandLAN, Addr: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), g.Port())}},
	}})
	_, err := Join(ctx, JoinOptions{EP4: g, Invite: h.inv, Session: [4]byte{1, 2, 3, 4}})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v", err)
	}
}

func TestGatherLoopback(t *testing.T) {
	srv, err := stunx.NewServer(netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("127.0.0.2"), deadAddr(t).Port(), deadAddr(t).Port())
	if err != nil {
		t.Skip(err)
	}
	defer srv.Close()
	ep := guestEP(t)
	g := Gather(context.Background(), GatherOptions{
		EP4: ep, STUNServers: []string{srv.Addr().String(), srv.AltAddr().String(), "127.0.0.1:9"},
		ProbeFiltering: true, Timeout: 2 * time.Second,
	})
	r := g.Report
	if r.Mapping != stunx.MappingNone || r.NATType != NATOpen {
		t.Errorf("mapping %v type %v", r.Mapping, r.NATType)
	}
	if r.UDPBlocked {
		t.Error("UDP reported blocked")
	}
	if !r.PublicV4.IsValid() || r.PublicV4.Port() != ep.Port() {
		t.Errorf("public %v", r.PublicV4)
	}
	found := false
	for _, c := range g.Candidates {
		found = found || c.Kind == joincode.CandReflexive
	}
	if !found {
		t.Errorf("no reflexive candidate: %v", g.Candidates)
	}
	if !r.Flags().Has(joincode.FlagMapEIM) {
		t.Errorf("flags %b", r.Flags())
	}
}

func TestDiagnoseRules(t *testing.T) {
	keys := func(d Diagnosis) string {
		var s []string
		for _, a := range d.Advice {
			s = append(s, strings.TrimPrefix(a.Key, "diag.advice."))
		}
		return strings.Join(s, ",")
	}
	sym := &Report{Mapping: stunx.MappingDependent}
	cone := &Report{Mapping: stunx.MappingIndependent, IPv6: true}
	cases := []struct {
		name  string
		local *Report
		flags joincode.Flags
		reply bool
		want  string
	}{
		{"first failure asks for reply", cone, joincode.FlagMapEIM, false, "send_reply,host_enable_upnp,ipv6_host_missing,host_firewall"},
		{"both symmetric", sym, joincode.FlagMapDep, true, "both_symmetric,host_enable_upnp,host_firewall,hotspot"},
		{"host symmetric", cone, joincode.FlagMapDep | joincode.FlagIPv6, true, "swap_host,host_enable_upnp,ipv6_firewall,host_firewall"},
		{"guest symmetric, host cgnat", sym, joincode.FlagMapEIM | joincode.FlagCGNAT, true, "guest_symmetric,host_cgnat,host_firewall,hotspot"},
		// A port-mapped host's NAT type is irrelevant: no "swap host", no "enable UPnP".
		{"host symmetric but port-mapped", cone, joincode.FlagMapDep | joincode.FlagPortMapped, true, "ipv6_host_missing,host_firewall,hotspot"},
	}
	for _, c := range cases {
		got := keys(DiagnoseJoin(c.local, &joincode.Invite{Flags: c.flags}, nil, c.reply))
		if got != c.want {
			t.Errorf("%s:\n got %s\nwant %s", c.name, got, c.want)
		}
	}
	if d := HostOutlook(sym); d.Summary.Key != "diag.host.hard" || len(d.Advice) != 1 || d.Advice[0].Key != "diag.host.enable_upnp" {
		t.Errorf("outlook %+v", d)
	}
	// The host outlook speaks to the host, never about "your friend".
	cg := &Report{Mapping: stunx.MappingIndependent, CGNAT: true}
	if d := HostOutlook(cg); len(d.Advice) != 1 || d.Advice[0].Key != "diag.host.cgnat" {
		t.Errorf("outlook %+v", d)
	}
	// A port mapping outranks a failed STUN check.
	mapped := &Report{UDPBlocked: true}
	mapped.PortMap.Mapping = &portmap.Mapping{Protocol: "upnp"}
	if d := HostOutlook(mapped); d.Summary.Key != "diag.host.good" {
		t.Errorf("outlook %+v", d)
	}
}

func TestNoSTUNServersIsNotUDPBlocked(t *testing.T) {
	g := Gather(context.Background(), GatherOptions{EP4: guestEP(t), STUNServers: nil, Timeout: time.Second})
	if g.Report.UDPBlocked {
		t.Fatal("no STUN query was sent, so nothing says UDP is blocked")
	}
	g = Gather(context.Background(), GatherOptions{EP4: guestEP(t), STUNServers: []string{"nonexistent.invalid:3478"}, Timeout: time.Second})
	if g.Report.UDPBlocked {
		t.Fatal("unresolvable servers say nothing about UDP")
	}
}

// A captured host punch resent from other addresses must not make the guest
// dial those addresses.
func TestReplayedPunchIgnored(t *testing.T) {
	h := startHost(t)
	h.inv.Candidates = []joincode.Candidate{{Kind: joincode.CandReflexive, Addr: deadAddr(t)}}
	g := guestEP(t)
	session := [4]byte{1, 2, 3, 4}
	pkt := transport.MakePunch(h.inv.Secret, transport.RoleHost, session)
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	go func() {
		time.Sleep(200 * time.Millisecond)
		for range 10 {
			c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				return
			}
			_, _ = c.WriteToUDPAddrPort(pkt, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), g.Port()))
			_ = c.Close()
		}
	}()
	var mu sync.Mutex
	var learned []netip.AddrPort
	_, _ = Join(ctx, JoinOptions{EP4: g, Invite: h.inv, Session: session,
		OnPunch: func(from netip.AddrPort) { mu.Lock(); learned = append(learned, from); mu.Unlock() }})
	mu.Lock()
	defer mu.Unlock()
	if len(learned) != 1 {
		t.Fatalf("learned %d addresses from one punch packet: %v", len(learned), learned)
	}
}
