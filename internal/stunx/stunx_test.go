package stunx

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/jinomee/mc/internal/transport"
)

func freePort(t *testing.T) uint16 {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	return uint16(c.LocalAddr().(*net.UDPAddr).Port) //nolint:gosec // test
}

func newServer(t *testing.T) *Server {
	t.Helper()
	for range 5 {
		s, err := NewServer(netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("127.0.0.2"), freePort(t), freePort(t))
		if err == nil {
			t.Cleanup(s.Close)
			return s
		}
	}
	t.Skip("could not bind test STUN server (127.0.0.2 unavailable?)")
	return nil
}

func TestBindingAndFiltering(t *testing.T) {
	srv := newServer(t)
	ep, err := transport.ListenUDP(4, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ep.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	res, err := Binding(ctx, ep, srv.Addr(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if res.Mapped.Port() != ep.Port() {
		t.Errorf("mapped %v, local port %d", res.Mapped, ep.Port())
	}
	if res.Other != srv.AltAddr() {
		t.Errorf("other = %v want %v", res.Other, srv.AltAddr())
	}
	// No NAT on loopback: every change request gets through.
	ep2, _ := transport.ListenUDP(4, 0)
	defer func() { _ = ep2.Close() }()
	f, err := ProbeFiltering(ctx, ep2, srv.Addr(), 500*time.Millisecond)
	if err != nil || f != FilteringIndependent {
		t.Fatalf("filtering = %v, %v", f, err)
	}
}

func TestQueryAllAndClassify(t *testing.T) {
	srv := newServer(t)
	ep, _ := transport.ListenUDP(4, 0)
	defer func() { _ = ep.Close() }()
	servers := []string{srv.Addr().String(), srv.AltAddr().String(), "127.0.0.1:1"}
	res := QueryAll(context.Background(), ep, servers, 4, 700*time.Millisecond)
	if !res[0].OK() || !res[1].OK() {
		t.Fatalf("queries failed: %+v", res)
	}
	if res[2].OK() {
		t.Fatal("dead server reported OK")
	}
	m, pub := ClassifyMapping(res, []netip.Addr{netip.MustParseAddr("127.0.0.1")})
	if m != MappingNone || pub.Port() != ep.Port() {
		t.Fatalf("classify = %v %v", m, pub)
	}
}

func TestClassifyMapping(t *testing.T) {
	r := func(server, mapped string) ServerResult {
		return ServerResult{Server: server, Resolved: netip.MustParseAddrPort(server), Mapped: netip.MustParseAddrPort(mapped)}
	}
	local := []netip.Addr{netip.MustParseAddr("192.168.1.2")}
	cases := []struct {
		name string
		in   []ServerResult
		want Mapping
	}{
		{"eim", []ServerResult{r("1.1.1.1:3478", "5.5.5.5:1000"), r("2.2.2.2:3478", "5.5.5.5:1000")}, MappingIndependent},
		{"symmetric", []ServerResult{r("1.1.1.1:3478", "5.5.5.5:1000"), r("2.2.2.2:3478", "5.5.5.5:1001")}, MappingDependent},
		{"single server", []ServerResult{r("1.1.1.1:3478", "5.5.5.5:1000")}, MappingUnknown},
		{"same ip twice", []ServerResult{r("1.1.1.1:3478", "5.5.5.5:1000"), r("1.1.1.1:3479", "5.5.5.5:1000")}, MappingUnknown},
		{"no nat", []ServerResult{r("1.1.1.1:3478", "192.168.1.2:1000")}, MappingNone},
		{"none", nil, MappingUnknown},
	}
	for _, c := range cases {
		if got, _ := ClassifyMapping(c.in, local); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}
