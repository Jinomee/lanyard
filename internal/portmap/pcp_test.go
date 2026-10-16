package portmap

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"
)

// fakePCP answers MAP requests like a router with external IP 198.51.100.1.
func fakePCP(t *testing.T, result byte) uint16 {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	go func() {
		buf := make([]byte, 1100)
		for {
			n, from, err := c.ReadFromUDP(buf)
			if err != nil {
				return
			}
			req := buf[:n]
			if n != pcpReqLen || req[0] != 2 || req[1] != pcpOpMap || req[24+12] != 17 {
				continue
			}
			resp := make([]byte, 60)
			resp[0], resp[1], resp[3] = 2, 0x81, result
			copy(resp[4:8], req[4:8]) // grant requested lifetime
			copy(resp[24:], req[24:24+36])
			ext := netip.AddrFrom16(netip.MustParseAddr("198.51.100.1").As16()).As16()
			binary.BigEndian.PutUint16(resp[24+18:], binary.BigEndian.Uint16(req[24+16:])+1)
			copy(resp[24+20:], ext[:])
			_, _ = c.WriteToUDP(resp, from)
		}
	}()
	return uint16(c.LocalAddr().(*net.UDPAddr).Port) //nolint:gosec // test
}

func TestPCPMap(t *testing.T) {
	port := fakePCP(t, 0)
	m := &pcpMapper{gw: netip.MustParseAddr("127.0.0.1"), port: port}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ext, ttl, err := m.add(ctx, 40000, 40000, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if ext != netip.MustParseAddrPort("198.51.100.1:40001") || ttl != time.Hour {
		t.Fatalf("got %v %v", ext, ttl)
	}
}

func TestPCPRefused(t *testing.T) {
	port := fakePCP(t, 2)
	m := &pcpMapper{gw: netip.MustParseAddr("127.0.0.1"), port: port}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, _, err := m.add(ctx, 40000, 40000, time.Hour); err == nil {
		t.Fatal("expected NOT_AUTHORIZED error")
	}
}

func TestPCPNoRouter(t *testing.T) {
	c, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	port := uint16(c.LocalAddr().(*net.UDPAddr).Port) //nolint:gosec // test
	_ = c.Close()
	m := &pcpMapper{gw: netip.MustParseAddr("127.0.0.1"), port: port}
	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Millisecond)
	defer cancel()
	if _, _, err := m.add(ctx, 40000, 40000, time.Hour); err == nil {
		t.Fatal("expected timeout")
	}
}
