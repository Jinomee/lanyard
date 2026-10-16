package transport

import (
	"net/netip"
	"path/filepath"
	"testing"
	"time"
)

func TestPunchPackets(t *testing.T) {
	secret := [10]byte{1, 2, 3}
	sess := [4]byte{9, 8, 7, 6}
	p := MakePunch(secret, RoleHost, sess)
	if p[0]&0xC0 != 0 {
		t.Fatal("punch packet would be mistaken for QUIC")
	}
	if isSTUN(p) {
		t.Fatal("punch packet looks like STUN")
	}
	role, s, ok := ParsePunch(secret, p)
	if !ok || role != RoleHost || s != sess {
		t.Fatalf("parse: %v %c %v", ok, role, s)
	}
	other := secret
	other[9] = 1
	if _, _, ok := ParsePunch(other, p); ok {
		t.Fatal("punch accepted with wrong secret")
	}
	p[6] ^= 1
	if _, _, ok := ParsePunch(secret, p); ok {
		t.Fatal("tampered punch accepted")
	}
}

func TestIdentityPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "id.pem")
	a, err := LoadOrCreateIdentity(path)
	if err != nil {
		t.Fatal(err)
	}
	b, err := LoadOrCreateIdentity(path)
	if err != nil {
		t.Fatal(err)
	}
	if a.Fingerprint() != b.Fingerprint() {
		t.Fatal("identity changed on reload")
	}
}

func TestEndpointDispatchesPunch(t *testing.T) {
	a, err := ListenUDP(4, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Close() }()
	b, err := ListenUDP(4, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b.Close() }()
	got := make(chan Packet, 1)
	b.OnPunch(func(p Packet) { got <- p })
	secret := [10]byte{}
	// The read loop starts lazily; send a few times.
	to := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), b.Port())
	deadline := time.After(3 * time.Second)
	for {
		if err := a.WriteTo(MakePunch(secret, RoleGuest, [4]byte{}), to); err != nil {
			t.Fatal(err)
		}
		select {
		case p := <-got:
			if p.From.Port() != a.Port() {
				t.Fatalf("from %v", p.From)
			}
			return
		case <-time.After(100 * time.Millisecond):
		case <-deadline:
			t.Fatal("punch not dispatched")
		}
	}
}
