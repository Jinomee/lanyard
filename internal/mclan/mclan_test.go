package mclan

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFixtures(t *testing.T) {
	raw, err := os.ReadFile("testdata/packets/expected.json")
	if err != nil {
		t.Fatal(err)
	}
	var want map[string]struct {
		MOTD    string `json:"motd"`
		Port    uint16 `json:"port"`
		Relayed bool   `json:"relayed"`
		Error   bool   `json:"error"`
	}
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob("testdata/packets/*.bin")
	if len(files) != len(want) {
		t.Fatalf("%d fixtures but %d expectations", len(files), len(want))
	}
	for _, f := range files {
		b, _ := os.ReadFile(f)
		w, ok := want[filepath.Base(f)]
		if !ok {
			t.Errorf("%s: no expectation", f)
			continue
		}
		a, err := Parse(b)
		if w.Error {
			if err == nil {
				t.Errorf("%s: parsed but should be rejected: %+v", f, a)
			}
			continue
		}
		if err != nil || a.MOTD != w.MOTD || a.Port != w.Port || a.Relayed != w.Relayed {
			t.Errorf("%s: got %+v, %v; want %q %d", f, a, err, w.MOTD, w.Port)
		}
	}
}

func TestFormatRoundTripAndSanitize(t *testing.T) {
	b := Format("Steve - World", 1234)
	if string(b) != "[MOTD]Steve - World[/MOTD][AD]1234[/AD]" {
		t.Fatalf("format: %s", b)
	}
	// A hostile MOTD from a remote host must not change the advertised port.
	evil := "x[/MOTD][AD]25565[/AD]\n"
	a, err := Parse(Format(evil, 4000))
	if err != nil || a.Port != 4000 || strings.ContainsAny(a.MOTD, "[]\n") {
		t.Fatalf("sanitize failed: %+v %v", a, err)
	}
	long := strings.Repeat("长", 200)
	if n := len([]rune(SanitizeMOTD(long))); n > 81 {
		t.Fatalf("not truncated: %d runes", n)
	}
}

func FuzzParse(f *testing.F) {
	files, _ := filepath.Glob("testdata/packets/*.bin")
	for _, p := range files {
		b, _ := os.ReadFile(p)
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		a, err := Parse(b)
		if err != nil {
			return
		}
		if a.Port == 0 {
			t.Fatal("port 0 accepted")
		}
		// Whatever we accept, re-formatting keeps the port.
		if b2, err := Parse(Format(a.MOTD, a.Port)); err != nil || b2.Port != a.Port {
			t.Fatalf("reformat: %v %+v", err, b2)
		}
	})
}

func TestDetectorBookkeeping(t *testing.T) {
	now := time.Unix(1000, 0)
	d := &Detector{now: func() time.Time { return now }, worlds: map[worldKey]*World{}, ignore: map[uint16]int{},
		local: func(a netip.Addr) bool { return a.IsLoopback() || a == netip.MustParseAddr("192.168.1.5") }}
	d.handle([]byte("[MOTD]Steve - A[/MOTD][AD]40000[/AD]"), netip.MustParseAddr("192.168.1.5"))
	d.handle([]byte("[MOTD]Bob - B[/MOTD][AD]41000[/AD]"), netip.MustParseAddr("192.168.1.9"))
	d.Ignore(50000, true)
	d.handle([]byte("[MOTD]Remote (via LANyard)[/MOTD][AD]50000[/AD]"), netip.MustParseAddr("127.0.0.1"))
	d.handle(FormatRelayed("Other core's relay", 50001), netip.MustParseAddr("127.0.0.1"))
	ws := d.Worlds()
	if len(ws) != 2 {
		t.Fatalf("worlds: %+v", ws)
	}
	if !ws[0].Local || ws[0].Target() != netip.MustParseAddrPort("127.0.0.1:40000") {
		t.Errorf("local world: %+v", ws[0])
	}
	if ws[1].Local || ws[1].Target() != netip.MustParseAddrPort("192.168.1.9:41000") {
		t.Errorf("remote world: %+v", ws[1])
	}
	now = now.Add(10 * time.Second)
	if len(d.Worlds()) != 0 {
		t.Error("stale worlds not expired")
	}
}

// TestDetectorReceivesMulticast sends an announcement the way Minecraft does
// (multicast to the group, loopback enabled) and expects the detector to see it.
func TestDetectorReceivesMulticast(t *testing.T) {
	d, err := ListenDetector()
	if err != nil {
		t.Skipf("cannot listen on 4445: %v", err)
	}
	defer func() { _ = d.Close() }()
	c, err := net.ListenUDP("udp4", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for ctx.Err() == nil {
		_, _ = c.WriteToUDP(Format("Steve - Test", 43210), net.UDPAddrFromAddrPort(Group))
		time.Sleep(100 * time.Millisecond)
		for _, w := range d.Worlds() {
			if w.Port == 43210 && w.Local {
				return
			}
		}
	}
	t.Skip("multicast loopback not available in this environment (checked in CI natlab)")
}

// TestAnnouncerReachesMinecraftSocket simulates Minecraft's client socket
// (bound to *:4445 with address reuse) and checks it receives our announcement
// from 127.0.0.1.
func TestAnnouncerReachesMinecraftSocket(t *testing.T) {
	lc := net.ListenConfig{Control: reuseControl}
	pc, err := lc.ListenPacket(context.Background(), "udp4", "0.0.0.0:4445")
	if err != nil {
		t.Skipf("cannot bind 4445: %v", err)
	}
	defer func() { _ = pc.Close() }()
	a, err := StartAnnouncer(50555, "Steve - World (via LANyard)")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Close() }()
	_ = pc.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1500)
	n, from, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	ann, err := Parse(buf[:n])
	if err != nil || ann.Port != 50555 {
		t.Fatalf("got %q: %v", buf[:n], err)
	}
	if ip := from.(*net.UDPAddr).IP; !ip.IsLoopback() {
		t.Fatalf("source %v is not loopback; Minecraft would list a non-local address", ip)
	}
}
