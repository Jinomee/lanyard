package engine

import (
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/jinomee/lanyard/internal/mclan"
)

func world(local bool, src string, port uint16, age time.Duration) mclan.World {
	return mclan.World{MOTD: src, Port: port, Source: netip.MustParseAddr(src), Local: local,
		FirstSeen: time.Now().Add(-age)}
}

func TestPickWorldNeverSharesOtherComputers(t *testing.T) {
	roommate := world(false, "192.168.1.9", 41000, time.Second)
	if _, ok := pickWorld([]mclan.World{roommate}, netip.AddrPort{}); ok {
		t.Fatal("a world on another computer must never be shared")
	}
	// Even if it was somehow the previous target.
	if _, ok := pickWorld([]mclan.World{roommate}, roommate.Target()); ok {
		t.Fatal("a world on another computer must never be shared, even when sticky")
	}
	// The host opens their own world later: it is picked.
	own := world(true, "127.0.0.1", 40000, 0)
	w, ok := pickWorld([]mclan.World{own, roommate}, netip.AddrPort{})
	if !ok || w.Target() != own.Target() {
		t.Fatalf("got %+v, want the local world", w)
	}
}

func TestPickWorldSticky(t *testing.T) {
	older := world(true, "127.0.0.1", 40000, time.Minute)
	newer := world(true, "127.0.0.1", 40001, 0)
	ws := []mclan.World{newer, older} // Detector order: newest first
	if w, _ := pickWorld(ws, netip.AddrPort{}); w.Port != newer.Port {
		t.Fatalf("first pick = %d, want the newest world", w.Port)
	}
	if w, _ := pickWorld(ws, older.Target()); w.Port != older.Port {
		t.Fatalf("sticky pick = %d, want the world friends are in", w.Port)
	}
}

func TestRejectLogIsBounded(t *testing.T) {
	var buf strings.Builder
	log := slog.New(slog.NewTextHandler(&buf, nil))
	var l logLimiter
	n := 0
	for range 1000 {
		if l.allow(log) {
			n++
		}
	}
	if n != rejectLogBurst {
		t.Fatalf("%d lines allowed in one window, want %d", n, rejectLogBurst)
	}
	l.start = time.Now().Add(-rejectLogWindow - time.Second) // the window ends
	if !l.allow(log) || !strings.Contains(buf.String(), "count=980") {
		t.Fatalf("summary not logged: %q", buf.String())
	}
}
