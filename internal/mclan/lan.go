package mclan

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"

	"golang.org/x/net/ipv4"

	"github.com/jinomee/mc/internal/netinfo"
)

// Interval is how often Minecraft (and LANyard) announce a world.
const Interval = 1500 * time.Millisecond

// staleAfter: a world not announced for this long is considered closed.
const staleAfter = 5 * time.Second

// World is a LAN world seen on the network.
type World struct {
	MOTD      string     `json:"motd"`
	Port      uint16     `json:"port"`
	Source    netip.Addr `json:"source"`
	Local     bool       `json:"local"` // announced by this computer
	FirstSeen time.Time  `json:"firstSeen"`
	LastSeen  time.Time  `json:"lastSeen"`
}

// Target is the TCP address to proxy to.
func (w World) Target() netip.AddrPort {
	if w.Local {
		return netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), w.Port)
	}
	return netip.AddrPortFrom(w.Source, w.Port)
}

type worldKey struct {
	src  netip.Addr
	port uint16
}

// Detector listens for LAN announcements (host side).
type Detector struct {
	conn *net.UDPConn
	now  func() time.Time

	mu     sync.Mutex
	worlds map[worldKey]*World
	ignore map[uint16]int
	local  func(netip.Addr) bool
}

// ListenRaw opens the LAN discovery port with address reuse and joins the
// Minecraft LAN group on every multicast-capable interface (Minecraft
// announces on its default interface with loopback enabled, so the local
// copy arrives on that interface).
func ListenRaw() (*net.UDPConn, error) {
	lc := net.ListenConfig{Control: reuseControl}
	pc, err := lc.ListenPacket(context.Background(), "udp4", "0.0.0.0:4445")
	if err != nil {
		return nil, err
	}
	conn := pc.(*net.UDPConn)
	p := ipv4.NewPacketConn(conn)
	group := &net.UDPAddr{IP: net.IP(Group.Addr().AsSlice())}
	joined := 0
	ifaces, _ := net.Interfaces()
	for i := range ifaces {
		ifi := ifaces[i]
		if ifi.Flags&net.FlagUp == 0 {
			continue
		}
		if ifi.Flags&(net.FlagMulticast|net.FlagLoopback) == 0 {
			continue
		}
		if p.JoinGroup(&ifi, group) == nil {
			joined++
		}
	}
	if joined == 0 {
		if err := p.JoinGroup(nil, group); err != nil {
			_ = conn.Close()
			return nil, errors.New("mclan: could not join the LAN discovery group on any interface")
		}
	}
	return conn, nil
}

// ListenDetector starts detecting LAN worlds.
func ListenDetector() (*Detector, error) {
	conn, err := ListenRaw()
	if err != nil {
		return nil, err
	}
	d := &Detector{
		conn:   conn,
		now:    time.Now,
		worlds: map[worldKey]*World{},
		ignore: map[uint16]int{},
		local:  netinfo.HasAddr,
	}
	go d.loop()
	return d, nil
}

func (d *Detector) loop() {
	buf := make([]byte, 1500)
	for {
		n, from, err := d.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		d.handle(buf[:n], from.Addr().Unmap())
	}
}

func (d *Detector) handle(b []byte, src netip.Addr) {
	a, err := Parse(b)
	if err != nil || a.Relayed {
		return
	}
	local := d.local(src)
	d.mu.Lock()
	defer d.mu.Unlock()
	if local && d.ignore[a.Port] > 0 {
		return // our own guest-side announcement
	}
	if local {
		src = netip.AddrFrom4([4]byte{127, 0, 0, 1}) // one entry per local world
	}
	k := worldKey{src, a.Port}
	now := d.now()
	w := d.worlds[k]
	if w == nil {
		w = &World{Port: a.Port, Source: src, Local: local, FirstSeen: now}
		d.worlds[k] = w
	}
	w.MOTD, w.LastSeen = a.MOTD, now
}

// Ignore excludes a local port (a LANyard guest listener) from detection.
// Calls nest: each Ignore(p, true) needs an Ignore(p, false).
func (d *Detector) Ignore(port uint16, on bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if on {
		d.ignore[port]++
	} else if d.ignore[port] > 0 {
		d.ignore[port]--
	}
}

// Worlds returns current worlds: local first, then most recently started.
func (d *Detector) Worlds() []World {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()
	var out []World
	for k, w := range d.worlds {
		if now.Sub(w.LastSeen) > staleAfter {
			delete(d.worlds, k)
			continue
		}
		out = append(out, *w)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Local != out[j].Local {
			return out[i].Local
		}
		if !out[i].FirstSeen.Equal(out[j].FirstSeen) {
			return out[i].FirstSeen.After(out[j].FirstSeen)
		}
		return out[i].Port < out[j].Port
	})
	return out
}

// Close stops listening.
func (d *Detector) Close() error { return d.conn.Close() }

// Announcer advertises a guest-side listener to the local Minecraft client.
type Announcer struct {
	conn   *net.UDPConn
	mc     *ipv4.PacketConn
	port   uint16
	mu     sync.Mutex
	motd   string
	cancel context.CancelFunc
	done   chan struct{}
}

// StartAnnouncer announces 127.0.0.1:port with motd every Interval. It sends
// both a unicast datagram to 127.0.0.1:4445 (reaches Minecraft's socket, which
// is bound to the wildcard address) and a multicast datagram on the loopback
// interface. Both come from 127.0.0.1, so Minecraft lists the world as
// "127.0.0.1:port" — reachable only from this computer.
func StartAnnouncer(port uint16, motd string) (*Announcer, error) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, err
	}
	a := &Announcer{conn: conn, port: port, motd: motd, done: make(chan struct{})}
	p := ipv4.NewPacketConn(conn)
	if lo := loopbackInterface(); lo != nil && p.SetMulticastInterface(lo) == nil {
		_ = p.SetMulticastLoopback(true)
		_ = p.SetMulticastTTL(1)
		a.mc = p
	}
	ctx, cancel := context.WithCancel(context.Background())
	a.cancel = cancel
	go a.loop(ctx)
	return a, nil
}

func loopbackInterface() *net.Interface {
	ifaces, _ := net.Interfaces()
	for i := range ifaces {
		if ifaces[i].Flags&net.FlagLoopback != 0 && ifaces[i].Flags&net.FlagUp != 0 {
			return &ifaces[i]
		}
	}
	return nil
}

// SetMOTD changes the announced text.
func (a *Announcer) SetMOTD(m string) {
	a.mu.Lock()
	a.motd = m
	a.mu.Unlock()
}

func (a *Announcer) loop(ctx context.Context) {
	defer close(a.done)
	unicast := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(Group.Port())}
	group := net.UDPAddrFromAddrPort(Group)
	t := time.NewTicker(Interval)
	defer t.Stop()
	for {
		a.mu.Lock()
		pkt := FormatRelayed(a.motd, a.port)
		a.mu.Unlock()
		_, _ = a.conn.WriteToUDP(pkt, unicast)
		if a.mc != nil {
			_, _ = a.conn.WriteToUDP(pkt, group)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Close stops announcing.
func (a *Announcer) Close() error {
	a.cancel()
	<-a.done
	return a.conn.Close()
}
