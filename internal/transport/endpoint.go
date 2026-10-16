package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/quic-go/quic-go"
)

// Packet is a non-QUIC datagram received on an endpoint (STUN or punch).
type Packet struct {
	Data []byte
	From netip.AddrPort
}

// Endpoint is one UDP socket shared by QUIC, STUN and hole-punch packets.
// Sharing the socket is essential: the NAT mapping that STUN discovers and that
// punch packets open is the very mapping QUIC then uses.
type Endpoint struct {
	family int // 4 or 6
	conn   *net.UDPConn
	tr     *quic.Transport

	ctx    context.Context
	cancel context.CancelFunc

	mu      sync.Mutex
	waiters map[string]chan Packet // keyed by STUN transaction ID
	onPunch func(Packet)
	onOther func(Packet)
}

// ListenUDP opens an endpoint for the given family (4 or 6) on port (0 = random).
// For IPv6 the socket is IPv6-only so that both families can share one port.
func ListenUDP(family, port int) (*Endpoint, error) {
	var network string
	var ip net.IP
	switch family {
	case 4:
		network, ip = "udp4", net.IPv4zero
	case 6:
		network, ip = "udp6", net.IPv6unspecified
	default:
		return nil, fmt.Errorf("transport: bad family %d", family)
	}
	c, err := net.ListenUDP(network, &net.UDPAddr{IP: ip, Port: port})
	if err != nil {
		return nil, err
	}
	return NewEndpoint(family, c), nil
}

// NewEndpoint wraps an existing UDP socket.
func NewEndpoint(family int, c *net.UDPConn) *Endpoint {
	ctx, cancel := context.WithCancel(context.Background())
	e := &Endpoint{
		family:  family,
		conn:    c,
		tr:      &quic.Transport{Conn: c},
		ctx:     ctx,
		cancel:  cancel,
		waiters: map[string]chan Packet{},
	}
	go e.readLoop()
	return e
}

// Family returns 4 or 6.
func (e *Endpoint) Family() int { return e.family }

// Transport returns the QUIC transport bound to this socket.
func (e *Endpoint) Transport() *quic.Transport { return e.tr }

// Port returns the local UDP port.
func (e *Endpoint) Port() uint16 {
	return uint16(e.conn.LocalAddr().(*net.UDPAddr).Port) //nolint:gosec // UDP ports fit in 16 bits
}

// WriteTo sends a raw datagram from this socket.
func (e *Endpoint) WriteTo(b []byte, to netip.AddrPort) error {
	_, err := e.tr.WriteTo(b, net.UDPAddrFromAddrPort(to))
	return err
}

// Await registers interest in a STUN response with the given transaction ID.
// The returned cancel function must be called when done.
func (e *Endpoint) Await(txid []byte) (<-chan Packet, func()) {
	ch := make(chan Packet, 4)
	k := string(txid)
	e.mu.Lock()
	e.waiters[k] = ch
	e.mu.Unlock()
	return ch, func() {
		e.mu.Lock()
		if e.waiters[k] == ch {
			delete(e.waiters, k)
		}
		e.mu.Unlock()
	}
}

// OnPunch sets the handler for punch packets.
func (e *Endpoint) OnPunch(f func(Packet)) {
	e.mu.Lock()
	e.onPunch = f
	e.mu.Unlock()
}

// OnOther sets a handler for unrecognised non-QUIC packets (tests, diagnostics).
func (e *Endpoint) OnOther(f func(Packet)) {
	e.mu.Lock()
	e.onOther = f
	e.mu.Unlock()
}

func (e *Endpoint) readLoop() {
	buf := make([]byte, 2048)
	for {
		n, addr, err := e.tr.ReadNonQUICPacket(e.ctx, buf)
		if err != nil {
			return
		}
		ua, ok := addr.(*net.UDPAddr)
		if !ok {
			continue
		}
		p := Packet{Data: append([]byte(nil), buf[:n]...), From: normalizeAddrPort(ua.AddrPort())}
		e.dispatch(p)
	}
}

func (e *Endpoint) dispatch(p Packet) {
	switch {
	case isSTUN(p.Data):
		e.mu.Lock()
		ch := e.waiters[string(p.Data[8:20])]
		e.mu.Unlock()
		if ch != nil {
			select {
			case ch <- p:
			default:
			}
		}
	case IsPunch(p.Data):
		e.mu.Lock()
		f := e.onPunch
		e.mu.Unlock()
		if f != nil {
			f(p)
		}
	default:
		e.mu.Lock()
		f := e.onOther
		e.mu.Unlock()
		if f != nil {
			f(p)
		}
	}
}

// isSTUN checks the RFC 5389 magic cookie and the two zero leading bits.
func isSTUN(b []byte) bool {
	return len(b) >= 20 && b[0]&0xC0 == 0 &&
		b[4] == 0x21 && b[5] == 0x12 && b[6] == 0xA4 && b[7] == 0x42
}

// Close shuts down the endpoint and every QUIC connection on it.
func (e *Endpoint) Close() error {
	e.cancel()
	err := e.tr.Close()
	if cerr := e.conn.Close(); err == nil && !errors.Is(cerr, net.ErrClosed) {
		err = cerr
	}
	return err
}

// normalizeAddrPort unmaps IPv4-in-IPv6 addresses.
func normalizeAddrPort(ap netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}
