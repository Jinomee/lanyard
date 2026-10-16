package transport

import (
	"context"
	"errors"
	"net"
	"net/netip"
)

// Relay is the extension point for the v1.1 user-self-hosted relay.
//
// A relay hands out a datagram socket whose packets are forwarded through a
// relay server the *user* runs (there is never a default relay). Because QUIC
// runs end-to-end over the returned PacketConn, certificate pinning and the
// secret check are unchanged: the relay only ever sees encrypted QUIC packets.
//
// Planned v1.1 flow: the host calls Allocate and adds the relay address as a
// candidate (kind "relay") to its invite; the guest's connect strategies get a
// "relay" entry that dials the host's relayed address through its own
// allocation. Nothing else in the engine needs to change.
type Relay interface {
	// Name identifies the relay in logs and diagnostics.
	Name() string
	// Allocate returns a packet socket on the relay and the public address
	// peers can send to.
	Allocate(ctx context.Context) (net.PacketConn, netip.AddrPort, error)
}

// ErrNoRelay is returned when no relay is configured (always, in v1).
var ErrNoRelay = errors.New("transport: no relay configured")

// NoRelay is the v1 relay: it never allocates.
type NoRelay struct{}

// Name implements Relay.
func (NoRelay) Name() string { return "none" }

// Allocate implements Relay.
func (NoRelay) Allocate(context.Context) (net.PacketConn, netip.AddrPort, error) {
	return nil, netip.AddrPort{}, ErrNoRelay
}

// RelayFor returns the relay for a configured address. v1 has no relay
// implementation, so this returns NoRelay regardless; v1.1 will dial addr.
func RelayFor(addr string) Relay {
	_ = addr
	return NoRelay{}
}
