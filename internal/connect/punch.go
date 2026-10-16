package connect

import (
	"context"
	"net/netip"
	"time"

	"github.com/jinomee/lanyard/internal/joincode"
	"github.com/jinomee/lanyard/internal/transport"
)

// PunchOptions configures HostPunch.
type PunchOptions struct {
	EP4, EP6 *transport.Endpoint
	Secret   [joincode.SecretLen]byte
	Reply    *joincode.Reply
	Interval time.Duration // default 250 ms
	Duration time.Duration // default 45 s
}

// HostPunch sends authenticated punch packets from the host's sockets to every
// candidate in a guest's reply code. Each packet opens (or refreshes) the
// host NAT's filter for that guest address, so the guest's next QUIC retry
// gets through; a packet that reaches the guest also teaches it the host's
// peer-reflexive address. It returns when ctx ends or Duration elapses.
func HostPunch(ctx context.Context, opt PunchOptions) {
	if opt.Interval == 0 {
		opt.Interval = 250 * time.Millisecond
	}
	if opt.Duration == 0 {
		opt.Duration = 45 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, opt.Duration)
	defer cancel()
	targets := make([]netip.AddrPort, 0, len(opt.Reply.Candidates))
	for _, c := range opt.Reply.Candidates {
		targets = append(targets, c.Addr)
	}
	t := time.NewTicker(opt.Interval)
	defer t.Stop()
	for {
		for _, a := range targets {
			ep := opt.EP4
			if !a.Addr().Is4() {
				ep = opt.EP6
			}
			if ep != nil {
				// A fresh nonce per packet: the guest accepts each nonce once
				// (replay protection), and a symmetric NAT may deliver the
				// packets for different targets from different addresses.
				_ = ep.WriteTo(transport.MakePunch(opt.Secret, transport.RoleHost, opt.Reply.Session), a)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
