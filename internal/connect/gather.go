// Package connect implements LANyard's connectivity strategies: candidate
// gathering (IPv6, router port mapping, STUN), the happy-eyeballs dialer,
// UDP hole punching and the plain-language failure diagnosis.
package connect

import (
	"context"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/jinomee/mc/internal/joincode"
	"github.com/jinomee/mc/internal/netinfo"
	"github.com/jinomee/mc/internal/portmap"
	"github.com/jinomee/mc/internal/stunx"
	"github.com/jinomee/mc/internal/transport"
)

// NAT type labels derived from mapping + filtering behaviour.
const (
	NATOpen           = "open"            // public address on this machine
	NATFullCone       = "full_cone"       // EIM + EIF
	NATRestricted     = "restricted"      // EIM + address-dependent filtering
	NATPortRestricted = "port_restricted" // EIM + address-and-port-dependent filtering
	NATCone           = "cone"            // EIM, filtering unknown
	NATSymmetric      = "symmetric"       // endpoint-dependent mapping
	NATUnknown        = "unknown"
)

// Report describes the local network as seen during gathering.
type Report struct {
	Time        time.Time            `json:"time"`
	ElapsedMs   int64                `json:"elapsedMs"`
	Local       netinfo.Addrs        `json:"local"`
	IPv6        bool                 `json:"ipv6"`
	IPv6Stun    string               `json:"ipv6Stun"` // "ok", "failed", "untested"
	STUN4       []stunx.ServerResult `json:"stun4"`
	STUN6       []stunx.ServerResult `json:"stun6,omitempty"`
	PublicV4    netip.AddrPort       `json:"publicV4,omitzero"`
	Mapping     stunx.Mapping        `json:"mapping"`
	Filtering   stunx.Filtering      `json:"filtering"`
	NATType     string               `json:"natType"`
	PortMap     portmap.Result       `json:"portMap"`
	CGNAT       bool                 `json:"cgnat"`
	CGNATReason string               `json:"cgnatReason,omitempty"` // i18n key
	UDPBlocked  bool                 `json:"udpBlocked"`
}

// GatherOptions configures Gather.
type GatherOptions struct {
	EP4, EP6       *transport.Endpoint // EP6 may be nil
	STUNServers    []string
	PortMap        bool
	PortMapOptions portmap.Options
	ProbeFiltering bool
	Timeout        time.Duration // overall budget; default 3 s
}

// Gathered is the result of Gather.
type Gathered struct {
	Report     Report
	Candidates []joincode.Candidate
	Mapping    *portmap.Mapping // nil if no router mapping; caller must Close
}

// Gather discovers this machine's candidates and NAT properties. All probes
// run in parallel within the time budget.
func Gather(ctx context.Context, opt GatherOptions) *Gathered {
	if opt.Timeout == 0 {
		opt.Timeout = 3 * time.Second
	}
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, opt.Timeout)
	defer cancel()

	g := &Gathered{}
	r := &g.Report
	r.Time = start
	r.Local = netinfo.Local()
	r.Filtering = stunx.FilteringUnknown
	r.IPv6Stun = "untested"

	stunTimeout := min(opt.Timeout, 1500*time.Millisecond)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		r.STUN4 = stunx.QueryAll(ctx, opt.EP4, opt.STUNServers, 4, stunTimeout)
	}()
	if opt.EP6 != nil && len(r.Local.GlobalV6) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res := stunx.QueryAll(ctx, opt.EP6, opt.STUNServers, 6, stunTimeout)
			for _, x := range res {
				if x.Error == "" || len(x.Error) < 4 || x.Error[:4] != "dns:" {
					r.STUN6 = append(r.STUN6, x)
				}
			}
		}()
	}
	if opt.PortMap {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.PortMap = portmap.Map(ctx, opt.EP4.Port(), opt.PortMapOptions)
		}()
	}
	if opt.ProbeFiltering {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.Filtering = probeFiltering(ctx, opt.STUNServers)
		}()
	}
	wg.Wait()

	// IPv6
	if len(r.STUN6) > 0 {
		r.IPv6Stun = "failed"
		for _, x := range r.STUN6 {
			if x.OK() {
				r.IPv6Stun = "ok"
			}
		}
	}
	r.IPv6 = opt.EP6 != nil && len(r.Local.GlobalV6) > 0 && r.IPv6Stun != "failed"

	// IPv4 NAT behaviour
	r.Mapping, r.PublicV4 = stunx.ClassifyMapping(r.STUN4, netinfo.AllLocal())
	r.UDPBlocked = !slices.ContainsFunc(r.STUN4, stunx.ServerResult.OK) && r.IPv6Stun != "ok"
	if r.Mapping == stunx.MappingNone {
		r.Filtering = stunx.FilteringNone
	}
	r.NATType = natType(r.Mapping, r.Filtering)

	// CGNAT / double NAT indicators.
	switch {
	case netinfo.IsCGNAT(r.Local.LANv4):
		r.CGNAT, r.CGNATReason = true, "cgnat.local_shared"
	case r.PortMap.Mapping != nil && !netinfo.IsPublicV4(r.PortMap.Mapping.External.Addr()):
		r.CGNAT, r.CGNATReason = true, "cgnat.router_private"
	case r.PortMap.Mapping != nil && r.PublicV4.IsValid() && r.PortMap.Mapping.External.Addr() != r.PublicV4.Addr():
		r.CGNAT, r.CGNATReason = true, "cgnat.address_mismatch"
	case r.PublicV4.IsValid() && netinfo.IsCGNAT(r.PublicV4.Addr()):
		r.CGNAT, r.CGNATReason = true, "cgnat.local_shared"
	}

	// Candidates, in preference order.
	add := func(k joincode.CandidateKind, ap netip.AddrPort) {
		if !ap.IsValid() || ap.Port() == 0 {
			return
		}
		for _, c := range g.Candidates {
			if c.Addr == ap {
				return
			}
		}
		g.Candidates = append(g.Candidates, joincode.Candidate{Kind: k, Addr: ap})
	}
	if opt.EP6 != nil {
		for i, a := range r.Local.GlobalV6 {
			if i == 2 {
				break
			}
			add(joincode.CandIPv6, netip.AddrPortFrom(a, opt.EP6.Port()))
		}
	}
	if m := r.PortMap.Mapping; m != nil {
		if !r.CGNAT {
			add(joincode.CandMapped, m.External)
		}
		g.Mapping = m
	}
	if r.PublicV4.IsValid() {
		add(joincode.CandReflexive, r.PublicV4)
	}
	if lan := r.Local.LANv4; lan.IsValid() && !netinfo.IsPublicV4(lan) {
		add(joincode.CandLAN, netip.AddrPortFrom(lan, opt.EP4.Port()))
	}
	r.ElapsedMs = time.Since(start).Milliseconds()
	return g
}

func natType(m stunx.Mapping, f stunx.Filtering) string {
	switch m {
	case stunx.MappingNone:
		return NATOpen
	case stunx.MappingDependent:
		return NATSymmetric
	case stunx.MappingIndependent:
		switch f {
		case stunx.FilteringIndependent:
			return NATFullCone
		case stunx.FilteringAddress:
			return NATRestricted
		case stunx.FilteringAddressAndPort:
			return NATPortRestricted
		}
		return NATCone
	}
	return NATUnknown
}

// probeFiltering runs the RFC 5780 filtering test against every server in
// parallel, each on its own fresh socket (so one probe cannot open the NAT
// filter for another), and returns the first conclusive answer.
func probeFiltering(ctx context.Context, servers []string) stunx.Filtering {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ch := make(chan stunx.Filtering, len(servers))
	for _, s := range servers {
		go func() {
			f := stunx.FilteringUnknown
			defer func() { ch <- f }()
			addr, err := stunx.Resolve(ctx, s, 4)
			if err != nil {
				return
			}
			ep, err := transport.ListenUDP(4, 0)
			if err != nil {
				return
			}
			defer func() { _ = ep.Close() }()
			if res, err := stunx.ProbeFiltering(ctx, ep, addr, 600*time.Millisecond); err == nil {
				f = res
			}
		}()
	}
	for range servers {
		if f := <-ch; f != stunx.FilteringUnknown {
			return f
		}
	}
	return stunx.FilteringUnknown
}

// Flags summarises the report for embedding in codes.
func (r *Report) Flags() joincode.Flags {
	var f joincode.Flags
	switch r.Mapping {
	case stunx.MappingIndependent, stunx.MappingNone:
		f |= joincode.FlagMapEIM
	case stunx.MappingDependent:
		f |= joincode.FlagMapDep
	}
	if r.PortMap.Mapping != nil && !r.CGNAT {
		f |= joincode.FlagPortMapped
	}
	if r.CGNAT {
		f |= joincode.FlagCGNAT
	}
	if r.IPv6 {
		f |= joincode.FlagIPv6
	}
	return f
}
