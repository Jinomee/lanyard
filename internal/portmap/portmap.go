// Package portmap asks the local router to forward a UDP port, trying
// UPnP-IGD, NAT-PMP and PCP in parallel. The first protocol to succeed wins;
// any other mapping that also succeeds is removed again.
package portmap

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/jackpal/gateway"
)

// Mapping is an active port mapping. Close removes it from the router.
type Mapping struct {
	Protocol string         `json:"protocol"` // "upnp", "natpmp", "pcp"
	External netip.AddrPort `json:"external"`
	Internal uint16         `json:"internal"`
	Lifetime time.Duration  `json:"lifetime"`

	m      mapper
	cancel context.CancelFunc
	done   chan struct{}
	lost   bool // the router gave the port to someone else: never delete it
}

// mapper is one protocol implementation.
type mapper interface {
	name() string
	// add requests a mapping for internalPort, preferring externalPort.
	add(ctx context.Context, internalPort, externalPort uint16, lifetime time.Duration) (ext netip.AddrPort, granted time.Duration, err error)
	// renew extends the mapping add created, on exactly that external port.
	// It must never create a mapping on another port.
	renew(ctx context.Context, internalPort, externalPort uint16, lifetime time.Duration) (granted time.Duration, err error)
	// remove deletes the mapping.
	remove(ctx context.Context, internalPort, externalPort uint16) error
}

// errLost means the external port now belongs to another computer.
var errLost = errors.New("port mapping taken over by another computer")

// Result reports what each protocol did, for diagnostics.
type Result struct {
	Mapping *Mapping          `json:"mapping,omitempty"`
	Errors  map[string]string `json:"errors,omitempty"` // protocol → error
	// PrivateExternal: the router answered but has no public address itself
	// (double NAT or carrier-grade NAT), so no mapping can help.
	PrivateExternal bool `json:"privateExternal,omitempty"`
}

// Available reports whether any protocol succeeded.
func (r Result) Available() bool { return r.Mapping != nil }

const defaultLifetime = 2 * time.Hour

// Options configures Map.
type Options struct {
	// Gateway overrides default-gateway discovery (tests).
	Gateway netip.Addr
	// Description shown in the router UI.
	Description string
	// Disabled protocols.
	NoUPnP, NoNATPMP, NoPCP bool
}

// Map races all protocols for internalPort until ctx expires.
func Map(ctx context.Context, internalPort uint16, opt Options) Result {
	gw := opt.Gateway
	if !gw.IsValid() {
		if ip, err := gateway.DiscoverGateway(); err == nil {
			gw, _ = netip.AddrFromSlice(ip)
			gw = gw.Unmap()
		}
	}
	var ms []mapper
	errs := map[string]string{}
	if !opt.NoUPnP {
		ms = append(ms, &upnpMapper{desc: opt.Description})
	}
	if gw.IsValid() && gw.Is4() {
		if !opt.NoNATPMP {
			ms = append(ms, &natpmpMapper{gw: gw})
		}
		if !opt.NoPCP {
			ms = append(ms, &pcpMapper{gw: gw})
		}
	} else {
		errs["natpmp"] = "no IPv4 default gateway"
		errs["pcp"] = "no IPv4 default gateway"
	}

	type res struct {
		m   mapper
		ext netip.AddrPort
		ttl time.Duration
		err error
	}
	ch := make(chan res, len(ms))
	for _, m := range ms {
		go func() {
			ext, ttl, err := m.add(ctx, internalPort, internalPort, defaultLifetime)
			ch <- res{m, ext, ttl, err}
		}()
	}
	var win *Mapping
	var mu sync.Mutex
	private := false
	for range ms {
		r := <-ch
		if r.err != nil {
			errs[r.m.name()] = r.err.Error()
			if errors.Is(r.err, ErrPrivateExternal) {
				private = true
			}
			continue
		}
		mu.Lock()
		switch {
		case win == nil:
			win = &Mapping{Protocol: r.m.name(), External: r.ext, Internal: internalPort, Lifetime: r.ttl, m: r.m}
		case r.m.name() == "upnp" && r.ext.Port() != win.External.Port():
			// A separate UPnP rule on another port: remove it (ctx may be done).
			go func() { //nolint:gosec // G118: deliberate fresh context for cleanup
				c, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				_ = r.m.remove(c, internalPort, r.ext.Port())
			}()
			errs[r.m.name()] = "ok (not used: " + win.Protocol + " was faster)"
		default:
			// Most routers (miniupnpd) keep one rule per port for all three
			// protocols, so deleting this "loser" would delete the winner
			// too. NAT-PMP/PCP mappings expire on their own.
			errs[r.m.name()] = "ok (same rule as " + win.Protocol + ")"
		}
		mu.Unlock()
	}
	if win != nil {
		win.startRenew()
	}
	if len(errs) == 0 {
		errs = nil
	}
	return Result{Mapping: win, Errors: errs, PrivateExternal: private && win == nil}
}

func (m *Mapping) startRenew() {
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	m.done = make(chan struct{})
	go func() {
		defer close(m.done)
		lifetime := m.Lifetime
		for {
			wait := lifetime / 2
			if wait <= 0 || wait > 30*time.Minute {
				wait = 30 * time.Minute // lifetime 0 = permanent; still refresh occasionally
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(wait):
			}
			c, cancel := context.WithTimeout(ctx, 5*time.Second)
			ttl, err := m.m.renew(c, m.Internal, m.External.Port(), defaultLifetime)
			cancel()
			if errors.Is(err, errLost) {
				m.lost = true
				return
			}
			if err == nil {
				lifetime = ttl
			}
		}
	}()
}

// Close removes the mapping from the router.
func (m *Mapping) Close() error {
	if m == nil || m.m == nil {
		return nil
	}
	if m.cancel != nil {
		m.cancel()
		<-m.done
	}
	if m.lost {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return m.m.remove(ctx, m.Internal, m.External.Port())
}

// localIPFor returns the local IPv4 address used to reach dst.
func localIPFor(dst netip.Addr) (netip.Addr, error) {
	c, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(dst, 9)))
	if err != nil {
		return netip.Addr{}, err
	}
	defer func() { _ = c.Close() }()
	ap := c.LocalAddr().(*net.UDPAddr).AddrPort()
	return ap.Addr().Unmap(), nil
}

// ErrPrivateExternal means the router's own WAN address is missing or not
// public: it sits behind another NAT (often the ISP's carrier-grade NAT).
var ErrPrivateExternal = errors.New("router has no public address (double NAT or carrier-grade NAT)")

var (
	cgnatPrefix   = netip.MustParsePrefix("100.64.0.0/10")
	errNoExternal = ErrPrivateExternal
)

func checkExternal(a netip.Addr) error {
	a = a.Unmap()
	if !a.IsValid() || a.IsUnspecified() || a.IsPrivate() || a.IsLoopback() || cgnatPrefix.Contains(a) {
		return ErrPrivateExternal
	}
	return nil
}

func wrap(proto string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", proto, err)
}
