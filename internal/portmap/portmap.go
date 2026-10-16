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
}

// mapper is one protocol implementation.
type mapper interface {
	name() string
	// add requests a mapping for internalPort, preferring externalPort.
	add(ctx context.Context, internalPort, externalPort uint16, lifetime time.Duration) (ext netip.AddrPort, granted time.Duration, err error)
	// remove deletes the mapping.
	remove(ctx context.Context, internalPort, externalPort uint16) error
}

// Result reports what each protocol did, for diagnostics.
type Result struct {
	Mapping *Mapping          `json:"mapping,omitempty"`
	Errors  map[string]string `json:"errors,omitempty"` // protocol → error
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
	for range ms {
		r := <-ch
		if r.err != nil {
			errs[r.m.name()] = r.err.Error()
			continue
		}
		mu.Lock()
		if win == nil {
			win = &Mapping{Protocol: r.m.name(), External: r.ext, Internal: internalPort, Lifetime: r.ttl, m: r.m}
		} else {
			// Lost the race: tidy up the router.
			go func() {
				c, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				_ = r.m.remove(c, internalPort, r.ext.Port())
			}()
			errs[r.m.name()] = "ok (not used: " + win.Protocol + " was faster)"
		}
		mu.Unlock()
	}
	if win != nil {
		win.startRenew()
	}
	if len(errs) == 0 {
		errs = nil
	}
	return Result{Mapping: win, Errors: errs}
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
			ext, ttl, err := m.m.add(c, m.Internal, m.External.Port(), defaultLifetime)
			cancel()
			if err == nil && ext.Port() == m.External.Port() {
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

var errNoExternal = errors.New("router reported no usable external address")

func checkExternal(a netip.Addr) error {
	if !a.IsValid() || a.IsUnspecified() {
		return errNoExternal
	}
	return nil
}

func wrap(proto string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", proto, err)
}
