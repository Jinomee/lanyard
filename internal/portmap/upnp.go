package portmap

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/huin/goupnp/dcps/internetgateway2"
)

// igdClient is the method set shared by the WANIPConnection and
// WANPPPConnection service clients.
type igdClient interface {
	AddPortMappingCtx(ctx context.Context, remoteHost string, externalPort uint16, protocol string,
		internalPort uint16, internalClient string, enabled bool, description string, leaseDuration uint32) error
	DeletePortMappingCtx(ctx context.Context, remoteHost string, externalPort uint16, protocol string) error
	GetExternalIPAddressCtx(ctx context.Context) (string, error)
}

type upnpMapper struct {
	desc    string
	clients []igdConn // discovered gateway services, preferred first
	client  igdClient // the one holding our mapping
	local   string
}

type igdConn struct {
	c     igdClient
	local string
}

func (u *upnpMapper) name() string { return "upnp" }

// discover finds every IGD connection service (IGDv2 IP, IGDv1 IP, PPP) on
// every gateway that answers. Mesh systems, a modem plus a router, or a
// router exposing a dead PPP service besides the live IP one all answer, and
// the first answer is often not the useful one.
func (u *upnpMapper) discover(ctx context.Context) error {
	var lists [3][]igdConn
	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		cs, _, _ := internetgateway2.NewWANIPConnection2ClientsCtx(ctx)
		for _, c := range cs {
			lists[0] = append(lists[0], igdConn{c, c.LocalAddr().String()})
		}
	}()
	go func() {
		defer wg.Done()
		cs, _, _ := internetgateway2.NewWANIPConnection1ClientsCtx(ctx)
		for _, c := range cs {
			lists[1] = append(lists[1], igdConn{c, c.LocalAddr().String()})
		}
	}()
	go func() {
		defer wg.Done()
		cs, _, _ := internetgateway2.NewWANPPPConnection1ClientsCtx(ctx)
		for _, c := range cs {
			lists[2] = append(lists[2], igdConn{c, c.LocalAddr().String()})
		}
	}()
	wg.Wait()
	u.clients = append(append(append([]igdConn(nil), lists[0]...), lists[1]...), lists[2]...)
	if len(u.clients) == 0 {
		return errors.New("no UPnP internet gateway found")
	}
	return nil
}

// add tries each gateway service until one with a public address maps the
// port. ErrPrivateExternal is reported only if no service could do better.
func (u *upnpMapper) add(ctx context.Context, internalPort, externalPort uint16, lifetime time.Duration) (netip.AddrPort, time.Duration, error) {
	if u.clients == nil {
		if err := u.discover(ctx); err != nil {
			return netip.AddrPort{}, 0, err
		}
	}
	var private, other error
	for _, c := range u.clients {
		ap, ttl, err := u.addVia(ctx, c, internalPort, externalPort, lifetime)
		if err == nil {
			u.client, u.local = c.c, c.local
			return ap, ttl, nil
		}
		if errors.Is(err, ErrPrivateExternal) {
			private = err
		} else {
			other = err
		}
		if ctx.Err() != nil {
			break
		}
	}
	if other != nil {
		return netip.AddrPort{}, 0, other
	}
	return netip.AddrPort{}, 0, private
}

func (u *upnpMapper) addVia(ctx context.Context, c igdConn, internalPort, externalPort uint16, lifetime time.Duration) (netip.AddrPort, time.Duration, error) {
	extStr, err := c.c.GetExternalIPAddressCtx(ctx)
	if err != nil {
		// miniupnpd answers 501 when its WAN address is private (CGNAT).
		if strings.Contains(err.Error(), "501") {
			return netip.AddrPort{}, 0, fmt.Errorf("%w (%w)", ErrPrivateExternal, err)
		}
		return netip.AddrPort{}, 0, wrap("get external IP", err)
	}
	ext, err := netip.ParseAddr(strings.TrimSpace(extStr))
	if err != nil {
		return netip.AddrPort{}, 0, ErrPrivateExternal
	}
	if err := checkExternal(ext); err != nil {
		return netip.AddrPort{}, 0, err
	}
	lease := uint32(lifetime / time.Second)
	try := func(port uint16, lease uint32) error {
		return c.c.AddPortMappingCtx(ctx, "", port, "UDP", internalPort, c.local, true, u.desc, lease)
	}
	ports := []uint16{externalPort, externalPort + 1, externalPort + 7, 20000 + externalPort%30000}
	var lastErr error
	for _, p := range ports {
		if p < 1024 {
			continue
		}
		err := try(p, lease)
		if err != nil && strings.Contains(err.Error(), "725") {
			// OnlyPermanentLeasesSupported: many older routers.
			lease = 0
			err = try(p, 0)
		}
		if err == nil {
			return netip.AddrPortFrom(ext.Unmap(), p), time.Duration(lease) * time.Second, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			break
		}
	}
	return netip.AddrPort{}, 0, wrap("add port mapping", lastErr)
}

// renew refreshes our rule on exactly externalPort. Trying other ports here
// would leave rules behind that nothing tracks or removes.
func (u *upnpMapper) renew(ctx context.Context, internalPort, externalPort uint16, lifetime time.Duration) (time.Duration, error) {
	if u.client == nil {
		return 0, errors.New("upnp: no mapping to renew")
	}
	lease := uint32(lifetime / time.Second)
	err := u.client.AddPortMappingCtx(ctx, "", externalPort, "UDP", internalPort, u.local, true, u.desc, lease)
	if err != nil && strings.Contains(err.Error(), "725") {
		lease = 0
		err = u.client.AddPortMappingCtx(ctx, "", externalPort, "UDP", internalPort, u.local, true, u.desc, 0)
	}
	if err != nil && strings.Contains(err.Error(), "718") {
		// ConflictInMappingEntry: another computer has the port now.
		return 0, fmt.Errorf("%w (%w)", errLost, err)
	}
	return time.Duration(lease) * time.Second, err
}

func (u *upnpMapper) remove(ctx context.Context, _, externalPort uint16) error {
	if u.client == nil {
		return nil
	}
	return u.client.DeletePortMappingCtx(ctx, "", externalPort, "UDP")
}
