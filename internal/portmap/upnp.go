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
	"github.com/huin/goupnp/soap"
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

// perServiceTimeout bounds each gateway service, so one that hangs can't use
// up the time the next (working) one needs.
const perServiceTimeout = 3 * time.Second

// add tries each gateway service until one with a public address maps the
// port. If none can, a service reporting a private WAN address (double NAT,
// CGNAT) is the most telling answer and is the one returned.
func (u *upnpMapper) add(ctx context.Context, internalPort, externalPort uint16, lifetime time.Duration) (netip.AddrPort, time.Duration, error) {
	if u.clients == nil {
		if err := u.discover(ctx); err != nil {
			return netip.AddrPort{}, 0, err
		}
	}
	var private, other error
	for _, c := range u.clients {
		sctx, cancel := context.WithTimeout(ctx, perServiceTimeout)
		ap, ttl, err := u.addVia(sctx, c, internalPort, externalPort, lifetime)
		cancel()
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
	if private != nil {
		return netip.AddrPort{}, 0, private
	}
	return netip.AddrPort{}, 0, other
}

// upnpCode returns the UPnP error code of a SOAP fault (0 if err isn't one).
func upnpCode(err error) int {
	var f *soap.SOAPFaultError
	if errors.As(err, &f) {
		return f.Detail.UPnPError.Errorcode
	}
	return 0
}

// UPnP error codes (UPnP-IGD WANIPConnection).
const (
	upnpActionFailed        = 501 // miniupnpd: also "my WAN address is private"
	upnpConflictInMapping   = 718
	upnpOnlyPermanentLeases = 725
)

func (u *upnpMapper) addVia(ctx context.Context, c igdConn, internalPort, externalPort uint16, lifetime time.Duration) (netip.AddrPort, time.Duration, error) {
	extStr, err := c.c.GetExternalIPAddressCtx(ctx)
	if err != nil {
		// miniupnpd answers 501 when its WAN address is private (CGNAT).
		if upnpCode(err) == upnpActionFailed {
			return netip.AddrPort{}, 0, fmt.Errorf("%w (%w)", ErrPrivateExternal, err)
		}
		return netip.AddrPort{}, 0, wrap("get external IP", err)
	}
	ext, err := netip.ParseAddr(strings.TrimSpace(extStr))
	if err != nil || ext.IsUnspecified() {
		// No address at all: typically a service for an unused connection
		// (a PPP service beside the live IP one), not a sign of CGNAT.
		return netip.AddrPort{}, 0, fmt.Errorf("get external IP: service has no address (%q)", extStr)
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
		if err != nil && upnpCode(err) == upnpOnlyPermanentLeases {
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
	if err != nil && upnpCode(err) == upnpOnlyPermanentLeases {
		lease = 0
		err = u.client.AddPortMappingCtx(ctx, "", externalPort, "UDP", internalPort, u.local, true, u.desc, 0)
	}
	if err != nil && upnpCode(err) == upnpConflictInMapping {
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
