package portmap

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
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
	desc   string
	client igdClient
	local  string
}

func (u *upnpMapper) name() string { return "upnp" }

// discover finds the first IGD connection service (IGDv2 IP, IGDv1 IP, PPP).
func (u *upnpMapper) discover(ctx context.Context) error {
	type found struct {
		c     igdClient
		local string
	}
	ch := make(chan found, 3)
	go func() {
		cs, _, _ := internetgateway2.NewWANIPConnection2ClientsCtx(ctx)
		for _, c := range cs {
			ch <- found{c, c.LocalAddr().String()}
			return
		}
		ch <- found{}
	}()
	go func() {
		cs, _, _ := internetgateway2.NewWANIPConnection1ClientsCtx(ctx)
		for _, c := range cs {
			ch <- found{c, c.LocalAddr().String()}
			return
		}
		ch <- found{}
	}()
	go func() {
		cs, _, _ := internetgateway2.NewWANPPPConnection1ClientsCtx(ctx)
		for _, c := range cs {
			ch <- found{c, c.LocalAddr().String()}
			return
		}
		ch <- found{}
	}()
	for range 3 {
		f := <-ch
		if f.c != nil {
			u.client, u.local = f.c, f.local
			return nil
		}
	}
	return errors.New("no UPnP internet gateway found")
}

func (u *upnpMapper) add(ctx context.Context, internalPort, externalPort uint16, lifetime time.Duration) (netip.AddrPort, time.Duration, error) {
	if u.client == nil {
		if err := u.discover(ctx); err != nil {
			return netip.AddrPort{}, 0, err
		}
	}
	extStr, err := u.client.GetExternalIPAddressCtx(ctx)
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
		return u.client.AddPortMappingCtx(ctx, "", port, "UDP", internalPort, u.local, true, u.desc, lease)
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

func (u *upnpMapper) remove(ctx context.Context, _, externalPort uint16) error {
	if u.client == nil {
		return nil
	}
	return u.client.DeletePortMappingCtx(ctx, "", externalPort, "UDP")
}
