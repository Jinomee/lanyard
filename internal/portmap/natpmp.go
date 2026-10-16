package portmap

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	natpmp "github.com/jackpal/go-nat-pmp"
)

type natpmpMapper struct {
	gw netip.Addr
}

func (n *natpmpMapper) name() string { return "natpmp" }

func (n *natpmpMapper) client(ctx context.Context) *natpmp.Client {
	timeout := 2 * time.Second
	if dl, ok := ctx.Deadline(); ok {
		timeout = time.Until(dl)
	}
	return natpmp.NewClientWithTimeout(net.IP(n.gw.AsSlice()), timeout)
}

func (n *natpmpMapper) add(ctx context.Context, internalPort, externalPort uint16, lifetime time.Duration) (netip.AddrPort, time.Duration, error) {
	type out struct {
		ap  netip.AddrPort
		ttl time.Duration
		err error
	}
	ch := make(chan out, 1)
	go func() {
		c := n.client(ctx)
		ext, err := c.GetExternalAddress()
		if err != nil {
			// Result code 3 = "network failure": the box has no external address.
			if strings.Contains(err.Error(), "result code 3") {
				err = fmt.Errorf("%w (%v)", ErrPrivateExternal, err)
			}
			ch <- out{err: err}
			return
		}
		ip := netip.AddrFrom4(ext.ExternalIPAddress)
		if err := checkExternal(ip); err != nil {
			ch <- out{err: err}
			return
		}
		r, err := c.AddPortMapping("udp", int(internalPort), int(externalPort), int(lifetime/time.Second))
		if err != nil {
			ch <- out{err: err}
			return
		}
		ch <- out{ap: netip.AddrPortFrom(ip, r.MappedExternalPort), ttl: time.Duration(r.PortMappingLifetimeInSeconds) * time.Second}
	}()
	select {
	case <-ctx.Done():
		return netip.AddrPort{}, 0, ctx.Err()
	case o := <-ch:
		return o.ap, o.ttl, o.err
	}
}

func (n *natpmpMapper) remove(ctx context.Context, internalPort, _ uint16) error {
	_, err := n.client(ctx).AddPortMapping("udp", int(internalPort), 0, 0)
	return err
}
