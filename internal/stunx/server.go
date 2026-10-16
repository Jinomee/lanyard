package stunx

import (
	"errors"
	"net"
	"net/netip"
	"sync"

	"github.com/pion/stun/v3"
)

// Server is a minimal RFC 5780-capable STUN server used by tests and the NAT
// lab. With two IP addresses it listens on all four (IP, port) combinations
// and honours CHANGE-REQUEST; with one address it is a plain binding server.
// It is not intended for production use.
type Server struct {
	conns map[netip.AddrPort]*net.UDPConn
	ipA   netip.Addr
	ipB   netip.Addr
	portA uint16
	portB uint16
	wg    sync.WaitGroup
}

// NewServer starts a server. ipB may be the zero Addr for a single-address server.
// portA/portB must be fixed ports (portB is the alternate port).
func NewServer(ipA, ipB netip.Addr, portA, portB uint16) (*Server, error) {
	s := &Server{conns: map[netip.AddrPort]*net.UDPConn{}, ipA: ipA, ipB: ipB, portA: portA, portB: portB}
	ips := []netip.Addr{ipA}
	if ipB.IsValid() {
		ips = append(ips, ipB)
	}
	for _, ip := range ips {
		for _, p := range []uint16{portA, portB} {
			ap := netip.AddrPortFrom(ip, p)
			c, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(ap))
			if err != nil {
				s.Close()
				return nil, err
			}
			s.conns[ap] = c
		}
	}
	for ap, c := range s.conns {
		s.wg.Add(1)
		go s.serve(ap, c)
	}
	return s, nil
}

// Addr returns the primary address.
func (s *Server) Addr() netip.AddrPort { return netip.AddrPortFrom(s.ipA, s.portA) }

// AltAddr returns the alternate (other IP, other port) address, if any.
func (s *Server) AltAddr() netip.AddrPort {
	if !s.ipB.IsValid() {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(s.ipB, s.portB)
}

// Close stops the server.
func (s *Server) Close() {
	for _, c := range s.conns {
		_ = c.Close()
	}
	s.wg.Wait()
}

func (s *Server) serve(local netip.AddrPort, c *net.UDPConn) {
	defer s.wg.Done()
	buf := make([]byte, 1500)
	for {
		n, from, err := c.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		m := &stun.Message{Raw: append([]byte(nil), buf[:n]...)}
		if m.Decode() != nil || m.Type != stun.BindingRequest {
			continue
		}
		var change byte
		if v, err := m.Get(stun.AttrChangeRequest); err == nil && len(v) == 4 {
			change = v[3]
		}
		srcIP, srcPort := local.Addr(), local.Port()
		if change&ChangeIP != 0 {
			if !s.ipB.IsValid() {
				continue
			}
			srcIP = s.other(srcIP, s.ipA, s.ipB)
		}
		if change&ChangePort != 0 {
			srcPort = s.other16(srcPort, s.portA, s.portB)
		}
		out := s.conns[netip.AddrPortFrom(srcIP, srcPort)]
		if out == nil {
			continue
		}
		from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
		setters := []stun.Setter{
			stun.NewTransactionIDSetter(m.TransactionID),
			stun.BindingSuccess,
			&stun.XORMappedAddress{IP: from.Addr().AsSlice(), Port: int(from.Port())},
			&stun.ResponseOrigin{IP: srcIP.AsSlice(), Port: int(srcPort)},
		}
		if s.ipB.IsValid() {
			alt := netip.AddrPortFrom(s.other(local.Addr(), s.ipA, s.ipB), s.other16(local.Port(), s.portA, s.portB))
			setters = append(setters, &stun.OtherAddress{IP: alt.Addr().AsSlice(), Port: int(alt.Port())})
		}
		setters = append(setters, stun.Fingerprint)
		resp, err := stun.Build(setters...)
		if err != nil {
			continue
		}
		_, _ = out.WriteToUDPAddrPort(resp.Raw, from)
	}
}

func (s *Server) other(v, a, b netip.Addr) netip.Addr {
	if v == a {
		return b
	}
	return a
}

func (s *Server) other16(v, a, b uint16) uint16 {
	if v == a {
		return b
	}
	return a
}
