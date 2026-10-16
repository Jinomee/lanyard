package portmap

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"
)

// PCP (RFC 6887) MAP client. Only the parts LANyard needs: request a UDP
// mapping for one internal port, renew it, delete it.

const (
	pcpPort      = 5351
	pcpVersion   = 2
	pcpOpMap     = 1
	pcpResponse  = 0x80
	pcpReqLen    = 24 + 36
	pcpMinRespLn = 24 + 36
)

type pcpMapper struct {
	gw    netip.Addr
	port  uint16 // 0 = 5351 (tests override)
	nonce [12]byte
}

func (p *pcpMapper) name() string { return "pcp" }

// pcpRequest builds a MAP request.
func pcpRequest(client netip.Addr, nonce [12]byte, internalPort, suggestedPort uint16, lifetime uint32) []byte {
	b := make([]byte, pcpReqLen)
	b[0] = pcpVersion
	b[1] = pcpOpMap
	binary.BigEndian.PutUint32(b[4:], lifetime)
	c16 := netip.AddrFrom16(client.As16())
	if client.Is4() {
		c16 = netip.AddrFrom16(netip.AddrFrom4(client.As4()).As16()) // ::ffff:a.b.c.d
	}
	a := c16.As16()
	copy(b[8:24], a[:])
	o := b[24:]
	copy(o[0:12], nonce[:])
	o[12] = 17 // UDP
	binary.BigEndian.PutUint16(o[16:], internalPort)
	binary.BigEndian.PutUint16(o[18:], suggestedPort)
	any4 := netip.AddrFrom16(netip.IPv4Unspecified().As16()).As16()
	copy(o[20:36], any4[:])
	return b
}

// pcpResult codes (RFC 6887 §7.4), for readable errors.
var pcpResults = map[byte]string{
	1: "UNSUPP_VERSION", 2: "NOT_AUTHORIZED", 3: "MALFORMED_REQUEST", 4: "UNSUPP_OPCODE",
	5: "UNSUPP_OPTION", 6: "MALFORMED_OPTION", 7: "NETWORK_FAILURE", 8: "NO_RESOURCES",
	9: "UNSUPP_PROTOCOL", 10: "USER_EX_QUOTA", 11: "CANNOT_PROVIDE_EXTERNAL",
	12: "ADDRESS_MISMATCH", 13: "EXCESSIVE_REMOTE_PEERS",
}

// parsePCPResponse validates a MAP response and returns the external address and lifetime.
func parsePCPResponse(b []byte, nonce [12]byte) (netip.AddrPort, uint32, error) {
	if len(b) < 4 {
		return netip.AddrPort{}, 0, errors.New("short PCP response")
	}
	if b[0] != pcpVersion {
		return netip.AddrPort{}, 0, fmt.Errorf("router speaks PCP/NAT-PMP version %d, not PCP v2", b[0])
	}
	if b[1] != pcpResponse|pcpOpMap {
		return netip.AddrPort{}, 0, errors.New("not a PCP MAP response")
	}
	if b[3] != 0 {
		name := pcpResults[b[3]]
		if name == "" {
			name = fmt.Sprintf("code %d", b[3])
		}
		return netip.AddrPort{}, 0, fmt.Errorf("router refused: %s", name)
	}
	if len(b) < pcpMinRespLn {
		return netip.AddrPort{}, 0, errors.New("short PCP response")
	}
	lifetime := binary.BigEndian.Uint32(b[4:])
	o := b[24:]
	if [12]byte(o[0:12]) != nonce {
		return netip.AddrPort{}, 0, errors.New("PCP nonce mismatch")
	}
	port := binary.BigEndian.Uint16(o[18:])
	ip := netip.AddrFrom16([16]byte(o[20:36])).Unmap()
	if err := checkExternal(ip); err != nil {
		return netip.AddrPort{}, 0, err
	}
	return netip.AddrPortFrom(ip, port), lifetime, nil
}

func (p *pcpMapper) roundTrip(ctx context.Context, internalPort, suggested uint16, lifetime uint32) (netip.AddrPort, uint32, error) {
	if p.nonce == ([12]byte{}) {
		_, _ = rand.Read(p.nonce[:])
	}
	local, err := localIPFor(p.gw)
	if err != nil {
		return netip.AddrPort{}, 0, err
	}
	c, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return netip.AddrPort{}, 0, err
	}
	defer func() { _ = c.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = c.SetReadDeadline(time.Now()) })
	defer stop()
	req := pcpRequest(local, p.nonce, internalPort, suggested, lifetime)
	port := p.port
	if port == 0 {
		port = pcpPort
	}
	dst := net.UDPAddrFromAddrPort(netip.AddrPortFrom(p.gw, port))
	buf := make([]byte, 1100)
	delay := 250 * time.Millisecond
	// RFC 6887 retransmits for longer, but a router that ignores five
	// requests (about 8 s) is not going to answer.
	for try := 0; try < 5 && ctx.Err() == nil; try++ {
		if _, err := c.WriteToUDP(req, dst); err != nil {
			return netip.AddrPort{}, 0, err
		}
		_ = c.SetReadDeadline(time.Now().Add(delay))
		for {
			n, from, err := c.ReadFromUDPAddrPort(buf)
			if err != nil {
				break // timeout: resend
			}
			if from.Addr().Unmap() != p.gw {
				continue
			}
			return parsePCPResponse(buf[:n], p.nonce)
		}
		delay *= 2
	}
	return netip.AddrPort{}, 0, errors.New("no PCP response from router")
}

func (p *pcpMapper) add(ctx context.Context, internalPort, externalPort uint16, lifetime time.Duration) (netip.AddrPort, time.Duration, error) {
	ap, ttl, err := p.roundTrip(ctx, internalPort, externalPort, uint32(lifetime/time.Second))
	if errors.Is(err, ErrPrivateExternal) {
		// The mapping exists but is useless; remove it even if ctx is done.
		c, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		_ = p.remove(c, internalPort, 0)
		cancel()
	}
	return ap, time.Duration(ttl) * time.Second, err
}

func (p *pcpMapper) renew(ctx context.Context, internalPort, externalPort uint16, lifetime time.Duration) (time.Duration, error) {
	ap, ttl, err := p.add(ctx, internalPort, externalPort, lifetime)
	if err == nil && ap.Port() != externalPort {
		// The router answered with another port (it rebooted, say): the
		// port in the invite no longer leads here.
		return ttl, fmt.Errorf("%w: router moved the mapping to port %d", errLost, ap.Port())
	}
	return ttl, err
}

func (p *pcpMapper) remove(ctx context.Context, internalPort, _ uint16) error {
	_, _, err := p.roundTrip(ctx, internalPort, 0, 0)
	if err != nil && errors.Is(err, errNoExternal) {
		return nil // deletion responses may carry an empty address
	}
	return err
}
