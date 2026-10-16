// Package stunx is a small STUN (RFC 5389/8489) client that runs on LANyard's
// shared UDP sockets, plus RFC 5780 NAT behaviour probes and a test server.
package stunx

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pion/stun/v3"

	"github.com/jinomee/mc/internal/transport"
)

// PacketIO is the subset of transport.Endpoint the client needs.
type PacketIO interface {
	WriteTo(b []byte, to netip.AddrPort) error
	Await(txid []byte) (<-chan transport.Packet, func())
}

// Response is a decoded binding response.
type Response struct {
	Mapped netip.AddrPort // XOR-MAPPED-ADDRESS (or MAPPED-ADDRESS)
	Other  netip.AddrPort // OTHER-ADDRESS, if the server supports RFC 5780
	From   netip.AddrPort // where the response actually came from
	RTT    time.Duration
}

// Change-request flags (RFC 5780 §7.2).
const (
	ChangeIP   = 0x04
	ChangePort = 0x02
)

// ErrTimeout means no response arrived.
var ErrTimeout = errors.New("stun: no response")

// Binding sends a binding request to server and waits for the response,
// retransmitting at 0, 250, 750 ms … until ctx expires. change sets the
// RFC 5780 CHANGE-REQUEST flags (0 for a normal request).
func Binding(ctx context.Context, io PacketIO, server netip.AddrPort, change byte) (Response, error) {
	setters := []stun.Setter{stun.TransactionID, stun.BindingRequest}
	if change != 0 {
		setters = append(setters, stun.RawAttribute{Type: stun.AttrChangeRequest, Value: []byte{0, 0, 0, change}})
	}
	setters = append(setters, stun.Fingerprint)
	req, err := stun.Build(setters...)
	if err != nil {
		return Response{}, err
	}
	ch, cancel := io.Await(req.TransactionID[:])
	defer cancel()

	start := time.Now()
	delay := 250 * time.Millisecond
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return Response{}, ErrTimeout
		case <-timer.C:
			if err := io.WriteTo(req.Raw, server); err != nil {
				return Response{}, fmt.Errorf("stun: send: %w", err)
			}
			timer.Reset(delay)
			delay *= 2
		case p := <-ch:
			res, err := parse(p.Data)
			if err != nil {
				continue
			}
			res.From = p.From
			res.RTT = time.Since(start)
			return res, nil
		}
	}
}

func parse(b []byte) (Response, error) {
	m := &stun.Message{Raw: append([]byte(nil), b...)}
	if err := m.Decode(); err != nil {
		return Response{}, err
	}
	if m.Type != stun.BindingSuccess {
		return Response{}, fmt.Errorf("stun: unexpected %v", m.Type)
	}
	var res Response
	var xor stun.XORMappedAddress
	if err := xor.GetFrom(m); err == nil {
		res.Mapped = toAP(xor.IP, xor.Port)
	} else {
		var ma stun.MappedAddress
		if err := ma.GetFrom(m); err != nil {
			return Response{}, errors.New("stun: no mapped address")
		}
		res.Mapped = toAP(ma.IP, ma.Port)
	}
	var oa stun.OtherAddress
	if err := oa.GetFrom(m); err == nil {
		res.Other = toAP(oa.IP, oa.Port)
	}
	return res, nil
}

func toAP(ip net.IP, port int) netip.AddrPort {
	a, _ := netip.AddrFromSlice(ip)
	return netip.AddrPortFrom(a.Unmap(), uint16(port)) //nolint:gosec // STUN ports are 16-bit
}

// ServerResult is the outcome of querying one configured server.
type ServerResult struct {
	Server   string         `json:"server"`
	Resolved netip.AddrPort `json:"resolved,omitzero"`
	Mapped   netip.AddrPort `json:"mapped,omitzero"`
	Other    netip.AddrPort `json:"other,omitzero"`
	RTTms    int64          `json:"rttMs,omitempty"`
	Error    string         `json:"error,omitempty"`
}

// OK reports whether the query succeeded.
func (r ServerResult) OK() bool { return r.Error == "" && r.Mapped.IsValid() }

// Resolve looks up a "host:port" STUN server for the given family (4 or 6).
func Resolve(ctx context.Context, server string, family int) (netip.AddrPort, error) {
	host, port, err := net.SplitHostPort(server)
	if err != nil {
		host, port = server, "3478"
	}
	p, err := net.LookupPort("udp", port)
	if err != nil {
		return netip.AddrPort{}, err
	}
	network := "ip4"
	if family == 6 {
		network = "ip6"
	}
	if a, err := netip.ParseAddr(host); err == nil {
		if (family == 4) != a.Unmap().Is4() {
			return netip.AddrPort{}, errors.New("no address for this IP version")
		}
		return netip.AddrPortFrom(a.Unmap(), uint16(p)), nil //nolint:gosec // validated by LookupPort
	}
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, network, host)
	if err != nil {
		return netip.AddrPort{}, err
	}
	if len(addrs) == 0 {
		return netip.AddrPort{}, errors.New("no address")
	}
	return netip.AddrPortFrom(addrs[0].Unmap(), uint16(p)), nil //nolint:gosec // validated by LookupPort
}

// QueryAll queries every server in parallel through io and returns results in
// the order of servers. Each query is bounded by timeout.
func QueryAll(ctx context.Context, io PacketIO, servers []string, family int, timeout time.Duration) []ServerResult {
	out := make([]ServerResult, len(servers))
	var wg sync.WaitGroup
	for i, s := range servers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			r := ServerResult{Server: s}
			addr, err := Resolve(ctx, s, family)
			if err != nil {
				r.Error = "dns: " + shortErr(err)
				out[i] = r
				return
			}
			r.Resolved = addr
			res, err := Binding(ctx, io, addr, 0)
			if err != nil {
				r.Error = shortErr(err)
			} else {
				r.Mapped, r.Other, r.RTTms = res.Mapped, res.Other, res.RTT.Milliseconds()
			}
			out[i] = r
		}()
	}
	wg.Wait()
	return out
}

func shortErr(err error) string {
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i >= 0 && len(s) > 80 {
		s = s[i+2:]
	}
	return s
}

// Mapping is the NAT mapping behaviour (RFC 4787).
type Mapping string

// Mapping behaviours.
const (
	MappingUnknown     Mapping = "unknown"
	MappingNone        Mapping = "none"      // no NAT: mapped address is local
	MappingIndependent Mapping = "eim"       // endpoint-independent
	MappingDependent   Mapping = "dependent" // address- and/or port-dependent ("symmetric")
)

// Filtering is the NAT filtering behaviour (RFC 4787).
type Filtering string

// Filtering behaviours.
const (
	FilteringUnknown        Filtering = "unknown"
	FilteringIndependent    Filtering = "eif"  // full cone
	FilteringAddress        Filtering = "adf"  // address-restricted
	FilteringAddressAndPort Filtering = "apdf" // port-restricted
	FilteringNone           Filtering = "none" // no NAT
)

// ClassifyMapping compares the reflexive address reported by servers at
// different IP addresses. Same address everywhere → endpoint-independent.
func ClassifyMapping(results []ServerResult, local []netip.Addr) (Mapping, netip.AddrPort) {
	byServerIP := map[netip.Addr]netip.AddrPort{}
	counts := map[netip.AddrPort]int{}
	for _, r := range results {
		if !r.OK() {
			continue
		}
		byServerIP[r.Resolved.Addr()] = r.Mapped
		counts[r.Mapped]++
	}
	if len(counts) == 0 {
		return MappingUnknown, netip.AddrPort{}
	}
	// The most frequently reported mapping is the public address.
	keys := make([]netip.AddrPort, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if counts[keys[i]] != counts[keys[j]] {
			return counts[keys[i]] > counts[keys[j]]
		}
		return keys[i].String() < keys[j].String()
	})
	public := keys[0]
	for _, l := range local {
		if l == public.Addr() {
			return MappingNone, public
		}
	}
	if len(byServerIP) < 2 {
		return MappingUnknown, public
	}
	if len(counts) == 1 {
		return MappingIndependent, public
	}
	return MappingDependent, public
}

// ProbeFiltering runs the RFC 5780 filtering test against one server using a
// socket that has not talked to anything else (so earlier traffic cannot
// have opened the NAT filter). It requires the server to report OTHER-ADDRESS.
func ProbeFiltering(ctx context.Context, io PacketIO, server netip.AddrPort, wait time.Duration) (Filtering, error) {
	c, cancel := context.WithTimeout(ctx, 2*wait)
	first, err := Binding(c, io, server, 0)
	cancel()
	if err != nil {
		return FilteringUnknown, err
	}
	if !first.Other.IsValid() {
		return FilteringUnknown, nil
	}
	c, cancel = context.WithTimeout(ctx, wait)
	_, err = Binding(c, io, server, ChangeIP|ChangePort)
	cancel()
	if err == nil {
		return FilteringIndependent, nil
	}
	c, cancel = context.WithTimeout(ctx, wait)
	_, err = Binding(c, io, server, ChangePort)
	cancel()
	if err == nil {
		return FilteringAddress, nil
	}
	return FilteringAddressAndPort, nil
}
