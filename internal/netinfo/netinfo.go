// Package netinfo inspects the local machine's addresses.
package netinfo

import (
	"net"
	"net/netip"
	"sort"
)

var (
	cgnatPrefix  = netip.MustParsePrefix("100.64.0.0/10")
	teredoPrefix = netip.MustParsePrefix("2001::/32")
	sixToFour    = netip.MustParsePrefix("2002::/16")
	nat64Prefix  = netip.MustParsePrefix("64:ff9b::/96")
	ulaPrefix    = netip.MustParsePrefix("fc00::/7")
)

// IsCGNAT reports whether a is in the shared address space used by carrier-grade NAT.
func IsCGNAT(a netip.Addr) bool { return cgnatPrefix.Contains(a.Unmap()) }

// IsPublicV4 reports whether a is a globally routable IPv4 address.
func IsPublicV4(a netip.Addr) bool {
	a = a.Unmap()
	return a.Is4() && a.IsGlobalUnicast() && !a.IsPrivate() && !IsCGNAT(a)
}

// IsUsableGlobalV6 reports whether a is a global IPv6 address worth putting in a
// join code. Teredo, 6to4, NAT64 and ULA addresses are excluded: they rarely
// accept unsolicited inbound traffic and would only slow connecting down.
func IsUsableGlobalV6(a netip.Addr) bool {
	if !a.Is6() || a.Is4In6() || !a.IsGlobalUnicast() {
		return false
	}
	for _, p := range []netip.Prefix{teredoPrefix, sixToFour, nat64Prefix, ulaPrefix} {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

// Addrs describes the machine's interesting addresses.
type Addrs struct {
	// GlobalV6 are usable global IPv6 addresses: stable ones first, then
	// temporary (privacy) ones; the OS's preferred source first in each group.
	GlobalV6 []netip.Addr `json:"globalV6,omitempty"`
	// TemporaryV6 are the GlobalV6 addresses recognised as temporary, shown
	// in diagnostics so the classification can be checked.
	TemporaryV6 []netip.Addr `json:"temporaryV6,omitempty"`
	// LANv4 is the IPv4 address used for outbound traffic (usually private).
	LANv4 netip.Addr `json:"lanV4,omitzero"`
	// AllV4 are all non-loopback IPv4 interface addresses.
	AllV4 []netip.Addr `json:"allV4,omitempty"`
}

// Local returns the machine's addresses. It never sends packets.
func Local() Addrs {
	var out Addrs
	ifaces, _ := net.Interfaces()
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifi.Addrs()
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(ipn.IP)
			if !ok {
				continue
			}
			ip = ip.Unmap()
			switch {
			case ip.Is4() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast():
				out.AllV4 = append(out.AllV4, ip)
			case IsUsableGlobalV6(ip):
				out.GlobalV6 = append(out.GlobalV6, ip)
			}
		}
	}
	// "Connecting" a UDP socket picks the source address the OS would use,
	// without sending anything.
	if a := preferredSource("udp4", "1.1.1.1:53"); a.IsValid() {
		out.LANv4 = a
	} else if len(out.AllV4) > 0 {
		out.LANv4 = out.AllV4[0]
	}
	tmp := temporaryV6()
	sortV6(out.GlobalV6, tmp, preferredSource("udp6", "[2400:3200::1]:53"))
	for _, a := range out.GlobalV6 {
		if tmp[a] {
			out.TemporaryV6 = append(out.TemporaryV6, a)
		}
	}
	return out
}

// sortV6 orders global IPv6 addresses for an invite: stable addresses before
// temporary (privacy) ones, which the OS rotates daily while a code may be
// used for longer; within each group the OS's preferred source first.
func sortV6(as []netip.Addr, temporary map[netip.Addr]bool, pref netip.Addr) {
	sort.SliceStable(as, func(i, j int) bool {
		if ti, tj := temporary[as[i]], temporary[as[j]]; ti != tj {
			return !ti
		}
		return as[i] == pref && as[j] != pref
	})
}

func preferredSource(network, dst string) netip.Addr {
	c, err := net.Dial(network, dst)
	if err != nil {
		return netip.Addr{}
	}
	defer func() { _ = c.Close() }()
	ua, ok := c.LocalAddr().(*net.UDPAddr)
	if !ok {
		return netip.Addr{}
	}
	return ua.AddrPort().Addr().Unmap()
}

// HasAddr reports whether a is one of this machine's addresses (or loopback).
func HasAddr(a netip.Addr) bool {
	a = a.Unmap()
	if a.IsLoopback() {
		return true
	}
	addrs, _ := net.InterfaceAddrs()
	for _, x := range addrs {
		if ipn, ok := x.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(ipn.IP); ok && ip.Unmap() == a {
				return true
			}
		}
	}
	return false
}

// AllLocal returns every interface address, including loopback.
func AllLocal() []netip.Addr {
	var out []netip.Addr
	addrs, _ := net.InterfaceAddrs()
	for _, x := range addrs {
		if ipn, ok := x.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(ipn.IP); ok {
				out = append(out, ip.Unmap())
			}
		}
	}
	return out
}
