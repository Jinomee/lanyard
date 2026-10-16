package netinfo

import (
	"net/netip"
	"unsafe"

	"golang.org/x/sys/windows"
)

// temporaryV6 returns the IPv6 privacy (temporary) addresses.
//
// A random interface identifier alone doesn't make an address temporary:
// Windows also randomises the identifier of its stable address by default
// (RandomizeIdentifiers). What differs is that Windows never registers a
// temporary address in DNS, so it lacks IP_ADAPTER_ADDRESS_DNS_ELIGIBLE.
// If that assumption were wrong, every address would land in one group and
// the order would fall back to the OS's preferred source, as before.
func temporaryV6() map[netip.Addr]bool {
	const ipAdapterAddressDNSEligible = 0x01
	size := uint32(16 << 10)
	var buf []byte
	for range 3 {
		buf = make([]byte, size)
		err := windows.GetAdaptersAddresses(windows.AF_INET6, windows.GAA_FLAG_SKIP_ANYCAST|windows.GAA_FLAG_SKIP_MULTICAST|windows.GAA_FLAG_SKIP_DNS_SERVER,
			0, (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])), &size) //nolint:gosec // buffer sized for the API
		if err == nil {
			break
		}
		if err != windows.ERROR_BUFFER_OVERFLOW { //nolint:errorlint // syscall errno
			return nil
		}
		buf = nil
	}
	if buf == nil {
		return nil
	}
	out := map[netip.Addr]bool{}
	for aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])); aa != nil; aa = aa.Next { //nolint:gosec // filled by the API
		for ua := aa.FirstUnicastAddress; ua != nil; ua = ua.Next {
			if ua.SuffixOrigin != windows.IpSuffixOriginRandom || ua.Flags&ipAdapterAddressDNSEligible != 0 {
				continue
			}
			if ip, ok := netip.AddrFromSlice(ua.Address.IP()); ok && ip.Is6() {
				out[ip] = true
			}
		}
	}
	return out
}
