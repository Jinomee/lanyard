package netinfo

import (
	"bufio"
	"encoding/hex"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// temporaryV6 returns the IPv6 privacy (temporary) addresses, from the
// IFA_F_TEMPORARY flag in /proc/net/if_inet6.
func temporaryV6() map[netip.Addr]bool {
	f, err := os.Open("/proc/net/if_inet6")
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	return parseIfInet6(bufio.NewScanner(f))
}

func parseIfInet6(sc *bufio.Scanner) map[netip.Addr]bool {
	const ifaFTemporary = 0x01
	out := map[netip.Addr]bool{}
	for sc.Scan() {
		// address ifindex prefixlen scope flags name
		fs := strings.Fields(sc.Text())
		if len(fs) < 5 {
			continue
		}
		b, err := hex.DecodeString(fs[0])
		if err != nil || len(b) != 16 {
			continue
		}
		flags, err := strconv.ParseUint(fs[4], 16, 32)
		if err != nil {
			continue
		}
		if flags&ifaFTemporary != 0 {
			out[netip.AddrFrom16([16]byte(b))] = true
		}
	}
	return out
}
