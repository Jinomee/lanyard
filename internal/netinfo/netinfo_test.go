package netinfo

import (
	"net/netip"
	"slices"
	"testing"
)

func TestSortV6StableFirst(t *testing.T) {
	tmp1 := netip.MustParseAddr("2001:db8::aaaa")
	tmp2 := netip.MustParseAddr("2001:db8::bbbb")
	stable := netip.MustParseAddr("2001:db8::1")
	as := []netip.Addr{tmp1, tmp2, stable}
	sortV6(as, map[netip.Addr]bool{tmp1: true, tmp2: true}, tmp2)
	if want := []netip.Addr{stable, tmp2, tmp1}; !slices.Equal(as, want) {
		t.Fatalf("got %v, want %v", as, want)
	}
}
