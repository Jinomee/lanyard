package netinfo

import (
	"bufio"
	"net/netip"
	"strings"
	"testing"
)

func TestParseIfInet6(t *testing.T) {
	const sample = `20010db8000000000000000000000001 02 40 00 80     eth0
20010db800000000a1b2c3d4e5f60718 02 40 00 01     eth0
fe800000000000000000000000000001 02 40 20 80     eth0
`
	got := parseIfInet6(bufio.NewScanner(strings.NewReader(sample)))
	if len(got) != 1 || !got[netip.MustParseAddr("2001:db8::a1b2:c3d4:e5f6:718")] {
		t.Fatalf("got %v", got)
	}
}
