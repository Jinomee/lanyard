//go:build natlab

// Package natlab builds small virtual internets out of Linux network
// namespaces and runs two real LANyard cores across them, behind emulated
// NATs:
//
//	              ly-inet (bridge br0 = "the internet", STUN server 11.0.0.100/.101)
//	            /                                    \
//	ly-hr (host router, NAT)                   ly-gr (guest router, NAT)
//	      |                                          |
//	ly-h (host PC: core + fake Minecraft)      ly-g (guest PC: core + fake client)
//
// NAT behaviours are built with nftables in the router namespaces:
//
//	full cone        masquerade (port-preserving) + DNAT of every inbound UDP packet
//	restricted       masquerade + DNAT only from addresses the host contacted (dynamic set)
//	port-restricted  masquerade, conntrack only (Linux default)
//	symmetric        masquerade fully-random (new port per destination)
//
// UPnP/NAT-PMP/PCP is a real miniupnpd. Requires root (CAP_NET_ADMIN), ip, nft.
package natlab

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// NAT kinds.
const (
	NATNone           = "none" // router routes but does not translate (IPv6 sites)
	NATFullCone       = "fullcone"
	NATRestricted     = "restricted"
	NATPortRestricted = "portrestricted"
	NATSymmetric      = "symmetric"
)

// Site is one side (host or guest).
type Site struct {
	NAT        string
	UPnP       bool // run miniupnpd on the router
	NoV4       bool // no IPv4 internet (the router has no IPv4 uplink)
	V6         bool // give the PC a global IPv6 address
	V6Firewall bool // stateful IPv6 firewall on the router (blocks unsolicited inbound)
	CGNAT      bool // the router's WAN sits behind a carrier NAT (port-restricted)
}

type siteAddrs struct {
	ns, router, carrier string
	wan4, lan4, pc4     string
	lanNet4             string
	carrierWAN4         string
	wan6, lan6, pc6     string
	lanNet6             string
}

var addrs = map[string]siteAddrs{
	"h": {ns: "ly-h", router: "ly-hr", carrier: "ly-hc", wan4: "11.0.0.10", lan4: "10.1.0.1", pc4: "10.1.0.2", lanNet4: "10.1.0.0/24",
		carrierWAN4: "11.0.0.30", wan6: "2001:db8:ff::10", lan6: "2001:db8:1::1", pc6: "2001:db8:1::2", lanNet6: "2001:db8:1::/64"},
	"g": {ns: "ly-g", router: "ly-gr", carrier: "ly-gc", wan4: "11.0.0.20", lan4: "10.2.0.1", pc4: "10.2.0.2", lanNet4: "10.2.0.0/24",
		carrierWAN4: "11.0.0.40", wan6: "2001:db8:ff::20", lan6: "2001:db8:2::1", pc6: "2001:db8:2::2", lanNet6: "2001:db8:2::/64"},
}

const (
	inetNS = "ly-inet"
	stunA  = "11.0.0.100"
	stunB  = "11.0.0.101"
	stunA6 = "2001:db8:ff::100"
	stunB6 = "2001:db8:ff::101"
)

// Lab is one instantiated topology.
type Lab struct {
	t     *testing.T
	work  string
	bin   string // lanyard-core
	help  string // helper
	procs []*exec.Cmd
	v6    bool
}

func run(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return string(out)
}

func ipns(t *testing.T, ns string, args ...string) {
	t.Helper()
	run(t, "ip", append([]string{"-n", ns}, args...)...)
}

func nsexec(t *testing.T, ns string, args ...string) string {
	t.Helper()
	return run(t, "ip", append([]string{"netns", "exec", ns}, args...)...)
}

// HasIPv6 reports whether the kernel supports IPv6.
func HasIPv6() bool {
	_, err := os.Stat("/proc/sys/net/ipv6")
	return err == nil
}

// Cleanup removes every lab namespace.
func Cleanup() {
	out, _ := exec.Command("ip", "netns", "list").Output()
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) > 0 && strings.HasPrefix(f[0], "ly-") {
			_ = exec.Command("ip", "netns", "del", f[0]).Run()
		}
	}
}

// NewLab builds the topology for host and guest sites.
func NewLab(t *testing.T, bin, help string, host, guest Site) *Lab {
	t.Helper()
	Cleanup()
	l := &Lab{t: t, work: t.TempDir(), bin: bin, help: help, v6: HasIPv6()}
	t.Cleanup(l.Close)

	run(t, "ip", "netns", "add", inetNS)
	ipns(t, inetNS, "link", "set", "lo", "up")
	ipns(t, inetNS, "link", "add", "br0", "type", "bridge")
	ipns(t, inetNS, "link", "set", "br0", "up")
	ipns(t, inetNS, "addr", "add", stunA+"/24", "dev", "br0")
	ipns(t, inetNS, "addr", "add", stunB+"/24", "dev", "br0")
	if l.v6 {
		nsexec(t, inetNS, "sysctl", "-qw", "net.ipv6.conf.all.forwarding=1")
		ipns(t, inetNS, "addr", "add", stunA6+"/64", "dev", "br0", "nodad")
		ipns(t, inetNS, "addr", "add", stunB6+"/64", "dev", "br0", "nodad")
	}
	l.site("h", host)
	l.site("g", guest)
	return l
}

// attach creates a veth pair: name (moved into ns) ↔ peer attached to br0.
func (l *Lab) attachToInternet(ns, ifname, peer string) {
	t := l.t
	run(t, "ip", "link", "add", peer, "type", "veth", "peer", "name", ifname)
	run(t, "ip", "link", "set", ifname, "netns", ns)
	run(t, "ip", "link", "set", peer, "netns", inetNS)
	ipns(t, inetNS, "link", "set", peer, "master", "br0")
	ipns(t, inetNS, "link", "set", peer, "up")
}

func (l *Lab) site(key string, s Site) {
	t := l.t
	a := addrs[key]
	for _, ns := range []string{a.router, a.ns} {
		run(t, "ip", "netns", "add", ns)
		ipns(t, ns, "link", "set", "lo", "up")
	}
	nsexec(t, a.router, "sysctl", "-qw", "net.ipv4.ip_forward=1")

	// Router WAN: directly on the internet, or behind a carrier NAT.
	if s.CGNAT {
		run(t, "ip", "netns", "add", a.carrier)
		ipns(t, a.carrier, "link", "set", "lo", "up")
		nsexec(t, a.carrier, "sysctl", "-qw", "net.ipv4.ip_forward=1")
		l.attachToInternet(a.carrier, "wan", key+"c-br")
		ipns(t, a.carrier, "addr", "add", a.carrierWAN4+"/24", "dev", "wan")
		ipns(t, a.carrier, "link", "set", "wan", "up")
		run(t, "ip", "link", "add", key+"c-lan", "type", "veth", "peer", "name", key+"r-wan")
		run(t, "ip", "link", "set", key+"c-lan", "netns", a.carrier)
		run(t, "ip", "link", "set", key+"r-wan", "netns", a.router)
		ipns(t, a.carrier, "link", "set", key+"c-lan", "name", "lan")
		ipns(t, a.router, "link", "set", key+"r-wan", "name", "wan")
		ipns(t, a.carrier, "addr", "add", "100.64.0.1/24", "dev", "lan")
		ipns(t, a.carrier, "link", "set", "lan", "up")
		ipns(t, a.router, "addr", "add", "100.64.0.10/24", "dev", "wan")
		ipns(t, a.router, "link", "set", "wan", "up")
		ipns(t, a.router, "route", "add", "default", "via", "100.64.0.1")
		// Route back to the home LAN is not needed: the home router NATs.
		l.nft(a.carrier, nftRules(NATPortRestricted, false, "100.64.0.10"))
	} else {
		l.attachToInternet(a.router, "wan", key+"r-br")
		if !s.NoV4 {
			ipns(t, a.router, "addr", "add", a.wan4+"/24", "dev", "wan")
		}
		ipns(t, a.router, "link", "set", "wan", "up")
	}

	// LAN between router and PC.
	run(t, "ip", "link", "add", key+"-lan", "type", "veth", "peer", "name", key+"-eth")
	run(t, "ip", "link", "set", key+"-lan", "netns", a.router)
	run(t, "ip", "link", "set", key+"-eth", "netns", a.ns)
	ipns(t, a.router, "link", "set", key+"-lan", "name", "lan")
	ipns(t, a.ns, "link", "set", key+"-eth", "name", "eth0")
	ipns(t, a.router, "addr", "add", a.lan4+"/24", "dev", "lan")
	ipns(t, a.router, "link", "set", "lan", "up")
	ipns(t, a.ns, "link", "set", "eth0", "up")
	// The PC always has a private IPv4 LAN address (Minecraft's LAN
	// discovery is IPv4 multicast); with NoV4 the router has no IPv4 uplink.
	ipns(t, a.ns, "addr", "add", a.pc4+"/24", "dev", "eth0")
	ipns(t, a.ns, "route", "add", "default", "via", a.lan4)

	if s.V6 {
		if !l.v6 {
			t.Skip("kernel has no IPv6")
		}
		other := addrs[map[string]string{"h": "g", "g": "h"}[key]]
		nsexec(t, a.router, "sysctl", "-qw", "net.ipv6.conf.all.forwarding=1")
		ipns(t, a.router, "addr", "add", a.wan6+"/64", "dev", "wan", "nodad")
		ipns(t, a.router, "addr", "add", a.lan6+"/64", "dev", "lan", "nodad")
		ipns(t, a.ns, "addr", "add", a.pc6+"/64", "dev", "eth0", "nodad")
		ipns(t, a.ns, "-6", "route", "add", "default", "via", a.lan6)
		ipns(t, a.router, "-6", "route", "add", other.lanNet6, "via", other.wan6)
	}

	l.nft(a.router, nftRules(s.NAT, s.V6Firewall, a.pc4))
	if s.UPnP {
		l.miniupnpd(key, a, s)
	}
}

// nftRules returns the router ruleset. pc is the PC's LAN IPv4 (DNAT target).
func nftRules(nat string, v6fw bool, pc string) string {
	var fwd, pre strings.Builder
	if nat == NATRestricted {
		// Per mapping: remember (remote address, internal = external port).
		fwd.WriteString(`    iifname "lan" oifname "wan" meta l4proto udp update @contacted { ip daddr . udp sport }` + "\n")
	}
	switch nat {
	case NATFullCone:
		fmt.Fprintf(&pre, "    iifname \"wan\" meta nfproto ipv4 meta l4proto udp dnat ip to %s\n", pc)
	case NATRestricted:
		fmt.Fprintf(&pre, "    iifname \"wan\" meta l4proto udp ip saddr . udp dport @contacted dnat ip to %s\n", pc)
	}
	masq := ""
	switch nat {
	case NATNone:
	case NATSymmetric:
		masq = `    oifname "wan" meta nfproto ipv4 masquerade fully-random` + "\n"
	default:
		masq = `    oifname "wan" meta nfproto ipv4 masquerade` + "\n"
	}
	v6in := `    iifname "wan" oifname "lan" meta nfproto ipv6 accept` + "\n"
	if v6fw {
		v6in = ""
	}
	if nat == NATNone {
		// Plain router: forward IPv4 both ways too.
		v6in += `    iifname "wan" oifname "lan" meta nfproto ipv4 accept` + "\n"
	}
	return fmt.Sprintf(`table inet filter {
  set contacted { type ipv4_addr . inet_service; flags dynamic,timeout; timeout 5m; }
  chain forward {
    type filter hook forward priority 0; policy drop;
    ct state established,related accept
    jump miniupnpd
%s    iifname "lan" accept
    ct status dnat accept
%s  }
  chain miniupnpd { }
  # Like every real router: nothing unsolicited from the WAN reaches the
  # router itself. (Besides realism this matters: an accepted packet would
  # leave a confirmed conntrack entry that later collides with the PC's
  # outbound punch and makes SNAT pick a different port.)
  chain input {
    type filter hook input priority 0; policy accept;
    iifname "wan" ct state established,related accept
    iifname "wan" drop
  }
  chain prerouting {
    type nat hook prerouting priority -100; policy accept;
    jump prerouting_miniupnpd
%s  }
  chain prerouting_miniupnpd { }
  chain postrouting {
    type nat hook postrouting priority 100; policy accept;
    jump postrouting_miniupnpd
%s  }
  chain postrouting_miniupnpd { }
}
`, fwd.String(), v6in, pre.String(), masq)
}

func (l *Lab) nft(ns, rules string) {
	l.t.Helper()
	f := filepath.Join(l.work, ns+".nft")
	if err := os.WriteFile(f, []byte(rules), 0o600); err != nil {
		l.t.Fatal(err)
	}
	nsexec(l.t, ns, "nft", "-f", f)
}

func (l *Lab) miniupnpd(key string, a siteAddrs, s Site) {
	conf := filepath.Join(l.work, key+"-miniupnpd.conf")
	body := fmt.Sprintf(`ext_ifname=wan
listening_ip=lan
http_port=0
enable_natpmp=yes
enable_upnp=yes
secure_mode=yes
system_uptime=yes
uuid=00000000-0000-4000-8000-00000000000%d
allow 1024-65535 %s 1024-65535
deny 0-65535 0.0.0.0/0 0-65535
`, map[string]int{"h": 1, "g": 2}[key], a.lanNet4)
	if err := os.WriteFile(conf, []byte(body), 0o600); err != nil {
		l.t.Fatal(err)
	}
	l.Start(a.router, key+"-miniupnpd", "miniupnpd", "-f", conf, "-d", "-4", "-P", filepath.Join(l.work, key+"-miniupnpd.pid"))
	time.Sleep(500 * time.Millisecond)
}

// Start runs a long-lived process in ns, logging to work/<name>.log.
func (l *Lab) Start(ns, name string, args ...string) *exec.Cmd {
	l.t.Helper()
	logf, err := os.Create(filepath.Join(l.work, name+".log"))
	if err != nil {
		l.t.Fatal(err)
	}
	cmd := exec.Command("ip", append([]string{"netns", "exec", ns}, args...)...)
	cmd.Stdout, cmd.Stderr = logf, logf
	if err := cmd.Start(); err != nil {
		l.t.Fatalf("start %s: %v", name, err)
	}
	l.procs = append(l.procs, cmd)
	return cmd
}

// Log returns a process's output so far.
func (l *Lab) Log(name string) string {
	b, _ := os.ReadFile(filepath.Join(l.work, name+".log"))
	return string(b)
}

// Home returns a core's config directory.
func (l *Lab) Home(key string) string { return filepath.Join(l.work, key+"-home") }

// StartCore runs a LANyard core in the PC namespace of key.
func (l *Lab) StartCore(key string) {
	l.Start(addrs[key].ns, key+"-core", l.bin, "serve", "-home", l.Home(key), "-v", "-no-update-checks")
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := l.ctl(key, "GET", "/v1/hello", ""); err == nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	l.t.Fatalf("core %s did not start:\n%s", key, l.Log(key+"-core"))
}

func (l *Lab) ctl(key, method, path, body string) ([]byte, error) {
	args := []string{"netns", "exec", addrs[key].ns, l.bin, "ctl", "-home", l.Home(key), method, path}
	if body != "" {
		args = append(args, body)
	}
	var stderr bytes.Buffer
	cmd := exec.Command("ip", args...)
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("%v: %s", err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

// Ctl calls the core API and decodes JSON into out (may be nil).
func (l *Lab) Ctl(key, method, path string, body any, out any) error {
	var b string
	if body != nil {
		j, _ := json.Marshal(body)
		b = string(j)
	}
	data, err := l.ctl(key, method, path, b)
	if err != nil {
		return err
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

// Helper runs the helper binary in a namespace and returns its output.
func (l *Lab) Helper(key string, args ...string) (string, error) {
	ns := inetNS
	if key != "" {
		ns = addrs[key].ns
	}
	out, err := exec.Command("ip", append([]string{"netns", "exec", ns, l.help}, args...)...).CombinedOutput()
	return string(out), err
}

// Close stops processes and removes namespaces.
func (l *Lab) Close() {
	for _, p := range l.procs {
		if p.Process != nil {
			_ = p.Process.Signal(os.Interrupt)
		}
	}
	time.Sleep(300 * time.Millisecond)
	for _, p := range l.procs {
		if p.Process != nil {
			_ = p.Process.Kill()
			_, _ = p.Process.Wait()
		}
	}
	Cleanup()
}
