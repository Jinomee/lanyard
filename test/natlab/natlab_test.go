//go:build natlab

package natlab

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jinomee/lanyard/internal/engine"
)

// Expectations.
const (
	OneWay = "oneway" // the invite alone connects
	Reply  = "reply"  // needs the reply-code exchange
	Fail   = "fail"   // cannot connect without a relay
)

type scenario struct {
	name  string
	host  Site
	guest Site
	// expected outcome and winning strategy
	expect   string
	strategy string
	// expected host diagnostics
	hostNAT    string
	hostMapped bool
	hostCGNAT  bool
	hostIPv6   bool
	// for Fail: an advice key the guest must show
	advice string
}

var scenarios = []scenario{
	{
		name: "fullcone_host", expect: OneWay, strategy: "reflexive", hostNAT: "full_cone",
		host: Site{NAT: NATFullCone}, guest: Site{NAT: NATPortRestricted},
	},
	{
		name: "restricted_host_symmetric_guest", expect: Reply, strategy: "reflexive", hostNAT: "restricted",
		host: Site{NAT: NATRestricted}, guest: Site{NAT: NATSymmetric},
	},
	{
		name: "portrestricted_both", expect: Reply, strategy: "reflexive", hostNAT: "port_restricted",
		host: Site{NAT: NATPortRestricted}, guest: Site{NAT: NATPortRestricted},
	},
	{
		name: "portrestricted_host_symmetric_guest", expect: Fail, hostNAT: "port_restricted",
		host: Site{NAT: NATPortRestricted}, guest: Site{NAT: NATSymmetric}, advice: "diag.advice.guest_symmetric",
	},
	{
		name: "symmetric_host_fullcone_guest", expect: Reply, strategy: "peer-reflexive", hostNAT: "symmetric",
		host: Site{NAT: NATSymmetric}, guest: Site{NAT: NATFullCone},
	},
	{
		// The table's other "fails" cell next to a symmetric host.
		name: "symmetric_host_portrestricted_guest", expect: Fail, hostNAT: "symmetric",
		host: Site{NAT: NATSymmetric}, guest: Site{NAT: NATPortRestricted}, advice: "diag.advice.swap_host",
	},
	{
		name: "symmetric_both", expect: Fail, hostNAT: "symmetric",
		host: Site{NAT: NATSymmetric}, guest: Site{NAT: NATSymmetric}, advice: "diag.advice.both_symmetric",
	},
	{
		name: "upnp_host_symmetric_guest", expect: OneWay, strategy: "mapped", hostNAT: "port_restricted", hostMapped: true,
		host: Site{NAT: NATPortRestricted, UPnP: true}, guest: Site{NAT: NATSymmetric},
	},
	{
		name: "cgnat_host_upnp_on_home_router", expect: Reply, strategy: "reflexive", hostNAT: "port_restricted", hostCGNAT: true,
		host: Site{NAT: NATPortRestricted, UPnP: true, CGNAT: true}, guest: Site{NAT: NATFullCone},
	},
	{
		name: "ipv6_only_open", expect: OneWay, strategy: "ipv6", hostIPv6: true,
		host: Site{NAT: NATNone, NoV4: true, V6: true}, guest: Site{NAT: NATNone, NoV4: true, V6: true},
	},
	{
		name: "ipv6_only_firewalled", expect: Reply, strategy: "ipv6", hostIPv6: true,
		host: Site{NAT: NATNone, NoV4: true, V6: true, V6Firewall: true}, guest: Site{NAT: NATNone, NoV4: true, V6: true, V6Firewall: true},
	},
}

func buildBinaries(t *testing.T) (core, helper string) {
	t.Helper()
	// CI builds as the normal user and runs the test binary as root.
	if c, h := os.Getenv("NATLAB_CORE"), os.Getenv("NATLAB_HELPER"); c != "" && h != "" {
		return c, h
	}
	dir := t.TempDir()
	core, helper = filepath.Join(dir, "lanyard-core"), filepath.Join(dir, "helper")
	for _, b := range [][2]string{{core, "github.com/jinomee/lanyard/cmd/lanyard-core"}, {helper, "github.com/jinomee/lanyard/test/natlab/helper"}} {
		cmd := exec.Command("go", "build", "-o", b[0], b[1])
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build %s: %v\n%s", b[1], err, out)
		}
	}
	return core, helper
}

func TestNATMatrix(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("NAT lab needs root")
	}
	for _, tool := range []string{"ip", "nft"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not installed", tool)
		}
	}
	core, helper := buildBinaries(t)
	only := os.Getenv("NATLAB_ONLY")
	for _, sc := range scenarios {
		if only != "" && !strings.Contains(sc.name, only) {
			continue
		}
		t.Run(sc.name, func(t *testing.T) {
			if (sc.host.UPnP || sc.guest.UPnP) && !haveMiniupnpd() {
				t.Skip("miniupnpd not installed")
			}
			runScenario(t, core, helper, sc)
		})
	}
}

func haveMiniupnpd() bool {
	_, err := exec.LookPath("miniupnpd")
	return err == nil
}

func waitState(t *testing.T, l *Lab, key, what string, timeout time.Duration, ok func(engine.State) bool) engine.State {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var s engine.State
	for time.Now().Before(deadline) {
		if err := l.Ctl(key, "GET", "/v1/state", nil, &s); err == nil && ok(s) {
			return s
		}
		time.Sleep(250 * time.Millisecond)
	}
	dump(t, l)
	t.Fatalf("timed out waiting for %s", what)
	return s
}

func dump(t *testing.T, l *Lab) {
	t.Helper()
	for _, name := range []string{"h-core", "g-core", "h-miniupnpd"} {
		if log := l.Log(name); log != "" {
			if len(log) > 6000 {
				log = log[len(log)-6000:]
			}
			t.Logf("---- %s ----\n%s", name, log)
		}
	}
	// Where do packets die? Capture briefly on every hop while the guest
	// keeps retrying, and show conntrack state of the routers.
	type capture struct{ ns, dev string }
	caps := []capture{{"ly-gr", "lan"}, {"ly-gr", "wan"}, {"ly-inet", "br0"}, {"ly-hr", "wan"}, {"ly-hr", "lan"}}
	outs := make([][]byte, len(caps))
	done := make(chan int, len(caps))
	for i, c := range caps {
		go func() {
			outs[i], _ = exec.Command("ip", "netns", "exec", c.ns, "timeout", "4", "tcpdump", "-lnni", c.dev,
				"-c", "20", "udp and not port 3478 and not port 3479 and not port 4445 and not port 1900 and not port 5351").CombinedOutput()
			done <- i
		}()
	}
	for range caps {
		<-done
	}
	for i, c := range caps {
		t.Logf("---- tcpdump %s %s ----\n%s", c.ns, c.dev, outs[i])
	}
	for _, ns := range []string{"ly-hr", "ly-gr", "ly-hc", "ly-inet"} {
		if out, err := exec.Command("ip", "netns", "exec", ns, "conntrack", "-L", "-p", "udp").CombinedOutput(); err == nil {
			t.Logf("---- conntrack %s ----\n%s", ns, out)
		}
		if out, err := exec.Command("ip", "netns", "exec", ns, "sysctl", "net.bridge.bridge-nf-call-iptables", "net.ipv4.ip_forward").CombinedOutput(); err == nil {
			t.Logf("---- sysctl %s ----\n%s", ns, out)
		}
	}
}

func runScenario(t *testing.T, core, helper string, sc scenario) {
	l := NewLab(t, core, helper, sc.host, sc.guest)
	l.Start(inetNS, "stun", helper, "stun", "-a", stunA, "-b", stunB, ifV6(l, "-a6", stunA6), ifV6(l, "-b6", stunB6))
	l.Start(addrs["h"].ns, "mc", helper, "mc", "-port", "25565", "-motd", "Steve - Lab World")
	l.StartCore("h")
	l.StartCore("g")
	time.Sleep(300 * time.Millisecond)

	stun := []string{stunA + ":3478", stunB + ":3478"}
	if l.v6 {
		stun = append(stun, "["+stunA6+"]:3478", "["+stunB6+"]:3478")
	}
	for _, k := range []string{"h", "g"} {
		var s map[string]any
		if err := l.Ctl(k, "GET", "/v1/settings", nil, &s); err != nil {
			t.Fatal(err)
		}
		s["stunServers"], s["upnp"], s["playerName"] = stun, k == "h" && sc.host.UPnP || k == "g" && sc.guest.UPnP, "lab-"+k
		if err := l.Ctl(k, "PUT", "/v1/settings", s, nil); err != nil {
			t.Fatal(err)
		}
	}

	// Host: auto mode, the fake world announces itself to LAN.
	if err := l.Ctl("h", "POST", "/v1/host/start", map[string]any{"mode": "auto"}, nil); err != nil {
		t.Fatal(err)
	}
	hs := waitState(t, l, "h", "host ready with detected world", 20*time.Second, func(s engine.State) bool {
		if s.Host != nil && s.Host.Status == engine.HostError {
			dump(t, l)
			t.Fatalf("host error %+v", s.Host.Error)
		}
		return s.Host != nil && s.Host.Status == engine.HostReady && s.Host.Target == "127.0.0.1:25565"
	}).Host
	r := hs.Report
	t.Logf("host report: nat=%s mapping=%s filtering=%s portmap=%v cgnat=%v(%s) ipv6=%v candidates in code=%s",
		r.NATType, r.Mapping, r.Filtering, r.PortMap.Mapping != nil, r.CGNAT, r.CGNATReason, r.IPv6, hs.Code)
	if sc.hostNAT != "" && r.NATType != sc.hostNAT {
		t.Errorf("host NAT type %q, want %q", r.NATType, sc.hostNAT)
	}
	if sc.hostMapped && r.PortMap.Mapping == nil {
		t.Errorf("host has no port mapping: %+v", r.PortMap.Errors)
	}
	if sc.hostCGNAT != r.CGNAT {
		t.Errorf("host CGNAT=%v want %v", r.CGNAT, sc.hostCGNAT)
	}
	if sc.hostIPv6 && !r.IPv6 {
		t.Errorf("host IPv6 not detected")
	}
	if t.Failed() {
		t.Logf("host port mapping errors: %v", r.PortMap.Errors)
		dump(t, l)
	}

	timeout := 120
	if sc.expect == Fail {
		timeout = 30
	}
	if err := l.Ctl("g", "POST", "/v1/join/start", map[string]any{"code": hs.Code, "timeoutSec": timeout}, nil); err != nil {
		t.Fatal(err)
	}

	isDone := func(s engine.State) bool {
		return s.Join != nil && (s.Join.Status == engine.JoinConnected || s.Join.Status == engine.JoinFailed)
	}
	var gs engine.State
	if sc.expect == OneWay {
		gs = waitState(t, l, "g", "one-way connection", 20*time.Second, isDone)
	} else {
		gs = waitState(t, l, "g", "reply code", 30*time.Second, func(s engine.State) bool {
			return isDone(s) || s.Join != nil && s.Join.Status == engine.JoinNeedReply && s.Join.ReplyCode != ""
		})
		if gs.Join.Status == engine.JoinConnected {
			t.Fatalf("connected one-way via %+v, expected %s", gs.Join.Via, sc.expect)
		}
		if gs.Join.Status != engine.JoinFailed {
			t.Logf("guest reply code: %s", gs.Join.ReplyCode)
			if err := l.Ctl("h", "POST", "/v1/host/reply", map[string]string{"code": gs.Join.ReplyCode}, nil); err != nil {
				t.Fatal(err)
			}
			gs = waitState(t, l, "g", "connection after reply", time.Duration(timeout+15)*time.Second, isDone)
		}
	}
	j := gs.Join
	for _, a := range j.Attempts {
		t.Logf("attempt %-15s %-28s phase=%-6s tries=%-3d outcome=%s %s", a.Strategy, a.Addr, a.Phase, a.Tries, a.Outcome, a.Error)
	}

	if sc.expect == Fail {
		if j.Status != engine.JoinFailed {
			t.Fatalf("expected failure, got %s via %+v", j.Status, j.Via)
		}
		var keys []string
		for _, a := range j.Failure.Advice {
			keys = append(keys, a.Key)
		}
		t.Logf("failure: %s advice %v", j.Failure.Summary.Key, keys)
		if j.Failure.Summary.Key != "diag.fail.unreachable" || !slices.Contains(keys, sc.advice) {
			t.Fatalf("diagnosis %+v does not contain %s", j.Failure, sc.advice)
		}
		return
	}
	if j.Status != engine.JoinConnected {
		dump(t, l)
		t.Fatalf("join failed: %+v", j.Failure)
	}
	wantPhase := "direct"
	if sc.expect == Reply {
		wantPhase = "punch"
	}
	t.Logf("connected via %s %s (%s phase)", j.Via.Strategy, j.Via.Addr, j.Via.Phase)
	if j.Via.Strategy != sc.strategy || j.Via.Phase != wantPhase {
		t.Errorf("via %s/%s, want %s/%s", j.Via.Strategy, j.Via.Phase, sc.strategy, wantPhase)
	}

	// The world shows up in the guest's LAN list and carries traffic.
	if out, err := l.Helper("g", "lanwait", "-port", portOf(j.LocalAddr), "-timeout", "5s"); err != nil {
		t.Errorf("LAN announcement not seen: %v %s", err, out)
	}
	if out, err := l.Helper("g", "client", "-addr", j.LocalAddr); err != nil {
		t.Fatalf("traffic through tunnel: %v %s", err, out)
	}
	if out, err := l.Helper("g", "client", "-addr", j.LocalAddr, "-size", "1000"); err != nil {
		t.Fatalf("second connection: %v %s", err, out)
	}
}

func ifV6(l *Lab, flag, v string) string {
	if !l.v6 {
		return flag + "="
	}
	return flag + "=" + v
}

func portOf(addr string) string {
	i := strings.LastIndexByte(addr, ':')
	return addr[i+1:]
}
