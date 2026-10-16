// Command stuncheck queries STUN servers and reports which answer, with RTT
// and RFC 5780 support. CI runs it against the default list (and a pool of
// candidates) so dead servers are noticed; see docs/DECISIONS.md.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jinomee/mc/internal/config"
	"github.com/jinomee/mc/internal/stunx"
	"github.com/jinomee/mc/internal/transport"
)

// candidates are extra servers worth evaluating for the default list.
var candidates = []string{
	"stun.qq.com:3478",
	"stun.douyucdn.cn:18000",
	"stun.cdnbye.com:3478",
	"stun.syncthing.net:3478",
	"stun.voipgate.com:3478",
	"stun.sipnet.com:3478",
	"stun.freeswitch.org:3478",
	"stun.l.google.com:3478",
	"stun1.l.google.com:19302",
	"global.stun.twilio.com:3478",
	"stunserver2025.stunprotocol.org:3478",
}

func main() {
	all := flag.Bool("all", false, "also check candidate servers")
	min := flag.Int("min", 2, "fail if fewer default IPv4 servers answer")
	flag.Parse()
	servers := append([]string(nil), config.DefaultSTUNServers...)
	if *all {
		servers = append(servers, candidates...)
	}
	servers = append(servers, flag.Args()...)
	okDefault := 0
	for _, fam := range []int{4, 6} {
		ep, err := transport.ListenUDP(fam, 0)
		if err != nil {
			fmt.Printf("IPv%d: no socket (%v)\n", fam, err)
			continue
		}
		res := stunx.QueryAll(context.Background(), ep, servers, fam, 3*time.Second)
		_ = ep.Close()
		fmt.Printf("\n## IPv%d\n\n| server | default | result | rtt | RFC 5780 |\n|---|---|---|---|---|\n", fam)
		for i, r := range res {
			def := i < len(config.DefaultSTUNServers)
			status := "ok " + r.Mapped.String()
			if !r.OK() {
				status = "FAIL " + r.Error
			} else if def && fam == 4 {
				okDefault++
			}
			rfc := ""
			if r.Other.IsValid() {
				rfc = "yes"
			}
			fmt.Printf("| %s | %v | %s | %dms | %s |\n", r.Server, def, strings.ReplaceAll(status, "|", "/"), r.RTTms, rfc)
		}
	}
	fmt.Printf("\n%d of %d default servers answered over IPv4\n", okDefault, len(config.DefaultSTUNServers))
	if okDefault < *min {
		os.Exit(1)
	}
}
