package connect

import (
	"github.com/jinomee/mc/internal/joincode"
	"github.com/jinomee/mc/internal/stunx"
)

// Advice is one piece of user-facing guidance: an i18n key plus parameters.
// The core never renders text itself, so every client can show it in the
// user's language.
type Advice struct {
	Key    string            `json:"key"`
	Params map[string]string `json:"params,omitempty"`
}

// Diagnosis explains why a join failed and what to try next.
type Diagnosis struct {
	Summary Advice   `json:"summary"`
	Advice  []Advice `json:"advice"`
}

const maxAdvice = 4

// DiagnoseRejection explains a join the host refused.
func DiagnoseRejection(reason string) Diagnosis {
	return Diagnosis{Summary: Advice{Key: "diag.fail." + reason}}
}

// DiagnoseJoin explains a join that never reached the host. local is the
// guest's own network report (may be nil if gathering never finished),
// inv the host's invite, attempts the dial log, replyIssued whether the
// guest already showed a reply code.
func DiagnoseJoin(local *Report, inv *joincode.Invite, attempts []Attempt, replyIssued bool) Diagnosis {
	d := Diagnosis{Summary: Advice{Key: "diag.fail.unreachable"}}
	for _, a := range attempts {
		if a.Outcome == OutCertMismatch {
			anyOK := false
			for _, b := range attempts {
				anyOK = anyOK || b.Outcome == OutOK
			}
			if !anyOK {
				d.Summary = Advice{Key: "diag.fail.cert_mismatch"}
				return d
			}
		}
	}
	add := func(key string, params ...string) {
		if len(d.Advice) >= maxAdvice {
			return
		}
		for _, x := range d.Advice {
			if x.Key == key {
				return
			}
		}
		a := Advice{Key: key}
		if len(params) > 0 {
			a.Params = map[string]string{}
			for i := 0; i+1 < len(params); i += 2 {
				a.Params[params[i]] = params[i+1]
			}
		}
		d.Advice = append(d.Advice, a)
	}

	if !replyIssued {
		add("diag.advice.send_reply")
	}
	if local != nil && local.UDPBlocked {
		add("diag.advice.udp_blocked")
	}
	hostSym := inv.Flags.Has(joincode.FlagMapDep)
	guestSym := local != nil && local.Mapping == stunx.MappingDependent
	switch {
	case hostSym && guestSym:
		add("diag.advice.both_symmetric")
	case hostSym:
		add("diag.advice.swap_host")
	case guestSym:
		add("diag.advice.guest_symmetric")
	}
	if inv.Flags.Has(joincode.FlagCGNAT) {
		add("diag.advice.host_cgnat")
	} else if !inv.Flags.Has(joincode.FlagPortMapped) {
		add("diag.advice.host_enable_upnp")
	}
	guestV6 := local != nil && local.IPv6
	hostV6 := inv.Flags.Has(joincode.FlagIPv6)
	switch {
	case guestV6 && hostV6:
		add("diag.advice.ipv6_firewall")
	case guestV6 && !hostV6:
		add("diag.advice.ipv6_host_missing")
	case !guestV6 && hostV6:
		add("diag.advice.ipv6_guest_missing")
	}
	add("diag.advice.host_firewall")
	add("diag.advice.hotspot")
	if hostSym && guestSym {
		add("diag.advice.relay_future")
	}
	return d
}

// HostOutlook predicts, from the host's own report, how easily friends will
// be able to join. Shown on the Host screen before anyone connects.
func HostOutlook(r *Report) Diagnosis {
	d := Diagnosis{}
	switch {
	case r.UDPBlocked && !r.IPv6:
		d.Summary = Advice{Key: "diag.host.udp_blocked"}
	case (r.PortMap.Mapping != nil && !r.CGNAT) || r.NATType == NATOpen || r.NATType == NATFullCone:
		d.Summary = Advice{Key: "diag.host.good"}
	case r.Mapping == stunx.MappingIndependent:
		d.Summary = Advice{Key: "diag.host.reply_likely"}
	case r.Mapping == stunx.MappingDependent:
		d.Summary = Advice{Key: "diag.host.hard"}
		d.Advice = append(d.Advice, Advice{Key: "diag.advice.host_enable_upnp"})
	default:
		d.Summary = Advice{Key: "diag.host.unknown"}
	}
	if r.CGNAT {
		d.Advice = append(d.Advice, Advice{Key: "diag.advice.host_cgnat"})
	}
	if r.IPv6 {
		d.Advice = append(d.Advice, Advice{Key: "diag.host.ipv6_ok"})
	}
	return d
}
