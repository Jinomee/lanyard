package i18n

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/jinomee/mc/internal/connect"
	"github.com/jinomee/mc/internal/transport"
)

var placeholder = regexp.MustCompile(`\{[a-zA-Z]+\}`)

func placeholders(s string) string {
	ps := placeholder.FindAllString(s, -1)
	sort.Strings(ps)
	return strings.Join(slicesCompact(ps), ",")
}

func slicesCompact(s []string) []string {
	var out []string
	for i, x := range s {
		if i == 0 || x != s[i-1] {
			out = append(out, x)
		}
	}
	return out
}

// TestCatalogsComplete: every language has exactly the same keys and the
// same placeholders as English.
func TestCatalogsComplete(t *testing.T) {
	en := catalogs[Default]
	if len(en) < 100 {
		t.Fatalf("English catalog suspiciously small: %d", len(en))
	}
	for lang, cat := range catalogs {
		if lang == Default {
			continue
		}
		for k, v := range en {
			tr, ok := cat[k]
			if !ok {
				t.Errorf("%s: missing %q", lang, k)
				continue
			}
			if placeholders(tr) != placeholders(v) {
				t.Errorf("%s: %q placeholders %s, English has %s", lang, k, placeholders(tr), placeholders(v))
			}
			if strings.TrimSpace(tr) == "" && strings.TrimSpace(v) != "" {
				t.Errorf("%s: %q is empty", lang, k)
			}
		}
		for k := range cat {
			if _, ok := en[k]; !ok {
				t.Errorf("%s: extra key %q not in English", lang, k)
			}
		}
	}
}

// dynamicKeys are built at runtime from a prefix plus a value.
func dynamicKeys() []string {
	var ks []string
	add := func(prefix string, vals ...string) {
		for _, v := range vals {
			ks = append(ks, prefix+v)
		}
	}
	reasons := []string{transport.ReasonBadSecret, transport.ReasonExpired, transport.ReasonDenied, transport.ReasonFull,
		transport.ReasonApprovalTimeout, transport.ReasonVersion, "kicked", "host_stopped"}
	add("diag.fail.", reasons...)
	add("diag.disconnected.", "lost", "kicked", "host_stopped", "bad_secret", "expired", "denied", "full", "approval_timeout")
	add("settings.err.", "playerName", "language", "stunServers", "udpPort", "guestPort", "manualPort", "inviteHours")
	add("update.err.", "not_configured", "bad_signature", "bad_manifest", "unreachable")
	add("strategy.", connect.StratIPv6, connect.StratMapped, connect.StratReflex, connect.StratLAN, connect.StratPeerRefl, connect.StratRelay, "unknown")
	add("phase.", connect.PhaseDirect, connect.PhasePunch)
	add("outcome.", connect.OutPending, connect.OutOK, connect.OutTimeout, connect.OutRefused, connect.OutUnreachable,
		connect.OutCertMismatch, connect.OutNoIPv6, connect.OutCancelled, connect.OutError)
	nats := []string{connect.NATOpen, connect.NATFullCone, connect.NATRestricted, connect.NATPortRestricted, connect.NATCone, connect.NATSymmetric, connect.NATUnknown}
	add("nat.", nats...)
	add("nat_hint.", nats...)
	add("nav.", "host", "join", "diag", "settings")
	add("firewall.", "allowed", "blocked", "missing", "unknown", "not_applicable")
	add("firewall.banner_", "missing", "blocked")
	return ks
}

var keyLiteral = regexp.MustCompile(`"((?:about|api|attempt|cgnat|clipboard|common|diag|err|firewall|gui|host|join|lan|nat|nat_hint|nav|outcome|phase|quit|settings|strategy|time|update)\.[a-z_.\-]*[a-z_])"`)

// TestReferencedKeysExist scans Go and frontend sources for key literals.
func TestReferencedKeysExist(t *testing.T) {
	en := catalogs[Default]
	refs := map[string]string{}
	for _, k := range dynamicKeys() {
		refs[k] = "dynamic"
	}
	scan := func(root string, exts ...string) {
		_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() && (d.Name() == "node_modules" || d.Name() == "wailsjs" || d.Name() == "dist" || d.Name() == "testdata") {
				return filepath.SkipDir
			}
			ok := false
			for _, e := range exts {
				ok = ok || strings.HasSuffix(p, e)
			}
			if !ok || strings.HasSuffix(p, "_test.go") {
				return nil
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return nil
			}
			for _, m := range keyLiteral.FindAllStringSubmatch(string(b), -1) {
				if strings.HasSuffix(m[1], ".") || strings.HasSuffix(m[1], "_") || strings.HasSuffix(m[1], ".json") {
					continue // a prefix, covered by dynamicKeys
				}
				refs[m[1]] = p
			}
			return nil
		})
	}
	scan("../../internal", ".go")
	scan("../../gui", ".go", ".ts")
	if len(refs) < 150 {
		t.Fatalf("only %d keys found; is the scan broken?", len(refs))
	}
	for k, where := range refs {
		if _, ok := en[k]; !ok {
			t.Errorf("key %q used in %s is missing from en.json", k, where)
		}
	}
}

func TestRender(t *testing.T) {
	if got := T("en", "lan.via", "motd", "Steve - World"); got != "Steve - World (via "+AppName("en")+")" {
		t.Fatalf("render: %q", got)
	}
	if Match("zh-Hans-CN") != "zh-CN" || Match("en_US") != Default || Match("fr") != Default {
		t.Fatal("language matching")
	}
	if T("en", "no.such.key") != "no.such.key" {
		t.Fatal("missing key should render as the key")
	}
}
