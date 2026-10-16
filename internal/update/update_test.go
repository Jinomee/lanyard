package update

import (
	"context"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"aead.dev/minisign"
)

func testKey(t *testing.T) minisign.PublicKey {
	t.Helper()
	b, err := os.ReadFile("testdata/test.pub")
	if err != nil {
		t.Fatal(err)
	}
	PublicKeyOverride = string(b)
	t.Cleanup(func() { PublicKeyOverride = "" })
	pk, ok := PublicKey()
	if !ok {
		t.Fatal("test key did not parse")
	}
	return pk
}

// The fixtures were signed with the reference minisign CLI (prehashed and
// legacy modes), so these tests prove compatibility, not just self-consistency.
func TestVerifyMinisignCLISignatures(t *testing.T) {
	pk := testKey(t)
	body, _ := os.ReadFile("testdata/manifest.json")
	for _, sigFile := range []string{"testdata/manifest.json.minisig", "testdata/manifest.json.legacy.minisig"} {
		sig, _ := os.ReadFile(sigFile)
		m, err := Verify(pk, body, sig)
		if err != nil {
			t.Fatalf("%s: %v", sigFile, err)
		}
		if m.Version != "9.9.9" || len(m.Files) != 3 {
			t.Fatalf("manifest %+v", m)
		}
	}
}

func TestVerifyRejectsTampering(t *testing.T) {
	pk := testKey(t)
	body, _ := os.ReadFile("testdata/manifest.json")
	sig, _ := os.ReadFile("testdata/manifest.json.minisig")
	tampered := []byte(strings.Replace(string(body), "example.invalid/a", "evil.invalid/a", 1))
	if _, err := Verify(pk, tampered, sig); err != ErrSignature {
		t.Fatalf("tampered manifest: %v", err)
	}
	// Signature from a different key.
	_, other, _ := minisign.GenerateKey(rand.Reader)
	if _, err := Verify(pk, body, minisign.Sign(other, body)); err != ErrSignature {
		t.Fatalf("foreign key: %v", err)
	}
	// Tampered trusted comment.
	bad := strings.Replace(string(sig), "LANyard 9.9.9", "LANyard 9.9.8", 1)
	if _, err := Verify(pk, body, []byte(bad)); err != ErrSignature {
		t.Fatalf("trusted comment: %v", err)
	}
}

func TestUnsetKeyDisablesUpdates(t *testing.T) {
	if _, ok := PublicKey(); ok && strings.TrimSpace(embeddedKey) == "UNSET" {
		t.Fatal("UNSET must not parse")
	}
}

func TestCheckerFallsBackToMirror(t *testing.T) {
	pk := testKey(t)
	body, _ := os.ReadFile("testdata/manifest.json")
	sig, _ := os.ReadFile("testdata/manifest.json.minisig")
	// "GitHub" serves a manifest with a broken signature; the mirror is good.
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".minisig") {
			_, _ = w.Write([]byte("garbage"))
			return
		}
		_, _ = w.Write(body)
	}))
	defer gh.Close()
	mirror := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".minisig") {
			_, _ = w.Write(sig)
			return
		}
		_, _ = w.Write(body)
	}))
	defer mirror.Close()
	c := &Checker{
		Sources: []Source{{"github", gh.URL + "/manifest.json", time.Second}, {"mirror", mirror.URL + "/manifest.json", time.Second}},
		Key:     pk, Current: "1.0.0", Lang: "zh-CN", Installed: true,
	}
	res := c.Check(context.Background())
	if res.Error != "" || res.Source != "mirror" || !res.Available || res.Latest != "9.9.9" || res.Notes != "测试版本" {
		t.Fatalf("result %+v", res)
	}
	if runtime.GOOS == "windows" && (res.Download == nil || res.Download.Kind != "installer") {
		t.Fatalf("download %+v", res.Download)
	}
	// Up to date.
	c.Current = "9.9.9"
	if res := c.Check(context.Background()); res.Available {
		t.Fatal("same version reported as update")
	}
}

func TestCheckerAllSourcesBad(t *testing.T) {
	pk := testKey(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("{}"))
	}))
	defer srv.Close()
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(2 * time.Second):
		case <-r.Context().Done():
		}
	}))
	defer slow.Close()
	c := &Checker{Sources: []Source{{"github", slow.URL + "/m.json", 200 * time.Millisecond}, {"mirror", srv.URL + "/m.json", time.Second}}, Key: pk, Current: "1.0.0"}
	t0 := time.Now()
	res := c.Check(context.Background())
	if res.Error != ErrSignature.Error() || res.Available {
		t.Fatalf("result %+v", res)
	}
	if time.Since(t0) > 1500*time.Millisecond {
		t.Fatal("source timeout not honoured")
	}
}

func TestNewer(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"1.0.1", "1.0.0", true},
		{"v1.10.0", "1.9.9", true},
		{"1.0.0", "1.0.0", false},
		{"1.0.0", "1.0.0-rc.1", true},
		{"1.0.0-rc.1", "1.0.0", false},
		{"0.1.0", "0.0.0-dev", true},
		{"garbage", "1.0.0", false},
		{"0.9.0", "1.0.0", false},
	}
	for _, c := range cases {
		if got := Newer(c.a, c.b); got != c.want {
			t.Errorf("Newer(%q,%q)=%v", c.a, c.b, got)
		}
	}
}
