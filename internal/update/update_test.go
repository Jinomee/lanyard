package update

import (
	"context"
	"crypto/rand"
	"errors"
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
	if _, err := Verify(pk, tampered, sig); !errors.Is(err, ErrSignature) {
		t.Fatalf("tampered manifest: %v", err)
	}
	// Signature from a different key.
	_, other, _ := minisign.GenerateKey(rand.Reader)
	if _, err := Verify(pk, body, minisign.Sign(other, body)); !errors.Is(err, ErrSignature) {
		t.Fatalf("foreign key: %v", err)
	}
	// Tampered trusted comment.
	bad := strings.Replace(string(sig), "LANyard 9.9.9", "LANyard 9.9.8", 1)
	if _, err := Verify(pk, body, []byte(bad)); !errors.Is(err, ErrSignature) {
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
		{"1.0.0-rc.2", "1.0.0-rc.1", true},
		{"1.0.0-rc.10", "1.0.0-rc.9", true},
		{"1.0.0-rc.1", "1.0.0-beta.2", true},
		{"1.0.0-rc.1.1", "1.0.0-rc.1", true},
		{"1.0.0-rc.1", "1.0.0-rc.1", false},
		{"1.0.0-1", "1.0.0-alpha", false}, // numeric identifiers sort first
		{"1.0.0+build.5", "1.0.0", false},
	}
	for _, c := range cases {
		if got := Newer(c.a, c.b); got != c.want {
			t.Errorf("Newer(%q,%q)=%v", c.a, c.b, got)
		}
	}
}

// signedSource serves a manifest for version, signed with sk.
func signedSource(t *testing.T, sk minisign.PrivateKey, version string, urls ...string) *httptest.Server {
	t.Helper()
	q := func(s string) string { return `"` + s + `"` }
	body := []byte(`{"product":"LANyard","version":` + q(version) + `,"files":[{"name":"x","os":` + q(runtime.GOOS) +
		`,"arch":` + q(runtime.GOARCH) + `,"kind":"portable","size":1,"sha256":"00","urls":[` + q(strings.Join(urls, `","`)) + `]}]}`)
	sig := minisign.Sign(sk, body)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".minisig") {
			_, _ = w.Write(sig)
			return
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestCheckerSourcePolicies(t *testing.T) {
	pk, sk, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	check := func(current string, srvs ...*httptest.Server) Result {
		c := &Checker{Key: pk, Current: current}
		for i, s := range srvs {
			c.Sources = append(c.Sources, Source{[]string{"github", "mirror"}[i], s.URL + "/manifest.json", time.Second})
		}
		return c.Check(context.Background())
	}
	const ghURL, mirrorURL = "https://github.com/x/releases/download/v3.0.0/x", "https://updates.example/x/3.0.0/x"

	// An old (validly signed) manifest on one source must not hide a newer one.
	old := signedSource(t, sk, "1.0.0", ghURL)
	mirror := signedSource(t, sk, "3.0.0", ghURL, strings.Replace(mirrorURL, "updates.example", "127.0.0.1", 1))
	res := check("2.0.0", old, mirror)
	if !res.Available || res.Latest != "3.0.0" || res.Source != "mirror" {
		t.Fatalf("stale first source: %+v", res)
	}
	// The mirror answered, so its download comes first.
	if !strings.Contains(res.Download.URLs[0], "127.0.0.1") {
		t.Fatalf("download URLs %v: mirror should come first", res.Download.URLs)
	}
	// Only stale answers: not available, no error.
	if res := check("2.0.0", old); res.Available || res.Error != "" || res.Latest != "1.0.0" {
		t.Fatalf("only stale: %+v", res)
	}
	// Pre-releases are offered only to pre-release users.
	rc := signedSource(t, sk, "3.0.0-rc.1", ghURL)
	if res := check("2.0.0", rc); res.Available {
		t.Fatalf("stable user offered a pre-release: %+v", res)
	}
	if res := check("2.0.0-rc.2", rc); !res.Available {
		t.Fatalf("pre-release user not offered the next pre-release: %+v", res)
	}
	// Neither a pre-release nor a replay of the current version on the first
	// source may hide a newer stable release on the second.
	stable := signedSource(t, sk, "2.1.0", ghURL)
	for _, first := range []*httptest.Server{rc, signedSource(t, sk, "2.0.0", ghURL)} {
		if res := check("2.0.0", first, stable); !res.Available || res.Latest != "2.1.0" {
			t.Fatalf("newer stable hidden: %+v", res)
		}
	}
}
