package corecmd

import (
	"bytes"
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/jinomee/mc/internal/api"
)

// TestSingleCoreAndDiscovery checks the discovery/lock contract a second
// client (the future mod) relies on: one core per user, found via core.json,
// a second core exits with ExitAlreadyRunning, shutdown removes core.json.
func TestSingleCoreAndDiscovery(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("LANYARD_HOME", dir)
	done := make(chan int, 1)
	go func() {
		done <- Main([]string{"serve", "-home", dir, "-no-update-checks"}, &bytes.Buffer{}, &bytes.Buffer{})
	}()

	ctx := context.Background()
	c, err := api.Ensure(ctx, dir, func() error { return nil }, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	h, err := c.Hello(ctx)
	if err != nil || h.Product == "" {
		t.Fatalf("hello: %+v %v", h, err)
	}

	var stderr bytes.Buffer
	if code := Main([]string{"serve", "-home", dir}, &bytes.Buffer{}, &stderr); code != api.ExitAlreadyRunning {
		t.Fatalf("second core exit code %d (%s)", code, stderr.String())
	}

	var out bytes.Buffer
	if code := Main([]string{"ctl", "-home", dir, "GET", "/v1/hello"}, &out, &stderr); code != 0 || !bytes.Contains(out.Bytes(), []byte(`"apiVersion":1`)) {
		t.Fatalf("ctl: %d %s %s", code, out.String(), stderr.String())
	}

	if err := c.Do(ctx, http.MethodPost, "/v1/shutdown", nil, nil); err != nil {
		t.Fatal(err)
	}
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("exit %d", code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("core did not stop")
	}
	if _, err := api.Discover(ctx, dir); err == nil {
		t.Fatal("stopped core still discoverable")
	}
}
