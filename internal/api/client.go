package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/jinomee/lanyard/internal/config"
	"github.com/jinomee/lanyard/internal/engine"
)

// Client talks to a core.
type Client struct {
	base  string
	token string
	http  *http.Client
}

// NewClient creates a client for addr ("127.0.0.1:port").
func NewClient(addr, token string) *Client {
	return &Client{
		base:  "http://" + addr,
		token: token,
		// Never use a proxy for loopback.
		http: &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{Proxy: nil}},
	}
}

// Error is an API error response.
type Error struct {
	Status int
	engine.UserError
}

func (e *Error) Error() string { return fmt.Sprintf("api %d: %s", e.Status, e.UserError.Error()) }

// Do performs a request. body and out may be nil.
func (c *Client) Do(ctx context.Context, method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		var eb ErrorBody
		_ = json.Unmarshal(data, &eb)
		return &Error{Status: resp.StatusCode, UserError: eb.Error}
	}
	if out == nil {
		return nil
	}
	if raw, ok := out.(*[]byte); ok {
		*raw = data
		return nil
	}
	return json.Unmarshal(data, out)
}

// Hello identifies the core.
func (c *Client) Hello(ctx context.Context) (Hello, error) {
	var h Hello
	err := c.Do(ctx, http.MethodGet, "/v1/hello", nil, &h)
	return h, err
}

// State returns the full state.
func (c *Client) State(ctx context.Context) (engine.State, error) {
	var s engine.State
	err := c.Do(ctx, http.MethodGet, "/v1/state", nil, &s)
	return s, err
}

// StartHost starts hosting.
func (c *Client) StartHost(ctx context.Context, mode string, manualPort int) error {
	return c.Do(ctx, http.MethodPost, "/v1/host/start", map[string]any{"mode": mode, "manualPort": manualPort}, nil)
}

// SubmitReply hands a guest's reply code to the host.
func (c *Client) SubmitReply(ctx context.Context, code string) error {
	return c.Do(ctx, http.MethodPost, "/v1/host/reply", map[string]string{"code": code}, nil)
}

// StartJoin starts joining.
func (c *Client) StartJoin(ctx context.Context, code string) error {
	return c.Do(ctx, http.MethodPost, "/v1/join/start", map[string]string{"code": code}, nil)
}

// Settings returns the settings.
func (c *Client) Settings(ctx context.Context) (config.Settings, error) {
	var s config.Settings
	err := c.Do(ctx, http.MethodGet, "/v1/settings", nil, &s)
	return s, err
}

// SetSettings stores settings.
func (c *Client) SetSettings(ctx context.Context, s config.Settings) (config.Settings, error) {
	var out config.Settings
	err := c.Do(ctx, http.MethodPut, "/v1/settings", s, &out)
	return out, err
}

// Addr returns the core's API address.
func (c *Client) Addr() string { return c.base[len("http://"):] }

// Token returns the bearer token.
func (c *Client) Token() string { return c.token }
