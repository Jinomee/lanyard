// Package api is the core's local control API: HTTP+JSON on 127.0.0.1,
// protected by a random bearer token stored in a per-user file. The GUI and
// the future Minecraft mod are both clients; see discovery.go for how a client
// finds (or starts) the one running core.
package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/jinomee/lanyard/internal/brand"
	"github.com/jinomee/lanyard/internal/config"
	"github.com/jinomee/lanyard/internal/engine"
	"github.com/jinomee/lanyard/internal/i18n"
)

// Hello is the unauthenticated-looking-but-authenticated handshake response.
type Hello struct {
	Product    string `json:"product"`
	Version    string `json:"version"`
	APIVersion int    `json:"apiVersion"`
	PID        int    `json:"pid"`
}

// ErrorBody is returned with every non-2xx response.
type ErrorBody struct {
	Error engine.UserError `json:"error"`
}

// Server serves the API for one engine.
type Server struct {
	e        *engine.Engine
	token    string
	pid      int
	shutdown func()
	srv      *http.Server
}

// NewServer creates a server. shutdown is called for POST /v1/shutdown.
func NewServer(e *engine.Engine, token string, pid int, shutdown func()) *Server {
	s := &Server{e: e, token: token, pid: pid, shutdown: shutdown}
	s.srv = &http.Server{Handler: s.handler(), ReadHeaderTimeout: 5 * time.Second}
	return s
}

// Serve accepts connections on ln until Close.
func (s *Server) Serve(ln net.Listener) error {
	err := s.srv.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Close stops the server.
func (s *Server) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return s.srv.Shutdown(ctx)
}

func isLoopbackHost(h string) bool {
	host := h
	if hh, _, err := net.SplitHostPort(h); err == nil {
		host = hh
	}
	host = strings.Trim(host, "[]")
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (s *Server) handler() http.Handler {
	mux := http.NewServeMux()
	h := func(pattern string, f func(w http.ResponseWriter, r *http.Request) (any, error)) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			v, err := f(w, r)
			if err != nil {
				writeErr(w, err)
				return
			}
			if v == nil {
				v = map[string]bool{"ok": true}
			}
			writeJSON(w, http.StatusOK, v)
		})
	}
	h("GET /v1/hello", func(http.ResponseWriter, *http.Request) (any, error) {
		return Hello{Product: brand.Name(), Version: brand.Version, APIVersion: engine.APIVersion, PID: s.pid}, nil
	})
	h("GET /v1/state", func(http.ResponseWriter, *http.Request) (any, error) { return s.e.State(), nil })

	h("POST /v1/host/start", func(_ http.ResponseWriter, r *http.Request) (any, error) {
		var req struct {
			Mode       string `json:"mode"`
			ManualPort int    `json:"manualPort"`
		}
		if err := decode(r, &req); err != nil {
			return nil, err
		}
		return nil, s.e.StartHost(req.Mode, req.ManualPort)
	})
	h("POST /v1/host/target", func(_ http.ResponseWriter, r *http.Request) (any, error) {
		var req struct {
			Mode       string `json:"mode"`
			ManualPort int    `json:"manualPort"`
		}
		if err := decode(r, &req); err != nil {
			return nil, err
		}
		return nil, s.e.SetHostTarget(req.Mode, req.ManualPort)
	})
	h("POST /v1/host/stop", func(http.ResponseWriter, *http.Request) (any, error) { s.e.StopHost(); return nil, nil })
	h("POST /v1/host/code/new", func(http.ResponseWriter, *http.Request) (any, error) { return nil, s.e.NewCode() })
	h("POST /v1/host/reply", func(_ http.ResponseWriter, r *http.Request) (any, error) {
		var req struct {
			Code string `json:"code"`
		}
		if err := decode(r, &req); err != nil {
			return nil, err
		}
		return nil, s.e.SubmitReply(req.Code)
	})
	h("POST /v1/host/approve", func(_ http.ResponseWriter, r *http.Request) (any, error) {
		var req struct {
			ID    string `json:"id"`
			Allow bool   `json:"allow"`
		}
		if err := decode(r, &req); err != nil {
			return nil, err
		}
		return nil, s.e.Approve(req.ID, req.Allow)
	})
	h("POST /v1/host/kick", func(_ http.ResponseWriter, r *http.Request) (any, error) {
		var req struct {
			ID string `json:"id"`
		}
		if err := decode(r, &req); err != nil {
			return nil, err
		}
		return nil, s.e.Kick(req.ID)
	})

	h("POST /v1/join/start", func(_ http.ResponseWriter, r *http.Request) (any, error) {
		var req struct {
			Code       string `json:"code"`
			TimeoutSec int    `json:"timeoutSec"` // optional; default 10 minutes
		}
		if err := decode(r, &req); err != nil {
			return nil, err
		}
		return nil, s.e.StartJoin(req.Code, time.Duration(req.TimeoutSec)*time.Second)
	})
	h("POST /v1/join/stop", func(http.ResponseWriter, *http.Request) (any, error) { s.e.StopJoin(); return nil, nil })
	h("POST /v1/code/parse", func(_ http.ResponseWriter, r *http.Request) (any, error) {
		var req struct {
			Text string `json:"text"`
		}
		if err := decode(r, &req); err != nil {
			return nil, err
		}
		return s.e.ParseCode(req.Text)
	})

	h("GET /v1/settings", func(http.ResponseWriter, *http.Request) (any, error) { return s.e.Settings(), nil })
	h("PUT /v1/settings", func(_ http.ResponseWriter, r *http.Request) (any, error) {
		var req config.Settings
		if err := decode(r, &req); err != nil {
			return nil, err
		}
		return s.e.SetSettings(req)
	})
	h("GET /v1/settings/defaults", func(http.ResponseWriter, *http.Request) (any, error) { return config.Defaults(), nil })
	h("POST /v1/identity/reset", func(http.ResponseWriter, *http.Request) (any, error) { return nil, s.e.ResetIdentity() })

	h("POST /v1/diagnostics/run", func(http.ResponseWriter, *http.Request) (any, error) { s.e.RunDiagnostics(); return nil, nil })
	h("POST /v1/update/check", func(http.ResponseWriter, *http.Request) (any, error) { s.e.CheckUpdate(); return nil, nil })
	h("GET /v1/logs", func(http.ResponseWriter, *http.Request) (any, error) {
		return map[string][]string{"lines": s.e.LogLines()}, nil
	})
	mux.HandleFunc("GET /v1/logs/export", func(w http.ResponseWriter, _ *http.Request) {
		b, err := s.e.ExportLogsBytes()
		if err != nil {
			writeErr(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write(b)
	})
	h("GET /v1/i18n/{lang}", func(_ http.ResponseWriter, r *http.Request) (any, error) {
		return i18n.Catalog(r.PathValue("lang")), nil
	})
	h("POST /v1/shutdown", func(http.ResponseWriter, *http.Request) (any, error) {
		if s.shutdown != nil {
			go s.shutdown()
		}
		return nil, nil
	})
	return s.guard(mux)
}

// guard enforces loopback Host headers and the bearer token.
func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isLoopbackHost(r.Host) {
			writeErr(w, &engine.UserError{Key: "api.err.host", Status: http.StatusForbidden})
			return
		}
		scheme, got, _ := strings.Cut(r.Header.Get("Authorization"), " ")
		if !strings.EqualFold(scheme, "Bearer") || subtle.ConstantTimeCompare([]byte(strings.TrimSpace(got)), []byte(s.token)) != 1 {
			writeErr(w, &engine.UserError{Key: "api.err.token", Status: http.StatusUnauthorized})
			return
		}
		s.e.Touch()
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

func decode(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, 64<<10))
	if err := dec.Decode(v); err != nil && !errors.Is(err, io.EOF) {
		return &engine.UserError{Key: "api.err.bad_request", Status: http.StatusBadRequest, Detail: err.Error()}
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, err error) {
	var ue *engine.UserError
	if !errors.As(err, &ue) {
		ue = &engine.UserError{Key: "api.err.internal", Detail: err.Error(), Status: http.StatusInternalServerError}
	}
	status := ue.Status
	if status == 0 {
		status = http.StatusBadRequest
	}
	writeJSON(w, status, ErrorBody{Error: *ue})
}
