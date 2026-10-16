// Package logbuf provides the core's logger: text lines to a small rotating
// file plus an in-memory ring for the diagnostics screen, and log export.
// Nothing is ever sent anywhere: export just writes a zip the user can attach
// to a bug report themselves.
package logbuf

import (
	"archive/zip"
	"bytes"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	maxFileSize = 2 << 20
	ringSize    = 400
)

// Sink is an io.Writer that keeps the last lines in memory and appends to a
// rotating file.
type Sink struct {
	dir  string
	mu   sync.Mutex
	f    *os.File
	size int64
	ring []string
	next int
	full bool
}

// FileName is the current log file name.
const FileName = "core.log"

// NewSink opens (or creates) dir/core.log. dir may be "" for memory only.
func NewSink(dir string) *Sink {
	s := &Sink{dir: dir, ring: make([]string, ringSize)}
	if dir != "" {
		_ = os.MkdirAll(dir, 0o700)
		if f, err := os.OpenFile(filepath.Join(dir, FileName), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err == nil {
			s.f = f
			if st, err := f.Stat(); err == nil {
				s.size = st.Size()
			}
		}
	}
	return s
}

// Write implements io.Writer; slog writes one record per call.
func (s *Sink) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	line := string(bytes.TrimRight(p, "\n"))
	s.ring[s.next] = line
	s.next = (s.next + 1) % ringSize
	if s.next == 0 {
		s.full = true
	}
	if s.f != nil {
		if s.size+int64(len(p)) > maxFileSize {
			s.rotate()
		}
		if s.f != nil {
			n, _ := s.f.Write(p)
			s.size += int64(n)
		}
	}
	return len(p), nil
}

func (s *Sink) rotate() {
	_ = s.f.Close()
	cur := filepath.Join(s.dir, FileName)
	_ = os.Rename(cur, cur+".1")
	f, err := os.OpenFile(cur, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		s.f = nil
		return
	}
	s.f, s.size = f, 0
}

// Lines returns the buffered lines, oldest first.
func (s *Sink) Lines() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	if s.full {
		out = append(out, s.ring[s.next:]...)
	}
	out = append(out, s.ring[:s.next]...)
	return out
}

// Close closes the file.
func (s *Sink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f != nil {
		return s.f.Close()
	}
	return nil
}

// Logger returns a text slog.Logger writing to s (and to extra, if non-nil).
func (s *Sink) Logger(extra io.Writer) *slog.Logger {
	var w io.Writer = s
	if extra != nil {
		w = io.MultiWriter(s, extra)
	}
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// Export writes a zip with the log files and extra named attachments.
func (s *Sink) Export(w io.Writer, extra map[string][]byte) error {
	z := zip.NewWriter(w)
	add := func(name string, b []byte) error {
		h := &zip.FileHeader{Name: name, Method: zip.Deflate, Modified: time.Now()}
		fw, err := z.CreateHeader(h)
		if err != nil {
			return err
		}
		_, err = fw.Write(b)
		return err
	}
	if s.dir != "" {
		s.mu.Lock()
		for _, n := range []string{FileName + ".1", FileName} {
			if b, err := os.ReadFile(filepath.Join(s.dir, n)); err == nil {
				if err := add(n, b); err != nil {
					s.mu.Unlock()
					return err
				}
			}
		}
		s.mu.Unlock()
	}
	for name, b := range extra {
		if err := add(name, b); err != nil {
			return err
		}
	}
	return z.Close()
}
