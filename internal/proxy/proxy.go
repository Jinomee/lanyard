// Package proxy pipes bytes between a TCP connection and a QUIC stream.
//
// LANyard never parses Minecraft traffic: every TCP connection the guest's
// game makes (server-list ping or game session) becomes one QUIC stream, and
// the host side turns it back into a TCP connection to the local Minecraft
// port. Authentication (online mode) is entirely between the two games.
package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/jinomee/lanyard/internal/transport"
)

// Stats counts bytes moved; safe for concurrent use.
type Stats struct {
	Up   atomic.Int64 // TCP → QUIC
	Down atomic.Int64 // QUIC → TCP
}

type countWriter struct {
	w io.Writer
	n *atomic.Int64
}

func (c countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n.Add(int64(n))
	return n, err
}

// Pipe copies in both directions until both sides are finished, propagating
// half-closes (FIN) and turning errors into resets. It closes both ends.
func Pipe(tcp net.Conn, s *quic.Stream, st *Stats) {
	if st == nil {
		st = &Stats{}
	}
	var wg sync.WaitGroup
	var once sync.Once
	abort := func() {
		once.Do(func() {
			s.CancelRead(1)
			s.CancelWrite(1)
			_ = tcp.Close()
		})
	}
	wg.Add(2)
	go func() { // TCP → stream
		defer wg.Done()
		_, err := io.Copy(countWriter{s, &st.Up}, tcp)
		if err != nil && !errors.Is(err, net.ErrClosed) {
			abort()
			return
		}
		_ = s.Close() // FIN on the stream's send side
	}()
	go func() { // stream → TCP
		defer wg.Done()
		_, err := io.Copy(countWriter{tcp, &st.Down}, s)
		if err != nil {
			abort()
			return
		}
		if cw, ok := tcp.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			_ = tcp.Close()
		}
	}()
	wg.Wait()
	_ = tcp.Close()
	s.CancelRead(0)
}

// Dialer opens TCP connections to the Minecraft target on the host.
type Dialer func(ctx context.Context) (net.Conn, error)

// TCPDialer returns a Dialer for a fixed address, resolved on every call so
// that a changing LAN-world port is followed.
func TCPDialer(addr func() string) Dialer {
	return func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		return d.DialContext(ctx, "tcp", addr())
	}
}

// ServeHost accepts proxy streams on an authenticated connection and pipes
// each to a fresh TCP connection from dial. It returns when the connection ends.
func ServeHost(ctx context.Context, conn *quic.Conn, dial Dialer, st *Stats) error {
	for {
		s, err := conn.AcceptStream(ctx)
		if err != nil {
			return err
		}
		go func() {
			var t [1]byte
			_ = s.SetReadDeadline(time.Now().Add(10 * time.Second))
			if _, err := io.ReadFull(s, t[:]); err != nil || t[0] != transport.StreamProxy {
				s.CancelRead(2)
				s.CancelWrite(2)
				return
			}
			_ = s.SetReadDeadline(time.Time{})
			tcp, err := dial(ctx)
			if err != nil {
				// Minecraft isn't listening (world closed?). Reset the stream so
				// the guest's game sees a refused connection quickly.
				s.CancelRead(3)
				s.CancelWrite(3)
				return
			}
			Pipe(tcp, s, st)
		}()
	}
}

// OpenGuest opens a proxy stream on conn for one accepted TCP connection.
func OpenGuest(ctx context.Context, conn *quic.Conn, tcp net.Conn, st *Stats) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	s, err := conn.OpenStreamSync(ctx)
	cancel()
	if err != nil {
		_ = tcp.Close()
		return
	}
	if _, err := s.Write([]byte{transport.StreamProxy}); err != nil {
		_ = tcp.Close()
		s.CancelWrite(1)
		return
	}
	Pipe(tcp, s, st)
}
