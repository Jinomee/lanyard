// Package proxy pipes bytes between a TCP connection and a QUIC stream.
//
// LANyard never parses Minecraft traffic: every TCP connection the guest's
// game makes (server-list ping or game session) becomes one QUIC stream, and
// the host side turns it back into a TCP connection to the local Minecraft
// port. Authentication (online mode) is entirely between the two games.
package proxy

import (
	"context"
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
	w   io.Writer
	n   *atomic.Int64
	err error // the write error, if the copy stopped because writing failed
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n.Add(int64(n))
	if err != nil {
		c.err = err
	}
	return n, err
}

// Pipe copies in both directions until both sides are finished, propagating
// half-closes (FIN). It closes both ends.
//
// The rules keep bytes already on their way (a server's kick message, say)
// from being thrown away:
//   - TCP read ends (FIN or reset): FIN the stream; queued data still goes.
//   - TCP write fails (the game is gone): tell the peer to stop sending, but
//     leave our sending side alone; reading the game socket ends by itself.
//   - Stream ends cleanly: half-close the TCP connection.
//   - Stream reset or connection lost: close the TCP connection.
//   - Stream write fails (the peer stopped reading): stop this direction
//     only; data the peer still sends keeps arriving.
//
// Once one direction has finished, the other gets halfCloseGrace to finish
// too, so a peer that never closes can't hold a game connection forever.
func Pipe(tcp net.Conn, s *quic.Stream, st *Stats) {
	if st == nil {
		st = &Stats{}
	}
	var wg sync.WaitGroup
	var firstDone sync.Once
	finished := func() {
		firstDone.Do(func() {
			dl := time.Now().Add(halfCloseGrace)
			_ = tcp.SetReadDeadline(dl)
			_ = s.SetReadDeadline(dl)
		})
	}
	wg.Add(2)
	go func() { // TCP → stream
		defer wg.Done()
		defer finished()
		w := &countWriter{w: s, n: &st.Up}
		_, _ = io.Copy(w, tcp)
		if w.err != nil {
			s.CancelWrite(1)
			return
		}
		_ = s.Close() // FIN on the stream's send side; buffered data is still delivered
	}()
	go func() { // stream → TCP
		defer wg.Done()
		defer finished()
		w := &countWriter{w: tcp, n: &st.Down}
		_, err := io.Copy(w, s)
		switch {
		case w.err != nil:
			s.CancelRead(1)
		case err != nil:
			_ = tcp.Close()
		default:
			if cw, ok := tcp.(interface{ CloseWrite() error }); ok {
				_ = cw.CloseWrite()
			} else {
				_ = tcp.Close()
			}
		}
	}()
	wg.Wait()
	_ = tcp.Close()
	s.CancelRead(0)
}

// halfCloseGrace is how long the other direction may continue after one
// direction of a proxied connection has ended.
const halfCloseGrace = 2 * time.Minute

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
