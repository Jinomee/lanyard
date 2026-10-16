package proxy_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/jinomee/mc/internal/proxy"
	"github.com/jinomee/mc/internal/transport"
)

// fakeMinecraft is a TCP server that echoes everything and, after the client
// half-closes, writes "bye" and closes. It stands in for the host's game.
func fakeMinecraft(t *testing.T) (addr string, conns *sync.WaitGroup) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	conns = &sync.WaitGroup{}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			conns.Add(1)
			go func() {
				defer conns.Done()
				defer func() { _ = c.Close() }()
				_, _ = io.Copy(c, c)
				_, _ = c.Write([]byte("bye"))
			}()
		}
	}()
	return ln.Addr().String(), conns
}

type host struct {
	ep     *transport.Endpoint
	id     *transport.Identity
	secret []byte
}

func startHost(t *testing.T, mcAddr string) *host {
	t.Helper()
	ep, err := transport.ListenUDP(4, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ep.Close() })
	id, err := transport.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	h := &host{ep: ep, id: id, secret: []byte("0123456789")}
	ln, err := ep.Transport().Listen(transport.ServerTLS(id), transport.QUICConfig())
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			go func() {
				ctl, hello, err := transport.HostAcceptHello(context.Background(), conn, 5*time.Second)
				if err != nil {
					_ = conn.CloseWithError(transport.CodeProtocol, "")
					return
				}
				if subtle.ConstantTimeCompare(hello.Secret, h.secret) != 1 {
					_ = ctl.Send(transport.Msg{T: "reject", Reason: transport.ReasonBadSecret})
					time.Sleep(50 * time.Millisecond)
					_ = conn.CloseWithError(transport.CodeBadSecret, "")
					return
				}
				_ = ctl.Send(transport.Msg{T: "admitted", MOTD: "Steve - Test World"})
				_ = proxy.ServeHost(context.Background(), conn, proxy.TCPDialer(func() string { return mcAddr }), nil)
			}()
		}
	}()
	return h
}

func (h *host) addr() netip.AddrPort {
	return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), h.ep.Port())
}

func dialGuest(t *testing.T, h *host, fp [12]byte, secret []byte) (*quic.Conn, string, error) {
	t.Helper()
	ep, err := transport.ListenUDP(4, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ep.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := ep.Transport().Dial(ctx, net.UDPAddrFromAddrPort(h.addr()), transport.ClientTLS(fp), transport.QUICConfig())
	if err != nil {
		return nil, "", err
	}
	_, motd, err := transport.GuestHello(ctx, conn, secret, "Alex", "test", nil)
	if err != nil {
		return nil, "", err
	}
	return conn, motd, nil
}

func TestEndToEndProxy(t *testing.T) {
	mcAddr, _ := fakeMinecraft(t)
	h := startHost(t, mcAddr)
	conn, motd, err := dialGuest(t, h, h.id.Fingerprint(), h.secret)
	if err != nil {
		t.Fatal(err)
	}
	if motd != "Steve - Test World" {
		t.Errorf("motd = %q", motd)
	}

	// The guest's local listener, as the guest's Minecraft would see it.
	gl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = gl.Close() }()
	var st proxy.Stats
	go func() {
		for {
			c, err := gl.Accept()
			if err != nil {
				return
			}
			go proxy.OpenGuest(context.Background(), conn, c, &st)
		}
	}()

	// Several concurrent "Minecraft" connections (ping + game), each 256 KiB.
	var wg sync.WaitGroup
	for i := range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := net.Dial("tcp", gl.Addr().String())
			if err != nil {
				t.Error(err)
				return
			}
			defer func() { _ = c.Close() }()
			payload := make([]byte, 256<<10)
			_, _ = rand.Read(payload)
			go func() {
				_, _ = c.Write(payload)
				_ = c.(*net.TCPConn).CloseWrite() // half-close: server must still answer
			}()
			got, err := io.ReadAll(c)
			if err != nil {
				t.Errorf("conn %d: %v", i, err)
				return
			}
			want := append(payload, "bye"...)
			if !bytes.Equal(got, want) {
				t.Errorf("conn %d: got %d bytes, want %d (equal prefix: %v)", i, len(got), len(want), bytes.HasPrefix(got, payload[:1024]))
			}
		}()
	}
	wg.Wait()
	if st.Up.Load() != 4*256<<10 {
		t.Errorf("stats up = %d", st.Up.Load())
	}
}

func TestWrongFingerprintRejected(t *testing.T) {
	mcAddr, _ := fakeMinecraft(t)
	h := startHost(t, mcAddr)
	fp := h.id.Fingerprint()
	fp[0] ^= 0xff
	_, _, err := dialGuest(t, h, fp, h.secret)
	if err == nil {
		t.Fatal("connection to a host with the wrong certificate must fail")
	}
}

func TestWrongSecretRejected(t *testing.T) {
	mcAddr, _ := fakeMinecraft(t)
	h := startHost(t, mcAddr)
	_, _, err := dialGuest(t, h, h.id.Fingerprint(), []byte("wrongwrong"))
	var re *transport.RejectError
	if !errors.As(err, &re) || re.Reason != transport.ReasonBadSecret {
		t.Fatalf("want bad_secret rejection, got %v", err)
	}
}

func TestMinecraftDownResetsStream(t *testing.T) {
	// Point the host at a closed port: the guest's TCP connection must be
	// closed promptly rather than hang.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := ln.Addr().String()
	_ = ln.Close()
	h := startHost(t, dead)
	conn, _, err := dialGuest(t, h, h.id.Fingerprint(), h.secret)
	if err != nil {
		t.Fatal(err)
	}
	a, b := net.Pipe()
	done := make(chan struct{})
	go func() { proxy.OpenGuest(context.Background(), conn, b, nil); close(done) }()
	_ = a.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = a.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("expected the connection to be closed")
	}
	<-done
}
