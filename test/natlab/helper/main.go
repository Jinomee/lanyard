// Command helper provides the actors of the NAT lab that are not LANyard
// itself: an RFC 5780 STUN server ("the internet"), a fake Minecraft world
// (echo server that announces itself to LAN like "Open to LAN" does), a fake
// Minecraft client, and a LAN-list watcher.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jinomee/lanyard/internal/mclan"
	"github.com/jinomee/lanyard/internal/stunx"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: helper stun|mc|client|lanwait ...")
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "stun":
		err = runSTUN(args)
	case "mc":
		err = runMC(args)
	case "client":
		err = runClient(args)
	case "lanwait":
		err = runLANWait(args)
	default:
		err = fmt.Errorf("unknown command %q", cmd)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "helper", cmd+":", err)
		os.Exit(1)
	}
}

func waitSignal() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c
}

func runSTUN(args []string) error {
	fs := flag.NewFlagSet("stun", flag.ExitOnError)
	a := fs.String("a", "", "primary IP")
	b := fs.String("b", "", "alternate IP")
	a6 := fs.String("a6", "", "primary IPv6 (optional)")
	b6 := fs.String("b6", "", "alternate IPv6 (optional)")
	_ = fs.Parse(args)
	s4, err := stunx.NewServer(netip.MustParseAddr(*a), netip.MustParseAddr(*b), 3478, 3479)
	if err != nil {
		return err
	}
	defer s4.Close()
	if *a6 != "" {
		s6, err := stunx.NewServer(netip.MustParseAddr(*a6), netip.MustParseAddr(*b6), 3478, 3479)
		if err != nil {
			return err
		}
		defer s6.Close()
	}
	fmt.Println("stun ready")
	waitSignal()
	return nil
}

func runMC(args []string) error {
	fs := flag.NewFlagSet("mc", flag.ExitOnError)
	port := fs.Int("port", 25565, "TCP port")
	motd := fs.String("motd", "Steve - Lab World", "LAN MOTD")
	announce := fs.Bool("announce", true, "send Open to LAN announcements")
	_ = fs.Parse(args)
	ln, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", *port))
	if err != nil {
		return err
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); _ = c.Close() }()
		}
	}()
	if *announce {
		uc, err := net.ListenUDP("udp4", nil)
		if err != nil {
			return err
		}
		go func() {
			for {
				_, _ = uc.WriteToUDP(mclan.Format(*motd, uint16(*port)), net.UDPAddrFromAddrPort(mclan.Group)) //nolint:gosec // test port
				time.Sleep(time.Second)
			}
		}()
	}
	fmt.Println("mc ready")
	waitSignal()
	return nil
}

func runClient(args []string) error {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	addr := fs.String("addr", "", "address")
	size := fs.Int("size", 256<<10, "bytes to echo")
	_ = fs.Parse(args)
	c, err := net.DialTimeout("tcp", *addr, 5*time.Second)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(20 * time.Second))
	payload := make([]byte, *size)
	_, _ = rand.Read(payload)
	go func() {
		_, _ = c.Write(payload)
		_ = c.(*net.TCPConn).CloseWrite()
	}()
	got, err := io.ReadAll(c)
	if err != nil {
		return err
	}
	if !bytes.Equal(got, payload) {
		return fmt.Errorf("echo mismatch: got %d bytes, want %d", len(got), len(payload))
	}
	fmt.Println("echo ok", len(got))
	return nil
}

func runLANWait(args []string) error {
	fs := flag.NewFlagSet("lanwait", flag.ExitOnError)
	port := fs.Int("port", 0, "expected AD port")
	timeout := fs.Duration("timeout", 10*time.Second, "timeout")
	_ = fs.Parse(args)
	conn, err := mclan.ListenRaw()
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	_ = conn.SetReadDeadline(time.Now().Add(*timeout))
	buf := make([]byte, 1500)
	for ctx.Err() == nil {
		n, from, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			return err
		}
		a, err := mclan.Parse(buf[:n])
		if err == nil && int(a.Port) == *port {
			if !from.Addr().Unmap().IsLoopback() {
				return fmt.Errorf("announcement came from %v, Minecraft would list a non-local address", from)
			}
			fmt.Printf("lan entry %q at 127.0.0.1:%d\n", a.MOTD, a.Port)
			return nil
		}
	}
	return ctx.Err()
}
