// Package mclan speaks Minecraft Java Edition's "Open to LAN" discovery
// protocol: the integrated server multicasts a small text datagram
//
//	[MOTD]<player> - <world>[/MOTD][AD]<port>[/AD]
//
// to 224.0.2.60:4445 every 1.5 s, and clients list every sender in
// Multiplayer → "Scanning for games on your local network". The address a
// client connects to is the datagram's *source IP* plus the AD port.
package mclan

import (
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Group is the Minecraft LAN multicast group and port.
var Group = netip.MustParseAddrPort("224.0.2.60:4445")

// MissingMOTD is what Minecraft shows when the MOTD tag is absent.
const MissingMOTD = "missing no"

// Announcement is one parsed LAN announcement.
type Announcement struct {
	MOTD string
	Port uint16
	// Relayed marks announcements made by LANyard itself for a remote world.
	Relayed bool
}

// relayMarker trails LANyard's own announcements. Minecraft ignores anything
// after [/AD], so the game still lists the world, while every LANyard core
// (even one in another process) can recognise and skip it.
const relayMarker = "[LY]"

// ErrNotAnnouncement means the datagram is not a usable LAN announcement.
var ErrNotAnnouncement = errors.New("mclan: not a LAN announcement")

// parseMOTD mirrors net.minecraft.client.server.LanServerPinger.parseMotd.
func parseMOTD(s string) string {
	i := strings.Index(s, "[MOTD]")
	if i < 0 {
		return MissingMOTD
	}
	rest := s[i+len("[MOTD]"):]
	j := strings.Index(rest, "[/MOTD]")
	if j < 0 {
		return MissingMOTD
	}
	return rest[:j]
}

// parseAddress mirrors LanServerPinger.parseAddress (including its refusal of
// datagrams with two [/MOTD] tags).
func parseAddress(s string) (string, bool) {
	i := strings.Index(s, "[/MOTD]")
	if i < 0 {
		return "", false
	}
	after := s[i+len("[/MOTD]"):]
	if strings.Contains(after, "[/MOTD]") {
		return "", false
	}
	k := strings.Index(after, "[AD]")
	if k < 0 {
		return "", false
	}
	ad := after[k+len("[AD]"):]
	l := strings.Index(ad, "[/AD]")
	if l < 0 {
		return "", false
	}
	return ad[:l], true
}

// Parse decodes a datagram the way Minecraft does. The AD field must be a
// valid TCP port (Minecraft itself would also accept "host:port", but no
// vanilla version sends that and LANyard only proxies to ports).
func Parse(b []byte) (Announcement, error) {
	if len(b) > 1024 || !utf8.Valid(b) {
		return Announcement{}, ErrNotAnnouncement
	}
	s := string(b)
	ad, ok := parseAddress(s)
	if !ok {
		return Announcement{}, ErrNotAnnouncement
	}
	p, err := strconv.ParseUint(strings.TrimSpace(ad), 10, 16)
	if err != nil || p == 0 {
		return Announcement{}, ErrNotAnnouncement
	}
	return Announcement{MOTD: parseMOTD(s), Port: uint16(p), Relayed: strings.HasSuffix(s, relayMarker)}, nil
}

// Format builds an announcement datagram. The MOTD is sanitised so that a
// MOTD received from a remote host can never inject tags.
func Format(motd string, port uint16) []byte {
	return []byte("[MOTD]" + SanitizeMOTD(motd) + "[/MOTD][AD]" + strconv.Itoa(int(port)) + "[/AD]")
}

// FormatRelayed builds the announcement for a world LANyard relays from a
// remote host (see relayMarker).
func FormatRelayed(motd string, port uint16) []byte {
	return append(Format(motd, port), relayMarker...)
}

// SanitizeMOTD removes tag brackets and control characters and limits length.
func SanitizeMOTD(s string) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if r == '[' || r == ']' || r < 0x20 || r == 0x7f || r == utf8.RuneError {
			continue
		}
		if n == 80 {
			b.WriteString("…")
			break
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}
