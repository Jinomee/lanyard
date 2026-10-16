package transport

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"

	"github.com/jinomee/lanyard/internal/joincode"
)

// Punch packet layout (21 bytes):
//
//	0x1F 'L' 'Y' 'P' | role (1) | session (4) | nonce (4) | HMAC-SHA256(secret, …)[:8]
//
// The first byte has both high bits clear, so quic-go hands it to
// ReadNonQUICPacket instead of treating it as QUIC. The HMAC means only
// someone holding the invite secret can make a peer accept a punch, which
// matters because a valid punch reveals a new address to dial.
const punchLen = 21

// Punch roles.
const (
	RoleHost  byte = 'H'
	RoleGuest byte = 'G'
)

var punchMagic = [4]byte{0x1F, 'L', 'Y', 'P'}

// IsPunch reports whether b looks like a punch packet (MAC not checked).
func IsPunch(b []byte) bool {
	return len(b) == punchLen && [4]byte(b[:4]) == punchMagic
}

// MakePunch builds an authenticated punch packet.
func MakePunch(secret [joincode.SecretLen]byte, role byte, session [joincode.SessionLen]byte) []byte {
	b := make([]byte, 0, punchLen)
	b = append(b, punchMagic[:]...)
	b = append(b, role)
	b = append(b, session[:]...)
	var nonce [4]byte
	_, _ = rand.Read(nonce[:])
	b = append(b, nonce[:]...)
	return append(b, punchMAC(secret, b[4:13])...)
}

// ParsePunch verifies a punch packet and returns its role and session.
func ParsePunch(secret [joincode.SecretLen]byte, b []byte) (role byte, session [joincode.SessionLen]byte, ok bool) {
	if !IsPunch(b) {
		return 0, session, false
	}
	if !hmac.Equal(b[13:], punchMAC(secret, b[4:13])) {
		return 0, session, false
	}
	copy(session[:], b[5:9])
	return b[4], session, true
}

// PunchNonce returns the random nonce of a punch packet (already verified
// with ParsePunch). Every packet a peer sends has a fresh one, so a nonce seen
// twice is a replay.
func PunchNonce(b []byte) [4]byte { return [4]byte(b[9:13]) }

func punchMAC(secret [joincode.SecretLen]byte, body []byte) []byte {
	m := hmac.New(sha256.New, secret[:])
	m.Write([]byte("lanyard punch v1"))
	m.Write(body)
	return m.Sum(nil)[:8]
}
