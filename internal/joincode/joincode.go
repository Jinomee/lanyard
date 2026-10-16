// Package joincode encodes and decodes LANyard join codes.
//
// Two code kinds exist:
//
//   - Invite ("LY1-…"): made by the host. Contains every address the host may
//     be reachable at, a random secret, a truncated fingerprint of the host's
//     TLS certificate, an expiry and NAT summary flags. Reusable until it
//     expires or the host revokes it.
//   - Reply ("LY1R-…"): made by a guest when the invite alone was not enough.
//     Contains the guest's addresses and an HMAC proof (keyed by the invite
//     secret) so the host only hole-punches toward people who hold the invite.
//
// Wire format (all integers big-endian), then Crockford base32 without padding:
//
//	byte  0      version<<4 | kind
//	byte  1      flags
//	bytes 2..5   expiry, Unix seconds
//	invite:      secret[10] fingerprint[12]
//	reply:       session[4]
//	bytes        base port (uint16)
//	byte         candidate count (≤ MaxCandidates)
//	candidates:  header byte (bits 0-2 kind, bit 3 IPv6, bit 4 own port),
//	             address (4 or 16 bytes), port (2 bytes, only if own-port bit)
//	reply only:  proof[8] = HMAC-SHA256(secret, all preceding bytes)[:8]
//	trailer:     CRC-32 (IEEE) of all preceding bytes
package joincode

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"net/netip"
	"strings"
	"time"
)

// Version is the current code format version.
const Version = 1

// Text prefixes. These are protocol constants, independent of the brand name.
const (
	InvitePrefix = "LY1-"
	ReplyPrefix  = "LY1R-"
)

// Sizes of fixed fields.
const (
	SecretLen      = 10
	FingerprintLen = 12
	SessionLen     = 4
	ProofLen       = 8
	MaxCandidates  = 8
)

// Kind distinguishes invites from replies.
type Kind uint8

// Code kinds.
const (
	KindInvite Kind = 0
	KindReply  Kind = 1
)

func (k Kind) String() string {
	switch k {
	case KindInvite:
		return "invite"
	case KindReply:
		return "reply"
	}
	return fmt.Sprintf("kind(%d)", uint8(k))
}

// CandidateKind says how an address was discovered; it decides which
// connection strategy uses it.
type CandidateKind uint8

// Candidate kinds.
const (
	CandIPv6      CandidateKind = 1 // global IPv6 address of the machine
	CandMapped    CandidateKind = 2 // router port mapping (UPnP / NAT-PMP / PCP)
	CandReflexive CandidateKind = 3 // STUN server-reflexive IPv4 address
	CandLAN       CandidateKind = 4 // private address on the local network
)

func (k CandidateKind) String() string {
	switch k {
	case CandIPv6:
		return "ipv6"
	case CandMapped:
		return "mapped"
	case CandReflexive:
		return "reflexive"
	case CandLAN:
		return "lan"
	}
	return fmt.Sprintf("cand(%d)", uint8(k))
}

// Candidate is one address at which a peer might be reachable.
type Candidate struct {
	Kind CandidateKind
	Addr netip.AddrPort
}

func (c Candidate) String() string { return c.Kind.String() + ":" + c.Addr.String() }

// Flags summarise the creator's network so the other side can give better
// advice when connecting fails.
type Flags uint8

// Flag bits.
const (
	FlagApproval   Flags = 1 << 0 // host approves each join manually
	FlagDedicated  Flags = 1 << 1 // target is a manually entered port (server), not a LAN world
	FlagMapEIM     Flags = 1 << 2 // NAT mapping is endpoint-independent
	FlagMapDep     Flags = 1 << 3 // NAT mapping is endpoint-dependent ("symmetric")
	FlagPortMapped Flags = 1 << 4 // router accepted a port mapping
	FlagCGNAT      Flags = 1 << 5 // carrier-grade / double NAT suspected
	FlagIPv6       Flags = 1 << 6 // creator has global IPv6
)

// Has reports whether all bits in g are set.
func (f Flags) Has(g Flags) bool { return f&g == g }

// Invite is the host's join code.
type Invite struct {
	Expires     time.Time
	Flags       Flags
	Secret      [SecretLen]byte
	Fingerprint [FingerprintLen]byte
	Candidates  []Candidate
}

// Reply is the guest's answer code for the hole-punching fallback.
type Reply struct {
	Expires    time.Time
	Flags      Flags
	Session    [SessionLen]byte
	Candidates []Candidate
	Proof      [ProofLen]byte
}

// Errors returned by the decoders. They map to user-facing messages.
var (
	ErrEmpty       = errors.New("joincode: empty")
	ErrPrefix      = errors.New("joincode: not a LANyard code")
	ErrCharacters  = errors.New("joincode: invalid characters")
	ErrChecksum    = errors.New("joincode: checksum mismatch (typo or incomplete copy)")
	ErrTruncated   = errors.New("joincode: truncated")
	ErrVersion     = errors.New("joincode: made by a newer version")
	ErrKind        = errors.New("joincode: wrong code kind")
	ErrCandidates  = errors.New("joincode: invalid candidate list")
	ErrTrailing    = errors.New("joincode: trailing data")
	ErrBadProof    = errors.New("joincode: reply proof does not match this invite")
	errTooManyCand = errors.New("joincode: too many candidates")
)

const (
	hdrKindMask = 0x07
	hdrIPv6     = 0x08
	hdrOwnPort  = 0x10
)

// ---- encoding ----

func appendHeader(b []byte, kind Kind, flags Flags, exp time.Time) []byte {
	b = append(b, byte(Version<<4)|byte(kind), byte(flags))
	return binary.BigEndian.AppendUint32(b, uint32(clampUnix(exp)))
}

func clampUnix(t time.Time) int64 {
	u := t.Unix()
	if u < 0 {
		return 0
	}
	if u > int64(^uint32(0)) {
		return int64(^uint32(0))
	}
	return u
}

// basePort picks the most common port among candidates so most entries can
// omit their port.
func basePort(cs []Candidate) uint16 {
	counts := map[uint16]int{}
	best, bestN := uint16(0), 0
	for _, c := range cs {
		p := c.Addr.Port()
		counts[p]++
		if counts[p] > bestN || (counts[p] == bestN && p < best) {
			best, bestN = p, counts[p]
		}
	}
	return best
}

func appendCandidates(b []byte, cs []Candidate) ([]byte, error) {
	if len(cs) > MaxCandidates {
		return nil, errTooManyCand
	}
	bp := basePort(cs)
	b = binary.BigEndian.AppendUint16(b, bp)
	b = append(b, byte(len(cs)))
	for _, c := range cs {
		if c.Kind == 0 || c.Kind > hdrKindMask {
			return nil, ErrCandidates
		}
		a := c.Addr.Addr().Unmap()
		if !a.IsValid() || a.Zone() != "" {
			return nil, ErrCandidates
		}
		h := byte(c.Kind)
		if a.Is6() {
			h |= hdrIPv6
		}
		own := c.Addr.Port() != bp
		if own {
			h |= hdrOwnPort
		}
		b = append(b, h)
		b = append(b, a.AsSlice()...)
		if own {
			b = binary.BigEndian.AppendUint16(b, c.Addr.Port())
		}
	}
	return b, nil
}

func finish(prefix string, b []byte) string {
	b = binary.BigEndian.AppendUint32(b, crc32.ChecksumIEEE(b))
	return prefix + b32encode(b)
}

// Encode returns the text form of the invite ("LY1-…").
func (inv *Invite) Encode() (string, error) {
	b := appendHeader(make([]byte, 0, 96), KindInvite, inv.Flags, inv.Expires)
	b = append(b, inv.Secret[:]...)
	b = append(b, inv.Fingerprint[:]...)
	b, err := appendCandidates(b, inv.Candidates)
	if err != nil {
		return "", err
	}
	return finish(InvitePrefix, b), nil
}

func (r *Reply) body() ([]byte, error) {
	b := appendHeader(make([]byte, 0, 96), KindReply, r.Flags, r.Expires)
	b = append(b, r.Session[:]...)
	return appendCandidates(b, r.Candidates)
}

// Sign computes the reply's proof from the invite secret.
func (r *Reply) Sign(secret [SecretLen]byte) error {
	b, err := r.body()
	if err != nil {
		return err
	}
	copy(r.Proof[:], proof(secret, b))
	return nil
}

// Verify checks the reply's proof against the invite secret.
func (r *Reply) Verify(secret [SecretLen]byte) bool {
	b, err := r.body()
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(r.Proof[:], proof(secret, b)) == 1
}

func proof(secret [SecretLen]byte, body []byte) []byte {
	m := hmac.New(sha256.New, secret[:])
	m.Write([]byte("lanyard reply v1"))
	m.Write(body)
	return m.Sum(nil)[:ProofLen]
}

// Encode returns the text form of the reply ("LY1R-…"). Call Sign first.
func (r *Reply) Encode() (string, error) {
	b, err := r.body()
	if err != nil {
		return "", err
	}
	b = append(b, r.Proof[:]...)
	return finish(ReplyPrefix, b), nil
}

// ---- decoding ----

// normalize strips the prefix and separators and returns the raw bytes plus the kind
// indicated by the prefix.
func normalize(s string) (Kind, []byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil, ErrEmpty
	}
	if rest, ok := cutLink(s); ok {
		s = rest
	}
	up := strings.ToUpper(s)
	var kind Kind
	switch {
	case strings.HasPrefix(up, ReplyPrefix):
		kind, s = KindReply, s[len(ReplyPrefix):]
	case strings.HasPrefix(up, InvitePrefix):
		kind, s = KindInvite, s[len(InvitePrefix):]
	default:
		return 0, nil, ErrPrefix
	}
	raw, err := b32decode(s)
	if err != nil {
		return 0, nil, err
	}
	if len(raw) < 6+4 {
		return 0, nil, ErrTruncated
	}
	body, sum := raw[:len(raw)-4], raw[len(raw)-4:]
	if crc32.ChecksumIEEE(body) != binary.BigEndian.Uint32(sum) {
		return 0, nil, ErrChecksum
	}
	if body[0]>>4 != Version {
		if body[0]>>4 > Version {
			return 0, nil, ErrVersion
		}
		return 0, nil, ErrPrefix
	}
	if Kind(body[0]&0x0f) != kind {
		return 0, nil, ErrKind
	}
	return kind, body, nil
}

type reader struct {
	b   []byte
	err error
}

func (r *reader) take(n int) []byte {
	if r.err != nil {
		return nil
	}
	if len(r.b) < n {
		r.err = ErrTruncated
		return nil
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}

func (r *reader) u8() byte {
	v := r.take(1)
	if v == nil {
		return 0
	}
	return v[0]
}

func (r *reader) u16() uint16 {
	v := r.take(2)
	if v == nil {
		return 0
	}
	return binary.BigEndian.Uint16(v)
}

func (r *reader) u32() uint32 {
	v := r.take(4)
	if v == nil {
		return 0
	}
	return binary.BigEndian.Uint32(v)
}

func (r *reader) candidates() []Candidate {
	bp := r.u16()
	n := int(r.u8())
	if r.err != nil {
		return nil
	}
	if n > MaxCandidates {
		r.err = ErrCandidates
		return nil
	}
	cs := make([]Candidate, 0, n)
	for range n {
		h := r.u8()
		k := CandidateKind(h & hdrKindMask)
		if h&^(hdrKindMask|hdrIPv6|hdrOwnPort) != 0 || k == 0 {
			if r.err == nil {
				r.err = ErrCandidates
			}
			return nil
		}
		var a netip.Addr
		if h&hdrIPv6 != 0 {
			v := r.take(16)
			if v == nil {
				return nil
			}
			a = netip.AddrFrom16([16]byte(v))
			if a.Is4In6() {
				r.err = ErrCandidates
				return nil
			}
		} else {
			v := r.take(4)
			if v == nil {
				return nil
			}
			a = netip.AddrFrom4([4]byte(v))
		}
		p := bp
		if h&hdrOwnPort != 0 {
			p = r.u16()
			if p == bp && r.err == nil {
				r.err = ErrCandidates // non-canonical
				return nil
			}
		}
		cs = append(cs, Candidate{Kind: k, Addr: netip.AddrPortFrom(a, p)})
	}
	if r.err == nil && basePort(cs) != bp {
		r.err = ErrCandidates // non-canonical base port
	}
	return cs
}

// DecodeInvite parses an invite code (also accepts a lanyard://join/ link).
func DecodeInvite(s string) (*Invite, error) {
	_, body, err := normalize(s)
	if err != nil {
		return nil, err
	}
	if Kind(body[0]&0x0f) != KindInvite {
		return nil, ErrKind
	}
	r := &reader{b: body[1:]}
	inv := &Invite{}
	inv.Flags = Flags(r.u8())
	inv.Expires = time.Unix(int64(r.u32()), 0).UTC()
	copy(inv.Secret[:], r.take(SecretLen))
	copy(inv.Fingerprint[:], r.take(FingerprintLen))
	inv.Candidates = r.candidates()
	if r.err != nil {
		return nil, r.err
	}
	if len(r.b) != 0 {
		return nil, ErrTrailing
	}
	return inv, nil
}

// DecodeReply parses a reply code. The proof is not checked; call Verify.
func DecodeReply(s string) (*Reply, error) {
	_, body, err := normalize(s)
	if err != nil {
		return nil, err
	}
	if Kind(body[0]&0x0f) != KindReply {
		return nil, ErrKind
	}
	r := &reader{b: body[1:]}
	rep := &Reply{}
	rep.Flags = Flags(r.u8())
	rep.Expires = time.Unix(int64(r.u32()), 0).UTC()
	copy(rep.Session[:], r.take(SessionLen))
	rep.Candidates = r.candidates()
	copy(rep.Proof[:], r.take(ProofLen))
	if r.err != nil {
		return nil, r.err
	}
	if len(r.b) != 0 {
		return nil, ErrTrailing
	}
	return rep, nil
}

// KindOf returns the kind of a code without fully decoding it.
func KindOf(s string) (Kind, error) {
	k, _, err := normalize(s)
	return k, err
}

// Expired reports whether t is past the expiry.
func Expired(expires, now time.Time) bool { return !now.Before(expires) }
