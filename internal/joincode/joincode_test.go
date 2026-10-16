package joincode

import (
	"bytes"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"
)

func sampleInvite() *Invite {
	inv := &Invite{
		Expires: time.Unix(1_800_000_000, 0).UTC(),
		Flags:   FlagMapEIM | FlagIPv6,
		Candidates: []Candidate{
			{CandIPv6, netip.MustParseAddrPort("[2001:db8:1234:5678::42]:40123")},
			{CandMapped, netip.MustParseAddrPort("198.51.100.7:40123")},
			{CandReflexive, netip.MustParseAddrPort("198.51.100.7:51000")},
			{CandLAN, netip.MustParseAddrPort("192.168.1.20:40123")},
		},
	}
	copy(inv.Secret[:], "0123456789")
	copy(inv.Fingerprint[:], "abcdefghijkl")
	return inv
}

func TestInviteRoundTrip(t *testing.T) {
	inv := sampleInvite()
	s, err := inv.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(s, InvitePrefix) {
		t.Fatalf("prefix: %q", s)
	}
	t.Logf("invite (%d chars): %s", len(s), s)
	if len(s) > 120 {
		t.Errorf("typical invite is %d chars, want ≤ 120", len(s))
	}
	got, err := DecodeInvite(s)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, inv) {
		t.Fatalf("round trip mismatch:\n got %+v\nwant %+v", got, inv)
	}
	// Lower case, separators, link form and surrounding whitespace all decode.
	variants := []string{
		strings.ToLower(s),
		"  " + s + "\n",
		InvitePrefix + spaced(s[len(InvitePrefix):], 5),
		Link(s),
		strings.ToUpper(Link(s)) + "/",
	}
	for _, v := range variants {
		if _, err := DecodeInvite(v); err != nil {
			t.Errorf("variant %q: %v", v, err)
		}
	}
}

func spaced(s string, n int) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if i > 0 && i%n == 0 {
			b.WriteByte('-')
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func TestReplyRoundTripAndProof(t *testing.T) {
	inv := sampleInvite()
	rep := &Reply{
		Expires: time.Unix(1_800_000_600, 0).UTC(),
		Flags:   FlagMapDep,
		Session: [4]byte{1, 2, 3, 4},
		Candidates: []Candidate{
			{CandReflexive, netip.MustParseAddrPort("203.0.113.9:6000")},
			{CandLAN, netip.MustParseAddrPort("10.0.0.5:6001")},
		},
	}
	if err := rep.Sign(inv.Secret); err != nil {
		t.Fatal(err)
	}
	s, err := rep.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(s, ReplyPrefix) {
		t.Fatalf("prefix: %q", s)
	}
	got, err := DecodeReply(s)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, rep) {
		t.Fatalf("mismatch:\n got %+v\nwant %+v", got, rep)
	}
	if !got.Verify(inv.Secret) {
		t.Fatal("proof should verify")
	}
	other := inv.Secret
	other[0] ^= 1
	if got.Verify(other) {
		t.Fatal("proof must not verify with another secret")
	}
	// Tampering with candidates breaks the proof even if CRC is recomputed.
	got.Candidates[0].Addr = netip.MustParseAddrPort("203.0.113.66:6000")
	if got.Verify(inv.Secret) {
		t.Fatal("proof must cover candidates")
	}
}

func TestKindMismatch(t *testing.T) {
	inv := sampleInvite()
	s, _ := inv.Encode()
	if _, err := DecodeReply(s); err == nil {
		t.Fatal("invite decoded as reply")
	}
	// Payload says invite but prefix says reply.
	forged := ReplyPrefix + s[len(InvitePrefix):]
	if _, err := DecodeReply(forged); !errors.Is(err, ErrKind) {
		t.Fatalf("want ErrKind, got %v", err)
	}
	k, err := KindOf(s)
	if err != nil || k != KindInvite {
		t.Fatalf("KindOf = %v, %v", k, err)
	}
}

func TestTypoDetected(t *testing.T) {
	s, _ := sampleInvite().Encode()
	body := []byte(s)
	for i := len(InvitePrefix); i < len(body); i++ {
		orig := body[i]
		for _, c := range []byte(alphabet) {
			if c == orig {
				continue
			}
			body[i] = c
			if _, err := DecodeInvite(string(body)); err == nil {
				t.Fatalf("single-character change at %d (%c→%c) not detected", i, orig, c)
			}
		}
		body[i] = orig
	}
	// Truncation is detected.
	for n := len(InvitePrefix); n < len(s); n++ {
		if _, err := DecodeInvite(s[:n]); err == nil {
			t.Fatalf("truncated code of length %d accepted", n)
		}
	}
}

func TestConfusableLetters(t *testing.T) {
	// Crockford: O→0, I/L→1.
	a, err := b32decode("0O1IL000")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := b32decode("00111000")
	if !bytes.Equal(a, b) {
		t.Fatalf("confusables not normalised: %x vs %x", a, b)
	}
	if _, err := b32decode("U"); err == nil {
		t.Fatal("U must be invalid")
	}
}

func TestErrors(t *testing.T) {
	cases := map[string]error{
		"":                  ErrEmpty,
		"hello":             ErrPrefix,
		"LY1-":              ErrTruncated,
		"LY1-!!!!":          ErrCharacters,
		"LY1-0000000000000000": ErrChecksum,
	}
	for in, want := range cases {
		if _, err := DecodeInvite(in); !errors.Is(err, want) {
			t.Errorf("%q: got %v want %v", in, err, want)
		}
	}
}

func TestNewerVersionRejected(t *testing.T) {
	b := appendHeader(nil, KindInvite, 0, time.Now())
	b[0] = 2<<4 | byte(KindInvite)
	s := finish(InvitePrefix, b)
	if _, err := DecodeInvite(s); !errors.Is(err, ErrVersion) {
		t.Fatalf("got %v", err)
	}
}

func TestFind(t *testing.T) {
	s, _ := sampleInvite().Encode()
	msgs := []string{
		"来玩！" + s + " 快点",
		"Join me: " + strings.ToLower(s) + ". See you",
		"link: " + Link(s),
		"Code: " + InvitePrefix + spaced(s[len(InvitePrefix):], 4) + " thanks",
	}
	for _, m := range msgs {
		got, k, ok := Find(m)
		if !ok || k != KindInvite {
			t.Errorf("Find(%q) failed", m)
			continue
		}
		if _, err := DecodeInvite(got); err != nil {
			t.Errorf("Find returned undecodable %q: %v", got, err)
		}
	}
	if _, _, ok := Find("nothing here LY1-ZZZZZZZZZZ"); ok {
		t.Error("garbage accepted")
	}
}

func TestTooManyCandidates(t *testing.T) {
	inv := sampleInvite()
	for len(inv.Candidates) <= MaxCandidates {
		inv.Candidates = append(inv.Candidates, inv.Candidates[0])
	}
	if _, err := inv.Encode(); err == nil {
		t.Fatal("expected error")
	}
}

func FuzzDecode(f *testing.F) {
	s, _ := sampleInvite().Encode()
	f.Add(s)
	rep := &Reply{Candidates: []Candidate{{CandLAN, netip.MustParseAddrPort("10.0.0.1:1")}}}
	_ = rep.Sign([SecretLen]byte{})
	r, _ := rep.Encode()
	f.Add(r)
	f.Add("LY1-")
	f.Add("lanyard://join/LY1R-00")
	f.Fuzz(func(t *testing.T, in string) {
		if inv, err := DecodeInvite(in); err == nil {
			out, err := inv.Encode()
			if err != nil {
				t.Fatalf("decoded invite does not re-encode: %v", err)
			}
			again, err := DecodeInvite(out)
			if err != nil || !reflect.DeepEqual(again, inv) {
				t.Fatalf("re-encode round trip failed: %v", err)
			}
		}
		if rp, err := DecodeReply(in); err == nil {
			out, err := rp.Encode()
			if err != nil {
				t.Fatalf("decoded reply does not re-encode: %v", err)
			}
			again, err := DecodeReply(out)
			if err != nil || !reflect.DeepEqual(again, rp) {
				t.Fatalf("re-encode round trip failed: %v", err)
			}
		}
		_, _, _ = Find(in)
	})
}

func FuzzEncode(f *testing.F) {
	f.Add(uint32(1_800_000_000), uint8(3), []byte("0123456789abcdefghijkl"), []byte{1, 192, 168, 0, 1, 0x9c, 0x40})
	f.Fuzz(func(t *testing.T, exp uint32, flags uint8, fixed []byte, cands []byte) {
		inv := &Invite{Expires: time.Unix(int64(exp), 0).UTC(), Flags: Flags(flags)}
		copy(inv.Secret[:], fixed)
		if len(fixed) > SecretLen {
			copy(inv.Fingerprint[:], fixed[SecretLen:])
		}
		// Build candidates from the byte soup: kind, 4 addr bytes, 2 port bytes.
		for len(cands) >= 7 && len(inv.Candidates) < MaxCandidates {
			k := CandidateKind(cands[0]%4 + 1)
			a := netip.AddrFrom4([4]byte(cands[1:5]))
			p := uint16(cands[5])<<8 | uint16(cands[6])
			inv.Candidates = append(inv.Candidates, Candidate{k, netip.AddrPortFrom(a, p)})
			cands = cands[7:]
		}
		s, err := inv.Encode()
		if err != nil {
			t.Fatal(err)
		}
		got, err := DecodeInvite(s)
		if err != nil {
			t.Fatalf("decode %q: %v", s, err)
		}
		if len(inv.Candidates) == 0 {
			inv.Candidates = got.Candidates // nil vs empty slice
		}
		if !reflect.DeepEqual(got, inv) {
			t.Fatalf("mismatch\n got %+v\nwant %+v", got, inv)
		}
	})
}
