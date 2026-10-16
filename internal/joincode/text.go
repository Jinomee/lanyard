package joincode

import (
	"regexp"
	"strings"

	"github.com/jinomee/mc/internal/brand"
)

// Crockford base32 alphabet: digits and letters without I, L, O, U.
const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

var decodeMap = func() [256]int8 {
	var m [256]int8
	for i := range m {
		m[i] = -1
	}
	for i := 0; i < len(alphabet); i++ {
		m[alphabet[i]] = int8(i)
		m[alphabet[i]|0x20] = int8(i) // lower case (digits unaffected: 0x30|0x20 == 0x30)
	}
	for _, c := range "oO" {
		m[c] = 0
	}
	for _, c := range "iIlL" {
		m[c] = 1
	}
	return m
}()

func b32encode(b []byte) string {
	var sb strings.Builder
	sb.Grow((len(b)*8 + 4) / 5)
	var acc uint32
	bits := 0
	for _, x := range b {
		acc = acc<<8 | uint32(x)
		bits += 8
		for bits >= 5 {
			bits -= 5
			sb.WriteByte(alphabet[(acc>>uint(bits))&31])
		}
	}
	if bits > 0 {
		sb.WriteByte(alphabet[(acc<<uint(5-bits))&31])
	}
	return sb.String()
}

// isSeparator reports characters that may appear inside a pasted code and are ignored.
func isSeparator(c byte) bool {
	return c == '-' || c == ' ' || c == '\t' || c == '\r' || c == '\n'
}

func b32decode(s string) ([]byte, error) {
	out := make([]byte, 0, len(s)*5/8)
	var acc uint32
	bits := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if isSeparator(c) {
			continue
		}
		v := decodeMap[c]
		if v < 0 {
			return nil, ErrCharacters
		}
		acc = acc<<5 | uint32(v)
		bits += 5
		if bits >= 8 {
			bits -= 8
			out = append(out, byte(acc>>uint(bits)))
		}
	}
	// Leftover bits must be zero padding shorter than one byte.
	if bits >= 5 || acc&((1<<uint(bits))-1) != 0 {
		return nil, ErrTruncated
	}
	return out, nil
}

// linkPrefix is "<scheme>://join/".
func linkPrefix() string { return brand.URIScheme() + "://join/" }

// Link wraps a code into a clickable join link.
func Link(code string) string { return linkPrefix() + code }

// cutLink strips the join-link prefix (case-insensitive), if present.
func cutLink(s string) (string, bool) {
	p := linkPrefix()
	if len(s) >= len(p) && strings.EqualFold(s[:len(p)], p) {
		return strings.TrimRight(s[len(p):], "/"), true
	}
	return s, false
}

var findRE = regexp.MustCompile(`(?i)\bLY1R?-[0-9A-Z][0-9A-Z \-]{8,}`)

// Find extracts the first plausible code from arbitrary text, for example a
// chat message copied to the clipboard ("Join me! LY1-ABCD…"). It returns the
// candidate string and its kind only if it decodes successfully.
func Find(text string) (string, Kind, bool) {
	if len(text) > 8192 {
		text = text[:8192]
	}
	for _, loc := range findRE.FindAllStringIndex(text, 4) {
		cand := strings.TrimRight(text[loc[0]:loc[1]], " -")
		// Chat apps sometimes break long tokens with spaces; try the greedy
		// match first, then progressively shorter cuts at spaces.
		for {
			if k, _, err := normalize(cand); err == nil {
				return compact(cand), k, true
			}
			i := strings.LastIndexByte(cand, ' ')
			if i < 0 {
				break
			}
			cand = strings.TrimRight(cand[:i], " -")
		}
	}
	return "", 0, false
}

// compact removes separators after the prefix and upper-cases the code.
func compact(code string) string {
	up := strings.ToUpper(strings.TrimSpace(code))
	prefix := InvitePrefix
	if strings.HasPrefix(up, ReplyPrefix) {
		prefix = ReplyPrefix
	}
	rest := up[len(prefix):]
	var sb strings.Builder
	sb.WriteString(prefix)
	for i := 0; i < len(rest); i++ {
		if !isSeparator(rest[i]) {
			sb.WriteByte(rest[i])
		}
	}
	return sb.String()
}
