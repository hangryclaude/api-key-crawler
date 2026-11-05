// Package known learns the secrets the user already owns and finds them again in any content.
// The store holds keyed hashes only: a learned value cannot be read back from disk, and a
// window of content that is not a learned value cannot match, because every candidate the
// rolling hash flags is confirmed by HMAC before it is reported.
package known

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"keyguard/internal/fp"
)

const (
	// window is the rolling-hash width. Every entry is indexed by the hash of its last
	// window bytes (suffixes of real keys are random, prefixes like "sk-ant-api03-" are
	// not), so nothing shorter than this can be stored.
	window = 12

	// MinLen is the shortest value, or encoded variant of one, the store accepts.
	MinLen = window

	storeVersion = 1
)

// Entry is one registered form of one learned value. It carries hashes and display
// metadata, never the value: Tail and Shape follow fp.Shape, which shows at most four
// characters of the random part and fewer for short values.
//
// The field order is the file's layout: storefast.go parses it positionally, and falls back
// to encoding/json for any other order, so reordering is safe but slow.
type Entry struct {
	ID         string `json:"id"`          // fp.ID(FP): what a human types to ignore it
	Name       string `json:"name"`        // e.g. OPENAI_API_KEY
	Source     string `json:"source"`      // where it was learned
	Len        int    `json:"len"`         // length of the variant's bytes
	Tail       string `json:"tail"`        // trailing characters of the raw value, per fp.Shape
	FP         string `json:"fp"`          // fingerprint of the RAW value
	VFP        string `json:"vfp"`         // fingerprint of the variant's bytes: the HMAC confirm
	Variant    string `json:"variant"`     // raw|base64|base64url|urlenc|json
	SuffixHash string `json:"suffix_hash"` // keyed rolling hash of the variant's last window bytes, 16 hex
	Shape      string `json:"shape"`       // fp.Shape of the raw value
}

// hasher is the keyed polynomial hash of one window: sum(b[j] * base^(window-1-j)) mod
// 2^64. The base comes from the root's salt, so a stored suffix hash cannot be tested
// without it.
type hasher struct {
	base uint64
	// out[b] is what byte b contributes after it has been shifted through the whole
	// window, so rolling forward is one multiply, one add and one table load.
	out [256]uint64
}

func newHasher(base uint64) *hasher {
	h := &hasher{base: base}
	p := uint64(1)
	for i := 0; i < window; i++ {
		p *= base
	}
	for b := range h.out {
		h.out[b] = uint64(b) * p
	}
	return h
}

// sum hashes one window; b must be exactly window bytes.
func (h *hasher) sum(b []byte) uint64 {
	var x uint64
	for _, c := range b {
		x = x*h.base + uint64(c)
	}
	return x
}

func hex16(x uint64) string {
	var b [8]byte
	for i := range b {
		b[i] = byte(x >> (56 - 8*i))
	}
	return hex.EncodeToString(b[:])
}

// variant is one byte string a learned value can show up as.
type variant struct {
	label string
	b     []byte
}

// variantsOf lists the forms of raw worth finding, raw first, without duplicates and
// without anything shorter than window. Labels are the four core.KnownMatch documents,
// plus "json" for a value that needs escaping inside a JSON string and "utf16le" and
// "utf16be" for a file saved in UTF-16.
//
// Beyond the plain encodings it registers the "stable" part of each base64 alignment: a
// value inside a larger base64 blob (basic-auth headers, docker auth, a whole key file
// piped through base64) is encoded relative to its offset in the blob, and only the
// characters that depend on the value's own bytes are the same in every blob.
func variantsOf(raw []byte) []variant {
	var out []variant
	seen := make(map[string]bool)
	add := func(label string, b []byte) {
		if len(b) < window || seen[string(b)] {
			return
		}
		seen[string(b)] = true
		out = append(out, variant{label, b})
	}
	add("raw", raw)
	add("base64", []byte(base64.StdEncoding.EncodeToString(raw)))
	add("base64url", []byte(base64.RawURLEncoding.EncodeToString(raw)))
	for _, u := range urlForms(raw) {
		add("urlenc", u)
	}
	for _, j := range jsonForms(raw) {
		add("json", j)
	}
	// Padding conventions differ between tools (python's urlsafe_b64encode pads, JWTs do
	// not, `base64 | tr -d =` strips), so register the other pairing too.
	add("base64", []byte(base64.RawStdEncoding.EncodeToString(raw)))
	add("base64url", []byte(base64.URLEncoding.EncodeToString(raw)))
	for _, s := range []struct {
		label string
		enc   *base64.Encoding
	}{{"base64", base64.RawStdEncoding}, {"base64url", base64.RawURLEncoding}} {
		for shift := 0; shift < 3; shift++ {
			add(s.label, stableBase64(s.enc, raw, shift))
		}
	}
	// A file saved as UTF-16 (a Windows tool, a PowerShell redirect, an export from an editor) holds
	// the value with a zero byte beside every character, and betterleaks and gitleaks read it as
	// binary and find nothing (STEAL P1-16). Both byte orders.
	add("utf16le", utf16Text(raw, false))
	add("utf16be", utf16Text(raw, true))
	return out
}

// utf16Text is raw as UTF-16 holds it, or nil for bytes that are not text: a binary value has no
// UTF-16 form worth looking for.
func utf16Text(raw []byte, bigEndian bool) []byte {
	if !utf8.Valid(raw) {
		return nil
	}
	units := utf16.Encode([]rune(string(raw)))
	out := make([]byte, 0, 2*len(units))
	for _, u := range units {
		if bigEndian {
			out = append(out, byte(u>>8), byte(u))
		} else {
			out = append(out, byte(u), byte(u>>8))
		}
	}
	return out
}

// stableBase64 is the base64 of raw as it appears inside a blob where raw starts at an
// offset that is shift mod 3, cut to the characters fixed by raw's own bytes: the leading
// characters that mix in the preceding byte(s) and the trailing one that mixes in the
// following byte are dropped.
func stableBase64(enc *base64.Encoding, raw []byte, shift int) []byte {
	buf := make([]byte, shift+len(raw))
	copy(buf[shift:], raw)
	e := enc.EncodeToString(buf)
	lead := [3]int{0, 2, 3}[shift]
	trail := 0
	if len(buf)%3 != 0 {
		trail = 1
	}
	if len(e)-trail <= lead {
		return nil
	}
	return []byte(e[lead : len(e)-trail])
}

// urlForms are the percent-encodings seen in the wild that differ from raw: RFC 3986
// strictly (python quote, Go QueryEscape, curl), JavaScript's encodeURIComponent, and Go's
// userinfo escaping, which keeps the sub-delimiters. A value made only of unreserved
// characters has none, which is the usual case for API keys.
func urlForms(raw []byte) [][]byte {
	unreserved := func(c byte) bool {
		return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			c == '-' || c == '_' || c == '.' || c == '~'
	}
	forms := [][]byte{
		pctEncode(raw, unreserved, false),
		pctEncode(raw, func(c byte) bool { return unreserved(c) || strings.IndexByte("!'()*", c) >= 0 }, false),
		pctEncode(raw, func(c byte) bool { return unreserved(c) || strings.IndexByte("!$&'()*+,;=", c) >= 0 }, false),
	}
	if bytes.IndexByte(raw, ' ') >= 0 {
		forms = append(forms, pctEncode(raw, unreserved, true))
	}
	out := forms[:0]
	for _, f := range forms {
		if string(f) != string(raw) {
			out = append(out, f)
		}
	}
	return out
}

// jsonForms are the ways a JSON encoder writes raw inside a string, when that is not raw
// itself: the minimal escaping of JavaScript, Go's extra \u003c \u003e \u0026, PHP's \/ with
// \uXXXX for non-ASCII, and Python's ensure_ascii. A password with a quote, a slash or an
// ampersand is in a .json file as one of these, not as typed.
func jsonForms(raw []byte) [][]byte {
	if !utf8.Valid(raw) {
		return nil
	}
	var out [][]byte
	for _, f := range []struct{ goStyle, slash, ascii bool }{
		{false, false, false}, {true, false, false}, {false, true, true}, {false, false, true},
	} {
		if e := jsonEscape(raw, f.goStyle, f.slash, f.ascii); string(e) != string(raw) {
			out = append(out, e)
		}
	}
	return out
}

func jsonEscape(raw []byte, goStyle, slash, ascii bool) []byte {
	const hexdigits = "0123456789abcdef"
	u := func(out []byte, r rune) []byte {
		return append(out, '\\', 'u', hexdigits[r>>12&15], hexdigits[r>>8&15], hexdigits[r>>4&15], hexdigits[r&15])
	}
	out := make([]byte, 0, len(raw)+8)
	for _, r := range string(raw) {
		switch {
		case r == '"' || r == '\\':
			out = append(out, '\\', byte(r))
		case r == '\n':
			out = append(out, '\\', 'n')
		case r == '\r':
			out = append(out, '\\', 'r')
		case r == '\t':
			out = append(out, '\\', 't')
		case r < 0x20:
			out = u(out, r)
		case goStyle && (r == '<' || r == '>' || r == '&' || r == 0x2028 || r == 0x2029):
			out = u(out, r)
		case slash && r == '/':
			out = append(out, '\\', '/')
		case ascii && r >= 0x80:
			if r > 0xffff {
				hi, lo := utf16.EncodeRune(r)
				out = u(u(out, hi), lo)
			} else {
				out = u(out, r)
			}
		default:
			out = utf8.AppendRune(out, r)
		}
	}
	return out
}

func pctEncode(raw []byte, keep func(byte) bool, plusForSpace bool) []byte {
	const hexdigits = "0123456789ABCDEF"
	out := make([]byte, 0, len(raw)+len(raw)/2)
	for _, c := range raw {
		switch {
		case keep(c):
			out = append(out, c)
		case c == ' ' && plusForSpace:
			out = append(out, '+')
		default:
			out = append(out, '%', hexdigits[c>>4], hexdigits[c&15])
		}
	}
	return out
}

// saltCheck is stored beside the entries so a regenerated salt shows up as an error
// instead of a store that silently matches nothing.
func saltCheck(kr *fp.Keyring) string { return kr.FP("keyguard known store v1") }

// tailOf is the part of fp.Shape after the ellipsis: the same grading, so a short value
// never gives a third of itself to the store.
func tailOf(shape string) string {
	if _, t, ok := strings.Cut(shape, "…"); ok {
		return t
	}
	return ""
}

// newEntries builds every registered form of one raw value. Values shorter than MinLen
// yield nothing.
func newEntries(kr *fp.Keyring, h *hasher, name, source string, raw []byte) []Entry {
	if len(raw) < MinLen {
		return nil
	}
	rawFP := kr.FPBytes(raw)
	shape := fp.Shape(string(raw))
	var out []Entry
	for _, v := range variantsOf(raw) {
		out = append(out, Entry{
			ID:         fp.ID(rawFP),
			Name:       name,
			Source:     source,
			Len:        len(v.b),
			Tail:       tailOf(shape),
			FP:         rawFP,
			VFP:        kr.FPBytes(v.b),
			Variant:    v.label,
			SuffixHash: hex16(h.sum(v.b[len(v.b)-window:])),
			Shape:      shape,
		})
	}
	return out
}
