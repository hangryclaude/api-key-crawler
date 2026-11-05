package bench

import (
	"encoding/base64"
	"net/url"
	"unicode/utf16"
)

// form is one spelling of a secret that a known-secret matcher registers.
type form struct {
	Variant string
	Pattern string
}

// registeredForms are the spellings PLAN's known-secret matcher registers for a value: as it is,
// base64 and base64url, percent-encoded, JSON-escaped, UTF-16 in both byte orders, and base64
// at the two alignments a value takes inside a longer string (one and two bytes before it). A
// plant is "known by design" when one of them is in the bytes the full scan feeds the matcher,
// so a matcher that skips one of them shows up as a miss of a plant that was fair to expect.
func registeredForms(raw string) []form {
	out := []form{
		{"raw", raw},
		{"base64", stdB64(raw)},
		{"base64url", rawURLB64(raw)},
	}
	if q := url.QueryEscape(raw); q != raw {
		out = append(out, form{"urlenc", q})
	}
	if j := jsonEscaped(raw); j != raw {
		out = append(out, form{"json", j})
	}
	out = append(out, form{"utf16le", utf16Form(raw, false)}, form{"utf16be", utf16Form(raw, true)})
	for k := 1; k <= 2; k++ {
		if a := alignedB64(raw, k); a != "" {
			out = append(out, form{"base64+" + string(rune('0'+k)), a})
		}
	}
	return out
}

// knownForms lists the patterns of registeredForms.
func knownForms(raw string) []string {
	fs := registeredForms(raw)
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.Pattern
	}
	return out
}

func utf16Form(s string, bigEndian bool) string {
	var b []byte
	for _, c := range utf16.Encode([]rune(s)) {
		if bigEndian {
			b = append(b, byte(c>>8), byte(c))
		} else {
			b = append(b, byte(c), byte(c>>8))
		}
	}
	return string(b)
}

// alignedB64 is the part of base64(<k bytes> + raw) that does not depend on those k bytes: the
// leading characters carry bits of them, and a final group that is not full carries padding.
// What is left is a substring of the base64 of any longer string that holds raw at that
// alignment ("user:" + raw, for instance, is one byte off the three-byte groups). It returns ""
// when fewer than 12 characters are left, too few to register.
func alignedB64(raw string, k int) string {
	s := base64.StdEncoding.EncodeToString(append(make([]byte, k), raw...))
	lead := (k*8 + 5) / 6
	end := (k + len(raw)) / 3 * 4
	if end-lead < 12 {
		return ""
	}
	return s[lead:end]
}
