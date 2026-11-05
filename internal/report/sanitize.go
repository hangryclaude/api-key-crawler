package report

import (
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"

	"keyguard/internal/fp"
)

// Everything in a report is metadata about a secret, never the secret. These functions are
// the last gate before text reaches the page: html/template stops markup injection, and the
// functions here stop a raw value that an upstream bug let through from being printed.

// clean removes what could reshape the page or hide text from the reader: control
// characters, bidi overrides (a filename can reverse how its own name displays), zero-width
// characters and invalid UTF-8.
func clean(s string) string {
	s = strings.ToValidUTF8(s, "\ufffd")
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\t' || r < 0x20 || r == 0x7f || r >= 0x80 && r < 0xa0:
			return ' '
		case r >= 0x200b && r <= 0x200f, r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069,
			r == 0x2060, r == 0xfeff, r == 0x2028, r == 0x2029:
			return -1
		}
		return r
	}, s)
}

// prose is for free text that engines or an LLM triager wrote. fp.Scrub is aggressive: it
// masks any random-looking 20+ character token, and a repo name with a date in it looks
// random. That is right for a sentence and wrong for a path, so paths and names go through
// ident instead.
func prose(s string) string { return fp.Scrub(clean(s)) }

// ident is for names that must stay readable: repo names, paths, refs, types.
func ident(s string) string { return maskRuns(clean(s)) }

// Mask is ident for other packages: notify runs every banner and text through it, so a
// notification cannot carry what the report would refuse to print.
func Mask(s string) string { return ident(s) }

// A run is a stretch of the characters keys are made of, minus '/', '.' and ':' so URLs and
// paths fall apart into short pieces that never look like a key.
func runByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
		c == '_' || c == '-' || c == '+' || c == '='
}

// secretLike is deliberately narrower than fp.Scrub: a long word-and-dash name such as
// "shop-factory-2026-11-final" must survive, a 24-character mixed-case-and-digit blob must
// not. Entropy of 20 random characters from a 62-letter alphabet is about 4.1 bits, hence
// the 4.0 floor; hex tops out at 4.0 so it gets its own length-based rule.
func secretLike(tok string) bool {
	if len(tok) < 20 {
		return false
	}
	if hexStretch(tok) {
		return true
	}
	var digit, letter, upper bool
	seps, longest, seg := 0, 0, 0
	for i := 0; i < len(tok); i++ {
		c := tok[i]
		switch {
		case c >= '0' && c <= '9':
			digit = true
		case c >= 'A' && c <= 'Z':
			letter, upper = true, true
		case c >= 'a' && c <= 'z':
			letter = true
		}
		if c == '-' || c == '_' {
			seps++
			seg = 0
			continue
		}
		if seg++; seg > longest {
			longest = seg
		}
	}
	// kebab-case and snake_case names: lots of separators, short lowercase words. A random
	// token has about one separator per 32 characters and capitals in most of its pieces,
	// so it never passes this test.
	if seps*8 > len(tok) && !upper && longest <= 12 {
		return false
	}
	e := fp.Entropy(tok)
	return e >= 4.3 || e >= 4.0 && digit && letter
}

// hexStretch finds 32 or more hex digits in a row: how digests and hex-encoded keys look,
// even when a short prefix such as "dop_v1_" keeps the whole run from being hex. Hex tops
// out at 4.0 bits per digit, below the general floor, so it needs its own rule.
func hexStretch(tok string) bool {
	start := -1
	for i := 0; i <= len(tok); i++ {
		if i < len(tok) && hexDigit(tok[i]) {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 && i-start >= 32 && fp.Entropy(tok[start:i]) >= 3.0 {
			return true
		}
		start = -1
	}
	return false
}

// hasSecretLike reports whether any run in s would be masked.
func hasSecretLike(s string) bool {
	for i := 0; i < len(s); {
		if !runByte(s[i]) {
			i++
			continue
		}
		j := i
		for j < len(s) && runByte(s[j]) {
			j++
		}
		if secretLike(s[i:j]) {
			return true
		}
		i = j
	}
	return false
}

func maskRuns(s string) string {
	if !hasSecretLike(s) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		if !runByte(s[i]) {
			b.WriteByte(s[i])
			i++
			continue
		}
		j := i
		for j < len(s) && runByte(s[j]) {
			j++
		}
		if secretLike(s[i:j]) {
			b.WriteString("«…»")
		} else {
			b.WriteString(s[i:j])
		}
		i = j
	}
	return b.String()
}

// safeShape returns s when it already has the form fp.Shape produces and re-derives the
// shape otherwise, so a raw value that reached Secret.Shape through a bug still prints as a
// shape. The longest constant prefix fp knows is 15 characters; the tail is at most 4.
func safeShape(s string) string {
	s = clean(s)
	if s == "-----BEGIN…KEY-----" {
		return s
	}
	if head, tail, ok := strings.Cut(s, "…"); ok &&
		utf8.RuneCountInString(head) <= 16 && utf8.RuneCountInString(tail) <= 4 && !strings.ContainsAny(s, " \t") {
		return s
	}
	return fp.Shape(s)
}

var longHex = regexp.MustCompile(`(?i)\b[0-9a-f]{40,64}\b`)

// shortSHA keeps the 10 characters git needs to find a commit (GitHub resolves an
// abbreviated hash in any commit or blob URL) and drops the rest, so no 40-character hash
// sits in the page looking like a key.
func shortSHA(s string) string {
	s = strings.TrimSpace(s)
	if len(s) < 7 || !isHex(s) {
		return ""
	}
	if len(s) > 10 {
		return s[:10]
	}
	return s
}

func hexDigit(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		if !hexDigit(s[i]) {
			return false
		}
	}
	return s != ""
}

// safeLink returns raw only when it is an https GitHub URL with nothing key-like in it.
// A hostile path or an engine bug must not turn into a javascript: or off-site link.
func safeLink(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || u.User != nil {
		return ""
	}
	switch strings.ToLower(u.Hostname()) {
	case "github.com", "gist.github.com":
	default:
		return ""
	}
	s := longHex.ReplaceAllStringFunc(u.String(), func(h string) string { return h[:10] })
	if hasSecretLike(s) {
		return ""
	}
	return s
}
