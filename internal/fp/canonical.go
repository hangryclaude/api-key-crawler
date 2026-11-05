package fp

import (
	"net/url"
	"strings"
)

// Canonical is the form of a credential that gets fingerprinted. Engines report different
// stretches of one credential (STEAL P0-08: titus every group, betterleaks the password only,
// trufflehog the whole URL), so their fingerprints differ and neither dedup nor agreement
// scoring can work. Canonical removes the framing that differs and nothing else:
//
//   - a PEM block becomes its header line, its body with every space and line break gone
//     (also the two-character \n that JSON and .env files store) and its footer line, so a
//     key wrapped at 64 columns, indented, CRLF-ended or written on one line is one secret;
//     text outside the markers is dropped. A block with no footer is left alone: it is an
//     extent we cannot complete.
//   - a URI that carries a password (scheme://user:password@host/...) becomes the password,
//     percent-decoded. The password is the secret; the rest is an address.
//
// Anything else comes back unchanged. A generic value has no framing, and guessing would
// merge two different secrets into one record.
//
// Keyring.FP does not call this. The known matcher hashes exact byte ranges of scanned
// files and compares them to stored hashes, and folding those would stop them matching. A
// normalizer calls Canonical on what an engine reported, then FP on the result.
func Canonical(raw string) string {
	if s, ok := canonicalPEM(raw); ok {
		return s
	}
	if s, ok := uriPassword(raw); ok {
		return s
	}
	return raw
}

const (
	pemBegin = "-----BEGIN "
	pemEnd   = "-----END "
	pemDash  = "-----"
)

var escapedBreaks = strings.NewReplacer(`\r`, "", `\n`, "")

func canonicalPEM(raw string) (string, bool) {
	b := strings.Index(raw, pemBegin)
	if b < 0 {
		return "", false
	}
	h := strings.Index(raw[b+len(pemBegin):], pemDash)
	if h < 0 {
		return "", false
	}
	headerEnd := b + len(pemBegin) + h + len(pemDash)
	e := strings.LastIndex(raw, pemEnd)
	if e < headerEnd {
		return "", false
	}
	f := strings.Index(raw[e+len(pemEnd):], pemDash)
	if f < 0 {
		return "", false
	}
	footerEnd := e + len(pemEnd) + f + len(pemDash)
	body := strings.Join(strings.Fields(escapedBreaks.Replace(raw[headerEnd:e])), "")
	return raw[b:headerEnd] + "\n" + body + "\n" + raw[e:footerEnd], true
}

// uriPassword takes the userinfo from the last "@" before the path, query or fragment, so a
// password that holds an "@" survives, and splits user from password at the first ":" so one
// that holds a ":" does too. A password with an unescaped "/", "?" or "#" ends the authority
// early and is not found; the value then falls through unchanged, which only costs a dedup.
func uriPassword(raw string) (string, bool) {
	i := strings.Index(raw, "://")
	if i <= 0 || !schemeOK(raw[:i]) {
		return "", false
	}
	rest := raw[i+len("://"):]
	if j := strings.IndexAny(rest, "/?#"); j >= 0 {
		rest = rest[:j]
	}
	at := strings.LastIndexByte(rest, '@')
	if at <= 0 {
		return "", false
	}
	_, pw, ok := strings.Cut(rest[:at], ":")
	if !ok || pw == "" {
		return "", false
	}
	if d, err := url.PathUnescape(pw); err == nil { // not QueryUnescape: "+" is a plus in a password
		pw = d
	}
	return pw, true
}

func schemeOK(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		case i > 0 && (c >= '0' && c <= '9' || c == '+' || c == '-' || c == '.'):
		default:
			return false
		}
	}
	return s != ""
}
