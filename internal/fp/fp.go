// Package fp turns raw secret values into salted fingerprints and safe display shapes.
// Every raw value keyguard touches passes through here on its way to being forgotten.
package fp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"
)

const saltLen = 40 // 32-byte HMAC key + 8-byte rolling-hash base

// Keyring holds the local salt. FP is HMAC-SHA256(salt, raw): the same secret is the same
// record across engines and runs, and the record is useless to anyone without the salt.
type Keyring struct {
	key  []byte
	base uint64
}

// Load reads <dir>/salt, creating dir (0700) and salt (0600) on first use.
func Load(dir string) (*Keyring, error) {
	p := filepath.Join(dir, "salt")
	b, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		if b, err = create(dir, p); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	return fromFile(p, b)
}

// Open reads <dir>/salt and never creates it: a missing salt is fs.ErrNotExist. A hook or a
// matcher that finds its salt gone must not mint a new one, because every hash stored under
// the old salt would silently stop matching and nothing would say so. Only the first
// install (Load) may create a salt.
func Open(dir string) (*Keyring, error) {
	p := filepath.Join(dir, "salt")
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	return fromFile(p, b)
}

func fromFile(p string, b []byte) (*Keyring, error) {
	if len(b) != saltLen {
		return nil, fmt.Errorf("fp: %s is %d bytes, want %d", p, len(b), saltLen)
	}
	return FromSalt(b), nil
}

// create writes the salt to a temp file and hard-links it into place, so two hooks racing
// on first use either both win with the same salt or one adopts the other's.
func create(dir, p string) ([]byte, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	b := make([]byte, saltLen)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp(dir, ".salt-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return nil, err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	if err := os.Link(tmp.Name(), p); errors.Is(err, os.ErrExist) {
		return os.ReadFile(p)
	} else if err != nil {
		return nil, err
	}
	return b, nil
}

// FromSalt builds a keyring from 40 salt bytes (tests and bench use throwaway salts).
func FromSalt(b []byte) *Keyring {
	return &Keyring{key: append([]byte(nil), b[:32]...), base: binary.LittleEndian.Uint64(b[32:40]) | 1}
}

// NewEphemeral is a random in-memory keyring for tests, bench and selftest.
func NewEphemeral() *Keyring {
	b := make([]byte, saltLen)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return FromSalt(b)
}

// FP is the fingerprint of a raw value: 32 hex chars of HMAC-SHA256.
func (k *Keyring) FP(raw string) string { return k.FPBytes([]byte(raw)) }

func (k *Keyring) FPBytes(raw []byte) string {
	m := hmac.New(sha256.New, k.key)
	m.Write(raw)
	return hex.EncodeToString(m.Sum(nil))[:32]
}

// Base is the odd 64-bit base the known matcher's rolling hash uses. It comes from the
// salt, so the stored window hashes are keyed too.
func (k *Keyring) Base() uint64 { return k.base }

// ID is the short handle humans type: "kg" + 6 hex.
func ID(fp string) string {
	if len(fp) < 6 {
		return "kg" + fp
	}
	return "kg" + fp[:6]
}

// prefixes are constant parts of well-known token formats; showing them leaks nothing.
// Longest first so "sk-ant-api03-" wins over "sk-".
var prefixes = func() []string {
	p := []string{
		"sk-ant-api03-", "sk-ant-admin01-", "sk-ant-", "sk-proj-", "sk-svcacct-", "sk-admin-",
		"sk-or-v1-", "sk-", "sk_live_", "sk_test_", "rk_live_", "rk_test_", "pk_live_", "pk_test_",
		"whsec_", "github_pat_", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "glpat-", "xoxb-", "xoxp-",
		"xoxa-", "xoxs-", "xoxe-", "xapp-", "AKIA", "ASIA", "AIza", "ya29.", "hf_", "gsk_", "xai-",
		"r8_", "npm_", "pypi-", "dckr_pat_", "dop_v1_", "doo_v1_", "lin_api_", "ntn_", "secret_",
		"shpat_", "shpss_", "shpca_", "shppa_", "SG.", "key-", "sk_", "phc_", "phx_", "pat", "eyJ",
		"AC", "SK", "fal_", "vercel_", "vc_", "cfut_", "re_", "tvly-", "pplx-", "csk-",
		// Mapbox public (pk.) and secret (sk.) tokens, and Sentry auth tokens: triage tells a
		// shippable public key from a secret one by this prefix, so Shape has to keep it.
		"pk.", "sk.", "sntrys_", "sntryu_",
	}
	sort.SliceStable(p, func(i, j int) bool { return len(p[i]) > len(p[j]) })
	return p
}()

// Shape is the display form of a secret: its constant prefix (if any), an ellipsis, and at
// most 4 trailing characters. It never shows more than 4 characters of the random part.
func Shape(raw string) string {
	if strings.HasPrefix(raw, "-----BEGIN") {
		return "-----BEGIN…KEY-----"
	}
	r := []rune(raw)
	p := ""
	for _, x := range prefixes {
		if strings.HasPrefix(raw, x) && utf8.RuneCountInString(x)+8 <= len(r) {
			p = x
			break
		}
	}
	rest := len(r) - utf8.RuneCountInString(p)
	tail := ""
	switch {
	case rest >= 20:
		tail = string(r[len(r)-4:])
	case rest >= 12:
		tail = string(r[len(r)-2:])
	}
	return p + "…" + tail
}

// Redact replaces every occurrence of raw in s with «shape».
func Redact(s, raw string) string {
	if raw == "" {
		return s
	}
	return strings.ReplaceAll(s, raw, "«"+Shape(raw)+"»")
}

// Context is the safe one-line context for a hit: raw replaced, any other token that looks
// like a secret masked (engines sometimes report a normalized raw that differs from the
// bytes on the line), control characters dropped, capped at 200 runes.
func Context(line, raw string) string {
	s := Scrub(Redact(line, raw))
	s = strings.Map(func(c rune) rune {
		if c == '\t' {
			return ' '
		}
		if c < 0x20 || c == 0x7f {
			return -1
		}
		return c
	}, s)
	if r := []rune(s); len(r) > 200 {
		s = string(r[:199]) + "…"
	}
	return s
}

// Scrub masks tokens of 20+ secret-alphabet characters that look random: entropy ≥ 3.5
// bits with a digit in it, or ≥ 4.3 without. Long camelCase identifiers reach ~3.9 but
// almost never carry digits; keys, hashes and base64 blobs almost always do.
func Scrub(s string) string {
	var b strings.Builder
	i := 0
	for i < len(s) {
		if !tokenByte(s[i]) {
			b.WriteByte(s[i])
			i++
			continue
		}
		j := i
		for j < len(s) && tokenByte(s[j]) {
			j++
		}
		if tok := s[i:j]; len(tok) >= 20 && looksRandom(tok) {
			b.WriteString("«…»")
		} else {
			b.WriteString(tok)
		}
		i = j
	}
	return b.String()
}

func looksRandom(tok string) bool {
	e := Entropy(tok)
	return e >= 4.3 || e >= 3.5 && strings.ContainsAny(tok, "0123456789")
}

func tokenByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
		c == '+' || c == '/' || c == '=' || c == '_' || c == '-' || c == '.'
}

// Entropy is Shannon entropy in bits per byte.
func Entropy(s string) float64 {
	if s == "" {
		return 0
	}
	var n [256]int
	for i := 0; i < len(s); i++ {
		n[s[i]]++
	}
	h, l := 0.0, float64(len(s))
	for _, c := range n {
		if c > 0 {
			p := float64(c) / l
			h -= p * math.Log2(p)
		}
	}
	return h
}
