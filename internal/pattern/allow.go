package pattern

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"math"
	"regexp"
	"slices"
	"unicode/utf8"

	"keyguard/internal/pattern/rules"
)

// The built-in allow lists. Nothing a scanned tree holds can silence a scan, so these are all there
// is: the filters the rule data carries, which are the upstream rules' own allow lists baked in when
// the table was generated, and the digests of documentation keys.
//
// A filter drops a finding after its regex has matched. It is evaluated on the secret (the rule's
// group, or the whole match) and, for the path lists, on the file path. The semantics are the
// reference engine's, and internal/pattern/rules/fidelity holds them to its examples:
//
//   - an entropy floor drops a secret at or under it (Strict) or under it;
//   - a secret that matches any DropRegex, or contains any DropWords word, or whose SHA-256 is a
//     DropSHA256 digest, is dropped;
//   - a secret that fails to match one pattern of every Require group is dropped.
//
// What the table does not carry (Filter.Residual, Filter.TokenRatio) is not evaluated here either.
// ENGINE.md says which rules that touches and what the differential shows for them.

// filter is a rules.Filter with its patterns compiled.
type filter struct {
	f        *rules.Filter
	drop     []*regexp.Regexp
	dropPath []*regexp.Regexp
	require  [][]*regexp.Regexp
	words    [][]byte
	sha      map[[sha256.Size]byte]struct{}
}

func compileAll(patterns []string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, len(patterns))
	for i, p := range patterns {
		out[i] = regexp.MustCompile(p)
	}
	return out
}

func newFilter(f *rules.Filter) *filter {
	c := &filter{f: f, drop: compileAll(f.DropRegex), dropPath: compileAll(f.DropPath)}
	for _, g := range f.Require {
		c.require = append(c.require, compileAll(g))
	}
	for _, w := range f.DropWords {
		c.words = append(c.words, []byte(w))
	}
	if len(f.DropSHA256) > 0 {
		c.sha = map[[sha256.Size]byte]struct{}{}
		for _, h := range f.DropSHA256 {
			var d [sha256.Size]byte
			if b, err := hex.DecodeString(h); err == nil && len(b) == len(d) {
				copy(d[:], b)
				c.sha[d] = struct{}{}
			}
		}
	}
	return c
}

// dropsPath says whether the path is on the filter's list of paths to leave alone.
func (c *filter) dropsPath(path string) bool {
	for _, re := range c.dropPath {
		if re.MatchString(path) {
			return true
		}
	}
	return false
}

// drops says whether the filter discards a finding with this secret.
func (c *filter) drops(secret []byte, entropy float64) bool {
	if min := c.f.Entropy.Min; min != 0 {
		if (c.f.Entropy.Strict && entropy <= min) || (!c.f.Entropy.Strict && entropy < min) {
			return true
		}
	}
	for _, re := range c.drop {
		if re.Match(secret) {
			return true
		}
	}
	for _, w := range c.words {
		if bytes.Contains(secret, w) {
			return true
		}
	}
	if len(c.sha) > 0 {
		if _, ok := c.sha[sha256.Sum256(secret)]; ok {
			return true
		}
	}
	for _, group := range c.require {
		ok := false
		for _, re := range group {
			if re.Match(secret) {
				ok = true
				break
			}
		}
		if !ok {
			return true
		}
	}
	return false
}

// floorsApply says whether any part of the filter needs the secret's entropy, so a rule with no
// floor never pays for it.
func (c *filter) needsEntropy() bool { return c.f.Entropy.Min != 0 }

// shannon is the entropy the reference engine's floors are written in: bits per character,
// counted over characters (runes), with the sum divided by the length in bytes. The two agree on
// ASCII, which is what a key is made of; they differ on other text, and the floors were tuned
// against the reference's number, so this is its number. The counts are summed in a fixed order, so
// a value on the line is on the same side of it every time.
func shannon(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	inv := 1.0 / float64(len(b))
	var counts [256]int
	ascii := true
	for _, c := range b {
		counts[c]++
		ascii = ascii && c < utf8.RuneSelf
	}
	h := 0.0
	if ascii {
		for _, n := range counts[:utf8.RuneSelf] {
			if n > 0 {
				f := float64(n) * inv
				h -= f * math.Log2(f)
			}
		}
		return h
	}
	// Other text: count whole runes. A byte that is not valid UTF-8 is one replacement character,
	// as it is when the reference ranges over the string.
	runes := map[rune]int{}
	for i := 0; i < len(b); {
		r, w := utf8.DecodeRune(b[i:])
		runes[r]++
		i += w
	}
	keys := make([]rune, 0, len(runes))
	for r := range runes {
		keys = append(keys, r)
	}
	slices.Sort(keys)
	for _, r := range keys {
		f := float64(runes[r]) * inv
		h -= f * math.Log2(f)
	}
	return h
}
