package bench

import (
	"strconv"
	"strings"

	"keyguard/internal/fp"
)

// Twin is an invalid twin (STEAL P0-26): a value with the look of a provider's format and one
// thing wrong with it, planted in the same file as a valid plant of that format. A scanner that
// reports it has a pattern that is too loose, and the valid plant beside it shows that the
// pattern is not simply too strict. All twins are negatives.
type Twin struct {
	Kind string // shape, floor or checksum
	Fake Fake
	// Neutral twins are planted under a variable name that carries no keyword, so that only the
	// provider's own pattern, and not a generic rule keyed on "key" or "token", can claim them.
	Neutral bool
	Why     string
	Tags    []string
}

// neutralNames are variable names no keyword rule fires on.
var neutralNames = []string{"BUILD_REF", "CACHE_ID", "TRACE_REF", "RELEASE_REF", "SNAPSHOT_REF", "ASSET_REF"}

// shorten returns parts with the last long random run cut by `by` characters.
func shorten(parts []part, by int) ([]part, bool) {
	out := append([]part(nil), parts...)
	for i := len(out) - 1; i >= 0; i-- {
		if out[i].set != "" && out[i].n > by+6 {
			out[i].n -= by
			return out, true
		}
	}
	return nil, false
}

// ruleFloor is the entropy gate a value has to clear to be accepted by one of a provider's rules:
// the lowest among them, and 0 when any of them has none. A valid fake needs 0.3 bits more than
// this, and a floor twin must fall 0.3 bits under it so that every rule refuses it; with a rule
// that has no gate there is no floor to fall under.
func ruleFloor(rules []string) float64 {
	if len(rules) == 0 {
		return 0
	}
	floor := -1.0
	for _, ref := range rules {
		c, err := lookupRule(ref)
		if err != nil {
			return 0
		}
		if floor < 0 || c.def.Entropy < floor {
			floor = c.def.Entropy
		}
	}
	return floor
}

// lowEntropy builds a value of the format whose entropy falls well under floor: every random
// run draws from a few symbols of its alphabet, so it still matches the pattern's character
// classes. It fails for a format too short to be made that plain.
func lowEntropy(g *Gen, parts []part, floor float64) (string, bool) {
	for _, symbols := range []int{3, 2} {
		low := make([]part, len(parts))
		for i, p := range parts {
			low[i] = p
			if p.set != "" {
				low[i].set = strings.Map(func(r rune) rune {
					if r == '-' || r == '_' {
						return -1
					}
					return r
				}, p.set)[:symbols]
			}
		}
		s := g.build(low...)
		if fp.Entropy(s)+0.3 <= floor {
			return s, true
		}
	}
	return "", false
}

// flatTwins are the near-misses of a format made of a prefix and random runs.
func flatTwins(g *Gen, rules []string, minEntropy float64, parts []part) []Twin {
	var out []Twin
	if short, ok := shorten(parts, 2); ok {
		s := g.token(minEntropy, short...)
		out = append(out, Twin{Kind: "shape", Neutral: true, Fake: Fake{Value: s, Raw: s}, Why: "two characters short"})
	}
	if floor := ruleFloor(rules); floor > 0 {
		if s, ok := lowEntropy(g, parts, floor); ok {
			out = append(out, Twin{Kind: "floor", Fake: Fake{Value: s, Raw: s}, Tags: []string{"floor-rejected"},
				Why: "right shape, entropy under the rule's floor of " + fmtFloor(floor)})
		}
	}
	return out
}

func fmtFloor(f float64) string { return strconv.FormatFloat(f, 'f', -1, 64) }

// crcTwins is the near-miss of a token that ends in GitHub's checksum: the entropy is right, the
// shape is right, and the last character is not what the checksum of the rest says. A regex cannot
// tell; GitHub's own scanner can (docs/STEAL.md W-08).
func crcTwins(prefix string) func(g *Gen) []Twin {
	return func(g *Gen) []Twin {
		good := prefix + withChecksum(g.token(4.0, rnd(alnum, 30)))
		last := good[len(good)-1]
		bad := good[:len(good)-1] + string(alnum[(strings.IndexByte(alnum, last)+1)%len(alnum)])
		return []Twin{{Kind: "checksum", Fake: Fake{Value: bad, Raw: bad}, Why: "the CRC32 suffix does not match the token"}}
	}
}
