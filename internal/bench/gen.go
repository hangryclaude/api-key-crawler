package bench

import (
	"hash/crc32"
	"hash/fnv"
	"math/rand/v2"
	"strings"

	"keyguard/internal/fp"
)

// Alphabets the provider formats draw from. Fakes are built from a documented prefix plus
// random characters of the right alphabet, never from a stored secret-shaped literal.
const (
	digits   = "0123456789"
	lower    = "abcdefghijklmnopqrstuvwxyz"
	upper    = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	letters  = lower + upper
	alnum    = digits + letters
	urlsafe  = alnum + "_-"
	hexLower = "0123456789abcdef"
	lowerNum = lower + digits
	upperNum = upper + digits
	b32      = upper + "234567" // AWS key ids are base32
	b58      = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	b64std   = alnum + "+/"
)

// newRand derives an independent, repeatable stream per label, so adding a plant never
// reshuffles the values of the others.
func newRand(seed uint64, label string) *rand.Rand {
	h := fnv.New64a()
	h.Write([]byte(label))
	return rand.New(rand.NewPCG(seed, h.Sum64()))
}

// Gen is the random source a provider builds one fake from.
type Gen struct {
	r *rand.Rand
}

// part is either a literal piece of a format or n random characters from set.
type part struct {
	lit string
	set string
	n   int
}

func lit(s string) part          { return part{lit: s} }
func rnd(set string, n int) part { return part{set: set, n: n} }

func (g *Gen) str(set string, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = set[g.r.IntN(len(set))]
	}
	return string(b)
}

func (g *Gen) build(parts ...part) string {
	var sb strings.Builder
	for i, p := range parts {
		switch {
		case p.set == "":
			sb.WriteString(p.lit)
		case i == len(parts)-1 && strings.Contains(p.set, "-"):
			// Rules anchor on \b, which a trailing '-' can not satisfy before a quote.
			sb.WriteString(g.str(p.set, p.n-1))
			sb.WriteString(g.str(alnum, 1))
		default:
			sb.WriteString(g.str(p.set, p.n))
		}
	}
	return sb.String()
}

// token builds a fake whose Shannon entropy clears the engines' own filters (they drop
// low-entropy matches as placeholders). Resampling is deterministic: it consumes the same
// stream every run.
func (g *Gen) token(minEntropy float64, parts ...part) string {
	// 20,000 draws: a hex string of 32 characters reaches 3.8 bits about one time in sixteen
	// (measured by simulation), and a format with a tighter floor needs far more tries than 200
	for i := 0; i < 20000; i++ {
		s := g.build(parts...)
		if fp.Entropy(s) > minEntropy {
			return s
		}
	}
	panic("bench: format cannot reach entropy floor")
}

func (g *Gen) pick(xs []string) string { return xs[g.r.IntN(len(xs))] }

func (g *Gen) intn(n int) int { return g.r.IntN(n) }

// base62 encodes v with the alphabet GitHub uses for its token checksums.
func base62(v uint32, width int) string {
	const a = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	b := make([]byte, 0, 6)
	for v > 0 {
		b = append(b, a[v%62])
		v /= 62
	}
	for len(b) < width {
		b = append(b, '0')
	}
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return string(b)
}

// withChecksum appends GitHub's 6-character CRC32 checksum, which npm adopted unchanged, so
// the fake survives engines that validate it.
func withChecksum(entropy string) string {
	return entropy + base62(crc32.ChecksumIEEE([]byte(entropy)), 6)
}

// luhn returns the check digit that makes digits+check pass the Luhn test.
func luhn(digits string) byte {
	sum := 0
	double := true
	for i := len(digits) - 1; i >= 0; i-- {
		d := int(digits[i] - '0')
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return byte('0' + (10-sum%10)%10)
}
