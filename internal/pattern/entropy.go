package pattern

import (
	"math/rand/v2"
	"slices"
)

// An entropy floor is a guess about how random a real key is. The upstream floors are flat numbers
// written one rule at a time (3.5 for most), and a flat number does not know how long the value is
// or what it is made of: a random 32-character hex string, which is what many vendors issue, has an
// entropy that falls under 3.5 often, because 16 symbols cannot go past 4 bits and 32 characters rarely
// reach 3.7. RandomFloor measures that instead of guessing it.
//
// It draws strings of length n uniformly from an alphabet, takes the entropy of each, and returns the
// value that a fraction q of them fall under. A floor at that value rejects, by construction, a fraction q of
// the keys the rule is meant to find and as many lookalikes as have less variety than a key does.
// The draw is seeded, so the number is a function of its arguments, and a table of them can be committed
// and checked.

// RandomFloor is the q-quantile of the entropy of n random characters of alphabet, over trials draws.
func RandomFloor(alphabet string, n int, q float64, trials int, seed uint64) float64 {
	if n <= 0 || alphabet == "" || trials <= 0 {
		return 0
	}
	r := rand.New(rand.NewPCG(seed, seed^0xa076_1d64_78bd_642f))
	buf := make([]byte, n)
	es := make([]float64, trials)
	for i := range es {
		for j := range buf {
			buf[j] = alphabet[r.IntN(len(alphabet))]
		}
		es[i] = shannon(buf)
	}
	slices.Sort(es)
	return es[min(int(q*float64(trials)), trials-1)]
}

// RejectRate is the fraction of n random characters of alphabet whose entropy is under floor.
func RejectRate(alphabet string, n int, floor float64, trials int, seed uint64) float64 {
	if n <= 0 || alphabet == "" || trials <= 0 {
		return 0
	}
	r := rand.New(rand.NewPCG(seed, seed^0xa076_1d64_78bd_642f))
	buf := make([]byte, n)
	under := 0
	for i := 0; i < trials; i++ {
		for j := range buf {
			buf[j] = alphabet[r.IntN(len(alphabet))]
		}
		if shannon(buf) < floor {
			under++
		}
	}
	return float64(under) / float64(trials)
}
