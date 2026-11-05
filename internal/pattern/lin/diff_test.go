package lin_test

import (
	"fmt"
	"hash/fnv"
	"os"
	"regexp"
	"regexp/syntax"
	"slices"
	"strconv"
	"sync/atomic"
	"testing"

	"keyguard/internal/pattern/lin"
	"keyguard/internal/pattern/rules"
)

// The per-rule differential fuzz: for every rule of the table that the matcher takes, the matcher and Go's
// regexp are given the same inputs and must return the same thing, the same matches with the same groups.
// The inputs are sampled from the rule's own syntax tree and then changed (sampler_test.go), so the
// test holds no secret-shaped literal and still reaches what each rule looks for.

// fuzzN is the number of inputs per rule: the gate asks for 100,000. KEYGUARD_LINFUZZ_N sets another
// number for a quick loop, and -short asks for 2,000.
func fuzzN() int {
	if v := os.Getenv("KEYGUARD_LINFUZZ_N"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			panic("KEYGUARD_LINFUZZ_N is not a positive number")
		}
		return n
	}
	if testing.Short() {
		return 2000
	}
	return 100000
}

func seedFor(id string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(id))
	if v := os.Getenv("KEYGUARD_LINFUZZ_SEED"); v != "" {
		h.Write([]byte(v))
	}
	return h.Sum64()
}

func flat(re *regexp.Regexp, b []byte) []int {
	var out []int
	for _, m := range re.FindAllSubmatchIndex(b, -1) {
		out = append(out, m...)
	}
	return out
}

func shortHash(b []byte) string {
	h := fnv.New32a()
	h.Write(b)
	return fmt.Sprintf("%08x", h.Sum32())
}

var (
	totalInputs, totalMatching, totalGaveUp, totalRules atomic.Int64
)

func TestEveryRuleMatchesLikeItsRegexp(t *testing.T) {
	n := fuzzN()
	for i := range rules.All {
		r := &rules.All[i]
		if r.Re == "" {
			continue
		}
		t.Run(r.ID, func(t *testing.T) {
			t.Parallel()
			ast, err := syntax.Parse(r.Re, syntax.Perl)
			if err != nil {
				t.Fatal(err)
			}
			p, err := lin.Compile(r.Re)
			if err != nil {
				if r.Kind != rules.Regex {
					t.Errorf("the table says kind %d, but the matcher refuses the rule: %v", r.Kind, err)
				}
				t.Skipf("runs as a regexp: %v", err)
			}
			if r.Kind == rules.Regex {
				t.Errorf("the matcher takes this rule, and the table says it is a plain regexp")
			}
			re := regexp.MustCompile(r.Re)
			s := newSampler(seedFor(r.ID), ast)
			var buf []int
			matching, gaveUp, bad := 0, 0, 0
			stats := os.Getenv("KEYGUARD_LINFUZZ_STATS") == "1"
			var worst, sum float64
			for k := 0; k < n; k++ {
				in := s.input(ast)
				want := flat(re, in)
				if stats {
					r := float64(p.Steps(in)) / float64(len(in)+1)
					worst, sum = max(worst, r), sum+r
				}
				var ok bool
				buf, ok = p.FindAll(in, buf[:0])
				if !ok {
					gaveUp++
					continue
				}
				if len(want) > 0 {
					matching++
				}
				if !slices.Equal(want, buf) {
					bad++
					if bad <= 3 {
						// An input is made up from the rule, but it is shaped like what the rule is for: the log
						// holds its hash and the offsets, and the input itself only when asked.
						t.Errorf("input %d (%d bytes, %s): the matcher found %v, regexp %v", k, len(in), shortHash(in), buf, want)
						if os.Getenv("KEYGUARD_LINFUZZ_DUMP") == "1" {
							t.Logf("%q", in)
						}
					}
				}
			}
			if stats {
				t.Logf("STEPS %s mean %.1f worst %.1f per byte", r.ID, sum/float64(n), worst)
			}
			totalInputs.Add(int64(n))
			totalMatching.Add(int64(matching))
			totalGaveUp.Add(int64(gaveUp))
			totalRules.Add(1)
			if bad > 0 {
				t.Errorf("%d of %d inputs differ", bad, n)
			}
			// Running out of budget is not a wrong answer (the regexp answers then), but a rule that does it
			// often is a rule the matcher is the wrong tool for. The inputs are the hardest kind: dense with
			// the rule's own words, which no code is, so a few rules built on long lazy runs do it on
			// a few per cent of them; they are listed by the count below, and the perf corpus has one in
			// 62,000 searches.
			if gaveUp*10 > n {
				t.Errorf("the matcher ran out of budget on %d of %d inputs", gaveUp, n)
			}
			// A rule the sampler cannot reach is not tested at all.
			if floor := n / 50; matching < floor {
				t.Errorf("only %d of %d inputs have a match: the sampler does not reach this rule", matching, n)
			}
		})
	}
	t.Cleanup(func() {
		t.Logf("%d rules, %d inputs, %d with a match, %d where the matcher gave up",
			totalRules.Load(), totalInputs.Load(), totalMatching.Load(), totalGaveUp.Load())
	})
}
