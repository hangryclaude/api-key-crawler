package pattern

import (
	"math/rand/v2"
	"slices"
	"strings"
	"testing"

	"keyguard/internal/pattern/rules"
)

// naiveHits is the definition the automaton must equal: every occurrence of every pattern in the
// ASCII-lower-cased buffer, overlapping ones included.
func naiveHits(buf []byte, pats []string) []acHit {
	low := strings.ToLower(string(buf))
	var out []acHit
	for pi, p := range pats {
		for from := 0; from+len(p) <= len(low); {
			i := strings.Index(low[from:], p)
			if i < 0 {
				break
			}
			out = append(out, acHit{int32(from + i + len(p) - 1), int32(pi)})
			from += i + 1
		}
	}
	slices.SortFunc(out, func(a, b acHit) int {
		if a.end != b.end {
			return int(a.end) - int(b.end)
		}
		return int(a.pat) - int(b.pat)
	})
	return out
}

func sortedHits(h []acHit) []acHit {
	h = slices.Clone(h)
	slices.SortFunc(h, func(a, b acHit) int {
		if a.end != b.end {
			return int(a.end) - int(b.end)
		}
		return int(a.pat) - int(b.pat)
	})
	return h
}

// randomText draws from a small alphabet that includes both cases, so that patterns occur often
// and overlap.
func randomText(r *rand.Rand, n int, alphabet string) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[r.IntN(len(alphabet))]
	}
	return b
}

func TestAutomatonEqualsNaiveSearch(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	for round := 0; round < 40; round++ {
		var pats []string
		seen := map[string]bool{}
		for len(pats) < 5+r.IntN(40) {
			p := string(randomText(r, 1+r.IntN(7), "abcab_-.k"))
			if !seen[p] {
				seen[p] = true
				pats = append(pats, p)
			}
		}
		m := buildAutomaton(pats)
		for _, size := range []int{0, 1, 7, 100, lanesMin - 1, lanesMin, lanesMin + 3, 20000} {
			buf := randomText(r, size, "abcABC_-.kK x")
			want := naiveHits(buf, pats)
			for _, lanes := range []int{1, 4} {
				got := sortedHits(m.scanLanes(buf, nil, lanes))
				if !slices.Equal(got, want) {
					t.Fatalf("round %d size %d lanes %d: %d hits, want %d", round, size, lanes, len(got), len(want))
				}
			}
		}
	}
}

// The four lanes hand their hits over in order, which window.go relies on.
func TestFourLanesReportHitsInOrder(t *testing.T) {
	r := rand.New(rand.NewPCG(3, 4))
	m := buildAutomaton([]string{"ab", "abc", "ca", "b-c"})
	buf := randomText(r, 50000, "abcABC-")
	got := m.scanLanes(buf, nil, 4)
	if len(got) == 0 {
		t.Fatal("no hits in 50 kB of dense text")
	}
	if !slices.IsSortedFunc(got, func(a, b acHit) int { return int(a.end) - int(b.end) }) {
		t.Error("hits are not in the order their last byte appears")
	}
}

func TestAutomatonFoldsAsciiCaseOnly(t *testing.T) {
	m := buildAutomaton([]string{"key"})
	for _, s := range []string{"key", "KEY", "kEy", "xxKeYxx"} {
		if n := len(m.scan([]byte(s), nil)); n != 1 {
			t.Errorf("%q: %d hits, want 1", s, n)
		}
	}
	// U+212A is the Kelvin sign. Go's (?i) folds it to k; the prefilter must not, so the rule's own
	// regex stays the judge of what counts.
	if n := len(m.scan([]byte("Key"), nil)); n != 0 {
		t.Errorf("Kelvin sign matched the keyword: %d hits", n)
	}
}

// The real table's prefilter: every keyword is found, and a rule without a keyword is always awake.
func TestPrefilterOfTheTable(t *testing.T) {
	p := newPrefilter(rules.All)
	if len(p.pats) < 400 {
		t.Fatalf("%d distinct keywords for %d rules", len(p.pats), len(rules.All))
	}
	for pi, kw := range p.pats {
		hits := p.m.scan([]byte("zz "+strings.ToUpper(kw)+" zz"), nil)
		found := false
		for _, h := range hits {
			found = found || int(h.pat) == pi
		}
		if !found {
			t.Errorf("keyword %q is not found in its own text", kw)
		}
		if len(p.patRules[pi]) == 0 {
			t.Errorf("keyword %q wakes no rule", kw)
		}
	}
	var noKeyword []string
	for _, ri := range p.always {
		noKeyword = append(noKeyword, rules.All[ri].ID)
	}
	slices.Sort(noKeyword)
	if want := []string{"kg-discord-bot-token", "kg-fal-key"}; !slices.Equal(noKeyword, want) {
		t.Errorf("rules with no keyword = %v, want %v", noKeyword, want)
	}
}

func BenchmarkAutomaton(b *testing.B) {
	p := newPrefilter(rules.All)
	r := rand.New(rand.NewPCG(5, 6))
	buf := randomText(r, 1<<20, "abcdefghijklmnopqrstuvwxyz_ \n")
	for _, lanes := range []int{1, 4} {
		b.Run(map[int]string{1: "1lane", 4: "4lanes"}[lanes], func(b *testing.B) {
			b.SetBytes(int64(len(buf)))
			var hits []acHit
			for i := 0; i < b.N; i++ {
				hits = p.m.scanLanes(buf, hits[:0], lanes)
			}
		})
	}
}
