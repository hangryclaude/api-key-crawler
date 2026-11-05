package pattern_test

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"keyguard/internal/pattern"
	"keyguard/internal/pattern/rules"
	"keyguard/internal/pattern/rules/fidelity"
	"keyguard/internal/testkit"
)

func exampleCache(t *testing.T) string {
	t.Helper()
	corpus := os.Getenv("KEYGUARD_RULECORPUS")
	if corpus == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			t.Fatal(err)
		}
		corpus = filepath.Join(home, ".cache", "keyguard-dev", "rulecorpus")
	}
	if _, err := os.Stat(filepath.Join(corpus, "index.json")); err != nil {
		if os.Getenv(testkit.RequireEnv) == "1" {
			t.Fatalf("the example cache is missing (%s=1, so this is a failure, not a skip): run bun scripts/rulegen/extract.mjs", testkit.RequireEnv)
		}
		t.Skip("no example cache: run bun scripts/rulegen/extract.mjs to make one")
	}
	return corpus
}

// The windows against the rules' own examples. Betterleaks tests each rule with strings that must fire it and
// strings that must not (8,398 of them, in the cache the rules package reads). Here each rule is scanned alone
// over each of its examples, and must report exactly the secrets that the rule evaluated over the whole text
// does (internal/pattern/rules/fidelity, which holds the table to betterleaks on these same examples). Alone,
// because another rule's finding would silence it; without composite parts, which the evaluation ignores.
// This is the test of anchor.go on real text: a window that is a byte too short loses an example here.
func TestEveryRuleFindsWhatItsExamplesSay(t *testing.T) {
	corpus := exampleCache(t)
	examples, rulesChecked, bad := 0, 0, 0
	for i := range rules.All {
		r := &rules.All[i]
		if r.Re == "" || r.ComponentOnly || len(r.Needs) > 0 {
			continue
		}
		set, err := fidelity.Load(corpus, r.ID)
		if err != nil {
			t.Fatal(err)
		}
		if set == nil {
			continue
		}
		rulesChecked++
		s := pattern.New([]rules.Rule{*r}, rules.Global, pattern.Options{Paths: pattern.PathsUpstream})
		for _, ex := range append(slices.Clone(set.Positives), set.Negatives...) {
			examples++
			want := fidelity.Findings(r, rules.Global, ex.Text, ex.Path)
			var got []string
			data := []byte(ex.Text)
			for _, f := range s.ScanBytes(ex.Path, data) {
				got = append(got, string(f.Secret(data)))
			}
			slices.Sort(want)
			slices.Sort(got)
			if !slices.Equal(want, got) {
				bad++
				if bad <= 10 {
					// only counts and a hash of the text are printed: an example is a made-up secret in a test line
					t.Errorf("%s: %d findings over the whole text, %d from windows (example %s)", r.ID, len(want), len(got), shortHash(ex.Path+"\x00"+ex.Text))
				}
			}
		}
	}
	t.Logf("%d rules, %d examples, %d disagreements", rulesChecked, examples, bad)
	if bad > 0 {
		t.Errorf("%d examples on which a rule alone does not report what it reports over the whole text", bad)
	}
}

func shortHash(s string) string {
	var h uint64 = 14695981039346656037
	for i := 0; i < len(s); i++ {
		h = (h ^ uint64(s[i])) * 1099511628211
	}
	return fmt.Sprintf("%08x", h>>32)
}
