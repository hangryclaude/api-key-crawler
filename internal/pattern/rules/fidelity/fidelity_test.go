package fidelity

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"keyguard/internal/pattern/rules"
)

// Nothing here is a key: the rules are made up and the values are built from parts.
func tokenRule() rules.Rule {
	return rules.Rule{
		ID: "demo-token", Keywords: []string{"demo"}, Re: `(?i)demo[_-]?token\s*=\s*"?([a-z0-9]{20})"?`,
		Filter: rules.Filter{Entropy: rules.Floor{Min: 3.0, Strict: true}},
		Src:    rules.Src{Lineage: "own", Licence: "own"},
	}
}

func value(n int) string { return strings.Repeat("a1b2c3d4e5", n)[:20] }

func cache(t *testing.T, s Set) string {
	t.Helper()
	dir := t.TempDir()
	b, _ := json.Marshal(s)
	if err := os.WriteFile(filepath.Join(dir, s.Rule+".json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func goodSet() Set {
	return Set{
		Rule:   "demo-token",
		Commit: "c",
		Positives: []Example{
			{Text: `DEMO_TOKEN = "` + value(2) + `"`, Secret: value(2)},
			{Text: "demo-token=" + value(2)},
		},
		Negatives: []Example{
			{Text: `DEMO_TOKEN = "short"`},
			{Text: `other = "` + value(2) + `"`},
			{Text: `demo_token = "` + strings.Repeat("a", 20) + `"`}, // a run of one letter: no entropy
		},
	}
}

func TestFindingsFollowBetterleaksRules(t *testing.T) {
	r := tokenRule()
	global := rules.Filter{}
	cases := []struct {
		name, text, path string
		want             int
	}{
		{"fires", `demo_token = "` + value(2) + `"`, "", 1},
		{"keyword gate is case blind", `DEMO_TOKEN="` + value(2) + `"`, "", 1},
		{"no keyword, no look", `tkn = "` + value(2) + `"`, "", 0},
		{"entropy gate", `demo_token = "` + strings.Repeat("a", 20) + `"`, "", 0},
		{"two matches", "demo_token=" + value(2) + "\ndemo-token=" + value(3), "", 2},
	}
	for _, c := range cases {
		if got := Findings(&r, global, c.text, c.path); len(got) != c.want {
			t.Errorf("%s: %d findings, want %d", c.name, len(got), c.want)
		}
	}
	if got := Findings(&r, global, `demo_token = "`+value(2)+`"`, ""); len(got) != 1 || got[0] != value(2) {
		t.Errorf("the secret is the group, not the match: %q", got)
	}
	// the global filter, and the path gates
	if got := Findings(&r, rules.Filter{DropWords: []string{"a1b2c3d4e5"}}, "demo_token="+value(2), ""); len(got) != 0 {
		t.Error("the global word filter did not drop the finding")
	}
	if got := Findings(&r, rules.Filter{DropPath: []string{`^vendor/`}}, "demo_token="+value(2), "vendor/x.txt"); len(got) != 0 {
		t.Error("the global path filter did not skip the file")
	}
	gated := tokenRule()
	gated.Path = `\.env$`
	if len(Findings(&gated, global, "demo_token="+value(2), "a.env")) != 1 || len(Findings(&gated, global, "demo_token="+value(2), "a.txt")) != 0 {
		t.Error("the rule's path gate does not gate")
	}
	fileOnly := rules.Rule{ID: "f", Path: `\.p12$`}
	if len(Findings(&fileOnly, global, "", "key.p12")) != 1 || len(Findings(&fileOnly, global, "", "key.txt")) != 0 {
		t.Error("a rule about a file name does not report the file")
	}
	req := tokenRule()
	req.Filter.Require = [][]string{{`^a1`}}
	if len(Findings(&req, global, "demo_token="+value(2), "")) != 1 || len(Findings(&req, global, "demo_token="+strings.Repeat("z9y8x7w6v5", 2), "")) != 0 {
		t.Error("a required pattern is not required")
	}
}

func TestEntropyGateDistinguishesBelowFromAt(t *testing.T) {
	// "ab" repeated has exactly 1 bit per byte
	two := strings.Repeat("ab", 10)
	r := rules.Rule{ID: "e", Re: `x=([ab]+)`}
	r.Filter.Entropy = rules.Floor{Min: 1, Strict: true} // upstream "entropy <= 1 discards"
	if len(Findings(&r, rules.Filter{}, "x="+two, "")) != 0 {
		t.Error("a value exactly on a strict floor was kept")
	}
	r.Filter.Entropy = rules.Floor{Min: 1} // upstream "entropy < 1 discards"
	if len(Findings(&r, rules.Filter{}, "x="+two, "")) != 1 {
		t.Error("a value exactly on a non-strict floor was dropped")
	}
}

func TestBuildAcceptsARuleThatMeetsItsExamples(t *testing.T) {
	r := tokenRule()
	g, err := Build(cache(t, goodSet()), []rules.Rule{r}, rules.Filter{}, "c")
	if err != nil {
		t.Fatal(err)
	}
	if e := g.Rules["demo-token"]; e.Positives != 2 || e.Negatives != 3 || len(e.Digest) != 16 {
		t.Errorf("entry %+v", e)
	}
	if g.Source != "betterleaks@c" || g.Examples != 5 {
		t.Errorf("golden %+v", g)
	}
}

func TestBuildNamesARuleThatDisagreesWithItsExamples(t *testing.T) {
	// A rewrite that loses the keyword gate fires on a false positive.
	loose := tokenRule()
	loose.Keywords = nil
	loose.Re = `([a-z0-9]{20})`
	_, err := Build(cache(t, goodSet()), []rules.Rule{loose}, rules.Filter{}, "c")
	if err == nil || !strings.Contains(err.Error(), "demo-token") || !strings.Contains(err.Error(), "false positives fired") {
		t.Errorf("a rule that fires on its false positives was accepted: %v", err)
	}
	// A rewrite that is stricter than upstream misses a true positive.
	strict := tokenRule()
	strict.Re = `demo_token\s*=\s*"([a-z0-9]{20})"`
	_, err = Build(cache(t, goodSet()), []rules.Rule{strict}, rules.Filter{}, "c")
	if err == nil || !strings.Contains(err.Error(), "true positives did not fire") {
		t.Errorf("a rule that misses its true positives was accepted: %v", err)
	}
}

func TestDigestChangesWithBehaviourAndNotWithOrder(t *testing.T) {
	r := tokenRule()
	set := goodSet()
	base := Evaluate(&r, rules.Filter{}, &set)

	shuffled := goodSet()
	shuffled.Positives[0], shuffled.Positives[1] = shuffled.Positives[1], shuffled.Positives[0]
	shuffled.Negatives[0], shuffled.Negatives[2] = shuffled.Negatives[2], shuffled.Negatives[0]
	if got := Evaluate(&r, rules.Filter{}, &shuffled); got.Digest != base.Digest {
		t.Error("the digest depends on the order the examples came in")
	}

	// a rewrite that still passes but reports another extent of the secret changes the digest
	wider := tokenRule()
	wider.Re = `(?i)(demo[_-]?token\s*=\s*"?[a-z0-9]{20})"?`
	if got := Evaluate(&wider, rules.Filter{}, &set); got.Digest == base.Digest {
		t.Error("the digest did not notice the rule reporting a different secret")
	}
	if got := Evaluate(&r, rules.Filter{}, &set); got.HintMisses != 0 {
		t.Errorf("%d hint misses for a rule that reports the secret it was built around", got.HintMisses)
	}
	if got := Evaluate(&wider, rules.Filter{}, &set); got.HintMisses == 0 {
		t.Error("a rule reporting another extent was not counted as missing the hint")
	}
}

func TestResidualRulesAreHeldToTheirTruePositivesOnly(t *testing.T) {
	r := tokenRule()
	r.Filter.Residual = 1 // upstream drops more than the table carries
	loose := goodSet()
	loose.Negatives = append(loose.Negatives, Example{Text: "demo_token=" + value(3)}) // upstream rejects it by what the table cannot see
	res := Evaluate(&r, rules.Filter{}, &loose)
	if len(res.Fired) != 0 || res.Unjudged != 1 {
		t.Errorf("a residual rule was judged on a false positive it cannot see: %+v", res)
	}
	plain := tokenRule()
	res = Evaluate(&plain, rules.Filter{}, &loose)
	if len(res.Fired) != 1 {
		t.Errorf("a plain rule was not judged on it: %+v", res)
	}
}

func TestBuildListsRulesWithoutExamples(t *testing.T) {
	r := tokenRule()
	other := rules.Rule{ID: "no-examples", Re: "x", Src: rules.Src{Lineage: "own", Licence: "own"}}
	g, err := Build(cache(t, goodSet()), []rules.Rule{r, other}, rules.Filter{}, "c")
	if err != nil {
		t.Fatal(err)
	}
	if len(g.WithoutExamples) != 1 || g.WithoutExamples[0] != "no-examples" {
		t.Errorf("rules without examples: %v", g.WithoutExamples)
	}
}

func TestBuildRefusesACacheFromAnotherCommit(t *testing.T) {
	r := tokenRule()
	r.Src = rules.Src{Lineage: "betterleaks", Licence: "MIT"}
	if _, err := Build(cache(t, goodSet()), []rules.Rule{r}, rules.Filter{}, "another"); err == nil || !strings.Contains(err.Error(), "extracted at") {
		t.Errorf("a cache from another commit was used: %v", err)
	}
}
