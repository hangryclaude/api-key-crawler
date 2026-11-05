package pattern_test

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"
	"testing"

	"keyguard/internal/pattern"
	"keyguard/internal/pattern/rules"
)

// The linear matchers against Go's regexp on whole scans. The per-rule fuzz in package lin holds each
// matcher to its regex on made-up inputs; this holds the engine to itself on real files: the same
// directory is scanned three ways, and every finding must come out the same in all three, down to the
// byte offsets, the entropy and the tags.
//
//   - the default scanner, where a rule of kind Shape or Assign runs on its matcher;
//   - Options.Regexp, where every rule runs on regexp, which is what the engine did before M3;
//   - the default scanner with the matchers' budget set to nothing, so that every search gives up
//     and the regexp answers: the path a hostile file takes.

func fingerprints(t *testing.T, s *pattern.Scanner, dir string) ([]string, pattern.Stats) {
	t.Helper()
	var out []string
	st, err := s.ScanDir(context.Background(), dir, func(f pattern.Finding, data []byte) {
		out = append(out, fmt.Sprintf("%s\t%s\t%d\t%d\t%d\t%d\t%d\t%.6f\t%s", f.Rule.ID, f.Path, f.Line,
			f.Base+f.MatchStart, f.Base+f.MatchEnd, f.Base+f.Start, f.Base+f.End, f.Entropy, strings.Join(f.Tags, ",")))
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(out)
	return out, st
}

func sameScan(t *testing.T, name, dir string) {
	t.Helper()
	opt := pattern.Options{Paths: pattern.PathsNative, Threads: 4}
	fast := pattern.New(rules.All, rules.Global, opt)
	if n := fast.LinearRules(); n < 450 {
		t.Fatalf("%d rules run on the linear matcher, the table has more than 450", n)
	}
	want, _ := fingerprints(t, pattern.New(rules.All, rules.Global, pattern.Options{Paths: opt.Paths, Threads: opt.Threads, Regexp: true}), dir)
	got, _ := fingerprints(t, fast, dir)
	if !slices.Equal(want, got) {
		t.Errorf("%s: the matchers found %d, regexp %d; first differences: %v", name, len(got), len(want), firstDiff(want, got))
	}

	gaveUp := pattern.New(rules.All, rules.Global, opt)
	gaveUp.SetLinBudget(0, 0)
	got, st := fingerprints(t, gaveUp, dir)
	if !slices.Equal(want, got) {
		t.Errorf("%s: with every walk handed back to regexp, %d found, regexp alone %d; first differences: %v", name, len(got), len(want), firstDiff(want, got))
	}
	t.Logf("%s: %d findings the same three ways; %d searches handed back to regexp in the forced run", name, len(want), st.Fallbacks)
}

// firstDiff names the first findings that only one side has (coordinates, never a value).
func firstDiff(a, b []string) []string {
	in := func(l []string) map[string]bool {
		m := map[string]bool{}
		for _, s := range l {
			m[s] = true
		}
		return m
	}
	ma, mb := in(a), in(b)
	var out []string
	for _, s := range a {
		if !mb[s] && len(out) < 3 {
			out = append(out, "regexp only: "+s)
		}
	}
	for _, s := range b {
		if !ma[s] && len(out) < 6 {
			out = append(out, "matchers only: "+s)
		}
	}
	return out
}

func TestMatchersAndRegexpFindTheSameOnBenchCorpusA(t *testing.T) {
	for _, seed := range []uint64{1, 2} {
		wt, blobs := corpusA(t, seed)
		sameScan(t, fmt.Sprintf("A%d-worktree", seed), wt)
		sameScan(t, fmt.Sprintf("A%d-all-blobs", seed), blobs)
	}
}

func TestMatchersAndRegexpFindTheSameOnThePerfCorpus(t *testing.T) {
	sameScan(t, "perf", perfDir(t))
}
