package bench

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"keyguard/internal/core"
	"keyguard/internal/fp"
)

// setMatcher is a known matcher over a few exact values.
type setMatcher struct {
	kr   *fp.Keyring
	vals map[string]string // raw -> name
}

func (m *setMatcher) Len() int { return len(m.vals) }
func (m *setMatcher) Match(data []byte) []core.KnownMatch {
	var out []core.KnownMatch
	for raw, name := range m.vals {
		for off := 0; ; {
			i := bytes.Index(data[off:], []byte(raw))
			if i < 0 {
				break
			}
			out = append(out, core.KnownMatch{EntryID: fp.ID(m.kr.FP(raw)), Name: name, Variant: "raw", Offset: off + i, Len: len(raw), FP: m.kr.FP(raw), Shape: fp.Shape(raw)})
			off += i + len(raw)
		}
	}
	return out
}

// miniRepo makes a repo with the given files in one commit, outside any work tree the test
// does not own, and returns its path.
func miniRepo(t *testing.T, files map[string]string) string {
	t.Helper()
	repo := t.TempDir()
	if _, err := git(repo, nil, "init", "-q", "-b", "main"); err != nil {
		t.Fatal(err)
	}
	for name, body := range files {
		p := filepath.Join(repo, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, args := range [][]string{{"add", "-A"}, {"-c", "user.name=t", "-c", "user.email=t@bench.invalid", "commit", "-q", "-m", "files"}} {
		if _, err := git(repo, nil, args...); err != nil {
			t.Fatal(err)
		}
	}
	return repo
}

func mirrorNamed(half string) string {
	for i := 0; ; i++ {
		if n := fmt.Sprintf("owner/mirror-%d", i); Half(n) == half {
			return n
		}
	}
}

// Corpus B by hand: four leaked keys, two engines, one mirror in each half. Everything the
// scorer should say can be counted on the fingers.
func TestOracleCountsWhatEachEngineFindsOfTheLeakedKeys(t *testing.T) {
	g := &Gen{r: newRand(21, "oracle")}
	s1 := g.token(4.0, lit("ghp_"), rnd(alnum, 36))
	s2 := g.token(4.5, lit("sk-ant-api03-"), rnd(urlsafe, 93), lit("AA"))
	s3 := g.token(4.2, lit("AIza"), rnd(urlsafe, 35))
	s4 := g.token(4.2, lit("AIza"), rnd(urlsafe, 35))
	files := map[string]string{
		"a.env":   "GITHUB_TOKEN=" + s1 + "\n",
		"b.py":    "x = 1\nANTHROPIC_API_KEY = '" + s2 + "'\n",
		"c.json":  "{\n  \"GOOGLE_API_KEY\": \"" + s3 + "\"\n}\n",
		"d/e.txt": "note\nGOOGLE_API_KEY=" + s4 + "\n",
	}
	repo := miniRepo(t, files)
	kr := KeyringFor(9)
	known := &setMatcher{kr: kr, vals: map[string]string{s1: "GITHUB_TOKEN", s2: "ANTHROPIC_API_KEY", s3: "GOOGLE_API_KEY", s4: "GOOGLE_API_KEY"}}
	tune, held := mirrorNamed(HalfTune), mirrorNamed(HalfHeldOut)
	mirrors := []OracleMirror{{tune, repo}, {held, repo}}

	// A reports s1 by fingerprint and s2 under another fingerprint on its line (a whole assignment);
	// B reports s1 only. Nobody reports s3 or s4.
	a := &fakeEngine{name: "A", avail: true, hits: []core.Hit{
		lenHit("A", "github", kr.FP(s1), "a.env", 1, len(s1)),
		lenHit("A", "anthropic", "other-fp", "b.py", 2, len(s2)+25),
	}}
	b := &fakeEngine{name: "B", avail: true, hits: []core.Hit{lenHit("B", "github", kr.FP(s1), "a.env", 1, len(s1))}}
	c := &fakeEngine{name: "C", avail: false}

	res, err := ScoreOracle(context.Background(), []core.Engine{a, b, c}, known, mirrors, OracleOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Mirrors != 2 || res.Secrets != 4 {
		t.Fatalf("%d mirrors, %d distinct secrets", res.Mirrors, res.Secrets)
	}
	ea, eb := res.Engines[0], res.Engines[1]
	// each mirror holds all four, so each half has four units and the engines are scored in both
	if ea.Secrets != 8 || ea.Found != 4 || ea.Contained != 2 || !near(ea.Recall, 0.5) {
		t.Errorf("A: %+v", ea)
	}
	if eb.Secrets != 8 || eb.Found != 2 || eb.Contained != 0 || !near(eb.Recall, 0.25) {
		t.Errorf("B: %+v", eb)
	}
	if h := ea.ByHalf[HalfTune]; h.Secrets != 4 || h.Found != 2 || !near(h.Recall, 0.5) {
		t.Errorf("A tune half: %+v", *h)
	}
	if res.Engines[2].Skipped == "" {
		t.Error("the engine that is not installed was scored")
	}
	if !near(res.Union.Recall, 0.5) || res.Union.Secrets != 8 {
		t.Errorf("union: %+v", res.Union)
	}
	// s3 and s4 are missed by everything: listed once, in the tune half; the held-out copies are only counted
	if len(res.Misses) != 2 || res.HeldOutMisses != 2 {
		t.Fatalf("%d listed misses, %d held-out misses", len(res.Misses), res.HeldOutMisses)
	}
	for _, m := range res.Misses {
		if m.Name != "GOOGLE_API_KEY" || m.Half != HalfTune || len(m.MissedBy) != 2 || m.Len != len(s3) || !strings.HasPrefix(m.Shape, "AIza…") || m.ID != fp.ID(kr.FP(s3)) && m.ID != fp.ID(kr.FP(s4)) {
			t.Errorf("miss %+v", m)
		}
	}
	// two keys with the same name, prefix and length are one rule to write
	if len(res.Candidates) != 1 || res.Candidates[0].Seen != 2 || res.Candidates[0].Name != "GOOGLE_API_KEY" || res.Candidates[0].Len != len(s3) {
		t.Errorf("rule candidates: %+v", res.Candidates)
	}

	out := t.TempDir()
	if err := res.WriteTo(out); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"oracle.json", "oracle.md"} {
		b, err := os.ReadFile(filepath.Join(out, name))
		if err != nil {
			t.Fatal(err)
		}
		for _, raw := range []string{s1, s2, s3, s4} {
			if bytes.Contains(b, []byte(raw)) {
				t.Errorf("%s carries a leaked key", name)
			}
		}
		if name == "oracle.md" {
			for _, want := range []string{"Missed by every engine", "Rules to write", "GOOGLE_API_KEY", "2 in the held-out half, counted and not listed"} {
				if !strings.Contains(string(b), want) {
					t.Errorf("oracle.md lacks %q", want)
				}
			}
		}
	}
}

func TestOracleNeedsAMatcher(t *testing.T) {
	if _, err := ScoreOracle(context.Background(), nil, nil, nil, OracleOptions{}); err == nil {
		t.Error("an oracle with nothing to find leaks with was accepted")
	}
}

// On the planted corpus the oracle must agree with the corpus score: the keys a matcher holding
// every planted value finds are the plants it knows, and the share betterleaks reports matches the
// share the corpus score says it finds of them. Two instruments, one number.
func TestOracleAgreesWithTheCorpusScore(t *testing.T) {
	c := sharedCorpus(t)
	mirror := filepath.Join(t.TempDir(), "corpus.git")
	if _, err := git(t.TempDir(), nil, "clone", "-q", "--mirror", c.Repo, mirror); err != nil {
		t.Fatal(err)
	}
	engines := realEngines(t, c, "betterleaks")
	name := mirrorNamed(HalfTune)
	res, err := ScoreOracle(context.Background(), engines, newNaive(c), []OracleMirror{{name, mirror}}, OracleOptions{})
	if err != nil {
		t.Fatal(err)
	}
	score, err := ScoreWith(context.Background(), engines, nil, c.Dir, ScoreOptions{OutDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	missed := map[string]bool{}
	for _, id := range append(append([]string{}, score.Engines[0].Missed...), score.Engines[0].MissedOther...) {
		missed[id] = true
	}
	known, found := 0, 0
	for _, p := range c.Truth.Plants {
		if p.Positive && p.Known {
			known++
			if !missed[p.ID] {
				found++
			}
		}
	}
	oe := res.Engines[0]
	if res.Secrets != known {
		t.Errorf("the oracle finds %d secrets, the matcher is known to find %d", res.Secrets, known)
	}
	want := float64(found) / float64(known)
	t.Logf("oracle: betterleaks finds %d of %d leaked keys (%.1f%%, %d by span); the corpus score says %d of %d (%.1f%%)",
		oe.Found, oe.Secrets, 100*oe.Recall, oe.Contained, found, known, 100*want)
	if d := oe.Recall - want; d > 0.03 || d < -0.03 {
		t.Errorf("the oracle says %.3f and the corpus score says %.3f", oe.Recall, want)
	}
	// what betterleaks misses are formats and places its rules do not cover: each is a rule candidate
	if len(res.Misses) == 0 || len(res.Candidates) == 0 {
		t.Errorf("betterleaks cannot find all %d known keys, yet no miss was listed", known)
	}
	for _, m := range res.Misses {
		if m.Len == 0 || m.Shape == "" || m.ID == "" {
			t.Errorf("miss %+v lacks display fields", m)
		}
	}
}
