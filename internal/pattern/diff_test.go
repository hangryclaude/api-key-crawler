package pattern_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"keyguard/internal/bench"
	"keyguard/internal/pattern"
	"keyguard/internal/pattern/rules"
	"keyguard/internal/testkit"
)

// The differential test: native against betterleaks 1.9.0, the program the rule table was copied from,
// on the same files with the same rules (rules/keyguard.toml: the defaults and our 12). Both scan a
// directory; the unit of comparison is the set of (rule, path, line) triples, line being the line the
// whole match starts on, which both report.
//
// What is held equal. Native has no decoding or archive views yet (a later milestone), so betterleaks
// is run with decoding and archives off, and native with the whole upstream path list applied to every
// rule (PathsUpstream). Under those terms the gate is that native reports 99.5% or more of what
// betterleaks reports, and that every difference has a name (classify).

type triple struct {
	rule, path string
	line       int
}

func (t triple) String() string { return fmt.Sprintf("%s\t%s\t%d", t.rule, t.path, t.line) }

func repoRoot(t testing.TB) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if b, err := os.ReadFile(filepath.Join(dir, "go.mod")); err == nil && bytes.HasPrefix(b, []byte("module keyguard")) {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the test")
		}
		dir = parent
	}
}

func without(env []string, keys ...string) []string {
	var out []string
next:
	for _, kv := range env {
		for _, k := range keys {
			if strings.HasPrefix(kv, k+"=") {
				continue next
			}
		}
		out = append(out, kv)
	}
	return out
}

// betterleaks runs the real thing over corpus (its working directory, so paths come out relative) and
// returns where it found what. The report holds the secrets; it is read from the pipe and only the three
// fields below are kept.
func betterleaks(t *testing.T, corpus string, extra ...string) map[triple]bool {
	set, _ := betterleaksTagged(t, corpus, extra...)
	return set
}

// betterleaksTagged is betterleaks that also says, per triple, what the report called the finding's
// tags: "decoded:base64" and the like, for a finding made in a decoded layer.
func betterleaksTagged(t *testing.T, corpus string, extra ...string) (map[triple]bool, map[triple][]string) {
	t.Helper()
	bin := testkit.EnginePath(t, "betterleaks")
	if out, err := exec.Command(bin, "version").Output(); err != nil || strings.TrimSpace(string(out)) != "1.9.0" {
		t.Skipf("the differential is pinned to betterleaks 1.9.0")
	}
	args := append([]string{"dir", ".", "--no-banner", "--no-color", "-l", "error", "-f", "json", "-r", "-",
		"--exit-code", "0", "-i", t.TempDir(), "-c", filepath.Join(repoRoot(t), "rules", "keyguard.toml"),
		"--ignore-gitleaks-allow"}, extra...)
	cmd := exec.Command(bin, args...)
	cmd.Dir = corpus
	cmd.Env = without(os.Environ(), "BETTERLEAKS_CONFIG", "GITLEAKS_CONFIG", "BETTERLEAKS_CONFIG_TOML", "GITLEAKS_CONFIG_TOML")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	set := map[triple]bool{}
	tags := map[triple][]string{}
	dec := json.NewDecoder(stdout)
	if _, err := dec.Token(); err != nil {
		t.Fatalf("betterleaks report: %v\n%s", err, stderr.String())
	}
	for dec.More() {
		var rec struct {
			RuleID    string
			File      string
			StartLine int
			Tags      []string
		}
		if err := dec.Decode(&rec); err != nil {
			t.Fatalf("betterleaks report: %v", err)
		}
		k := triple{rec.RuleID, rec.File, rec.StartLine}
		set[k] = true
		tags[k] = rec.Tags
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("betterleaks: %v\n%s", err, stderr.String())
	}
	return set, tags
}

// native scans the same directory.
func native(t *testing.T, corpus string, policy pattern.PathPolicy) (map[triple]bool, pattern.Stats) {
	t.Helper()
	s := pattern.New(rules.All, rules.Global, pattern.Options{Paths: policy, Threads: 4})
	set := map[triple]bool{}
	st, err := s.ScanDir(context.Background(), corpus, func(f pattern.Finding, _ []byte) {
		set[triple{f.Rule.ID, f.Path, f.Line}] = true
	})
	if err != nil {
		t.Fatal(err)
	}
	return set, st
}

// diff names every difference.
type diff struct {
	bl, nat        map[triple]bool
	missing, extra []triple
}

func compare(bl, nat map[triple]bool) diff {
	d := diff{bl: bl, nat: nat}
	for k := range bl {
		if !nat[k] {
			d.missing = append(d.missing, k)
		}
	}
	for k := range nat {
		if !bl[k] {
			d.extra = append(d.extra, k)
		}
	}
	less := func(a []triple) {
		sort.Slice(a, func(i, j int) bool { return a[i].String() < a[j].String() })
	}
	less(d.missing)
	less(d.extra)
	return d
}

func (d diff) recall() float64 {
	if len(d.bl) == 0 {
		return 1
	}
	return 1 - float64(len(d.missing))/float64(len(d.bl))
}

var byID = func() map[string]*rules.Rule {
	m := map[string]*rules.Rule{}
	for i := range rules.All {
		m[rules.All[i].ID] = &rules.All[i]
	}
	return m
}()

// binary says whether native would not read the file: a NUL byte in its first 8 KiB.
func binary(corpus, path string) bool {
	b, err := os.ReadFile(filepath.Join(corpus, filepath.FromSlash(path)))
	if err != nil {
		return false
	}
	return bytes.IndexByte(b[:min(len(b), 8<<10)], 0) >= 0
}

// classify puts every triple on one side or the other into a named class. A triple that fits no class
// is "unexplained", which a test treats as a failure.
func (d diff) classify(corpus string) (missing, extra map[string][]triple) {
	missing, extra = map[string][]triple{}, map[string][]triple{}
	for _, k := range d.missing {
		c := "unexplained"
		if binary(corpus, k.path) {
			c = "binary file (a NUL byte in its first 8 KiB; native reads its strings in a later milestone)"
		}
		missing[c] = append(missing[c], k)
	}
	for _, k := range d.extra {
		r := byID[k.rule]
		c := "unexplained"
		switch {
		case r.Filter.Residual > 0:
			c = "residual filter terms of the rule are not carried (rules.Filter.Residual)"
		case r.Filter.TokenRatio > 0:
			c = "token-efficiency filter of the rule is not carried (rules.Filter.TokenRatio)"
		}
		extra[c] = append(extra[c], k)
	}
	return
}

// dump writes the differences, as coordinates only, where KEYGUARD_DIFF_DUMP says, for a person to read.
func (d diff) dump(t *testing.T, name string) {
	dir := os.Getenv("KEYGUARD_DIFF_DUMP")
	if dir == "" {
		return
	}
	for _, part := range []struct {
		what string
		list []triple
	}{{"missing", d.missing}, {"extra", d.extra}} {
		var b strings.Builder
		for _, k := range part.list {
			b.WriteString(k.String() + "\n")
		}
		if err := os.WriteFile(filepath.Join(dir, name+"."+part.what+".tsv"), []byte(b.String()), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func byRule(list []triple) string {
	n := map[string]int{}
	for _, k := range list {
		n[k.rule]++
	}
	var parts []string
	for r, c := range n {
		parts = append(parts, fmt.Sprintf("%s %d", r, c))
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ")
}

func report(t *testing.T, name string, d diff, corpus string, st pattern.Stats) {
	t.Helper()
	missing, extra := d.classify(corpus)
	t.Logf("%s: betterleaks %d, native %d, in both %d; native has %.2f%% of betterleaks's; %d files read, %d binary skipped",
		name, len(d.bl), len(d.nat), len(d.bl)-len(d.missing), 100*d.recall(), st.Files, st.Binary)
	for c, l := range missing {
		t.Logf("%s: betterleaks only, %d: %s [%s]", name, len(l), c, byRule(l))
	}
	for c, l := range extra {
		t.Logf("%s: native only, %d: %s [%s]", name, len(l), c, byRule(l))
	}
	d.dump(t, name)
	if l := missing["unexplained"]; len(l) > 0 {
		t.Errorf("%s: %d triples betterleaks reports and native does not, and nothing explains: %v", name, len(l), head(l, 12))
	}
	if l := extra["unexplained"]; len(l) > 0 {
		t.Errorf("%s: %d triples native reports and betterleaks does not, and nothing explains: %v", name, len(l), head(l, 12))
	}
	if r := d.recall(); r < 0.995 {
		t.Errorf("%s: native reports %.2f%% of betterleaks's findings, the gate is 99.5%%", name, 100*r)
	}
}

func head(l []triple, n int) []string {
	var out []string
	for _, k := range l[:min(len(l), n)] {
		out = append(out, k.String())
	}
	return out
}

// corpusA is the bench's planted corpus for a seed: the work tree at HEAD, and a tree that holds every blob
// the history ever had at the path it was first seen under, so that the placements that exist only in
// history are scanned too.
var corpusCache sync.Map

func corpusA(t *testing.T, seed uint64) (worktree, blobs string) {
	t.Helper()
	type pair struct{ wt, bl string }
	if v, ok := corpusCache.Load(seed); ok {
		p := v.(pair)
		return p.wt, p.bl
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is needed to build the bench corpus")
	}
	base, err := os.MkdirTemp("", "native-diff-")
	if err != nil {
		t.Fatal(err)
	}
	c, err := bench.Generate(filepath.Join(base, "corpus"), bench.Options{Seed: seed})
	if err != nil {
		t.Fatal(err)
	}
	blobs = filepath.Join(base, "blobs")
	dumpBlobs(t, c.Repo, blobs)
	corpusCache.Store(seed, pair{c.Repo, blobs})
	return c.Repo, blobs
}

func git(t testing.TB, dir string, stdin []byte, args ...string) []byte {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(without(os.Environ(), "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
	cmd.Stdin = bytes.NewReader(stdin)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git %v: %v", args, err)
	}
	return out
}

// dumpBlobs writes every distinct blob of the repo to out/<oid prefix>/<path it was first listed under>.
func dumpBlobs(t testing.TB, repo, out string) {
	t.Helper()
	listing := git(t, repo, nil, "rev-list", "--objects", "--all")
	var oids, paths []string
	for _, line := range strings.Split(string(listing), "\n") {
		oid, path, ok := strings.Cut(line, " ")
		if ok && path != "" {
			oids = append(oids, oid)
			paths = append(paths, path)
		}
	}
	types := strings.Split(strings.TrimSpace(string(git(t, repo, []byte(strings.Join(oids, "\n")+"\n"), "cat-file", "--batch-check=%(objecttype)"))), "\n")
	var blobIdx []int
	var want []string
	for i, ty := range types {
		if ty == "blob" {
			blobIdx = append(blobIdx, i)
			want = append(want, oids[i])
		}
	}
	data := git(t, repo, []byte(strings.Join(want, "\n")+"\n"), "cat-file", "--batch")
	for _, i := range blobIdx {
		nl := bytes.IndexByte(data, '\n')
		var size int
		if _, err := fmt.Sscanf(string(data[:nl]), oids[i]+" blob %d", &size); err != nil {
			t.Fatalf("cat-file header %q: %v", data[:nl], err)
		}
		body := data[nl+1 : nl+1+size]
		data = data[nl+1+size+1:]
		p := filepath.Join(out, oids[i][:10], filepath.FromSlash(paths[i]))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, body, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDifferentialOnBenchCorpusA(t *testing.T) {
	for _, seed := range []uint64{1, 2} {
		wt, blobs := corpusA(t, seed)
		for _, c := range []struct{ name, dir string }{{"A" + fmt.Sprint(seed) + "-worktree", wt}, {"A" + fmt.Sprint(seed) + "-all-blobs", blobs}} {
			bl := betterleaks(t, c.dir, "--max-decode-depth", "0", "--max-archive-depth", "0")
			nat, st := native(t, c.dir, pattern.PathsUpstream)
			report(t, c.name, compare(bl, nat), c.dir, st)
		}
	}
}

// The perf corpus: 278 MB of public code, left in the cache by the research run and by scripts/perf. It is
// not in the repository, so the test skips without it.
func TestDifferentialOnThePerfCorpus(t *testing.T) {
	home, _ := os.UserHomeDir()
	dir := os.Getenv("KEYGUARD_PERF_CORPUS")
	if dir == "" {
		dir = filepath.Join(home, ".cache", "keyguard-dev", "perf", "corpus")
	}
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		t.Skip("no perf corpus (scripts/perf/corpus.py builds one)")
	}
	bl := betterleaks(t, dir, "--max-decode-depth", "0", "--max-archive-depth", "0")
	nat, st := native(t, dir, pattern.PathsUpstream)
	report(t, "perf", compare(bl, nat), dir, st)
}

// Some tests run betterleaks, so the run ends by checking that none of them changed an engine.
func TestMain(m *testing.M) { testkit.Main(m) }

// The same, against betterleaks as keyguard runs it: decoding to depth 5 and archives to depth 8. What
// native does not report then is what the views of a later milestone are for. The test names it: a finding
// inside an archive (its path has the "!" betterleaks puts between archive and member), or one made
// in a decoded layer (a "decoded:" tag). Anything else is a gap, and a failure.
func TestDifferentialAsShipped(t *testing.T) {
	type corp struct{ name, dir string }
	var cs []corp
	wt, blobs := corpusA(t, 1)
	cs = append(cs, corp{"A1-worktree", wt}, corp{"A1-all-blobs", blobs})
	if home, err := os.UserHomeDir(); err == nil {
		p := filepath.Join(home, ".cache", "keyguard-dev", "perf", "corpus")
		if fi, err := os.Stat(p); err == nil && fi.IsDir() {
			cs = append(cs, corp{"perf", p})
		}
	}
	for _, c := range cs {
		bl, tags := betterleaksTagged(t, c.dir)
		nat, _ := native(t, c.dir, pattern.PathsUpstream)
		d := compare(bl, nat)
		classes := map[string][]triple{}
		for _, k := range d.missing {
			cl := "unexplained"
			switch {
			case strings.Contains(k.path, "!"):
				cl = "inside an archive"
			case hasPrefixTag(tags[k], "decoded:"):
				cl = "made in a decoded layer"
			case binary(c.dir, k.path):
				cl = "binary file"
			}
			classes[cl] = append(classes[cl], k)
		}
		t.Logf("%s: betterleaks as shipped %d, native has %d of them (%.2f%%)", c.name, len(bl), len(bl)-len(d.missing), 100*d.recall())
		for cl, l := range classes {
			t.Logf("%s: %d %s [%s]", c.name, len(l), cl, byRule(l))
		}
		if l := classes["unexplained"]; len(l) > 0 {
			t.Errorf("%s: %d findings of betterleaks as shipped that native lacks and no view explains: %v", c.name, len(l), head(l, 12))
		}
	}
}

func hasPrefixTag(tags []string, prefix string) bool {
	for _, t := range tags {
		if strings.HasPrefix(t, prefix) {
			return true
		}
	}
	return false
}
