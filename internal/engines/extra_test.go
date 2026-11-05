package engines

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"keyguard/internal/core"
	"keyguard/internal/fp"
	"keyguard/internal/testkit"
)

// scriptEngine is a stand-in binary that prints a canned report, for the paths a real engine
// cannot be made to take: validation verdicts, a crash that mentions a key on stderr.
// It replaces only the engine process; git and the parsing around it are real.
func scriptEngine(t *testing.T, name string, kr core.Fingerprinter, stdout, stderr string, exit int) core.Engine {
	t.Helper()
	dir := t.TempDir()
	out := filepath.Join(dir, "stdout")
	errf := filepath.Join(dir, "stderr")
	if err := os.WriteFile(out, []byte(stdout), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(errf, []byte(stderr), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, name)
	script := fmt.Sprintf("#!/bin/sh\ncat '%s'\ncat '%s' >&2\nexit %d\n", out, errf, exit)
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	e, err := New(name, bin, kr)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestBetterleaksVerdicts(t *testing.T) {
	f := getFixture(t)
	verdicts := map[string]core.Verified{
		"valid": core.Live, "invalid": core.Dead, "revoked": core.Dead, "error": core.VerifyError,
		"unknown": core.VerifyError, "needs_validation": core.Unverified, "none": core.Unverified, "": core.Unverified,
	}
	var recs []map[string]any
	byFP := map[string]string{}
	root := t.TempDir()
	for status := range verdicts {
		raw := fake("github")
		byFP[f.kr.FP(raw)] = status
		recs = append(recs, map[string]any{
			"RuleID": "github-pat", "File": filepath.Join(root, "a.txt"), "StartLine": 3, "Secret": raw, "Match": "T=" + raw,
			"MatchContext": "T=" + raw, "ValidationStatus": status,
		})
	}
	report, _ := json.Marshal(recs)
	e := scriptEngine(t, "betterleaks", f.kr, string(report), "", 0)
	var hits []core.Hit
	if err := e.ScanDir(context.Background(), root, testOpts(), func(h core.Hit) { hits = append(hits, h) }); err != nil {
		t.Fatal(err)
	}
	assertSafe(t, "betterleaks", hits)
	if len(hits) != len(verdicts) {
		t.Fatalf("%d hits, want %d", len(hits), len(verdicts))
	}
	for _, h := range hits {
		if want := verdicts[byFP[h.FP]]; h.Verified != want {
			t.Errorf("status %q mapped to %q, want %q", byFP[h.FP], h.Verified, want)
		}
	}
}

func TestTrufflehogRecords(t *testing.T) {
	f := getFixture(t)
	live, errd, plain, v2 := fake("stripe"), fake("stripe"), fake("stripe"), fake("stripe")
	root := t.TempDir()
	rec := func(raw, rawV2 string, verified bool, verr string) map[string]any {
		r := map[string]any{
			"DetectorName": "Stripe", "Verified": verified, "Raw": raw, "RawV2": rawV2,
			"SourceMetadata": map[string]any{"Data": map[string]any{"Filesystem": map[string]any{"file": filepath.Join(root, ".env"), "line": 7}}},
		}
		if verr != "" {
			r["VerificationError"] = verr
		}
		return r
	}
	var stream strings.Builder
	for _, r := range []map[string]any{rec(live, "", true, ""), rec(errd, "", false, "dial tcp: lookup failed"), rec(plain, "", false, ""), rec("", v2, false, ""), rec("", "", false, "")} {
		b, _ := json.Marshal(r)
		stream.Write(b)
		stream.WriteString("\n")
	}
	e := scriptEngine(t, "trufflehog", f.kr, stream.String(), "", 0)
	var hits []core.Hit
	if err := e.ScanDir(context.Background(), root, testOpts(), func(h core.Hit) { hits = append(hits, h) }); err != nil {
		t.Fatal(err)
	}
	assertSafe(t, "trufflehog", hits)
	want := map[string]core.Verified{
		f.kr.FP(live): core.Live, f.kr.FP(errd): core.VerifyError,
		// A rejected key and a detector with no verifier look the same; neither may become Dead.
		f.kr.FP(plain): core.Unverified, f.kr.FP(v2): core.Unverified,
	}
	if len(hits) != len(want) { // the record with no value at all is dropped
		t.Fatalf("%d hits, want %d", len(hits), len(want))
	}
	for _, h := range hits {
		if w, ok := want[h.FP]; !ok || h.Verified != w {
			t.Errorf("verified %q for %s, want %q", h.Verified, h.Shape, w)
		}
		if h.Loc.Line != 7 || h.Loc.Path != ".env" {
			t.Errorf("location %+v", h.Loc)
		}
	}
}

// Real validation: one request per provider with a made-up key. Offline it comes back as an
// error, online as a rejection; either way it is not "unverified".
func TestVerifyEndToEnd(t *testing.T) {
	f := getFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	root := t.TempDir()
	gh := fake("github")
	writeLines(t, root, ".env", "GITHUB_TOKEN="+gh)
	o := core.ScanOpts{Verify: true, Loc: core.Location{Source: "local:" + root, Kind: "file", Visibility: core.Local}}

	var hits []core.Hit
	e := newEngine(t, "betterleaks", f.kr)
	if err := e.ScanDir(ctx, root, o, func(h core.Hit) { hits = append(hits, h) }); err != nil {
		t.Fatal(err)
	}
	assertSafe(t, "betterleaks verify", hits)
	if len(hits) != 1 || hits[0].FP != f.kr.FP(gh) {
		t.Fatalf("betterleaks reported %d hits", len(hits))
	}
	if v := hits[0].Verified; v != core.Dead && v != core.VerifyError {
		t.Errorf("betterleaks --validation left a made-up key %q", v)
	}

	hits = nil
	tr := newEngine(t, "trufflehog", f.kr)
	if err := tr.ScanDir(ctx, root, o, func(h core.Hit) { hits = append(hits, h) }); err != nil {
		t.Fatal(err)
	}
	assertSafe(t, "trufflehog verify", hits)
	if len(hits) != 1 || hits[0].FP != f.kr.FP(gh) {
		t.Fatalf("trufflehog reported %d hits", len(hits))
	}
	if v := hits[0].Verified; v != core.Unverified && v != core.VerifyError {
		t.Errorf("trufflehog verified a made-up key as %q", v)
	}
}

// A crashing engine, or one that prints garbage, must not turn the key it was looking at
// into an error message.
func TestErrorsDoNotLeak(t *testing.T) {
	f := getFixture(t)
	raw := fake("openai")
	for _, name := range Names {
		t.Run(name+"/exit", func(t *testing.T) {
			stderr := "fatal: cannot read config near " + raw + "\n"
			if name == "trufflehog" { // its log is kept by line type, see thLog
				stderr = `{"level":"error","msg":"error running scan","error":"fatal: cannot read config near ` + raw + `"}` + "\n"
			}
			e := scriptEngine(t, name, f.kr, "", stderr, 2)
			err := e.ScanDir(context.Background(), t.TempDir(), testOpts(), func(core.Hit) {})
			if err == nil || !strings.Contains(err.Error(), "fatal") {
				t.Fatalf("want an explanatory error, got %v", err)
			}
			assertNoRaw(t, "error", []byte(err.Error()))
		})
		t.Run(name+"/garbage", func(t *testing.T) {
			e := scriptEngine(t, name, f.kr, `[{"RuleID": "x", "Secret": `+raw+` oops`, "", 0)
			err := e.ScanDir(context.Background(), t.TempDir(), testOpts(), func(core.Hit) {})
			if err == nil {
				t.Fatal("garbage report accepted")
			}
			assertNoRaw(t, "error", []byte(err.Error()))
		})
		t.Run(name+"/scratch", func(t *testing.T) {
			resetAudit()
			empty := "[]" // trufflehog prints nothing when it finds nothing
			if name == "trufflehog" {
				empty = ""
			}
			e := scriptEngine(t, name, f.kr, empty, "", 0)
			if err := e.ScanDir(context.Background(), t.TempDir(), testOpts(), func(core.Hit) {}); err != nil {
				t.Fatal(err)
			}
			assertScratchClean(t)
		})
	}
}

func TestFlags(t *testing.T) {
	kr := fp.NewEphemeral()
	rules := filepath.Join(t.TempDir(), "rules.toml")
	if err := os.WriteFile(rules, []byte("[extend]\nuseDefault = true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	has := func(args []string, want ...string) bool {
		for i := range args {
			if slices.Equal(args[i:min(len(args), i+len(want))], want) {
				return true
			}
		}
		return false
	}
	mk := func(name string) core.Engine { e, _ := New(name, "/bin/true", kr); return e }

	t.Run("betterleaks", func(t *testing.T) {
		e := mk("betterleaks").(*leaks)
		o := core.ScanOpts{Verify: true, Threads: 3, Rules: rules}
		a := e.gitArgs(o, rules, "/scratch", "/repo/.git", []string{"^abc", "--all"})
		for _, w := range [][]string{{"git"}, {"--validation"}, {"--validation-rps", "10"}, {"--validation-workers", "10"}, {"--validation-max-requests", "200"},
			{"--validation-timeout", "10s"}, {"--git-workers", "3"}, {"-c", rules}, {"--ignore-gitleaks-allow"},
			{"--log-opts=^abc --all"}, {"--exit-code", "0"}, {"-r", "-"}, {"-f", "json"}, {"-i", "/scratch"}, {"--match-context", "0L"}} {
			if !has(a, w...) {
				t.Errorf("betterleaks args lack %v: %v", w, a)
			}
		}
		for _, never := range []string{"-v", "--verbose", "--validation-debug", "--validation-env-vars", "--token", "-b", "--baseline-path", "--confidence", "--isolate-rule"} {
			if slices.Contains(a, never) {
				t.Errorf("betterleaks must never get %s: %v", never, a)
			}
		}
		if a[len(a)-1] != "/repo/.git" {
			t.Errorf("target is not last: %v", a)
		}
		o.Verify, o.Threads = false, 0
		if b := e.gitArgs(o, rules, "/s", "/r", []string{"--all"}); has(b, "--validation") || slices.Contains(b, "--git-workers") {
			t.Errorf("--validation without Verify, or workers in a pooled scan: %v", b)
		}
		// The gate: stdlib regexes below a megabyte, no generic-password, inline markers ignored like everywhere.
		st := e.stagedArgs(o, rules, "/s", "stdlib")
		if !has(st, "--pre-commit", "--staged") || !has(st, "--regex-engine", "stdlib") || !has(st, "--disable-rule", "generic-password") || !slices.Contains(st, "--ignore-gitleaks-allow") {
			t.Errorf("staged args: %v", st)
		}
		if has(e.gitArgs(o, rules, "/s", "/r", []string{"--all"}), "--disable-rule") {
			t.Error("generic-password is off at the gate only; the sweeps keep it")
		}
		if env := threadsEnv(core.ScanOpts{Threads: 3}); !slices.Equal(env, []string{"GOMAXPROCS=3"}) {
			t.Errorf("threads env %v", env)
		}
		// Without a rules file the defaults are written into the scratch dir and still passed with -c:
		// never left to whatever .gitleaks.toml sits in the scanned tree.
		scratch := t.TempDir()
		cfg, err := config(core.ScanOpts{}, scratch)
		if err != nil {
			t.Fatal(err)
		}
		if b, err := os.ReadFile(cfg); err != nil || string(b) != defaultConfigTOML || !filepath.IsAbs(cfg) {
			t.Errorf("default config %q: %q, %v", cfg, b, err)
		}
	})
	t.Run("gitleaks", func(t *testing.T) {
		e := mk("gitleaks").(*leaks)
		o := core.ScanOpts{Verify: true, Threads: 3}
		a := e.gitArgs(o, "/c.toml", "/s", "/r", []string{"--all"})
		for _, no := range []string{"--validation", "--git-workers", "--match-context"} {
			if has(a, no) {
				t.Errorf("gitleaks does not take %s: %v", no, a)
			}
		}
		for _, w := range [][]string{{"--ignore-gitleaks-allow"}, {"--max-decode-depth", "0"}, {"--max-archive-depth", "3"}, {"-c", "/c.toml"}} {
			if !has(a, w...) {
				t.Errorf("gitleaks args lack %v: %v", w, a)
			}
		}
		if st := e.stagedArgs(o, "/c.toml", "/s", "stdlib"); has(st, "--regex-engine") || has(st, "--disable-rule") || !slices.Contains(st, "--ignore-gitleaks-allow") {
			t.Errorf("gitleaks staged args: %v", st)
		}
	})
	t.Run("trufflehog", func(t *testing.T) {
		e := mk("trufflehog").(*truffle)
		a := e.gitArgs(core.ScanOpts{Threads: 4}, "/repo with space/.git", trufflePass{branch: "abc", since: "def"})
		for _, w := range [][]string{{"git", "file:///repo%20with%20space/.git", "--bare", "--trust-local-git-config"}, {"--no-verification"}, {"--concurrency=4"}, {"--branch=abc"}, {"--since-commit=def"},
			{"--no-update"}, {"--json"}, {"--no-ignore-tag"}, {truffleResults}, {"--fail-on-scan-errors"}} {
			if !has(a, w...) {
				t.Errorf("trufflehog args lack %v: %v", w, a)
			}
		}
		if a := e.gitArgs(core.ScanOpts{Verify: true}, "/r", trufflePass{}); has(a, "--no-verification") || has(a, "--branch=") || !slices.Contains(a, verifyFlag()) {
			t.Errorf("Verify must drop --no-verification and take the allowlist: %v", a)
		}
	})
	t.Run("titus", func(t *testing.T) {
		e := mk("titus").(*titus)
		a := e.gitArgs(core.ScanOpts{Threads: 2}, "/r/.git", "/ign")
		for _, w := range [][]string{{"scan", "/r/.git", "--git"}, {"--output", ":memory:"}, {"--workers", "2"}, {"--readers", "2"}, {"--format", "json"}, {"-q"}, {"--ignore", "/ign"}, {"--accessibility", "private"}} {
			if !has(a, w...) {
				t.Errorf("titus args lack %v: %v", w, a)
			}
		}
		for _, never := range []string{"--incremental", "--score-scope", "--validate", "--include-noisy", "--extract"} {
			if slices.Contains(a, never) {
				t.Errorf("titus must never get %s: %v", never, a)
			}
		}
	})
}

// Past maxTrufflePasses new heads, trufflehog runs once over everything and the results are
// cut back to the range; the old secret must stay out.
func TestTrufflehogManyHeads(t *testing.T) {
	f := getFixture(t)
	e := newEngine(t, "trufflehog", f.kr)
	resetAudit()
	repo := t.TempDir()
	gitIn(repo, nil, "init", "-q", "-b", "main")
	old := fake("stripe")
	writeLines(t, repo, "old.env", "S="+old)
	gitIn(repo, nil, "add", "-A")
	gitIn(repo, nil, "commit", "-q", "-m", "old")
	base := gitIn(repo, nil, "rev-parse", "HEAD")
	newRaws := map[string]string{}
	for i := range maxTrufflePasses + 3 {
		gitIn(repo, nil, "checkout", "-q", "-b", fmt.Sprintf("b%d", i), base)
		raw := fake("npm")
		newRaws[fmt.Sprintf("b%d", i)] = raw
		writeLines(t, repo, fmt.Sprintf("n%d.sh", i), "export NPM_TOKEN="+raw)
		gitIn(repo, nil, "add", "-A")
		gitIn(repo, nil, "commit", "-q", "-m", "new")
	}
	hits := scanGit(t, e, repo, core.Range{Revs: []string{"--all", "--not", base}}, testOpts())
	got := map[string]bool{}
	for _, h := range hits {
		got[h.FP] = true
		if h.FP == f.kr.FP(old) {
			t.Error("a secret from before the range was reported")
		}
	}
	for b, raw := range newRaws {
		if !got[f.kr.FP(raw)] {
			t.Errorf("secret on %s not reported", b)
		}
	}
}

// A secret that exists only in a merge's conflict resolution is in no parent: log shows no
// diff for the merge, so only blob-based scanning (and the combined diff parse) can place it.
func TestEvilMerge(t *testing.T) {
	f := getFixture(t)
	repo := t.TempDir()
	gitIn(repo, nil, "init", "-q", "-b", "main")
	writeLines(t, repo, "conf.txt", "mode=base", "tail")
	gitIn(repo, nil, "add", "-A")
	gitIn(repo, nil, "commit", "-q", "-m", "base")
	gitIn(repo, nil, "checkout", "-q", "-b", "side")
	writeLines(t, repo, "conf.txt", "mode=side", "tail")
	gitIn(repo, nil, "commit", "-q", "-am", "side")
	gitIn(repo, nil, "checkout", "-q", "main")
	writeLines(t, repo, "conf.txt", "mode=main", "tail")
	gitIn(repo, nil, "commit", "-q", "-am", "main")
	cmd := gitCmd(context.Background(), repo, nil, "merge", "-q", "side")
	_ = cmd.Run() // conflicts, as intended
	gh := fake("github")
	writeLines(t, repo, "conf.txt", "mode=merged", "TOKEN="+gh)
	gitIn(repo, nil, "add", "-A")
	gitIn(repo, nil, "commit", "-q", "-m", "resolve")
	merge := gitIn(repo, nil, "rev-parse", "HEAD")

	e := newEngine(t, "titus", f.kr)
	resetAudit()
	hits := scanGit(t, e, repo, core.Range{All: true}, testOpts())
	ok := false
	for _, h := range hits {
		if h.FP == f.kr.FP(gh) {
			ok = h.Loc.Commit == merge && h.Loc.Path == "conf.txt" && h.Loc.Line == 2
		}
	}
	if !ok {
		t.Errorf("titus did not place the merge-only secret at the merge commit")
	}
}

// Paths git is happy with and shells are not.
func TestOddPaths(t *testing.T) {
	f := getFixture(t)
	repo := t.TempDir()
	gitIn(repo, nil, "init", "-q", "-b", "main")
	paths := []string{"dir with space/key file.txt", "ключ/файл.env", "it's/\"quoted\".txt", "tab\there.txt"}
	raws := map[string]string{}
	for _, p := range paths {
		raw := fake("stripe")
		raws[p] = raw
		writeLines(t, repo, p, "S="+raw)
	}
	gitIn(repo, nil, "add", "-A")
	gitIn(repo, nil, "commit", "-q", "-m", "odd")
	for _, name := range Names {
		t.Run(name, func(t *testing.T) {
			e := newEngine(t, name, f.kr)
			resetAudit()
			hits := scanGit(t, e, repo, core.Range{All: true}, testOpts())
			for p, raw := range raws {
				ok := false
				for _, h := range hits {
					ok = ok || h.FP == f.kr.FP(raw) && h.Loc.Path == p && h.Loc.Line == 1
				}
				if !ok {
					t.Errorf("%s: no hit at %q", name, p)
				}
			}
		})
	}
}

// One blob in two files is one titus finding and two places to fix.
func TestTitusSameBlobTwoPaths(t *testing.T) {
	f := getFixture(t)
	repo := t.TempDir()
	gitIn(repo, nil, "init", "-q", "-b", "main")
	raw := fake("stripe")
	for _, p := range []string{"a/one.env", "b/two.env"} {
		writeLines(t, repo, p, "S="+raw)
	}
	gitIn(repo, nil, "add", "-A")
	gitIn(repo, nil, "commit", "-q", "-m", "copy")
	e := newEngine(t, "titus", f.kr)
	resetAudit()
	var paths []string
	for _, h := range scanGit(t, e, repo, core.Range{All: true}, testOpts()) {
		if h.FP == f.kr.FP(raw) {
			paths = append(paths, h.Loc.Path)
		}
	}
	slices.Sort(paths)
	if !slices.Equal(paths, []string{"a/one.env", "b/two.env"}) {
		t.Errorf("paths %v", paths)
	}
}

// Hits are held back in batches so refs resolve in one git call; the batch size must not
// change what comes out.
func TestBatchedRefs(t *testing.T) {
	f := getFixture(t)
	e := newEngine(t, "betterleaks", f.kr)
	resetAudit()
	whole := scanGit(t, e, f.mirror, core.Range{All: true}, testOpts())
	defer func(n int) { flushAt = n }(flushAt)
	flushAt = 2
	batched := scanGit(t, e, f.mirror, core.Range{All: true}, testOpts())
	key := func(hs []core.Hit) []string {
		var k []string
		for _, h := range hs {
			k = append(k, h.FP+h.Loc.Key()+h.Loc.Ref)
		}
		slices.Sort(k)
		return k
	}
	if !slices.Equal(key(whole), key(batched)) || len(whole) < 13 {
		t.Errorf("batched scan differs: %d vs %d hits", len(whole), len(batched))
	}
}

// The mirror and the worktree it was cloned from hold the same history: engines must agree.
func TestMirrorMatchesWorktree(t *testing.T) {
	f := getFixture(t)
	for _, name := range Names {
		e := newEngine(t, name, f.kr)
		resetAudit()
		key := func(hs []core.Hit) []string {
			var k []string
			for _, h := range hs {
				k = append(k, fmt.Sprintf("%s %s %s %d %s", h.FP, h.Loc.Commit, h.Loc.Path, h.Loc.Line, h.Loc.Ref))
			}
			slices.Sort(k)
			return k
		}
		a := key(scanGit(t, e, f.work, core.Range{All: true}, testOpts()))
		b := key(scanGit(t, e, f.mirror, core.Range{All: true}, testOpts()))
		if !slices.Equal(a, b) {
			t.Errorf("%s: worktree and mirror disagree (%d vs %d hits)", name, len(a), len(b))
		}
	}
}

// A linked worktree (`git worktree add`) keeps its git dir under the main repo's .git; scans
// started from it must still see the whole history and the refs of the main repo.
func TestLinkedWorktree(t *testing.T) {
	f := getFixture(t)
	main := t.TempDir()
	gitIn(main, nil, "init", "-q", "-b", "main")
	st := fake("stripe")
	writeLines(t, main, "old.env", "S="+st)
	gitIn(main, nil, "add", "-A")
	gitIn(main, nil, "commit", "-q", "-m", "old")
	linked := filepath.Join(t.TempDir(), "wt")
	gitIn(main, nil, "worktree", "add", "-q", "-b", "side", linked)
	np := fake("npm")
	writeLines(t, linked, "side.sh", "export NPM_TOKEN="+np)
	gitIn(linked, nil, "add", "-A")
	gitIn(linked, nil, "commit", "-q", "-m", "side")
	for _, name := range Names {
		t.Run(name, func(t *testing.T) {
			e := newEngine(t, name, f.kr)
			resetAudit()
			hits := scanGit(t, e, linked, core.Range{All: true}, testOpts())
			if got := fpSet(f.kr, hits, map[string]string{"stripe": st, "npm": np}); !slices.Equal(got, []string{"npm", "stripe"}) {
				t.Errorf("%s from a linked worktree found %v", name, got)
			}
		})
	}
}

// The real mirror is read-only ground: scanning it must leave it exactly as it was.
func TestRealMirrorUntouched(t *testing.T) {
	mirror := testkit.RealMirror(t, "hangryclaude", "headroom")
	f := getFixture(t)
	before := snapshot(t, mirror)
	for _, name := range Names {
		e := newEngine(t, name, f.kr)
		if err := e.ScanGit(context.Background(), mirror, core.Range{All: true}, testOpts(), func(core.Hit) {}); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if snapshot(t, mirror) != before {
		t.Error("scanning the mirror changed it")
	}
}

// A recorded tip may be an annotated tag's own id; it has to count as the commit it points to.
func TestSinceAnnotatedTag(t *testing.T) {
	f := getFixture(t)
	repo := t.TempDir()
	gitIn(repo, nil, "init", "-q", "-b", "main")
	a, b := fake("stripe"), fake("npm")
	writeLines(t, repo, "a.env", "S="+a)
	gitIn(repo, nil, "add", "-A")
	gitIn(repo, nil, "commit", "-q", "-m", "a")
	gitIn(repo, nil, "tag", "-a", "-m", "release", "rel")
	tagObj := gitIn(repo, nil, "rev-parse", "rel") // the tag object, not the commit
	writeLines(t, repo, "b.sh", "export NPM_TOKEN="+b)
	gitIn(repo, nil, "add", "-A")
	gitIn(repo, nil, "commit", "-q", "-m", "b")
	for _, name := range Names {
		t.Run(name, func(t *testing.T) {
			e := newEngine(t, name, f.kr)
			resetAudit()
			hits := scanGit(t, e, repo, core.Range{All: true, Since: map[string]string{"refs/heads/main": tagObj}}, testOpts())
			if got := fpSet(f.kr, hits, map[string]string{"stripe": a, "npm": b}); !slices.Equal(got, []string{"npm"}) {
				t.Errorf("%s: since an annotated tag reported %v, want only the later commit", name, got)
			}
		})
	}
}

func TestNewAll(t *testing.T) {
	f := getFixture(t)
	paths := map[string]string{"betterleaks": needEngine(t, "betterleaks"), "titus": filepath.Join(t.TempDir(), "no-such-dir", "titus")}
	all, err := NewAll(paths, f.kr)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != len(Names) {
		t.Fatalf("%d engines", len(all))
	}
	for i, e := range all {
		if e.Name() != Names[i] {
			t.Errorf("engine %d is %s, want %s", i, e.Name(), Names[i])
		}
	}
	if !all[0].Available() || all[3].Available() {
		t.Error("availability does not follow the configured paths")
	}
}

// realKeys makes throwaway private keys the way a developer would find them on disk. A
// private key is several lines long, so its raw value spans lines; the base64 body lines are
// registered too, so a context that shows even one of them fails the audit.
func realKeys(t *testing.T) map[string]string {
	t.Helper()
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ek, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecDER, err := x509.MarshalECPrivateKey(ek)
	if err != nil {
		t.Fatal(err)
	}
	p8, err := x509.MarshalPKCS8PrivateKey(rk)
	if err != nil {
		t.Fatal(err)
	}
	enc := func(typ string, der []byte) string {
		raw := strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})))
		register(raw)
		for _, l := range strings.Split(raw, "\n")[1:] {
			if len(l) >= 32 {
				register(l)
			}
		}
		return raw
	}
	return map[string]string{
		"rsa":   enc("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(rk)),
		"ec":    enc("EC PRIVATE KEY", ecDER),
		"pkcs8": enc("PRIVATE KEY", p8),
	}
}

func TestPrivateKeys(t *testing.T) {
	f := getFixture(t)
	keys := realKeys(t)
	repo := t.TempDir()
	gitIn(repo, nil, "init", "-q", "-b", "main")
	for kind, raw := range keys {
		writeLines(t, repo, "id_"+kind, strings.Split(raw, "\n")...)
	}
	gitIn(repo, nil, "add", "-A")
	gitIn(repo, nil, "commit", "-q", "-m", "keys")
	commit := gitIn(repo, nil, "rev-parse", "HEAD")
	for _, name := range Names {
		t.Run(name, func(t *testing.T) {
			e := newEngine(t, name, f.kr)
			resetAudit()
			hits := scanGit(t, e, repo, core.Range{All: true}, testOpts())
			for kind, raw := range keys {
				canon := fp.Canonical(raw) // however an engine wraps the block, this is the one secret
				ok := false
				for _, h := range hits {
					if h.FP == f.kr.FP(canon) {
						ok = h.Loc.Path == "id_"+kind && h.Loc.Line == 1 && h.Loc.Commit == commit && h.Type == "private-key" &&
							h.Len == len(canon) && h.Shape == fp.Shape(canon)
					}
				}
				if !ok {
					t.Errorf("%s: %s key not reported whole at line 1", name, kind)
				}
			}
			for _, h := range hits {
				if h.Type != "private-key" {
					t.Errorf("%s: %s typed %q", name, h.Rule, h.Type)
				}
			}
		})
	}
}

// A blob kept alive only by a tag on it is in no commit's tree. Only titus, which reads
// blobs, can see it; it reports it without a commit or path but names the tag.
func TestBlobOnlyReachableThroughTag(t *testing.T) {
	f := getFixture(t)
	repo := t.TempDir()
	gitIn(repo, nil, "init", "-q", "-b", "main")
	writeLines(t, repo, "a.txt", "hello")
	gitIn(repo, nil, "add", "-A")
	gitIn(repo, nil, "commit", "-q", "-m", "a")
	raw := fake("stripe")
	cmd := gitCmd(context.Background(), repo, nil, "hash-object", "-w", "--stdin")
	cmd.Stdin = strings.NewReader("KEY=" + raw + "\n")
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	gitIn(repo, nil, "tag", "-a", "-m", "keyblob", "keytag", strings.TrimSpace(string(out)))
	for _, name := range Names {
		t.Run(name, func(t *testing.T) {
			e := newEngine(t, name, f.kr)
			resetAudit()
			hits := scanGit(t, e, repo, core.Range{All: true}, testOpts())
			if name != "titus" {
				if len(hits) != 0 {
					t.Errorf("%s reported %d hits for a blob in no commit", name, len(hits))
				}
				return
			}
			if len(hits) != 1 || hits[0].FP != f.kr.FP(raw) || hits[0].Loc.Commit != "" || hits[0].Loc.Path != "" || hits[0].Loc.Ref != "refs/tags/keytag" || hits[0].Loc.Blob == "" {
				t.Errorf("titus: %d hits, first %+v", len(hits), hits[0].Loc)
			}
			// A range only asks for what its commits introduced, and this is in none of them.
			if hits := scanGit(t, e, repo, core.Range{Revs: []string{"main"}}, testOpts()); len(hits) != 0 {
				t.Errorf("titus: ranged scan reported the tag-only blob")
			}
		})
	}
}

// A repo with no commits has no history. Titus alone would fall back to reading the files of
// the working tree, which is not what ScanGit means, so no engine is started at all.
func TestEmptyRepoAndEmptyRange(t *testing.T) {
	f := getFixture(t)
	empty := t.TempDir()
	gitIn(empty, nil, "init", "-q", "-b", "main")
	st := fake("stripe")
	writeLines(t, empty, "x.env", "S="+st)
	gitIn(empty, nil, "add", "-A") // staged but never committed
	for _, name := range Names {
		t.Run(name, func(t *testing.T) {
			e := newEngine(t, name, f.kr)
			resetAudit()
			if hits := scanGit(t, e, empty, core.Range{All: true}, testOpts()); len(hits) != 0 {
				t.Errorf("%d hits from a repo without commits", len(hits))
			}
			if hits := scanGit(t, e, f.mirror, core.Range{Revs: []string{"main", "^main"}}, testOpts()); len(hits) != 0 {
				t.Errorf("%d hits from a range that selects nothing", len(hits))
			}
			if scratchRuns != 0 {
				t.Errorf("an engine process was started for an empty range")
			}
		})
	}
}

// The sweep runs engines from a worker pool; one Engine value serves many scans at once.
func TestConcurrentScans(t *testing.T) {
	f := getFixture(t)
	key := func(hs []core.Hit) string {
		var k []string
		for _, h := range hs {
			k = append(k, fmt.Sprintf("%s %s %s %d %s", h.FP, h.Loc.Commit, h.Loc.Path, h.Loc.Line, h.Loc.Ref))
		}
		slices.Sort(k)
		return strings.Join(k, "\n")
	}
	for _, name := range Names {
		t.Run(name, func(t *testing.T) {
			e := newEngine(t, name, f.kr)
			want := key(scanGit(t, e, f.mirror, core.Range{All: true}, testOpts()))
			const n = 6
			got := make([]string, n)
			errs := make([]error, n)
			var wg sync.WaitGroup
			for i := range n {
				wg.Add(1)
				go func() {
					defer wg.Done()
					var hits []core.Hit
					errs[i] = e.ScanGit(context.Background(), f.mirror, core.Range{All: true}, testOpts(), func(h core.Hit) { hits = append(hits, h) })
					got[i] = key(hits)
				}()
			}
			wg.Wait()
			for i := range n {
				if errs[i] != nil || got[i] != want {
					t.Errorf("concurrent scan %d: err=%v, results differ=%v", i, errs[i], got[i] != want)
				}
			}
		})
	}
}

// Commit dates lie when clocks are skewed. The origin of a blob is the first commit in
// history that has it, whatever the dates say: here a side branch is dated after the origin
// and the revert before everything, which makes a date-ordered walk list the revert first.
func TestTitusOriginUnderClockSkew(t *testing.T) {
	f := getFixture(t)
	repo := t.TempDir()
	gitIn(repo, nil, "init", "-q", "-b", "main")
	raw := fake("stripe")
	commit := func(path, content, date string) string {
		writeLines(t, repo, path, content)
		gitIn(repo, nil, "add", "-A")
		env := []string{"GIT_AUTHOR_DATE=" + date, "GIT_COMMITTER_DATE=" + date}
		gitIn(repo, env, "commit", "-q", "-m", "c")
		return gitIn(repo, nil, "rev-parse", "HEAD")
	}
	origin := commit("p.env", "S="+raw, "2026-03-01T10:00:00Z")
	gitIn(repo, nil, "checkout", "-q", "-b", "side")
	commit("z.txt", "unrelated", "2026-04-01T10:00:00Z")
	gitIn(repo, nil, "checkout", "-q", "main")
	commit("p.env", "S=changed", "2026-02-01T10:00:00Z")
	commit("p.env", "S="+raw, "2026-01-01T10:00:00Z") // reverts to the original blob
	e := newEngine(t, "titus", f.kr)
	resetAudit()
	var at []string
	for _, h := range scanGit(t, e, repo, core.Range{All: true}, testOpts()) {
		if h.FP == f.kr.FP(raw) {
			at = append(at, h.Loc.Commit)
		}
	}
	if !slices.Equal(at, []string{origin}) {
		t.Errorf("titus placed the blob at %v, want only its first commit %s", at, short(origin))
	}
}
