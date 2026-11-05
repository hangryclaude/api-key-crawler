package engines

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"keyguard/internal/core"
	"keyguard/internal/fp"
	"keyguard/internal/testkit"
)

// Real binaries, real git, throwaway state. Where the engines are is testkit's business
// (needEngine); a test that needs one that is missing is skipped, or failed in CI.

// realMirror is the one real repo the perf test may read, counts and seconds only.
func realMirror() (string, bool) { return testkit.LookupMirror("hangryclaude", "headroom") }

var (
	testRoot string
	shared   struct {
		once sync.Once
		fx   *fixture
		err  error
	}

	rawMu        sync.Mutex
	raws         []string // every planted secret value, so audits can search for them
	leaked       []string // descriptions (never contents) of audit failures
	scratchFiles []string
	scratchRuns  int // engine processes started since resetAudit
)

func TestMain(m *testing.M) {
	if os.Getenv(hookHelperEnv) != "" {
		os.Exit(hookHelper()) // git started this binary as a pre-commit hook; see blind_test.go
	}
	root, err := os.MkdirTemp("", "keyguard-engines-test-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	testRoot = root
	gitcfg := filepath.Join(root, "gitconfig")
	cfg := "[user]\n\tname = Test\n\temail = test@example.invalid\n[init]\n\tdefaultBranch = main\n[protocol \"file\"]\n\tallow = always\n"
	must(os.WriteFile(gitcfg, []byte(cfg), 0o600))
	tmp := filepath.Join(root, "tmp")
	must(os.Mkdir(tmp, 0o700))
	for k, v := range map[string]string{
		"KEYGUARD_HOME":       filepath.Join(root, "kg"),
		"GIT_CONFIG_GLOBAL":   gitcfg,
		"GIT_CONFIG_NOSYSTEM": "1",
		"TMPDIR":              tmp,
	} {
		must(os.Setenv(k, v))
	}
	auditScratch = recordScratch
	code := testkit.Run(m)
	// Every engine run owns a private scratch dir under the data root and removes it; one left
	// behind is a leak.
	if left, _ := os.ReadDir(filepath.Join(root, "kg", "tmp")); len(left) > 0 && code == 0 {
		for _, e := range left {
			fmt.Fprintln(os.Stderr, "scratch dir left behind:", e.Name())
		}
		code = 1
	}
	os.RemoveAll(root)
	os.Exit(code)
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

// recordScratch runs inside the engine, just before its private TMPDIR is removed. It notes
// the file names and whether any holds a planted secret; contents are never kept.
func recordScratch(dir string) {
	rawMu.Lock()
	defer rawMu.Unlock()
	scratchRuns++
	filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(dir, p)
		scratchFiles = append(scratchFiles, rel)
		b, _ := os.ReadFile(p)
		for _, r := range raws {
			if bytes.Contains(b, []byte(r)) {
				leaked = append(leaked, "engine scratch file "+rel+" holds a planted secret")
				break
			}
		}
		return nil
	})
}

func resetAudit() {
	rawMu.Lock()
	defer rawMu.Unlock()
	leaked, scratchFiles, scratchRuns = nil, nil, 0
}

// assertNoRaw fails if data holds any planted secret. label says where the data came from;
// the secret itself is never printed.
func assertNoRaw(t *testing.T, label string, data []byte) {
	t.Helper()
	rawMu.Lock()
	defer rawMu.Unlock()
	for _, r := range raws {
		if bytes.Contains(data, []byte(r)) {
			t.Errorf("%s contains a planted secret (%s)", label, fp.Shape(r))
		}
	}
}

// ownScratchFiles are the only files keyguard itself puts in an engine's scratch dir.
var ownScratchFiles = map[string]bool{"titus.ignore": true, "exclude-paths.txt": true, "default.toml": true}

// assertScratchClean fails if any engine run since resetAudit left a planted secret in its
// scratch dir, or left anything there that keyguard did not put there (a clone, a datastore).
func assertScratchClean(t *testing.T) {
	t.Helper()
	rawMu.Lock()
	defer rawMu.Unlock()
	for _, l := range leaked {
		t.Error(l)
	}
	for _, f := range scratchFiles {
		if !ownScratchFiles[f] {
			t.Errorf("engine left %q in its scratch dir", f)
		}
	}
}

const (
	// No vowels: a string of these cannot spell a word, and trufflehog drops a find that
	// contains one (about 1 random Slack token in 100, measured), which would fail a test for
	// the dice and not for the detector.
	lowerCS = "bcdfghjklmnpqrstvwxyz"
	upperCS = "BCDFGHJKLMNPQRSTVWXYZ"
	digitCS = "0123456789"
	alnumCS = lowerCS + upperCS + digitCS
	safeCS  = alnumCS + "_-"
	hexCS   = "0123456789abcdef"
	alphaCS = lowerCS + upperCS
)

var stopwords = []string{"test", "example", "sample", "dummy", "fake", "demo", "token", "passw", "secret", "admin", "1234", "abcd", "0000", "aaaa", "xxxx"}

// tok is n random characters of cs. Strings an entropy filter or a stopword list would
// reasonably drop are re-rolled, so a detector missing a fake means the detector, not the dice.
func tok(cs string, n int) string {
	minEntropy := 0.0
	for _, bound := range []float64{math.Log2(float64(len(cs))), math.Log2(float64(n))} {
		if minEntropy == 0 || bound < minEntropy {
			minEntropy = bound
		}
	}
	minEntropy *= 0.9
	for {
		rb := make([]byte, n)
		if _, err := rand.Read(rb); err != nil {
			panic(err)
		}
		b := make([]byte, n)
		for i := range b {
			b[i] = cs[int(rb[i])%len(cs)]
		}
		s := string(b)
		low := strings.ToLower(s)
		bad := fp.Entropy(s) < minEntropy
		for _, w := range stopwords {
			bad = bad || strings.Contains(low, w)
		}
		if !bad {
			return s
		}
	}
}

func register(raw string) string {
	rawMu.Lock()
	raws = append(raws, raw)
	rawMu.Unlock()
	return raw
}

// A provider's fake is a constant prefix plus random characters of the right alphabet and
// length: the format, never a literal secret.
var fakeMakers = map[string]func() string{
	"anthropic":    func() string { return "sk-ant-api03-" + tok(safeCS, 93) + "AA" },
	"openai":       func() string { return "sk-proj-" + tok(safeCS, 74) + "T3BlbkFJ" + tok(safeCS, 74) },
	"github":       func() string { return "ghp_" + tok(alnumCS, 36) },
	"stripe":       func() string { return "sk_live_" + tok(alnumCS, 24) },
	"slack":        func() string { return "xoxb-" + tok(digitCS, 12) + "-" + tok(digitCS, 12) + "-" + tok(alnumCS, 24) },
	"huggingface":  func() string { return "hf_" + tok(alphaCS, 34) },
	"npm":          func() string { return "npm_" + tok(alnumCS, 36) },
	"sendgrid":     func() string { return "SG." + tok(alnumCS, 22) + "." + tok(alnumCS, 43) },
	"groq":         func() string { return "gsk_" + tok(alnumCS, 52) },
	"linear":       func() string { return "lin_api_" + tok(alnumCS, 40) },
	"digitalocean": func() string { return "dop_v1_" + tok(hexCS, 64) },
	// The detector wants a word boundary after the token, which a trailing "-" is not (1 in 100).
	"telegram": func() string { return tok(digitCS, 10) + ":AA" + tok(safeCS, 32) + tok(alnumCS, 1) },
	"mailgun":  func() string { return "key-" + tok(hexCS, 32) },
}

func fake(provider string) string {
	mk, ok := fakeMakers[provider]
	if !ok {
		panic("no fake for " + provider)
	}
	return register(mk())
}

// plant is a secret committed to the fixture and where git says it first appears.
type plant struct {
	name   string
	raw    string
	path   string
	line   int
	commit string
	author string
	date   string // RFC 3339 UTC, as the engines are expected to report it
}

type fixture struct {
	work   string // worktree
	mirror string // bare --mirror clone of work
	plants []*plant
	c      map[string]string // c1..c6 -> commit id
	kr     *fp.Keyring
}

func (f *fixture) git(args ...string) string {
	return gitIn(f.work, nil, args...)
}

func gitIn(dir string, env []string, args ...string) string {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		panic(fmt.Sprintf("git %s: %v: %s", strings.Join(args, " "), err, errb.String()))
	}
	return strings.TrimSpace(out.String())
}

// commit writes files (path -> lines), commits them as author at date, and returns the
// commit id. Plants named in want get their line from where their value really is.
func (f *fixture) commit(label, author, date string, files map[string][]string, plants ...*plant) string {
	for p, lines := range files {
		full := filepath.Join(f.work, p)
		must(os.MkdirAll(filepath.Dir(full), 0o755))
		must(os.WriteFile(full, []byte(strings.Join(lines, "\n")+"\n"), 0o644))
	}
	f.git("add", "-A")
	env := []string{
		"GIT_AUTHOR_NAME=" + author, "GIT_AUTHOR_EMAIL=" + strings.ToLower(strings.Fields(author)[0]) + "@example.invalid",
		"GIT_AUTHOR_DATE=" + date, "GIT_COMMITTER_NAME=" + author, "GIT_COMMITTER_EMAIL=x@example.invalid", "GIT_COMMITTER_DATE=" + date,
	}
	gitIn(f.work, env, "commit", "-q", "-m", label)
	sha := f.git("rev-parse", "HEAD")
	f.c[label] = sha
	for _, p := range plants {
		p.commit, p.author, p.date = sha, author, date
		for i, l := range files[p.path] {
			if strings.Contains(l, p.raw) {
				p.line = i + 1
				break
			}
		}
		if p.line == 0 {
			panic("plant " + p.name + " not in " + p.path)
		}
		f.plants = append(f.plants, p)
	}
	return sha
}

func newPlant(name, path string) *plant { return &plant{name: name, raw: fake(name), path: path} }

// buildFixture makes the repo every engine test shares: 13 providers over six commits on
// main, a second branch, a commit reachable only from refs/pull/1/head and one only from a tag.
func buildFixture(root string) (*fixture, error) {
	f := &fixture{work: filepath.Join(root, "work"), c: map[string]string{}, kr: fp.NewEphemeral()}
	must(os.MkdirAll(f.work, 0o755))
	f.git("init", "-q", "-b", "main")

	anth := newPlant("anthropic", "src/app.py")
	groq := newPlant("groq", "src/util.py")
	f.commit("c1", "Alice Archer", "2026-01-01T10:00:00Z", map[string][]string{
		"src/app.py":  {"import os", "", `ANTHROPIC_API_KEY = "` + anth.raw + `"`, `print("hi")`},
		"src/util.py": {"# util", `GROQ_API_KEY = "` + groq.raw + `"`},
	}, anth, groq)

	oai, gh, lin, mg := newPlant("openai", "conf/config.yaml"), newPlant("github", "conf/config.yaml"), newPlant("linear", "conf/config.yaml"), newPlant("mailgun", "conf/mail.ini")
	f.commit("c2", "Bob Baker", "2026-01-02T10:00:00Z", map[string][]string{
		"src/app.py":       {"import os", "", `ANTHROPIC_API_KEY = "` + anth.raw + `"`, `print("hi")`},
		"src/util.py":      {"# util", `GROQ_API_KEY = "` + groq.raw + `"`},
		"conf/config.yaml": {"name: demo", `openai_key: "` + oai.raw + `"`, "github_token: " + gh.raw, "linear: " + lin.raw},
		"conf/mail.ini":    {"[mail]", `MAILGUN_KEY = "` + mg.raw + `"`},
	}, oai, gh, lin, mg)

	st, do := newPlant("stripe", "env/prod.env"), newPlant("digitalocean", "deploy/do.sh")
	f.commit("c3", "Alice Archer", "2026-01-03T10:00:00Z", map[string][]string{
		// anthropic moves from line 3 to line 4: engines that read diffs must not report it again.
		"src/app.py":   {"import os", "import sys", "", `ANTHROPIC_API_KEY = "` + anth.raw + `"`, `print("hi")`},
		"env/prod.env": {"STRIPE_SECRET=" + st.raw},
		"deploy/do.sh": {"#!/bin/sh", "export DO_TOKEN=" + do.raw},
	}, st, do)

	f.git("checkout", "-q", "-b", "feature")
	sl, hf, tg := newPlant("slack", "feature/notes.md"), newPlant("huggingface", "feature/notes.md"), newPlant("telegram", "feature/bot.txt")
	f.commit("c4", "Carol Chen", "2026-01-04T10:00:00Z", map[string][]string{
		"feature/notes.md": {"# notes", "", "SLACK_TOKEN=" + sl.raw, `hf = "` + hf.raw + `"`},
		"feature/bot.txt":  {`telegram_bot_token = "` + tg.raw + `"`},
	}, sl, hf, tg)

	f.git("checkout", "-q", "main")
	f.git("checkout", "-q", "-b", "pr-tmp")
	np := newPlant("npm", "pr/ci.sh")
	f.commit("c5", "Dan Dole", "2026-01-05T10:00:00Z", map[string][]string{
		"pr/ci.sh": {"#!/bin/sh", "export NPM_TOKEN=" + np.raw},
	}, np)
	f.git("update-ref", "refs/pull/1/head", f.c["c5"])
	f.git("checkout", "-q", "main")
	f.git("branch", "-q", "-D", "pr-tmp")

	f.git("checkout", "-q", "--detach", "main")
	sg := newPlant("sendgrid", "rel/release.txt")
	f.commit("c6", "Eve East", "2026-01-06T10:00:00Z", map[string][]string{
		"rel/release.txt": {"release notes", "mail = " + sg.raw},
	}, sg)
	f.git("tag", "v1", f.c["c6"])
	f.git("checkout", "-q", "main")

	f.mirror = filepath.Join(root, "mirror.git")
	gitIn(root, nil, "clone", "-q", "--mirror", f.work, f.mirror)
	return f, nil
}

// getFixture builds the shared repo once. Some detectors drop random-looking values that
// happen to contain a dictionary word or miss an entropy bar (trufflehog does this to
// letters-only tokens), so the fixture is re-rolled until every engine finds everything it
// is expected to. What the tests then measure is the wrapper, not the dice.
func getFixture(t *testing.T) *fixture {
	t.Helper()
	shared.once.Do(func() {
		for attempt := 1; attempt <= 12; attempt++ {
			fx, err := tryFixture(filepath.Join(testRoot, fmt.Sprintf("fx%d", attempt)))
			if err != nil {
				shared.err = err
				return
			}
			missing := calibrate(fx)
			if len(missing) == 0 {
				shared.fx = fx
				return
			}
			t.Logf("re-rolling fixture (attempt %d): %s did not detect", attempt, strings.Join(missing, ", "))
		}
		shared.err = errors.New("no fixture that every installed engine fully detects after 12 attempts")
	})
	if shared.err != nil {
		t.Fatal(shared.err)
	}
	return shared.fx
}

func tryFixture(root string) (fx *fixture, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("fixture: %v", r)
		}
	}()
	must(os.MkdirAll(root, 0o755))
	return buildFixture(root)
}

// calibrate runs every installed engine over the fixture and returns "engine:provider" for
// each planted value an engine should have found and did not.
func calibrate(f *fixture) (missing []string) {
	for _, name := range Names {
		bin, err := testkit.LookupEngine(name)
		if err != nil {
			continue // not installed: its tests are skipped (failed in CI), and there is nothing to calibrate
		}
		e, err := New(name, bin, f.kr)
		if err != nil {
			continue
		}
		var hits []core.Hit
		_ = e.ScanGit(context.Background(), f.work, core.Range{All: true}, core.ScanOpts{}, func(h core.Hit) { hits = append(hits, h) })
		for _, p := range f.plants {
			if _, skip := expectedMiss[name][p.name]; skip {
				continue
			}
			ok := false
			for _, h := range hits {
				ok = ok || h.FP == f.kr.FP(p.raw) && h.Loc.Commit == p.commit && h.Loc.Path == p.path && h.Loc.Line == p.line
			}
			if !ok {
				missing = append(missing, name+":"+p.name)
			}
		}
	}
	return missing
}

func (f *fixture) byName(name string) *plant {
	for _, p := range f.plants {
		if p.name == name {
			return p
		}
	}
	return nil
}

// fpIndex maps a fingerprint back to the plant, for judging engine output.
func (f *fixture) fpIndex() map[string]*plant {
	m := map[string]*plant{}
	for _, p := range f.plants {
		m[f.kr.FP(p.raw)] = p
	}
	return m
}

// lineAt reads line n of path at commit straight from git, as ground truth for a location.
func (f *fixture) lineAt(commit, path string, n int) string {
	out := f.git("show", commit+":"+path)
	lines := strings.Split(out, "\n")
	if n < 1 || n > len(lines) {
		return ""
	}
	return lines[n-1]
}

func needEngine(t *testing.T, name string) string {
	t.Helper()
	return testkit.EnginePath(t, name)
}
