package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"keyguard/internal/core"
)

func TestRemoteID(t *testing.T) {
	rel := t.TempDir()
	if err := os.Mkdir(filepath.Join(rel, "sibling"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(rel)
	for in, want := range map[string]struct {
		id    string
		local bool
	}{
		"https://github.com/hangryclaude/shop.git":     {"github.com/hangryclaude/shop", false},
		"https://github.com/hangryclaude/shop":         {"github.com/hangryclaude/shop", false},
		"https://www.github.com/Owner/Name/":           {"github.com/owner/name", false},
		"git@github.com:Owner/Name.git":                {"github.com/owner/name", false},
		"ssh://git@github.com/o/n.git":                 {"github.com/o/n", false},
		"ssh://git@github.com:22/o/n.git":              {"github.com/o/n", false},
		"https://user:" + "pw" + "@github.com/o/n.git": {"github.com/o/n", false}, // built in parts: a literal credential URI trips scanners
		"git://github.com/o/n.git":                     {"github.com/o/n", false},
		"https://github.com/o/n.wiki.git":              {"github.com/o/n.wiki", false},
		"https://gist.github.com/abc123def.git":        {"gist.github.com/abc123def", false},
		"git@gist.github.com:abc123def.git":            {"gist.github.com/abc123def", false},
		"https://gist.github.com/someone/abc123def":    {"gist.github.com/someone/abc123def", false},
		"https://gitlab.com/o/n.git":                   {"", false},
		"git@bitbucket.org:o/n.git":                    {"", false},
		"https://github.com/":                          {"", false},
		"":                                             {"", false},
		"file:///tmp/x.git":                            {"", true},
		"/srv/git/x.git":                               {"", true},
		"../elsewhere":                                 {"", true},
		"./here":                                       {"", true},
		".":                                            {"", true},
		"sibling":                                      {"", true}, // a relative directory that exists
		"not-a-dir-and-not-a-url":                      {"", false},
		"https://github.com.evil.example/o/n.git":      {"", false},
		"https://evil.example/github.com/o/n.git":      {"", false},
		"https://notgithub.com/o/n.git":                {"", false},
		"git@github.com.evil.example:o/n.git":          {"", false},
		"https://github.com@evil.example/o/n.git":      {"", false}, // the host is evil.example; github.com is only a username
		"https://evil.example@github.com/o/n.git":      {"github.com/o/n", false},
		"https://github.com:443/o/n.git":               {"github.com/o/n", false},
		"HTTPS://GITHUB.COM/O/N.GIT":                   {"github.com/o/n", false},
	} {
		id, local := remoteID(in)
		if id != want.id || local != want.local {
			t.Errorf("remoteID(%q) = (%q, %v), want (%q, %v)", in, id, local, want.id, want.local)
		}
	}
}

func TestVisibilityFromTheSnapshot(t *testing.T) {
	w := newWorld(t)
	w.srcs = []core.Source{
		{ID: "github.com/o/open", Kind: "repo", Visibility: core.Public},
		{ID: "github.com/o/closed", Kind: "repo", Visibility: core.Private},
		{ID: "github.com/o/open.wiki", Kind: "wiki", Visibility: core.Public},
		{ID: "gist.github.com/o/abc123def", Kind: "gist", Visibility: core.SecretGist},
	}
	w.saveInventorySnapshot()
	vis := visibilityFrom(w.paths.Inventory)
	for url, want := range map[string]core.Visibility{
		"https://github.com/o/open.git":         core.Public,
		"git@github.com:O/Open.git":             core.Public,
		"https://github.com/o/closed.git":       core.Private,
		"https://github.com/o/open.wiki.git":    core.Public,
		"https://gist.github.com/abc123def.git": core.SecretGist,
		"https://github.com/o/just-created.git": core.Unknown, // not listed yet: cautious
		"https://gitlab.com/o/open.git":         core.Unknown,
		"file:///tmp/x.git":                     core.Local,
		"/srv/x.git":                            core.Local,
		"":                                      core.Unknown,
	} {
		if got := vis("origin", url); got != want {
			t.Errorf("visibility(%q) = %q, want %q", url, got, want)
		}
	}
	// With no inventory at all, every GitHub remote is unknown, never private.
	none := visibilityFrom(filepath.Join(t.TempDir(), "missing.json"))
	if got := none("origin", "https://github.com/o/closed.git"); got != core.Unknown {
		t.Errorf("without a snapshot a remote must be unknown, got %q", got)
	}
}

func TestBlockedJournal(t *testing.T) {
	p := core.PathsAt(t.TempDir())
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	hits := []core.Hit{
		{FP: strings.Repeat("a", 32), Type: "github", Rule: "github-pat", Engine: "betterleaks", Shape: "ghp_…abcd", Loc: core.Location{Source: "local:/x", Path: "a.py", Line: 3}},
		{FP: "", Shape: "no fingerprint, no record"},
		{FP: strings.Repeat("b", 32), Shape: "sk-…wxyz", Loc: core.Location{Path: "b.env", Line: 1}},
	}
	if err := appendBlocked(p, "pre-commit", hits, now); err != nil {
		t.Fatal(err)
	}
	if err := appendBlocked(p, "pre-push", hits[:1], now); err != nil {
		t.Fatal(err)
	}
	if err := appendBlocked(p, "pre-push", nil, now); err != nil {
		t.Fatal(err)
	}
	recs, err := readBlocked(p)
	if err != nil || len(recs) != 3 {
		t.Fatalf("records: %d %v", len(recs), err)
	}
	if recs[0].ID != "kgaaaaaa" || recs[0].Layer != "pre-commit" || recs[0].Path != "a.py" || recs[0].Line != 3 || recs[0].At != "2026-11-03T12:00:00Z" {
		t.Errorf("first record: %+v", recs[0])
	}
	if fi, _ := os.Stat(blockedPath(p)); fi.Mode().Perm() != 0o600 {
		t.Errorf("journal mode %v", fi.Mode().Perm())
	}

	// A lines that does not parse is skipped, not fatal.
	f, _ := os.OpenFile(blockedPath(p), os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString("{not json\n")
	f.Close()
	if recs, _ := readBlocked(p); len(recs) != 3 {
		t.Errorf("a bad line broke the journal: %d records", len(recs))
	}

	// Past the size limit the journal is moved aside, not truncated.
	big := make([]byte, maxBlockedBytes+1)
	for i := range big {
		big[i] = ' '
	}
	if err := os.WriteFile(blockedPath(p), big, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := appendBlocked(p, "pre-commit", hits[:1], now); err != nil {
		t.Fatal(err)
	}
	aside, _ := filepath.Glob(blockedPath(p) + ".*")
	if len(aside) != 1 {
		t.Fatalf("expected the full journal to be moved aside, found %v", aside)
	}
	if recs, _ := readBlocked(p); len(recs) != 1 {
		t.Errorf("the fresh journal should hold only the new record, got %d", len(recs))
	}
}

func TestHooksFailOpenOnTheirOwnTrouble(t *testing.T) {
	m := newMachine(t)
	repo := m.repo("app")
	m.write("app/a.txt", "fine\n")
	m.mustGit(repo, "add", "-A")

	// An unknown hook, and a hook run outside a repo, are not reasons to stop git.
	if r := m.run(repo, "", binPath, "hook", "post-merge"); r.code != 0 || !strings.Contains(r.out, "unknown hook") {
		t.Errorf("unknown hook: %d %s", r.code, r.out)
	}
	if r := m.run(m.dir, "", binPath, "hook", "reference-transaction", "prepared"); r.code != 0 {
		t.Errorf("reference-transaction outside a repo: %d %s", r.code, r.out)
	}

	// A config that does not parse: said out loud, the defaults used, the commit still judged.
	m.write(filepath.Join(m.root, "state", "config.json"), "{oops")
	r := m.run(repo, "", binPath, "hook", "pre-commit")
	if r.code != 0 || !strings.Contains(r.out, "not valid config") || !strings.Contains(r.out, "using the defaults") {
		t.Errorf("bad config: %d\n%s", r.code, r.out)
	}
	tok := fakeKey(t, "ghp_", 36)
	m.write("app/leak.py", "T = \""+tok+"\"\n")
	m.mustGit(repo, "add", "leak.py")
	if r := m.run(repo, "", binPath, "hook", "pre-commit"); r.code == 0 || strings.Contains(r.out, tok) {
		t.Errorf("a broken config must not switch the scan off: %d\n%s", r.code, r.out)
	}
	m.mustGit(repo, "reset", "-q", "leak.py")
	os.Remove(filepath.Join(m.root, "state", "config.json"))

	// A learned store whose salt has gone: reported, and everything else still runs.
	m.learn("OPENAI_API_KEY", fakeKey(t, "sk-proj-", 48))
	salt := filepath.Join(m.root, "state", "known", "salt")
	if err := os.Rename(salt, salt+".moved"); err != nil {
		t.Fatal(err)
	}
	r = m.run(repo, "", binPath, "hook", "pre-commit")
	if r.code != 0 || !strings.Contains(r.out, "salt") {
		t.Errorf("missing salt: %d\n%s", r.code, r.out)
	}
	if _, err := os.Stat(salt); err == nil {
		t.Error("a hook minted a new salt beside a learned store, which orphans every hash in it")
	}
}

func TestHooksTakeTheirDataFromTheRealRootNotTheEnvironment(t *testing.T) {
	m := newMachine(t)
	m.install()
	real := fakeKey(t, "sk-proj-", 48)
	m.learn("OPENAI_API_KEY", real)
	repo := m.repo("app")
	m.write("app/README.md", "hi\n")
	m.mustGit(repo, "add", "-A")
	m.mustGit(repo, "commit", "-q", "-m", "init")

	// Someone points KEYGUARD_HOME at a directory with an ignore list that "allows" the real
	// key's fingerprint, and a config that names no engines. Neither may weaken the gate.
	alt := filepath.Join(m.dir, "alt")
	listing := m.kg("known", "list", "--json")
	var rows []struct{ FP string }
	if err := json.Unmarshal([]byte(listing.out), &rows); err != nil || len(rows) != 1 {
		t.Fatalf("known list: %v %s", err, listing.out)
	}
	m.write(filepath.Join(alt, "state", "ignore.json"), `{"version":1,"ignored":{"`+rows[0].FP+`":{"id":"x","reason":"nope","at":"2026-01-01T00:00:00Z"}}}`)
	m.write(filepath.Join(alt, "state", "config.json"), `{"engines":{"betterleaks":"/nonexistent/betterleaks"},"tiers":{"precommit":[],"prepush":[]}}`)
	env := []string{"KEYGUARD_HOME=" + alt}

	m.write("app/deploy.sh", "export K="+real+"\n")
	m.mustGit(repo, "add", "deploy.sh")
	if r := m.runWith(env, repo, "", "git", "commit", "-q", "--no-verify", "-m", "sneaky"); r.code == 0 {
		t.Fatalf("KEYGUARD_HOME turned the learned key's gate off:\n%s", r.out)
	}
	tok := fakeKey(t, "ghp_", 36)
	m.mustGit(repo, "reset", "-q")
	m.write("app/leak.py", "T = \""+tok+"\"\n")
	m.mustGit(repo, "add", "leak.py")
	if r := m.runWith(env, repo, "", "git", "commit", "-q", "-m", "token"); r.code == 0 {
		t.Fatalf("KEYGUARD_HOME's config switched the regex engine off:\n%s", r.out)
	}
	m.mustGit(repo, "reset", "-q")

	// But it can add: a second root's learned store is matched as well.
	second := fakeKey(t, "sk-proj-", 48)
	m.write(filepath.Join(m.home, "other", ".env"), "SECOND_API_KEY="+second+"\n")
	// Learn into the alt root from a home that holds only that .env, so the first key is not in it.
	altHome := filepath.Join(m.dir, "althome")
	m.write(filepath.Join(altHome, "dev", "x", ".env"), "SECOND_API_KEY="+second+"\n")
	if r := m.runWith([]string{"KEYGUARD_HOME=" + alt, "HOME=" + altHome}, m.dir, "", binPath, "learn", "--no-engine", "--no-gh"); r.code != 0 {
		t.Fatalf("learn into the second root: %d\n%s", r.code, r.out)
	}
	m.write("app/second.sh", "export K="+second+"\n")
	m.mustGit(repo, "add", "second.sh")
	if r := m.git(repo, "commit", "-q", "--no-verify", "-m", "second without the env"); r.code != 0 {
		t.Fatalf("a key learned only in the second root should pass when that root is not loaded:\n%s", r.out)
	}
	m.write("app/third.sh", "export K="+second+"\n")
	m.mustGit(repo, "add", "third.sh")
	if r := m.runWith(env, repo, "", "git", "commit", "-q", "--no-verify", "-m", "third with the env"); r.code == 0 {
		t.Fatalf("KEYGUARD_HOME should add its learned store to the real one:\n%s", r.out)
	}
}

func TestAMissingBinaryMeansNoGatesAndTheDoctorSaysSo(t *testing.T) {
	m := newMachine(t)
	m.install()
	repo := m.repo("app")
	bin := filepath.Join(m.root, "bin", "keyguard")
	if err := os.Rename(bin, bin+".moved"); err != nil {
		t.Fatal(err)
	}
	tok := fakeKey(t, "ghp_", 36)
	m.write("app/leak.py", "T = \""+tok+"\"\n")
	m.mustGit(repo, "add", "-A")
	// git must keep working: the hook one-liner is a no-op without its binary...
	if r := m.git(repo, "commit", "-q", "-m", "x"); r.code != 0 {
		t.Fatalf("a missing binary broke git: %s", r.out)
	}
	// ...which is exactly why the doctor treats it as the loudest failure there is.
	r := m.kg("doctor", "--quick", "--json")
	var rep struct {
		Checks []struct{ ID, Status, Summary string } `json:"checks"`
	}
	if err := json.Unmarshal([]byte(r.out), &rep); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range rep.Checks {
		if c.ID == "hooks.binary" && c.Status == "fail" && strings.Contains(c.Summary, "silently off") {
			found = true
		}
	}
	if !found {
		t.Errorf("the doctor did not flag the missing binary:\n%s", r.out)
	}
}

// The hook budgets from PLAN.md: pre-commit p50 <= 150 ms, reference-transaction p50 <= 40 ms.
// They are measured the way git runs them (through sh, on a repo, with the real binary and
// the real engine) and only enforced when the machine is not busy with something else.
func TestHookLatency(t *testing.T) {
	m := newMachine(t)
	m.install()
	m.learn("OPENAI_API_KEY", fakeKey(t, "sk-proj-", 48))
	repo := m.repo("app")
	m.write("app/README.md", "hello\n")
	m.mustGit(repo, "add", "-A")
	m.mustGit(repo, "commit", "-q", "-m", "init")
	bin := filepath.Join(m.root, "bin", "keyguard")
	wrap := func(args string) []string {
		return []string{"sh", "-c", "test -x " + bin + " || exit 0; exec " + bin + " hook " + args}
	}

	// pre-commit: one small file staged.
	m.write("app/src/main.go", "package main\n\nfunc main() { println(\"hello\") }\n")
	m.mustGit(repo, "add", "src/main.go")
	pre := wrap("pre-commit")
	prePct := measure(t, m, repo, "", pre, 3, 20)

	// reference-transaction: a new commit no ref has taken yet.
	head := m.mustGit(repo, "rev-parse", "HEAD")
	tree := m.mustGit(repo, "write-tree")
	next := m.mustGit(repo, "commit-tree", tree, "-p", head, "-m", "pending")
	ref := wrap("reference-transaction prepared")
	refPct := measure(t, m, repo, head+" "+next+" refs/heads/main\n", ref, 3, 20)

	// A call that exits before touching git or any file.
	quiet := wrap("reference-transaction committed")
	quietPct := measure(t, m, repo, head+" "+next+" refs/heads/main\n", quiet, 3, 20)

	// The bare process, for scale.
	ver := measure(t, m, repo, "", []string{binPath, "version"}, 3, 20)

	t.Logf("pre-commit            p50 %6.1f ms  p95 %6.1f ms  (budget 150)", prePct[0], prePct[1])
	t.Logf("reference-transaction p50 %6.1f ms  p95 %6.1f ms  (budget 40)", refPct[0], refPct[1])
	t.Logf("ref-tx, committed     p50 %6.1f ms  p95 %6.1f ms", quietPct[0], quietPct[1])
	t.Logf("keyguard version      p50 %6.1f ms  p95 %6.1f ms", ver[0], ver[1])

	if load := loadAverage(); load > float64(runtime.NumCPU()) {
		t.Logf("load average %.1f exceeds %d cores: budgets are logged, not enforced", load, runtime.NumCPU())
		return
	}
	if prePct[0] > 150 {
		t.Errorf("pre-commit p50 %.1f ms is over the 150 ms budget", prePct[0])
	}
	if refPct[0] > 40 {
		t.Errorf("reference-transaction p50 %.1f ms is over the 40 ms budget", refPct[0])
	}
}

// measure runs argv n times after warm-up runs and returns p50 and p95 in milliseconds.
func measure(t *testing.T, m *machine, dir, stdin string, argv []string, warm, n int) [2]float64 {
	t.Helper()
	var ms []float64
	for i := 0; i < warm+n; i++ {
		start := time.Now()
		r := m.run(dir, stdin, argv[0], argv[1:]...)
		el := float64(time.Since(start).Microseconds()) / 1000
		if r.code != 0 {
			t.Fatalf("%v exited %d:\n%s", argv, r.code, r.out)
		}
		if i >= warm {
			ms = append(ms, el)
		}
	}
	sort.Float64s(ms)
	return [2]float64{ms[len(ms)/2], ms[min(len(ms)-1, int(float64(len(ms))*0.95))]}
}

func loadAverage() float64 {
	if b, err := os.ReadFile("/proc/loadavg"); err == nil {
		var l float64
		if _, err := fmt.Sscan(strings.Fields(string(b))[0], &l); err == nil {
			return l
		}
	}
	out, err := exec.Command("sysctl", "-n", "vm.loadavg").Output() // "{ 1.20 1.05 0.98 }"
	if err != nil {
		return 0
	}
	f := strings.Fields(strings.Trim(string(out), "{} \n"))
	var l float64
	if len(f) == 0 {
		return 0
	}
	if _, err := fmt.Sscan(f[0], &l); err != nil {
		return 0
	}
	return l
}
