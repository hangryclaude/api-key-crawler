package mirror

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"keyguard/internal/core"
)

func TestClassifiersAgainstTheMessagesGitAndGitHubPrint(t *testing.T) {
	notFoundMsgs := []string{
		"remote: Repository not found.\nfatal: repository 'https://github.com/o/r.wiki.git/' not found\n",
		"fatal: unable to access 'https://github.com/o/r.git/': The requested URL returned error: 404\n",
		"fatal: '/srv/git/gone.git' does not appear to be a git repository\nfatal: Could not read from remote repository.\n",
		"ERROR: Repository not found.\nfatal: Could not read from remote repository.\n",
	}
	for _, m := range notFoundMsgs {
		if !notFound([]byte(m)) {
			t.Errorf("not recognised as not-found: %q", m)
		}
		if authFailed([]byte(m)) {
			t.Errorf("not-found misread as an auth failure: %q", m)
		}
	}
	authMsgs := []string{
		"remote: Invalid username or token. Password authentication is not supported for Git operations.\nfatal: Authentication failed for 'https://github.com/o/r.git/'\n",
		"fatal: could not read Username for 'https://github.com': terminal prompts disabled\n",
		"fatal: unable to access 'https://github.com/o/r.git/': The requested URL returned error: 403\n",
	}
	for _, m := range authMsgs {
		if !authFailed([]byte(m)) {
			t.Errorf("not recognised as an auth failure: %q", m)
		}
		if notFound([]byte(m)) {
			t.Errorf("auth failure misread as not-found: %q", m)
		}
	}
	// Failures that are neither must stay plain errors: a wiki on a flaky network is not "absent".
	for _, m := range []string{
		"fatal: unable to access 'https://github.com/o/r.wiki.git/': Could not resolve host: github.com\n",
		"error: RPC failed; HTTP 500 curl 22 The requested URL returned error: 500\n",
		"fatal: early EOF\nfatal: index-pack failed\n",
		"",
	} {
		if notFound([]byte(m)) || authFailed([]byte(m)) {
			t.Errorf("misclassified: %q", m)
		}
	}
}

func TestSyncErrorsCarryTheirKindAndNeverACredential(t *testing.T) {
	m, err := New(Config{Root: filepath.Join(t.TempDir(), "mirrors")})
	if err != nil {
		t.Fatal(err)
	}
	tok := fakeSecret(t, "ghp_", 36)
	pat := fakeSecret(t, "github_pat_", 40)
	stderr := []byte("remote: noise\nfatal: unable to access 'https://x-access-token:" + tok + "@github.com/o/r.git/' with " + pat + ": The requested URL returned error: 403\n" +
		"hint: after the fatal line\n")
	err = m.syncErr("fetch", core.Source{ID: "github.com/o/r"}, errors.New("exit status 128"), stderr)
	if !errors.Is(err, ErrAuth) {
		t.Errorf("err = %v, want ErrAuth", err)
	}
	for i, leak := range []string{tok, pat, "x-access-token"} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("error leaks credential %d", i)
		}
	}
	line := lastLine([]byte("fatal: unable to access 'https://user:"+tok+"@github.com/o/r.git/': nope\n"), nil)
	if strings.Contains(line, tok) || strings.Contains(line, "user:") {
		t.Error("lastLine leaks credentials")
	}
	long := lastLine([]byte(strings.Repeat("é", 500)), nil)
	if len([]rune(long)) > 200 {
		t.Errorf("lastLine not clipped: %d runes", len([]rune(long)))
	}
	if got := lastLine(nil, errors.New("exit status 1")); got != "exit status 1" {
		t.Errorf("lastLine fallback = %q", got)
	}
	if !errors.Is(m.syncErr("clone", core.Source{}, errors.New("x"), []byte("remote: Repository not found.")), ErrNotFound) {
		t.Error("ErrNotFound not wrapped")
	}
	if !errors.Is(m.syncErr("clone", core.Source{}, ErrTimeout, nil), ErrTimeout) {
		t.Error("ErrTimeout not wrapped")
	}
}

func TestCloneURLsAreHeldToGitHubOverHTTPS(t *testing.T) {
	e := newTenv(t, func(c *Config) { c.AllowLocal = false })
	for _, ok := range []string{
		"https://github.com/o/r.git", "https://github.com/o/r.wiki.git", "https://gist.github.com/3f9a1c0de27b4658a1d2e3f4a5b6c7d8.git",
	} {
		if _, err := e.m.remote(core.Source{ID: "github.com/o/r", CloneURL: ok}); err != nil {
			t.Errorf("%s rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"http://github.com/o/r.git", "https://evil.example/o/r.git", "https://github.com.evil.example/o/r.git",
		"https://user:" + "pw" + "@github.com/o/r.git", "https://github.com:8443/o/r.git", "ssh://git@github.com/o/r.git", "git://github.com/o/r.git",
		"ext::sh -c id", "-oProxyCommand=id", "file:///etc", "/etc", "https://github.com/o/r.git?x=1", "https://github.com/o/r.git#frag", "\x00",
	} {
		if _, err := e.m.remote(core.Source{ID: "github.com/o/r", CloneURL: bad}); err == nil {
			t.Errorf("%q accepted: the credential helper answers for any host git talks to", bad)
		}
		if _, err := e.m.SyncResult(context.Background(), core.Source{ID: "github.com/o/r", CloneURL: bad, Account: "hangryclaude"}); err == nil {
			t.Errorf("Sync accepted %q", bad)
		}
	}
	if _, err := os.Stat(filepath.Join(e.root, "github.com")); err == nil {
		t.Error("a rejected source still created directories")
	}

	// With no CloneURL the remote is derived from the ID, the way the bootstrap built it.
	for id, want := range map[string]string{
		"github.com/o/r":                          "https://github.com/o/r.git",
		"github.com/o/r.wiki":                     "https://github.com/o/r.wiki.git",
		"gist.github.com/hangryclaude/abc123def4": "https://gist.github.com/abc123def4.git",
	} {
		if got, err := e.m.remote(core.Source{ID: id}); err != nil || got != want {
			t.Errorf("remote(%s) = %q, %v; want %q", id, got, err, want)
		}
	}
	if _, err := e.m.SyncResult(context.Background(), core.Source{ID: "github.com/o/r", Account: "a b; rm"}); err == nil {
		t.Error("an account that is not a login reached the credential helper")
	}
}

// spyGit is a shell wrapper that records every argument vector, then runs the real git.
func spyGit(t *testing.T, dir string) (script, log string) {
	t.Helper()
	log = filepath.Join(dir, "git-calls.log")
	script = filepath.Join(dir, "spy-git")
	body := "#!/bin/sh\nIFS=$(printf '\\037')\nprintf '%s\\n' \"$*\" >> " + shellQuote(log) + "\nunset IFS\nexec git \"$@\"\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return script, log
}

func TestEveryGitCallCarriesTheHookSwitchesAndOnlyNetworkCallsCarryCredentials(t *testing.T) {
	spyDir := t.TempDir()
	script, logPath := spyGit(t, spyDir)
	e := newTenv(t, func(c *Config) { c.Git = script })
	s := e.src("hangryclaude", "headroom", "repo")
	s.Account = "hangryclaude"
	e.sync(s) // clone
	e.commit("x", "x\n", "more")
	e.sync(s) // fetch
	if _, err := e.m.Tips(context.Background(), s); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	calls := strings.Split(strings.TrimSpace(string(raw)), "\n")
	var verbs []string
	for _, ln := range calls {
		args := strings.Split(ln, "\x1f")
		for _, pair := range [][2]string{
			{"-c", "hook.keyguard-reftx.enabled=false"}, {"-c", "hook.keyguard-precommit.enabled=false"},
			{"-c", "hook.keyguard-prepush.enabled=false"}, {"-c", "core.hooksPath=/dev/null"},
			{"-c", "gc.auto=0"}, {"-c", "maintenance.auto=false"},
		} {
			if !hasPair(args, pair[0], pair[1]) {
				t.Errorf("call lacks %s %s: %q", pair[0], pair[1], ln)
			}
		}
		verb := verbOf(args)
		verbs = append(verbs, verb)
		network := verb == "clone" || verb == "fetch"
		helper := "credential.helper=" + e.m.helper("hangryclaude")
		if network != slices.Contains(args, helper) {
			t.Errorf("%s: credential helper present = %v, want %v", verb, !network, network)
		}
		if !network && slices.ContainsFunc(args, func(a string) bool { return strings.HasPrefix(a, "credential.") || strings.HasPrefix(a, "http.") }) {
			t.Errorf("%s runs offline but carries credential or http settings: %q", verb, ln)
		}
		if network {
			reset := slices.Index(args, "credential.helper=")
			set := slices.Index(args, helper)
			if reset < 0 || set < reset {
				t.Errorf("%s: the user's own helpers must be reset before ours is added: %q", verb, ln)
			}
		}
		switch verb {
		case "clone":
			if !slices.Contains(args, "--mirror") || !slices.Contains(args, "--") {
				t.Errorf("clone is not a guarded --mirror clone: %q", ln)
			}
			if i := slices.Index(args, "--"); i < 0 || !strings.HasPrefix(args[i+1], "file://") {
				t.Errorf("remote must follow --: %q", ln)
			}
		case "fetch":
			if !slices.Contains(args, "--prune") || !slices.Contains(args, "--prune-tags") || args[len(args)-1] != "origin" {
				t.Errorf("fetch is not `--prune --prune-tags origin`: %q", ln)
			}
		}
		if verb != "clone" && !hasPrefixArg(args, "--git-dir=") {
			t.Errorf("%s does not name its repository explicitly: %q", verb, ln)
		}
	}
	// clone + for-each-ref, then for-each-ref + fetch + for-each-ref, then Tips' for-each-ref.
	if want := []string{"clone", "for-each-ref", "for-each-ref", "fetch", "for-each-ref", "for-each-ref"}; !slices.Equal(verbs, want) {
		t.Errorf("git calls = %v, want %v", verbs, want)
	}
}

func hasPair(args []string, a, b string) bool {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == a && args[i+1] == b {
			return true
		}
	}
	return false
}

func hasPrefixArg(args []string, p string) bool {
	return slices.ContainsFunc(args, func(a string) bool { return strings.HasPrefix(a, p) })
}

// verbOf finds the git subcommand: the first argument that is not an option or an option value.
func verbOf(args []string) string {
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "-c":
			i++
		case strings.HasPrefix(args[i], "-"):
		default:
			return args[i]
		}
	}
	return ""
}

// The helper string is the one part of the credential path no test can reach by talking to
// GitHub, so it is driven by real git's own `credential fill` against a stand-in gh.
func TestCredentialHelperAnswersRealGitWithTheNamedAccountsToken(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "dir with spaces") // the gh path is spliced into a shell string
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	tok := fakeSecret(t, "gho_", 36)
	other := fakeSecret(t, "gho_", 36)
	gh := filepath.Join(dir, "gh")
	script := "#!/bin/sh\n" +
		"[ \"$1 $2 $3\" = \"auth token --user\" ] || { echo \"bad args: $*\" >&2; exit 2; }\n" +
		"case \"$4\" in hangryclaude) echo " + tok + " ;; alt-builds) echo " + other + " ;; *) exit 1 ;; esac\n"
	if err := os.WriteFile(gh, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	e := newTenv(t, func(c *Config) { c.GH = gh })

	for acct, want := range map[string]string{"hangryclaude": tok, "alt-builds": other} {
		args := e.m.gitArgs(acct, true, "credential", "fill")
		for _, a := range args {
			if strings.Contains(a, tok) || strings.Contains(a, other) {
				t.Fatal("a token reached argv")
			}
		}
		cmd := exec.Command("git", args...)
		cmd.Env = e.m.env()
		cmd.Stdin = strings.NewReader("protocol=https\nhost=github.com\n\n")
		var out, errb bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errb
		if err := cmd.Run(); err != nil {
			t.Fatalf("git credential fill as %s: %v\n%s", acct, err, errb.String())
		}
		got := out.String()
		if !strings.Contains(got, "username="+acct+"\n") || !strings.Contains(got, "pass"+"word="+want+"\n") {
			t.Errorf("credential fill as %s answered\n%s", acct, strings.ReplaceAll(strings.ReplaceAll(got, tok, "«A»"), other, "«B»"))
		}
	}
	if !strings.Contains(e.m.helper("hangryclaude"), "'"+gh+"'") {
		t.Errorf("gh path is not shell-quoted in the helper: %s", e.m.helper("hangryclaude"))
	}
}

func TestShellQuoteSurvivesHostilePaths(t *testing.T) {
	for _, p := range []string{"/usr/bin/gh", "/a b/gh", "/it's/gh", "/$(id)/gh", "/a;b/gh", "/`x`/gh", "/a\"b/gh"} {
		out, err := exec.Command("sh", "-c", "printf %s "+shellQuote(p)).Output()
		if err != nil || string(out) != p {
			t.Errorf("shellQuote(%q) round-trips to %q (%v)", p, out, err)
		}
	}
}

func TestAStaleLockFromAKilledFetchIsClearedAndAFreshOneIsNot(t *testing.T) {
	e := newTenv(t, func(c *Config) { c.StaleLockAge = time.Hour })
	s := e.src("o", "n", "repo")
	e.sync(s)
	dest := e.m.Path(s)
	lock := filepath.Join(dest, "refs", "heads", "main.lock")
	if err := os.MkdirAll(filepath.Dir(lock), 0o700); err != nil {
		t.Fatal(err)
	}

	e.commit("x", "x\n", "more")
	write(t, lock, "")
	// Fresh: some other git may be running right now, so leave it alone and say so.
	_, _, err := e.m.Sync(context.Background(), s)
	if err == nil || !strings.Contains(err.Error(), "main.lock") {
		t.Fatalf("err = %v, want the lock named", err)
	}
	if _, serr := os.Stat(lock); serr != nil {
		t.Fatal("a fresh lock was removed")
	}

	// Old enough that no live fetch can still own it (the fetch timeout is shorter).
	old := time.Now().Add(-3 * time.Hour)
	if err := os.Chtimes(lock, old, old); err != nil {
		t.Fatal(err)
	}
	r := e.sync(s)
	if r.After["refs/heads/main"] != e.git("rev-parse", "main") {
		t.Fatalf("fetch did not land after clearing the lock: %+v", r)
	}
	if _, serr := os.Stat(lock); !errors.Is(serr, os.ErrNotExist) {
		t.Errorf("stale lock still there: %v", serr)
	}
}
