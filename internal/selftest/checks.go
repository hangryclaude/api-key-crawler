package selftest

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"keyguard/internal/engines"
	"keyguard/internal/fp"
	"keyguard/internal/install"
)

// check is one thing to prove. Each builds its own repos from nothing, so any of them runs
// alone (--only) and the order only matters for the report.
type check struct {
	id    string
	group string
	name  string
	run   func(*suite) (detail string, err error)
}

type groupInfo struct{ id, title string }

var groups = []groupInfo{
	{"machine", "the throwaway machine"},
	{"precommit", "pre-commit"},
	{"reftx", "reference-transaction"},
	{"prepush", "pre-push"},
	{"text", "keys in the text git keeps"},
	{"quiet", "nothing blocked that should not be"},
	{"mirror", "bare mirrors"},
	{"roots", "data roots"},
	{"failopen", "failing open, never shut"},
	{"hygiene", "hygiene"},
	{"speed", "speed, p50 of the timed runs"},
}

func machineCheck() check {
	return check{"machine", "machine", "wired to the binary under test", checkMachine}
}

// checks is every check, in the order they run. A function and not a variable: the check
// functions refer back to the registry's types.
func checks() []check {
	return []check{
		machineCheck(),

		{"precommit-known", "precommit", "blocks a learned key, also in base64", checkPrecommitKnown},
		{"precommit-scanner", "precommit", "blocks a token nobody has learned", checkPrecommitScanner},
		{"precommit-message", "precommit", "says what, where, how to fix, how to allow", checkPrecommitMessage},
		{"precommit-names", "precommit", "blocks key files by name, passes look-alikes", checkPrecommitNames},
		{"precommit-clean", "precommit", "passes ordinary code without a word", checkPrecommitClean},
		{"precommit-forms", "precommit", "judges commit -a and commit <path> too", checkPrecommitForms},
		{"precommit-allow", "precommit", "allow by id only: a comment on the line allows nothing", checkPrecommitAllow},
		{"precommit-blind", "precommit", "an ignore file, a config, .gitattributes or a comment cannot hide a token", checkPrecommitBlind},
		{"precommit-husky", "precommit", "runs beside the repo's own hooks", checkPrecommitHusky},
		{"precommit-worktree", "precommit", "runs in linked worktrees and a bare repo's worktrees", checkPrecommitWorktree},

		{"reftx-noverify", "reftx", "stops --no-verify from committing a learned key", checkRefNoVerify},
		{"reftx-ways", "reftx", "cannot be skipped: hooksPath, env, plumbing, amend, pick", checkRefWays},

		{"push-clean", "prepush", "passes a clean push, a tag and a delete", checkPushClean},
		{"push-unknown", "prepush", "blocks a token pushed after --no-verify", checkPushUnknown},
		{"push-rewrites", "prepush", "blocks it after a cherry-pick and a rebase", checkPushRewrites},
		{"push-known", "prepush", "blocks a learned key that skipped the other gates", checkPushKnown},

		{"text-message", "text", "blocks a learned key in a commit message", checkTextMessage},
		{"text-tag", "text", "blocks a learned key in a tag annotation", checkTextTag},
		{"text-refname", "text", "blocks a branch or tag named after a learned key", checkTextRefName},
		{"text-push", "text", "blocks it at the push when no other gate saw it", checkTextPush},

		{"quiet-clone", "quiet", "clone of a repo whose history holds a learned key", checkQuietClone},
		{"quiet-fetch", "quiet", "fetch, fetch --tags, fetch into a branch", checkQuietFetch},
		{"quiet-pull", "quiet", "pull --ff-only, --rebase and merge", checkQuietPull},
		{"quiet-rebase", "quiet", "rebase onto leaked history", checkQuietRebase},
		{"quiet-stash", "quiet", "stash and pop with the key in the work tree", checkQuietStash},
		{"quiet-branch", "quiet", "branch and tag make, push and delete", checkQuietBranch},
		{"quiet-remove", "quiet", "removing the key, reverting its commit", checkQuietRemove},

		{"mirror-skip", "mirror", "clone --mirror and fetch inside the cache", checkMirror},

		{"roots-add", "roots", "$KEYGUARD_HOME adds a second learned store", checkRootsAdd},
		{"roots-keep", "roots", "$KEYGUARD_HOME cannot take the real store away", checkRootsKeep},

		{"failopen-store", "failopen", "an unreadable second store: warns, keeps the first", checkRootsBroken},
		{"failopen-config", "failopen", "an unreadable config or no engine costs a scan, not git", checkFailOpen},
		{"failopen-pins", "failopen", "an engine that is not the pinned binary is skipped, not run", checkFailOpenPins},

		{"engines-clean", "hygiene", "no engine updated itself or left a datastore behind", checkEnginesClean},
		{"hooks-quiet", "hygiene", "no hook fell back to fail-open unasked", checkHooksQuiet},
		{"no-leaks", "hygiene", "no fake in any output or file keyguard wrote", checkNoLeaks},

		{"speed-precommit", "speed", "pre-commit, budget 150 ms", checkSpeedPreCommit},
		{"speed-reftx", "speed", "reference-transaction, budget 40 ms", checkSpeedRefTx},
		{"speed-prepush", "speed", "pre-push to a local remote, budget 1 s", checkSpeedPrePush},
	}
}

var (
	allowRE  = regexp.MustCompile(`keyguard allow (kg[0-9a-f]{6})`)
	headerRE = regexp.MustCompile(`(?m)^\s+FILE\s+LINE\s+TYPE\s+SECRET\s+WHY\s*$`)
)

// checkMachine proves the machine is what every other check assumes: git sees the three
// hooks and they name the binary under test; that binary runs and loads the learned store;
// and an engine is there to read what the store does not know.
func checkMachine(s *suite) (string, error) {
	r := s.run(runOpts{dir: s.dir}, "git", "config", "--global", "--get-regexp", `^hook\.keyguard-`)
	want := len(install.HookKeys(s.bin))
	if n := len(nonEmpty(r.out)); r.code != 0 || n != want {
		return "", fmt.Errorf("git sees %d keyguard hook settings, want %d (config hooks need a recent git; 2.54 and 2.55 are the ones tried on this Mac)", n, want)
	}
	if !strings.Contains(r.out, s.bin) {
		return "", fmt.Errorf("the hook settings do not name the binary under test")
	}

	probe := filepath.Join(s.dir, "probe.txt")
	if err := os.WriteFile(probe, []byte("key = "+s.k+"\n"), 0o600); err != nil {
		return "", err
	}
	if m := s.run(runOpts{dir: s.dir}, s.bin, "match", probe); m.code != 1 || s.leaks(m.out) > 0 {
		return "", fmt.Errorf("the binary does not find the learned key in a file (match exited %d): %s", m.code, s.line(m.out))
	}
	if err := os.WriteFile(probe, []byte("nothing secret here\n"), 0o600); err != nil {
		return "", err
	}
	if m := s.run(runOpts{dir: s.dir}, s.bin, "match", probe); m.code != 0 {
		return "", fmt.Errorf("the binary says a file with nothing in it holds a learned key (match exited %d): %s", m.code, s.line(m.out))
	}

	if s.regex == "" {
		return "", fmt.Errorf("no regex engine (betterleaks or gitleaks) is installed, so staged files are never scanned for tokens nobody has learned")
	}
	e, err := engines.New(s.regex, s.engine[s.regex], fp.NewEphemeral())
	if err != nil || !e.Available() {
		return "", fmt.Errorf("%s is configured at %s but does not run", s.regex, s.engine[s.regex])
	}
	return fmt.Sprintf("git %s, %s %s reads staged files, %d learned secrets in %d forms",
		s.gitVersion, s.regex, e.Version(), s.secrets, s.forms), nil
}

func nonEmpty(text string) []string {
	var out []string
	for _, l := range strings.Split(text, "\n") {
		if strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}

func firstGroup(re *regexp.Regexp, text string) string {
	if m := re.FindStringSubmatch(text); m != nil {
		return m[1]
	}
	return ""
}

// shq quotes a path for sh. The paths here are our own temp dirs, but a TMPDIR with a space in
// it is not unheard of.
func shq(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
