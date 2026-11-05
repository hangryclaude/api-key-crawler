package engines

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"keyguard/internal/core"
)

// What an engine's process may inherit, and what it is given instead (STEAL section 5.1,
// PLAN invariants 1 and 6). The scanners shell out to git, read ignore files and configs from
// the directory they run in, and spool to TMPDIR, so every one of those is decided here and
// not left to whatever environment a hook or a launchd job happened to have.

// gitHermetic shuts the user's git configuration out of every git an engine starts, and ours
// too. keyguard's own hooks live in ~/.gitconfig: a git run inside an engine would fire the
// reference-transaction hook on a clone. A refs/replace entry cannot hide a leaking commit
// when replacement is off, and nothing may prompt.
var gitHermetic = []string{
	"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_CONFIG_NOSYSTEM=1",
	"GIT_NO_REPLACE_OBJECTS=1", "GIT_TERMINAL_PROMPT=0", "GIT_OPTIONAL_LOCKS=0",
}

// gitRedirect are the variables that point git at a repository other than the one named on
// the command line. A hook sets them, and a scan of a mirror must not inherit them.
var gitRedirect = []string{"GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR", "GIT_PREFIX", "GIT_NAMESPACE"}

// configEnv is every way betterleaks and gitleaks can be handed a config from the
// environment. A repo-local .gitleaks.toml with an allowlist of ".*" silences them completely
// (measured), so the scan's config is always the -c argument.
var configEnv = []string{"BETTERLEAKS_CONFIG", "GITLEAKS_CONFIG", "BETTERLEAKS_CONFIG_TOML", "GITLEAKS_CONFIG_TOML"}

// credentialEnv are tokens an engine has no use for in an offline scan. The one scan that
// needs a GitHub token (ScanAPI) is given it through ScanOpts.Env.
var credentialEnv = []string{"GITHUB_TOKEN", "GH_TOKEN"}

const defaultConfigTOML = "[extend]\nuseDefault = true\n"

// emptyTreeSHA1 is the id of the tree with nothing in it. As GIT_ATTR_SOURCE it makes git
// read no .gitattributes: a `*.env -diff` line makes `git diff` print "Binary files differ"
// for the file, and the engine sees an empty diff (reproduced on betterleaks 1.9.0 and
// gitleaks 8.30.1). Git has needed it since 2.40. A repository that uses SHA-256 objects does
// not know this id and the scan fails, which is loud; GitHub does not host such repositories.
const emptyTreeSHA1 = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"

// diffEnv is added for engines that read `git diff` or `git log -p`.
var diffEnv = []string{"GIT_ATTR_SOURCE=" + emptyTreeSHA1}

// defaultThreads is what an engine gets when the caller names no cap: the sweep runs eight
// engines at once on 18 cores (STEAL P0-07). Uncapped, gitleaks burned 63.8 CPU-seconds in
// 4.3 of wall time. A caller that scans one huge repository alone passes ScanOpts.Threads.
const defaultThreads = 2

func threads(o core.ScanOpts) int {
	if o.Threads > 0 {
		return o.Threads
	}
	return defaultThreads
}

// threadsEnv caps the Go runtime of the child. Titus's workers are native threads that
// GOMAXPROCS does not bound, so it gets --workers as well.
func threadsEnv(o core.ScanOpts) []string {
	return []string{"GOMAXPROCS=" + strconv.Itoa(threads(o))}
}

// callerEnv is ScanOpts.Env without anything that would undo the rest of this file.
func callerEnv(o core.ScanOpts) []string {
	var out []string
	for _, kv := range o.Env {
		k, _, _ := strings.Cut(kv, "=")
		switch {
		case k == "TMPDIR", k == "GOMAXPROCS", k == "TITUS_CACHE_DIR", strings.HasPrefix(k, "GIT_"),
			strings.HasPrefix(k, "BETTERLEAKS_"), strings.HasPrefix(k, "GITLEAKS_"):
			continue
		}
		out = append(out, kv)
	}
	return out
}

// jobEnv is what every plan adds: the thread cap and the caller's extras.
func jobEnv(o core.ScanOpts, extra ...string) []string {
	return slices.Concat(threadsEnv(o), callerEnv(o), extra)
}

func dropped(k string) bool {
	return slices.Contains(configEnv, k) || slices.Contains(gitRedirect, k) || slices.Contains(credentialEnv, k) ||
		k == "GOMAXPROCS" || k == "GIT_ATTR_SOURCE" || k == "TITUS_CACHE_DIR" ||
		k == "GIT_CONFIG_PARAMETERS" || k == "GIT_CONFIG_COUNT" ||
		strings.HasPrefix(k, "GIT_CONFIG_KEY_") || strings.HasPrefix(k, "GIT_CONFIG_VALUE_")
}

// childEnv is the inherited environment minus what must not be inherited, plus the hermetic
// git settings, plus the job's own variables (which win: the last duplicate is the one used).
// scratch is the child's TMPDIR; "" for the short git helpers of this package.
func childEnv(scratch string, j job) []string {
	env := make([]string, 0, len(os.Environ())+16)
	for _, kv := range os.Environ() {
		if k, _, _ := strings.Cut(kv, "="); !dropped(k) && !(k == "TMPDIR" && scratch != "") {
			env = append(env, kv)
		}
	}
	if scratch != "" {
		env = append(env, "TMPDIR="+scratch)
	}
	env = append(env, "NO_COLOR=1")
	env = append(env, gitHermetic...)
	return append(env, j.env...)
}

// scratchRoot is the directory engines spool under: <data root>/tmp, which the installer
// creates 0700 (STEAL P0-04). One more thing in one known place for selftest and doctor to
// watch, instead of wherever $TMPDIR happens to point.
func scratchRoot() string { return core.PathsAt(core.Root()).Tmp }

// newScratch makes the private directory of one engine run. It is removed when the run ends,
// so nothing a scanner spools outlives it. When the data root cannot be written the run still
// happens, in the system temp dir, and says so: a hook must not skip its scan over a mode bit.
func (b *base) newScratch() (string, error) {
	root := scratchRoot()
	if err := os.MkdirAll(root, 0o700); err == nil {
		if d, err := os.MkdirTemp(root, b.name+"-"); err == nil {
			return d, nil
		}
	}
	b.note("%s ran with its scratch dir in the system temp dir: the keyguard tmp dir is not writable", b.name)
	return os.MkdirTemp("", "keyguard-"+b.name+"-")
}

// subdir makes an empty directory inside scratch, for an engine to run in or be pointed at.
func subdir(scratch, name string) (string, error) {
	d := filepath.Join(scratch, name)
	return d, os.Mkdir(d, 0o700)
}

// gitCmd builds a git invocation that cannot be redirected by a hook's environment and does not
// read the user's configuration. Scans of a mirror run inside keyguard's own pre-push hook
// sometimes, and GIT_DIR from that hook would silently point every one of these commands at
// the repo being pushed. env is added after the hermetic settings.
func gitCmd(ctx context.Context, dir string, env []string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	cmd.Env = append(childEnv("", job{env: env}), "LC_ALL=C")
	return cmd
}

// stagedRepo is the repository a pre-commit scan reads, by absolute paths.
//
// git hands a hook GIT_INDEX_FILE as a path relative to the directory it started the hook in
// (".git/index", or ".git/next-index-<n>.lock" for commit -a and commit --only). The scan runs
// from an empty directory, where that path names nothing: the index would be empty, nothing
// would be found, and the commit would go through (reproduced: 0 findings). Everything is
// resolved against this process's directory, which is git's, before anything moves.
type stagedRepo struct{ gitDir, workTree, index string }

func resolveStaged(ctx context.Context, wt string) (stagedRepo, error) {
	here, err := os.Getwd()
	if err != nil {
		return stagedRepo{}, err
	}
	abs := func(p string) string {
		if p == "" || filepath.IsAbs(p) {
			return p
		}
		return filepath.Join(here, p)
	}
	s := stagedRepo{gitDir: abs(os.Getenv("GIT_DIR")), workTree: abs(os.Getenv("GIT_WORK_TREE")), index: abs(os.Getenv("GIT_INDEX_FILE"))}
	if s.gitDir == "" || s.workTree == "" {
		// A normal commit exports only GIT_INDEX_FILE (a linked worktree adds GIT_DIR), so the
		// rest is asked of git, in one call: a hook has 150 ms and each process is a few.
		out, err := gitOut(ctx, wt, "rev-parse", "--absolute-git-dir", "--show-toplevel")
		if err != nil {
			return stagedRepo{}, err
		}
		found := strings.Split(strings.TrimSpace(string(out)), "\n")
		if len(found) != 2 {
			return stagedRepo{}, fmt.Errorf("engines: cannot place the repository of %s", filepath.Base(wt))
		}
		if s.gitDir == "" {
			s.gitDir = found[0]
		}
		if s.workTree == "" {
			s.workTree = found[1]
		}
	}
	if s.index == "" {
		s.index = filepath.Join(s.gitDir, "index")
	}
	return s, nil
}

func (s stagedRepo) env() []string {
	return []string{"GIT_DIR=" + s.gitDir, "GIT_WORK_TREE=" + s.workTree, "GIT_INDEX_FILE=" + s.index}
}

// git runs a git command against the staged state, from the work tree.
func (s stagedRepo) git(ctx context.Context, args ...string) *exec.Cmd {
	return gitCmd(ctx, s.workTree, s.env(), args...)
}

// stagedSize says whether anything is staged and how many lines it adds. The count is a proxy
// for size that costs one git call and decides the regex engine (see regexEngine).
func (s stagedRepo) stagedSize(ctx context.Context) (lines int, any bool, err error) {
	cmd := s.git(ctx, "diff", "--cached", "--numstat", "--no-ext-diff", "--no-textconv", "-z")
	var stderr tailBuf
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		if ctx.Err() != nil {
			return 0, false, ctx.Err()
		}
		return 0, false, fmt.Errorf("engines: git diff --cached: %v; stderr: %s", err, stderr.text())
	}
	if len(bytes.TrimSpace(out)) == 0 {
		return 0, false, nil
	}
	for _, rec := range bytes.Split(out, []byte{0}) {
		added, _, _ := strings.Cut(strings.TrimLeft(string(rec), "\n"), "\t")
		if n, err := strconv.Atoi(added); err == nil { // "-" is a binary file
			lines += n
		}
	}
	return lines, true, nil
}

// stdlibLines is where the staged diff stops being small. Go's own regexp engine starts faster
// and is 1.4x quicker than re2 on a handful of lines (23 against 33 ms p50, STEAL K11), and
// 4.4x slower on hundreds of megabytes. 20,000 added lines is about a megabyte.
const stdlibLines = 20000

func regexEngine(addedLines int) string {
	if addedLines < stdlibLines {
		return "stdlib"
	}
	return "re2"
}
