package sweep

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strings"

	"keyguard/internal/core"
	"keyguard/internal/fp"
)

// gitRedirect are the variables that point git at a repository other than the one named
// with -C. A hook sets them; a scan of a mirror must not inherit them.
var gitRedirect = []string{
	"GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR", "GIT_PREFIX", "GIT_NAMESPACE",
	"GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES",
}

// gitEnv is the environment of every git command the sweep runs against a mirror: the caller's,
// minus what would point git elsewhere or add config, plus the hermetic switches of PLAN
// invariant 6. refs/replace/* is data the repository's owner controls, and with it honored
// a replacement commit decides what an old commit contains, so a leaking one can be made to
// read clean. No config of this Mac decides how a mirror is read either.
func gitEnv() []string {
	env := make([]string, 0, len(os.Environ())+6)
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		if !slices.Contains(gitRedirect, name) && !strings.HasPrefix(name, "GIT_CONFIG_") {
			env = append(env, kv)
		}
	}
	return append(env, "GIT_TERMINAL_PROMPT=0", "GIT_OPTIONAL_LOCKS=0", "GIT_NO_REPLACE_OBJECTS=1",
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_CONFIG_NOSYSTEM=1")
}

// gitCmd is a git command in repo. Only read-only plumbing runs through here, so no hook
// can fire; the environment is cleaned so the command cannot be steered elsewhere.
func gitCmd(ctx context.Context, git, repo string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, git, append([]string{"-C", repo}, args...)...)
	cmd.Env = gitEnv()
	return cmd
}

// listRefs reads every ref of repo with its tip, as Mirror.Sync reports them.
func listRefs(ctx context.Context, git, repo string) (map[string]string, error) {
	var stderr tailBuffer
	cmd := gitCmd(ctx, git, repo, "for-each-ref", "--format=%(objectname) %(refname)")
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("sweep: git for-each-ref in %s: %w%s", repo, err, stderr.suffix())
	}
	refs := map[string]string{}
	for _, ln := range strings.Split(string(out), "\n") {
		if tip, name, ok := strings.Cut(ln, " "); ok {
			refs[name] = tip
		}
	}
	return refs, nil
}

var objectRE = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)

// peeledCommits resolves ref tips to the commits they point at, in order and without
// duplicates, dropping anything the repo no longer has (a tip gc'd after a force-push) or
// that is not a commit (a ref to a blob or tree). Annotated tags are peeled: excluding the
// tag object itself would exclude nothing.
func peeledCommits(ctx context.Context, git, repo string, tips map[string]string) ([]string, error) {
	var in bytes.Buffer
	for _, ref := range slices.Sorted(maps.Keys(tips)) {
		if t := tips[ref]; objectRE.MatchString(t) {
			in.WriteString(t + "^{commit}\n")
		}
	}
	if in.Len() == 0 {
		return nil, nil
	}
	cmd := gitCmd(ctx, git, repo, "cat-file", "--batch-check")
	cmd.Stdin = &in
	var stderr tailBuffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("sweep: git cat-file in %s: %w%s", repo, err, stderr.suffix())
	}
	var commits []string
	for _, ln := range strings.Split(string(out), "\n") {
		if f := strings.Fields(ln); len(f) == 3 && f[1] == "commit" && !slices.Contains(commits, f[0]) {
			commits = append(commits, f[0])
		}
	}
	return commits, nil
}

// incrementalRange is the range of commits an engine that finished at old has not seen:
// everything reachable now but not from the old tips. ok is false when no old tip survives,
// and the caller must scan everything.
func incrementalRange(ctx context.Context, git, repo string, old map[string]string) (r core.Range, ok bool, err error) {
	commits, err := peeledCommits(ctx, git, repo, old)
	if err != nil || len(commits) == 0 {
		return core.Range{}, false, err
	}
	return core.Range{Revs: append([]string{"--all", "--not"}, commits...), Since: maps.Clone(old)}, true, nil
}

// revArgs turns a Range into rev-list arguments for the known pass. It takes the same
// shapes the engines do, and nothing git would read as an option with side effects.
func revArgs(r core.Range) ([]string, error) {
	var args []string
	if r.All {
		args = append(args, "--all")
	}
	for _, v := range r.Revs {
		if err := validRev(v); err != nil {
			return nil, err
		}
		args = append(args, v)
	}
	if len(args) == 0 {
		return nil, errors.New("sweep: empty range: set All or Revs")
	}
	return args, nil
}

func validRev(s string) error {
	if s == "" || strings.ContainsAny(s, " \t\r\n\x00") {
		return fmt.Errorf("sweep: bad rev %q", s)
	}
	if !strings.HasPrefix(s, "-") {
		return nil
	}
	name, _, _ := strings.Cut(s, "=")
	switch name {
	case "--all", "--not", "--branches", "--tags", "--remotes", "--glob", "--exclude":
		return nil
	}
	return fmt.Errorf("sweep: rev option %q not allowed", name)
}

// tailBuffer keeps the last few KiB written to it: enough of a child's stderr to explain a
// failure, bounded so a chatty child cannot grow memory.
type tailBuffer struct{ b []byte }

const tailMax = 2048

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.b = append(t.b, p...)
	if len(t.b) > tailMax {
		t.b = t.b[len(t.b)-tailMax:]
	}
	return len(p), nil
}

// suffix is ": <last stderr line>" ready to append to an error, scrubbed because git may
// echo URLs or paths and a path can be anything.
func (t *tailBuffer) suffix() string {
	s := strings.TrimSpace(string(t.b))
	if s == "" {
		return ""
	}
	if i := strings.LastIndex(s, "\n"); i >= 0 {
		s = s[i+1:]
	}
	return ": " + safeText(s)
}

var userinfoRE = regexp.MustCompile(`(?i)(https?|ssh|git|ftp)://[^\s/@]+@`)

// safeText makes a message from outside fit for Notes and error strings: URL credentials
// are cut out, tokens that look like secrets are masked, and it is shortened. No raw value
// may reach disk through a message, however it got there.
func safeText(s string) string {
	s = userinfoRE.ReplaceAllString(s, "$1://…@")
	s = fp.Scrub(s)
	if r := []rune(s); len(r) > 300 {
		s = string(r[:299]) + "…"
	}
	return s
}

// safeErr is safeText for an error.
func safeErr(err error) string { return safeText(err.Error()) }
