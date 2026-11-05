package mirror

import (
	"bytes"
	"cmp"
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"time"
)

// hookOff is PLAN.md invariant 6: keyguard's own hooks must not run inside the mirrors.
// A fetch that brings in a leaked key would otherwise be blocked by the very reference-
// transaction hook that exists to stop leaks, and the sweep would never see the key.
var hookOff = []string{
	"-c", "hook.keyguard-reftx.enabled=false",
	"-c", "hook.keyguard-precommit.enabled=false",
	"-c", "hook.keyguard-prepush.enabled=false",
	"-c", "core.hooksPath=/dev/null",
}

// quiet keeps git from spawning background maintenance behind our back: a detached gc
// would outlive the sync that started it, race the next fetch, and hold the directory open.
var quiet = []string{
	"-c", "gc.auto=0",
	"-c", "maintenance.auto=false",
	// Deciding whether each updated ref was a forced update walks history; mirrors of
	// force-pushed repos pay for it on every fetch and nothing here reads the answer.
	"-c", "fetch.showForcedUpdates=false",
}

// helper is the per-account credential helper. git runs it
// only when it needs a login, and it asks gh for the named account's token at that moment,
// so the token never sits in argv or a file and the active gh account is never flipped.
func (m *Mirror) helper(acct string) string {
	return fmt.Sprintf(`!f(){ echo username=%s; echo "password=$(%s auth token --user %s)"; }; f`,
		acct, shellQuote(m.cfg.GH), acct)
}

// shellQuote single-quotes s for sh, for the one place a path reaches a shell string.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// gitArgs builds one git command line: the hook switches first on every call, then, for
// network operations, the credential helper. The empty credential.helper resets whatever
// the user's own config lists (osxkeychain), so only the named account's token is offered.
func (m *Mirror) gitArgs(acct string, network bool, args ...string) []string {
	a := slices.Concat(hookOff, quiet)
	if network {
		a = append(a, "-c", "credential.helper=")
		if acct != "" {
			a = append(a, "-c", "credential.helper="+m.helper(acct))
		}
		// Give up on a connection that has moved under a byte per second for five minutes
		// instead of waiting out the whole timeout on a dead socket.
		a = append(a, "-c", "http.lowSpeedLimit=1", "-c", "http.lowSpeedTime=300")
	}
	return append(a, args...)
}

// env is the child environment: the caller's, minus anything that would aim git at a
// different repository (keyguard also runs inside git hooks, which export GIT_DIR) or make
// it narrate credentials, plus switches that make a missing login fail instead of prompt.
func (m *Mirror) env() []string {
	var out []string
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		switch {
		case strings.HasPrefix(k, "GIT_TRACE"), k == "GIT_CURL_VERBOSE", repoVars[k], injectsConfig(k):
			continue
		}
		out = append(out, kv)
	}
	return append(out,
		"GIT_TERMINAL_PROMPT=0",
		"GIT_ASKPASS=/usr/bin/true",
		"GCM_INTERACTIVE=never",
		"LC_ALL=C", // stderr is matched for "not found" below; keep it in English
		// PLAN invariant 6, the part that does not need the global config blanked: no system
		// config of this Mac, and no refs/replace entry of a repository's owner deciding what one
		// of its commits contains.
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_NO_REPLACE_OBJECTS=1",
	)
}

// injectsConfig names the variables through which a parent process hands git config: a git
// hook gets its own -c flags that way, and any caller can. The mirror's git is not to read
// config it did not choose.
func injectsConfig(k string) bool {
	return k == "GIT_CONFIG_COUNT" || k == "GIT_CONFIG_PARAMETERS" ||
		strings.HasPrefix(k, "GIT_CONFIG_KEY_") || strings.HasPrefix(k, "GIT_CONFIG_VALUE_")
}

var repoVars = map[string]bool{
	"GIT_DIR": true, "GIT_WORK_TREE": true, "GIT_INDEX_FILE": true, "GIT_OBJECT_DIRECTORY": true,
	"GIT_ALTERNATE_OBJECT_DIRECTORIES": true, "GIT_COMMON_DIR": true, "GIT_NAMESPACE": true,
	"GIT_PREFIX": true, "GIT_QUARANTINE_PATH": true, "GIT_CEILING_DIRECTORIES": true,
}

// git runs one command and returns what it wrote. A timeout or cancellation kills git's whole
// process group: git spawns git-remote-https, the credential helper's shell and gh, and a
// stuck grandchild must not outlive the sync.
func (m *Mirror) git(ctx context.Context, timeout time.Duration, acct string, network bool, args ...string) (stdout, stderr []byte, err error) {
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(runCtx, m.cfg.Git, m.gitArgs(acct, network, args...)...)
	cmd.Env = m.env()
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &capped{w: &errb, max: 64 << 10}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 5 * time.Second
	err = cmd.Run()
	if err != nil && runCtx.Err() != nil {
		if ctx.Err() != nil {
			return out.Bytes(), errb.Bytes(), ctx.Err()
		}
		return out.Bytes(), errb.Bytes(), fmt.Errorf("%w after %s", ErrTimeout, timeout)
	}
	return out.Bytes(), errb.Bytes(), err
}

// capped keeps the head of what a child writes and swallows the rest, so a chatty failure
// cannot grow without bound.
type capped struct {
	w   *bytes.Buffer
	max int
}

func (c *capped) Write(p []byte) (int, error) {
	if room := c.max - c.w.Len(); room > 0 {
		c.w.Write(p[:min(room, len(p))])
	}
	return len(p), nil
}

// notFound recognises GitHub's answer for a repository, or wiki, that is not there:
//
//	remote: Repository not found.
//	fatal: repository 'https://github.com/o/r.wiki.git/' not found
//
// plus the equivalents for an HTTP 404 and for a path or ssh remote that does not exist.
func notFound(stderr []byte) bool {
	s := strings.ToLower(string(stderr))
	return strings.Contains(s, "repository not found") ||
		strings.Contains(s, "returned error: 404") ||
		strings.Contains(s, "does not appear to be a git repository") ||
		(strings.Contains(s, "repository '") && strings.Contains(s, "' not found"))
}

func authFailed(stderr []byte) bool {
	s := strings.ToLower(string(stderr))
	for _, w := range []string{"authentication failed", "could not read username", "invalid username or token", "returned error: 401", "returned error: 403", "permission denied"} {
		if strings.Contains(s, w) {
			return true
		}
	}
	return false
}

var (
	userinfoRE = regexp.MustCompile(`(//)[^/@\s]+@`)
	tokenRE    = regexp.MustCompile(`\b(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b`)
)

// lastLine is the most informative single line of a failed git run, safe to put in an error:
// git's own "fatal:" (else "error:") line if there is one, the last line otherwise. URL
// credentials and GitHub-shaped tokens are masked even though git should never print them,
// and any of roots (the cache directory, as given and as git resolves it) is abbreviated.
func lastLine(stderr []byte, err error, roots ...string) string {
	var last, fatal, errLine string
	for _, ln := range strings.Split(string(stderr), "\n") {
		ln = strings.TrimSpace(ln)
		switch {
		case ln == "":
			continue
		case strings.HasPrefix(ln, "fatal:"):
			fatal = ln
		case strings.HasPrefix(ln, "error:"):
			errLine = ln
		}
		last = ln
	}
	line := cmp.Or(fatal, errLine, last)
	if line == "" && err != nil {
		line = err.Error()
	}
	line = userinfoRE.ReplaceAllString(line, "$1")
	line = tokenRE.ReplaceAllString(line, "«token»")
	for _, r := range roots {
		// The cache root is long and says nothing; shortening it keeps the part that matters
		// (which lock, which ref) inside the clip.
		if r != "" {
			line = strings.ReplaceAll(line, r, "<mirrors>")
		}
	}
	if r := []rune(line); len(r) > 200 {
		line = string(r[:199]) + "…"
	}
	return line
}
