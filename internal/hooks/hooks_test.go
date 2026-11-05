package hooks

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"keyguard/internal/core"
)

func TestRunDispatch(t *testing.T) {
	e := newTenv(t)
	e.activate()
	repo := e.initRepo("r")
	key := fakeGitHub()
	base := e.quietCommit(repo, "a.txt", "a\n", "base")
	sha := e.dangling(repo, base, "k.txt", key+"\n", "c") // as git commit leaves it while the ref update is prepared
	e.write(repo, "staged.txt", key+"\n")
	e.must(repo, "add", "staged.txt")
	e.write(repo, "msg.txt", "deploy "+key+"\n")
	var stderr strings.Builder
	d := Deps{Dir: repo, Stderr: &stderr, Known: newSubMatcher([]string{"K=" + key}), FP: testKeyring}

	if code := Run(context.Background(), "no-such-hook", nil, strings.NewReader(""), d); code != 0 || !strings.Contains(stderr.String(), `unknown hook "no-such-hook"`) {
		t.Errorf("unknown hook: code %d, stderr %q", code, stderr.String())
	}
	for _, c := range []struct {
		name  string
		args  []string
		stdin string
		want  string
	}{
		{NamePreCommit, nil, "", "commit blocked"},
		{NameCommitMsg, []string{"msg.txt"}, "", "commit message blocked"},
		{NameRefTx, []string{"prepared"}, fmt.Sprintf("%s %s refs/heads/x\n", zeroOID, sha), "ref update blocked"},
		{NamePrePush, []string{"origin", "u"}, fmt.Sprintf("refs/heads/main %s refs/heads/main %s\n", sha, zeroOID), "push blocked"},
	} {
		stderr.Reset()
		if code := Run(context.Background(), c.name, c.args, strings.NewReader(c.stdin), d); code != 1 || !strings.Contains(stderr.String(), c.want) {
			t.Errorf("%s: code %d, stderr:\n%s", c.name, code, stderr.String())
		}
		assertNoLeak(t, c.name, stderr.String(), key)
	}
}

// Everything Deps leaves nil is a check that is off, never a crash: the hooks must run
// with a bare Deps{} (a fresh install before any engine is wired).
func TestZeroDepsAreSafe(t *testing.T) {
	e := newTenv(t)
	e.activate()
	repo := e.initRepo("r")
	sha := e.quietCommit(repo, "a.txt", "a\n", "c")
	e.write(repo, "b.txt", "b\n")
	e.must(repo, "add", "b.txt")
	var stderr strings.Builder
	d := Deps{Dir: repo, Stderr: &stderr}
	for name, c := range map[string]struct {
		args  []string
		stdin string
	}{
		NamePreCommit: {nil, ""},
		NameCommitMsg: {[]string{"b.txt"}, ""},
		NameRefTx:     {[]string{"prepared"}, fmt.Sprintf("%s %s refs/heads/x\n", zeroOID, sha)},
		NamePrePush:   {[]string{"origin", "u"}, fmt.Sprintf("refs/heads/main %s refs/heads/main %s\n", sha, zeroOID)},
	} {
		if code := Run(context.Background(), name, c.args, strings.NewReader(c.stdin), d); code != 0 {
			t.Errorf("%s with zero Deps: code %d, stderr %q", name, code, stderr.String())
		}
	}
	// And a nil Stderr falls back to os.Stderr instead of panicking.
	if code := Run(context.Background(), NameRefTx, []string{"committed"}, strings.NewReader(""), Deps{Dir: repo}); code != 0 {
		t.Errorf("nil Stderr: code %d", code)
	}
	var _ core.KnownMatcher = (*subMatcher)(nil)
}
