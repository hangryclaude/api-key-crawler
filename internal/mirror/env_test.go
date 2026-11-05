package mirror

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"keyguard/internal/core"
)

// tenv is a sandbox: a private HOME, a private global git config, an upstream repository
// to mirror, and a mirror root. Nothing here can reach ~/.gitconfig or ~/.keyguard.
type tenv struct {
	t       *testing.T
	tmp     string
	root    string // mirror cache root
	up      string // upstream working repository
	plain   string // global git config without keyguard hooks
	hooked  string // the same plus keyguard hooks that log and fail
	hookLog string
	pidFile string
	m       *Mirror
}

func newTenv(t *testing.T, mod func(*Config)) *tenv {
	t.Helper()
	tmp := t.TempDir()
	e := &tenv{t: t, tmp: tmp, root: filepath.Join(tmp, "mirrors"), up: filepath.Join(tmp, "upstream"),
		plain: filepath.Join(tmp, "gitconfig-plain"), hooked: filepath.Join(tmp, "gitconfig-hooked"),
		hookLog: filepath.Join(tmp, "hook.log"), pidFile: filepath.Join(tmp, "blocker.pid")}
	base := "[user]\n\tname = t\n\temail = t@example.com\n[init]\n\tdefaultBranch = main\n[protocol \"file\"]\n\tallow = always\n" +
		"[protocol \"ext\"]\n\tallow = always\n" +
		// A remote that never answers, for the timeout test: file:///kg-block runs a shell that
		// records its pid and sleeps. Inside one ext:: argument "% " stands for a space.
		"[url \"ext::sh -c echo% $$% >% " + e.pidFile + ";% exec% sleep% 31\"]\n\tinsteadOf = file:///kg-block\n"
	write(t, e.plain, base)
	hook := func(name, event string) string {
		// The whole command is quoted: an unquoted ';' would start a config comment.
		return fmt.Sprintf("[hook %q]\n\tevent = %s\n\tcommand = \"echo %s >> %s; exit 1\"\n", name, event, event, shellQuote(e.hookLog))
	}
	write(t, e.hooked, base+hook("keyguard-reftx", "reference-transaction")+hook("keyguard-precommit", "pre-commit")+hook("keyguard-prepush", "pre-push"))

	t.Setenv("HOME", tmp)
	t.Setenv("KEYGUARD_HOME", filepath.Join(tmp, "kg"))
	t.Setenv("GIT_CONFIG_GLOBAL", e.plain)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	for _, k := range []string{"GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_TRACE", "GIT_CURL_VERBOSE"} {
		t.Setenv(k, "")
		os.Unsetenv(k)
	}

	cfg := Config{Root: e.root, AllowLocal: true}
	if mod != nil {
		mod(&cfg)
	}
	m, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.m = m
	e.git("init", "-q", "-b", "main")
	e.commit("README", "one\n", "first")
	return e
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// useHooks makes the process-wide git config the one carrying keyguard's hooks, so anything
// the Mirror runs would trip them if it forgot the switches. e.git keeps using the plain one.
func (e *tenv) useHooks() { e.t.Setenv("GIT_CONFIG_GLOBAL", e.hooked) }

// git runs real git in the upstream repository under the plain config.
func (e *tenv) git(args ...string) string {
	e.t.Helper()
	if _, err := os.Stat(e.up); err != nil {
		if err := os.MkdirAll(e.up, 0o755); err != nil {
			e.t.Fatal(err)
		}
	}
	cmd := exec.Command("git", append([]string{"-C", e.up}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL="+e.plain)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		e.t.Fatalf("git %v: %v\n%s", args, err, errb.String())
	}
	return strings.TrimSpace(out.String())
}

func (e *tenv) commit(file, content, msg string) string {
	e.t.Helper()
	write(e.t, filepath.Join(e.up, file), content)
	e.git("add", file)
	e.git("commit", "-q", "-m", msg)
	return e.git("rev-parse", "HEAD")
}

// src is the upstream as a Source; owner and name only decide the mirror path.
func (e *tenv) src(owner, name, kind string) core.Source {
	id := "github.com/" + owner + "/" + name
	return core.Source{ID: id, Kind: kind, Owner: owner, Name: name, CloneURL: "file://" + e.up, Visibility: core.Private}
}

func (e *tenv) sync(s core.Source) Result {
	e.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	r, err := e.m.SyncResult(ctx, s)
	if err != nil {
		e.t.Fatalf("Sync(%s): %v", s.ID, err)
	}
	return r
}

// tips reads the upstream's refs under refs/ in the same form the mirror reports them.
func (e *tenv) tips() map[string]string {
	e.t.Helper()
	out := map[string]string{}
	for _, ln := range strings.Split(e.git("for-each-ref", "--format=%(objectname) %(refname)"), "\n") {
		if tip, ref, ok := strings.Cut(ln, " "); ok {
			out[ref] = tip
		}
	}
	return out
}

// fakeSecret builds a token-shaped string at run time so no such literal exists in source.
func fakeSecret(t *testing.T, prefix string, n int) string {
	t.Helper()
	const cs = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		x, err := rand.Int(rand.Reader, big.NewInt(int64(len(cs))))
		if err != nil {
			t.Fatal(err)
		}
		b[i] = cs[x.Int64()]
	}
	return prefix + string(b)
}

// rawGitCmd is git exactly as a person would run it: none of the Mirror's switches, the
// process environment as it stands (which may carry the hooked config).
func rawGitCmd(args ...string) *exec.Cmd {
	cmd := exec.Command("git", args...)
	cmd.Env = os.Environ()
	return cmd
}
