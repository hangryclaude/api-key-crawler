package mirror

import (
	"context"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"keyguard/internal/core"
)

// The sweep scope (PLAN.md): a source a stranger cannot read is never fetched, and a mirror of
// it that is already on disk is left as it was.
func TestExposedOnlyRefusesAPrivateSourceAndTouchesNothing(t *testing.T) {
	spyDir := t.TempDir()
	script, logPath := spyGit(t, spyDir)
	e := newTenv(t, func(c *Config) { c.Git = script; c.ExposedOnly = true })
	s := e.src("o", "n", "repo")

	for _, vis := range []core.Visibility{core.Private, core.Local, ""} {
		s.Visibility = vis
		_, err := e.m.SyncResult(context.Background(), s)
		if !errors.Is(err, ErrNotExposed) {
			t.Fatalf("visibility %q: %v", vis, err)
		}
		if _, _, err := e.m.Sync(context.Background(), s); !errors.Is(err, ErrNotExposed) {
			t.Fatalf("visibility %q through core.Mirror: %v", vis, err)
		}
	}
	if _, err := os.Stat(e.root); err != nil {
		t.Fatal(err)
	}
	if ents, _ := os.ReadDir(e.root); len(ents) != 0 {
		t.Fatalf("a refused source left %d entries under the cache root", len(ents))
	}
	if b, err := os.ReadFile(logPath); err == nil {
		t.Fatalf("git ran for a source that was refused:\n%s", b)
	}

	// Exposed means public, a secret gist, or not yet known; those are fetched.
	for _, vis := range []core.Visibility{core.Public, core.SecretGist, core.Unknown} {
		other := e.src("o", "n-"+string(vis), "repo")
		other.Visibility = vis
		if r := e.sync(other); !r.Cloned {
			t.Fatalf("visibility %q: %+v", vis, r)
		}
	}
}

func TestExposedOnlyLeavesAnExistingMirrorOfAFlippedRepoExactlyAsItWas(t *testing.T) {
	e := newTenv(t, func(c *Config) { c.ExposedOnly = true })
	s := e.src("o", "n", "repo")
	s.Visibility = core.Public
	first := e.sync(s)

	e.commit("later", "x\n", "after it went private")
	e.git("tag", "-a", "v2", "-m", "x")
	dir := e.m.Path(s)
	before := dirState(t, dir)

	s.Visibility = core.Private
	if _, err := e.m.SyncResult(context.Background(), s); !errors.Is(err, ErrNotExposed) {
		t.Fatalf("%v", err)
	}
	if after := dirState(t, dir); !maps.Equal(before, after) {
		t.Fatalf("the mirror of a repo that went private changed while it was refused")
	}
	if tips, err := e.m.Tips(context.Background(), s); err != nil || !maps.Equal(tips, first.After) {
		t.Fatalf("it holds what it held: %v %v", tips, err)
	}

	// The day it is public again the fetch resumes where the mirror stopped.
	s.Visibility = core.Public
	if r := e.sync(s); r.Cloned || r.After["refs/tags/v2"] == "" {
		t.Fatalf("%+v", r)
	}
}

func dirState(t *testing.T, dir string) map[string]string {
	t.Helper()
	m := map[string]string{}
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		m[strings.TrimPrefix(p, dir)] = fi.ModTime().String() + " " + fi.Mode().String()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// A repository's owner controls refs/replace/*. With a replacement honored, an old commit can
// be made to read as something else, and a leaking one to read clean. Every git the mirror
// starts, and the sweep after it, runs with replacement off (PLAN invariant 6).
func TestAReplaceRefCannotRewriteACommitForGitRunInTheMirrorsEnvironment(t *testing.T) {
	e := newTenv(t, nil)
	c1 := e.commit("a", "real content\n", "the real commit")
	e.commit("b", "more\n", "second")
	empty := e.git("hash-object", "-t", "tree", "/dev/null")
	decoy := e.git("commit-tree", empty, "-m", "a decoy that says nothing")
	e.git("replace", c1, decoy)
	s := e.src("o", "n", "repo")
	e.sync(s) // mirror clones refs/replace/* with everything else
	dir := e.m.Path(s)

	read := func(env []string) string {
		cmd := rawGitCmd("--git-dir="+dir, "cat-file", "-p", c1)
		cmd.Env = env
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("%v", err)
		}
		return string(out)
	}
	if got := read(append(os.Environ(), "GIT_CONFIG_GLOBAL="+e.plain)); !strings.Contains(got, "a decoy that says nothing") {
		t.Fatalf("control: git run the ordinary way should have read the decoy, got\n%s", got)
	}
	if got := read(e.m.env()); !strings.Contains(got, "the real commit") || strings.Contains(got, "decoy") {
		t.Fatalf("in the mirror's environment the commit is what it is, got\n%s", got)
	}
}

func TestChildGitEnvironmentIsHermeticWhereTheSandboxLetsItBe(t *testing.T) {
	e := newTenv(t, nil)
	t.Setenv("GIT_CONFIG_COUNT", "1")
	t.Setenv("GIT_CONFIG_KEY_0", "core.hooksPath")
	t.Setenv("GIT_CONFIG_VALUE_0", "/tmp/evil")
	t.Setenv("GIT_CONFIG_PARAMETERS", "'core.hooksPath=/tmp/evil'")
	env := strings.Join(e.m.env(), "\n")
	for _, want := range []string{"GIT_NO_REPLACE_OBJECTS=1", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_SYSTEM=/dev/null"} {
		if !strings.Contains(env, want) {
			t.Errorf("child environment lacks %s", want)
		}
	}
	// What a caller (a git hook, say) put in the environment as config would otherwise be read
	// by every command the mirror runs.
	for _, bad := range []string{"GIT_CONFIG_COUNT=", "GIT_CONFIG_KEY_0=", "GIT_CONFIG_VALUE_0=", "GIT_CONFIG_PARAMETERS="} {
		if strings.Contains(env, bad) {
			t.Errorf("child environment still has %s", bad)
		}
	}
	// And it still fetches.
	r := e.sync(e.src("o", "n", "repo"))
	if !r.Cloned {
		t.Fatalf("%+v", r)
	}
}
