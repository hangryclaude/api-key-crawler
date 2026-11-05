package bench

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"keyguard/internal/testkit"
)

// Every test runs against throwaway state: KEYGUARD_HOME and the global git config point into
// a temp dir, so nothing here can read or write the real ~/.keyguard or ~/.gitconfig.
var testHome string

func TestMain(m *testing.M) {
	home, err := os.MkdirTemp("", "keyguard-bench-test-")
	if err != nil {
		panic(err)
	}
	testHome = home
	gitconfig := filepath.Join(home, "gitconfig")
	if err := os.WriteFile(gitconfig, nil, 0o600); err != nil {
		panic(err)
	}
	os.Setenv("KEYGUARD_HOME", filepath.Join(home, "keyguard"))
	os.Setenv("GIT_CONFIG_GLOBAL", gitconfig)
	code := testkit.Run(m)
	os.RemoveAll(home)
	os.Exit(code)
}

var shared struct {
	once sync.Once
	c    *Corpus
	err  error
}

// sharedCorpus is the seed-1 corpus most tests read; generating it takes a couple of seconds,
// so it is built once per test binary inside the temp home.
func sharedCorpus(t *testing.T) *Corpus {
	t.Helper()
	shared.once.Do(func() {
		shared.c, shared.err = Generate(filepath.Join(testHome, "shared"), Options{Seed: 1})
	})
	if shared.err != nil {
		t.Fatal(shared.err)
	}
	return shared.c
}

// recOf returns the in-memory record of a plant (raw value, rendered file).
func recOf(c *Corpus, id string) *plantRec {
	for _, r := range c.recs {
		if r.id == id {
			return r
		}
	}
	return nil
}

func gitOut(t *testing.T, repo string, args ...string) string {
	t.Helper()
	out, err := git(repo, nil, args...)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// gitOK reports whether a git command exits zero (merge-base --is-ancestor answers by exit code).
func gitOK(repo string, args ...string) bool {
	_, err := git(repo, nil, args...)
	return err == nil
}
