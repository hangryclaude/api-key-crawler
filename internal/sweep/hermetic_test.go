package sweep

import (
	"strings"
	"testing"

	"keyguard/internal/core"
)

// refs/replace/* in a mirror is the repository owner's data. With it honored, a replacement
// commit stands in for a real one, and a commit that leaked a key reads as an empty one. The
// sweep reads mirrors with replacement off (PLAN invariant 6).
func TestAReplaceRefCannotHideAKeyFromTheKnownPass(t *testing.T) {
	w, known, _ := worldWithKnown(t)
	a := w.addRepo("a", core.Public)
	raw := fakeKey(t, "sk-", 48)
	known.add(raw, "OPENAI_API_KEY")
	c1 := a.commit("env", map[string]string{".env": "OPENAI_API_KEY=" + raw + "\n"})
	a.commit("remove it", map[string]string{".env": ""})
	empty := a.git("hash-object", "-t", "tree", "/dev/null")
	decoy := a.git("commit-tree", empty, "-m", "nothing to see")
	a.git("replace", c1, decoy)

	if out := a.git("rev-list", "--objects", "--all"); strings.Contains(out, ".env") {
		t.Fatalf("control: with replacement honored the key's commit should be gone from the walk:\n%s", out)
	}
	mustPoll(t, w.runner())
	s := w.secret(raw)
	if len(s.Locations) != 1 || s.Locations[0].Commit != c1 || s.Locations[0].Path != ".env" {
		t.Fatalf("the key is in the real commit, whatever the replace ref says: %+v", s.Locations)
	}
}

func TestSweepGitRunsWithoutAnyConfigButItsOwn(t *testing.T) {
	t.Setenv("GIT_CONFIG_COUNT", "1")
	t.Setenv("GIT_CONFIG_KEY_0", "core.hooksPath")
	t.Setenv("GIT_CONFIG_VALUE_0", "/tmp/elsewhere")
	t.Setenv("GIT_CONFIG_PARAMETERS", "'core.hooksPath=/tmp/elsewhere'")
	t.Setenv("GIT_DIR", "/tmp/not-the-mirror")
	env := strings.Join(gitEnv(), "\n")
	for _, want := range []string{"GIT_NO_REPLACE_OBJECTS=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0"} {
		if !strings.Contains(env, want) {
			t.Errorf("missing %s", want)
		}
	}
	for _, bad := range []string{"GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0", "GIT_CONFIG_PARAMETERS", "GIT_DIR="} {
		if strings.Contains(env, bad) {
			t.Errorf("the environment still carries %s", bad)
		}
	}
	// The caller's global config (a test's identity, the user's own) is replaced, not extended.
	for _, kv := range gitEnv() {
		if strings.HasPrefix(kv, "GIT_CONFIG_GLOBAL=") && kv != "GIT_CONFIG_GLOBAL=/dev/null" {
			t.Errorf("%s", kv)
		}
	}
}
