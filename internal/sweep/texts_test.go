package sweep

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"keyguard/internal/core"
)

// STEAL P0-13, the third path. A key typed into a commit message, an author name, a tag's
// annotation or a branch name is in no blob and no engine reads it, so only the known pass can
// see it. These are all places GitHub shows to strangers.
func TestTheKnownPassReadsMessagesAuthorsTagsAndRefNames(t *testing.T) {
	w, known, _ := worldWithKnown(t)
	a := w.addRepo("a", core.Public)
	raw := fakeKey(t, "sk-", 48)
	known.add(raw, "OPENAI_API_KEY")

	a.commit("init", map[string]string{"README.md": "a project\n"})
	a.git("-c", "user.name=ok", "commit", "-q", "--allow-empty", "-m", "subject\n\nthe key is "+raw)
	a.git("-c", "user.name="+raw, "commit", "-q", "--allow-empty", "-m", "an author named for a key")
	old := a.git("rev-parse", "HEAD~2")
	a.git("tag", "-a", "v1", "-m", "release, key "+raw, old) // a tag on a commit that is nobody's news
	a.git("branch", raw)

	r := w.runner()
	mustPoll(t, r)

	sec := w.secret(raw)
	if sec.Known == "" || sec.Severity != core.Critical || !sec.Exposed() {
		t.Fatalf("a learned key in the text of a public repo should be critical: %+v", sec)
	}
	places := map[string]core.Location{}
	for _, l := range sec.Locations {
		places[l.Path] = l
	}
	for _, field := range []string{"(commit message)", "(author name)", "(tag annotation)", "(ref name)"} {
		if _, ok := places[field]; !ok {
			t.Errorf("no location says %s: %+v", field, sec.Locations)
		}
	}
	if m := places["(commit message)"]; m.Commit == "" || m.Line != 3 {
		t.Errorf("the message hit should name its commit and the line it is on: %+v", m)
	}
	if tag := places["(tag annotation)"]; tag.Ref != "refs/tags/v1" {
		t.Errorf("the tag annotation hit should name the tag: %+v", tag)
	}
	for _, l := range sec.Locations {
		if strings.Contains(l.Path+l.Ref+l.Source+l.URL, raw) {
			t.Fatalf("a location holds the key itself: %+v", l)
		}
	}
	if l := places["(ref name)"]; l.Ref != "" {
		t.Errorf("a ref named for the key must not be named in its hit: %+v", l)
	}
	// The mirror is a git store of the repo, which holds the key by construction; what keyguard
	// wrote (findings, per-source state, run records) must not.
	err := filepath.WalkDir(w.paths.State, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if b, rerr := os.ReadFile(p); rerr == nil && strings.Contains(string(b), raw) {
			t.Errorf("%s holds the key", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// A tag made later on an old commit adds nothing to the range, and is still looked at.
func TestATagOnAnOldCommitIsReadAtTheNextPoll(t *testing.T) {
	w, known, _ := worldWithKnown(t)
	a := w.addRepo("a", core.Public)
	raw := fakeKey(t, "sk-", 48)
	known.add(raw, "OPENAI_API_KEY")
	a.commit("init", map[string]string{"README.md": "a project\n"})
	a.commit("second", map[string]string{"b.txt": "b\n"})
	r := w.runner()
	mustPoll(t, r)
	if _, ok := w.store.Get(w.kr.FP(raw)); ok {
		t.Fatal("the key is in the findings before anything holds it")
	}

	a.git("tag", "-a", "v1", "-m", "notes, key "+raw, "HEAD~1")
	w.pushed("a")
	mustPoll(t, r)
	sec := w.secret(raw)
	if len(sec.Locations) != 1 || sec.Locations[0].Path != "(tag annotation)" {
		t.Errorf("the new tag's annotation was not read: %+v", sec.Locations)
	}
}

// A repo whose messages and refs hold nothing says nothing, and a failing git is not a clean read.
func TestTheTextPassIsQuietWhenThereIsNothingAndLoudWhenGitFails(t *testing.T) {
	w, known, _ := worldWithKnown(t)
	a := w.addRepo("a", core.Public)
	known.add(fakeKey(t, "sk-", 48), "OPENAI_API_KEY")
	a.commit("init", map[string]string{"README.md": "a project\n"})
	st := mustPoll(t, w.runner())
	for _, n := range st.Notes {
		if strings.Contains(n, "commit messages") || strings.Contains(n, "ref names") {
			t.Errorf("a quiet repo produced a text note: %s", n)
		}
	}

	g := GitKnown{Git: "git"}
	err := g.scanText(t.Context(), t.TempDir(), []string{"--all"}, known, core.Location{}, func(core.Hit) {})
	if err == nil || !strings.Contains(err.Error(), "commit messages") || !strings.Contains(err.Error(), "ref names and tag annotations") {
		t.Errorf("a directory that is no repository must fail both reads, not look clean: %v", err)
	}
}
