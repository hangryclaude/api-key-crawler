package known

import (
	"bytes"
	"io"
	"os/exec"
	"strings"
	"testing"

	"keyguard/internal/fp"
)

// matcherFor registers the values under ephemeral salt, the way selftest and bench do.
func textMatcher(t testing.TB, vals map[string]string) *Matcher {
	t.Helper()
	kr := fp.NewEphemeral()
	var es []Entry
	for name, v := range vals {
		es = append(es, EntriesFor(kr, name, "test", []byte(v))...)
	}
	m, err := NewMatcher(kr, es)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// gitOut runs git in dir and returns its stdout. Arguments can hold fakes, so only the
// subcommand is named on failure.
func gitOut(t testing.TB, dir string, args ...string) []byte {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		t.Fatalf("git %s: %v: %s", args[0], err, errb.String())
	}
	return out.Bytes()
}

func TestMatchMessagesAndRefsOnARealRepo(t *testing.T) {
	testEnv(t)
	r := newRNG(t)
	// Plain alphanumerics: git trims white space from messages and names, and a ref name
	// can hold only some characters.
	mk := func(prefix string) string { return prefix + randFrom(r, alnum, 40) }
	inMsg, inBody, inAuthor, inTag, inBranch, inLight := mk("sk-proj-"), mk("ghp_"), mk("sk-live_"), mk("tok_"), mk("tok1"), mk("tok2")
	m := textMatcher(t, map[string]string{"IN_SUBJECT": inMsg, "IN_BODY": inBody, "IN_AUTHOR": inAuthor, "IN_TAG": inTag, "IN_BRANCH": inBranch, "IN_LIGHT": inLight})

	repo := t.TempDir()
	gitOut(t, repo, "init", "-q", "-b", "main")
	gitOut(t, repo, "-c", "user.name=Plain", "-c", "user.email=plain@example.invalid", "commit", "-q", "--allow-empty", "-m", "clean")
	gitOut(t, repo, "-c", "user.name=Plain", "-c", "user.email=plain@example.invalid", "commit", "-q", "--allow-empty", "-m", "subject "+inMsg+"\n\nfirst line\nsecond "+inBody+" line")
	gitOut(t, repo, "-c", "user.name="+inAuthor, "-c", "user.email=a@example.invalid", "commit", "-q", "--allow-empty", "-m", "authored")
	gitOut(t, repo, "-c", "user.name=Plain", "-c", "user.email=plain@example.invalid", "tag", "-a", "v1", "-m", "release "+inTag)
	gitOut(t, repo, "tag", inLight)
	gitOut(t, repo, "branch", inBranch)

	var got []TextHit
	collect := func(h TextHit) { got = append(got, h) }

	// Commit messages and authors.
	if err := MatchMessages(m, bytes.NewReader(gitOut(t, repo, "log", "-z", "--format="+MessageFormat, "main", "--")), collect); err != nil {
		t.Fatal(err)
	}
	want := map[string]struct {
		field string
		line  int
	}{"IN_SUBJECT": {"commit message", 1}, "IN_BODY": {"commit message", 4}, "IN_AUTHOR": {"author name", 1}}
	for _, h := range got {
		w, ok := want[h.Name]
		if !ok {
			t.Errorf("unexpected hit on %s", h.Name)
			continue
		}
		if h.Field != w.field || h.Line != w.line || len(h.Commit) != 40 {
			t.Errorf("%s: field %q line %d commit %q, want %q line %d", h.Name, h.Field, h.Line, h.Commit, w.field, w.line)
		}
		delete(want, h.Name)
	}
	if len(want) != 0 {
		t.Errorf("not found in the commits: %v", want)
	}

	// Ref names and tag annotations.
	got = nil
	if err := MatchRefs(m, bytes.NewReader(gitOut(t, repo, "for-each-ref", "--format="+RefFormat)), collect); err != nil {
		t.Fatal(err)
	}
	wantRef := map[string]string{"IN_TAG": "tag annotation", "IN_LIGHT": "ref name", "IN_BRANCH": "ref name"}
	for _, h := range got {
		if h.Field == "ref contents" || h.Field == "commit message" { // the commits' own messages, seen through the tips
			continue
		}
		w, ok := wantRef[h.Name]
		if !ok || h.Field != w {
			t.Errorf("hit on %s in %q", h.Name, h.Field)
			continue
		}
		if !strings.HasPrefix(h.Ref, "refs/") {
			t.Errorf("%s: ref %q", h.Name, h.Ref)
		}
		delete(wantRef, h.Name)
	}
	if len(wantRef) != 0 {
		t.Errorf("not found in the refs: %v", wantRef)
	}
}

func TestTextHitsAreShapesNeverValues(t *testing.T) {
	r := newRNG(t)
	key := "sk-proj-" + randFrom(r, alnum, 40)
	other := "ghp_" + randFrom(r, alnum, 36)
	m := textMatcher(t, map[string]string{"A": key, "B": other})
	text := []byte("first line\nuse " + key + " and " + other + " together\nlast line\n")
	var hits []TextHit
	MatchText(m, "commit message", "abc", "", text, func(h TextHit) { hits = append(hits, h) })
	if len(hits) != 2 {
		t.Fatalf("%d hits", len(hits))
	}
	for _, h := range hits {
		if h.Line != 2 {
			t.Errorf("line %d", h.Line)
		}
		assertNoValue(t, []string{key, other}, map[string][]byte{"context": []byte(h.Context), "shape": []byte(h.Shape)})
		if !strings.Contains(h.Context, "«") {
			t.Errorf("context shows no shape: %q", h.Context)
		}
	}
}

func TestMatchMessagesToleratesRecordsItCannotPlace(t *testing.T) {
	key := "sk-proj-" + randFrom(newRNG(t), alnum, 40)
	m := textMatcher(t, map[string]string{"A": key})
	// No marker, no author lines, a truncated record, a trailing NUL: each is still searched.
	for name, in := range map[string]string{
		"no marker":     "just text " + key + "\x00",
		"short record":  "\x01KG " + strings.Repeat("a", 40) + "\nname\n" + key + "\x00",
		"no final NUL":  "\x01KG " + strings.Repeat("a", 40) + "\nn\ne\nmessage " + key,
		"empty records": "\x00\x00\x01KG " + strings.Repeat("a", 40) + "\nn\ne\n" + key + "\x00\x00",
	} {
		n := 0
		if err := MatchMessages(m, strings.NewReader(in), func(TextHit) { n++ }); err != nil || n != 1 {
			t.Errorf("%s: %d hits, err %v", name, n, err)
		}
	}
	// A record past the cap is an error, not a silent skip.
	big := io.LimitReader(repeat('a'), maxRecord+1)
	if err := MatchMessages(m, big, func(TextHit) {}); err == nil {
		t.Error("an oversized record was read without complaint")
	}
}

type repeat byte

func (r repeat) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(r)
	}
	return len(p), nil
}
