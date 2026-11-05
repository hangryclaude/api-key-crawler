package known

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"keyguard/internal/fp"
)

// newRepo makes a real git repository under the test's isolated environment.
func newRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	git(t, dir, "init", "-q", "-b", "main")
	return dir
}

func writeFile(t *testing.T, dir, rel, content string) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func commit(t *testing.T, dir, msg string) string {
	t.Helper()
	git(t, dir, "add", "-A")
	git(t, dir, "commit", "-q", "-m", msg)
	return strings.TrimSpace(git(t, dir, "rev-parse", "HEAD"))
}

// matcherFor registers the given values (name -> raw) under a fresh keyring.
func matcherFor(t testing.TB, values map[string]string) (*Matcher, *fp.Keyring) {
	t.Helper()
	kr := fp.NewEphemeral()
	var entries []Entry
	names := make([]string, 0, len(values))
	for n := range values {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		entries = append(entries, EntriesFor(kr, n, "/test/"+n, []byte(values[n]))...)
	}
	m, err := NewMatcher(kr, entries)
	if err != nil {
		t.Fatal(err)
	}
	return m, kr
}

func lines(n int, prefix string) string {
	var sb strings.Builder
	for i := 1; i <= n; i++ {
		fmt.Fprintf(&sb, "%s line %d\n", prefix, i)
	}
	return sb.String()
}

type where struct {
	path string
	line int
	name string
}

func (w where) String() string { return fmt.Sprintf("%s:%d %s", w.path, w.line, w.name) }

func whereAll(lm []LineMatch) []string {
	var out []string
	for _, l := range lm {
		out = append(out, where{l.Path, l.Line, l.Name}.String())
	}
	sort.Strings(out)
	return out
}

func TestMatchDiffRealGitStaged(t *testing.T) {
	testEnv(t)
	r := newRNG(t)
	s1 := "sk-proj-" + randFrom(r, alnum, 40)
	s2 := "ghp_" + randFrom(r, alnum, 36)
	s3 := randFrom(r, alnum, 30)
	s4 := randFrom(r, hexchars, 40)
	s5 := randFrom(r, alnum, 30)
	m, _ := matcherFor(t, map[string]string{"S1": s1, "S2": s2, "S3": s3, "S4": s4, "S5": s5})

	dir := newRepo(t)
	// The old tree holds S3 on a line the change removes, and S5 on an unchanged line that
	// shows up as context under -U3.
	writeFile(t, dir, "a.txt", lines(4, "a")+"old token "+s3+"\n"+lines(3, "tail"))
	writeFile(t, dir, "keep.txt", lines(2, "k")+"stays "+s5+"\n"+lines(2, "k2"))
	writeFile(t, dir, "docs/with space.txt", lines(3, "d"))
	writeFile(t, dir, "naïve.txt", lines(3, "n"))
	writeFile(t, dir, "crlf.txt", "one\r\ntwo\r\n")
	writeFile(t, dir, "nonl.txt", "first\nlast")
	commit(t, dir, "base")

	// The change: S1 added mid-file, S3 removed, a new file with the base64 of S2, a path
	// with a space, a non-ASCII path, CRLF, and a secret on a last line without a newline.
	writeFile(t, dir, "a.txt", lines(4, "a")+"new line with key "+s1+" in it\n"+lines(3, "tail"))
	writeFile(t, dir, "keep.txt", lines(2, "k")+"stays "+s5+"\n"+lines(2, "k2")+"appended\n")
	writeFile(t, dir, "new.env", "A=1\nB="+b64(s2)+"\nC=3\n")
	writeFile(t, dir, "docs/with space.txt", lines(3, "d")+"secret="+s4+"\n")
	writeFile(t, dir, "naïve.txt", lines(3, "n")+"x "+s3+"\n")
	writeFile(t, dir, "crlf.txt", "one\r\ntwo\r\nkey="+s1+"\r\n")
	writeFile(t, dir, "nonl.txt", "first\nlast "+s4)
	// git calls a file binary when it holds a NUL; random bytes only usually do, so make sure.
	bin := append(noise(r, 500, false), []byte(s1)...)
	bin[0] = 0
	writeFile(t, dir, "blob.bin", string(bin))
	git(t, dir, "add", "-A")

	want := []string{
		"a.txt:5 S1",
		"crlf.txt:3 S1",
		"docs/with space.txt:4 S4",
		"naïve.txt:4 S3",
		"new.env:2 S2",
		"nonl.txt:2 S4",
	}
	for _, args := range [][]string{
		{"diff", "--cached", "-U0", "--no-color", "--no-ext-diff"},
		{"diff", "--cached", "-U3", "--no-color", "--no-ext-diff"},
		{"-c", "core.quotePath=false", "diff", "--cached", "-U0", "--no-color", "--no-ext-diff"},
		{"-c", "diff.mnemonicPrefix=true", "diff", "--cached", "-U1", "--no-color", "--no-ext-diff"},
	} {
		diff := git(t, dir, args...)
		got := whereAll(m.MatchDiff([]byte(diff)))
		if strings.Join(got, "|") != strings.Join(want, "|") {
			t.Errorf("git %s:\n got  %q\n want %q", strings.Join(args, " "), got, want)
		}
	}

	// Context never carries the value, carries the shape, and columns point at the secret.
	diff := git(t, dir, "diff", "--cached", "-U0", "--no-color", "--no-ext-diff")
	for _, lm := range m.MatchDiff([]byte(diff)) {
		if lm.Name == "S1" && lm.Path == "a.txt" {
			if !strings.Contains(lm.Context, "«sk-proj-…") || !strings.Contains(lm.Context, "new line with key") || lm.Offset != len("new line with key ") {
				t.Errorf("context is wrong (offset %d, %d bytes)", lm.Offset, len(lm.Context))
			}
			if lm.Variant != "raw" || lm.Len != len(s1) || lm.EntryID == "" {
				t.Errorf("match fields: %+v", lm.KnownMatch)
			}
		}
		assertNoValue(t, []string{s1, s2, s3, s4, s5}, map[string][]byte{"context": []byte(lm.Context)})
	}

	// A diff with nothing to find costs nothing and returns nil.
	if got := m.MatchDiff([]byte(git(t, dir, "diff", "--cached", "-U0", "--no-color", "--no-ext-diff", "--", "keep.txt"))); got != nil {
		t.Errorf("clean diff matched: %v", whereAll(got))
	}
}

func TestMatchDiffManyHunksAndLineNumbers(t *testing.T) {
	testEnv(t)
	r := newRNG(t)
	s := "sk-proj-" + randFrom(r, alnum, 40)
	m, _ := matcherFor(t, map[string]string{"S": s})
	dir := newRepo(t)
	var base, next strings.Builder
	for i := 1; i <= 12000; i++ {
		fmt.Fprintf(&base, "line %d\n", i)
		switch {
		case i == 700 || i == 9000:
			fmt.Fprintf(&next, "line %d\nadded after %d token=%s\n", i, i, s)
		case i == 5000:
			// removed: a deletion before later hunks must shift nothing
		case i == 11990:
			fmt.Fprintf(&next, "line %d\n+++ b/fake.txt %s\n", i, s) // content that looks like a header
		default:
			fmt.Fprintf(&next, "line %d\n", i)
		}
	}
	writeFile(t, dir, "big.txt", base.String())
	commit(t, dir, "base")
	writeFile(t, dir, "big.txt", next.String())
	git(t, dir, "add", "-A")
	// 701 (700 plus the added line); 9000 is shifted by the added line before it and the
	// removed line 5000, then +1 for its own added line: 9001; the header look-alike near the end is 11990 + 1 + 1 - 1 + 1.
	want := []string{"big.txt:11992 S", "big.txt:701 S", "big.txt:9001 S"}
	for _, u := range []string{"-U0", "-U3"} {
		got := whereAll(m.MatchDiff([]byte(git(t, dir, "diff", "--cached", u, "--no-color"))))
		if strings.Join(got, "|") != strings.Join(want, "|") {
			t.Errorf("%s: got %q want %q", u, got, want)
		}
	}
}

func TestMatchDiffTwoSecretsOnOneLine(t *testing.T) {
	testEnv(t)
	r := newRNG(t)
	a := "ghp_" + randFrom(r, alnum, 36)
	b := randFrom(r, alnum, 40)
	m, _ := matcherFor(t, map[string]string{"A": a, "B": b})
	dir := newRepo(t)
	writeFile(t, dir, "x.txt", "base\n")
	commit(t, dir, "base")
	writeFile(t, dir, "x.txt", "base\nuser:"+a+" and also "+b+"\n")
	git(t, dir, "add", "-A")
	got := m.MatchDiff([]byte(git(t, dir, "diff", "--cached", "-U0", "--no-color")))
	if len(got) != 2 || got[0].Line != 2 || got[1].Line != 2 || got[0].Name != "A" || got[1].Name != "B" {
		t.Fatalf("got %+v", got)
	}
	for _, lm := range got {
		if !strings.Contains(lm.Context, "«ghp_…") || strings.Count(lm.Context, "«") != 2 {
			t.Errorf("each context should show both secrets as shapes (%d bytes)", len(lm.Context))
		}
	}
}

// A long secret that starts more than 80 bytes before another match must not reappear,
// cut at the window's edge, in the other match's context.
func TestMatchDiffContextNeverShowsTheTailOfALongSecret(t *testing.T) {
	testEnv(t)
	r := newRNG(t)
	long := "eyJ" + randFrom(r, urlchars, 400)
	short := "ghp_" + randFrom(r, alnum, 36)
	m, _ := matcherFor(t, map[string]string{"LONG": long, "SHORT": short})
	dir := newRepo(t)
	writeFile(t, dir, "x.txt", "base\n")
	commit(t, dir, "base")
	// The window around SHORT starts 80 bytes before it, which is 15 bytes before the end of
	// LONG: too few for fp.Scrub to mask (it takes tokens of 20+), so only the replacement
	// of the whole of LONG keeps them out.
	writeFile(t, dir, "x.txt", "base\n"+long+strings.Repeat(" ", 65)+short+"\n")
	git(t, dir, "add", "-A")
	got := m.MatchDiff([]byte(git(t, dir, "diff", "--cached", "-U0", "--no-color")))
	if len(got) != 2 {
		t.Fatalf("%d matches", len(got))
	}
	for _, lm := range got {
		assertNoValue(t, []string{long, short}, map[string][]byte{"context of " + lm.Name: []byte(lm.Context)})
		if strings.Count(lm.Context, "«") != 2 {
			t.Errorf("context of %s should show both secrets as shapes (%d bytes)", lm.Name, len(lm.Context))
		}
	}
}

func TestMatchDiffLogOfCommitsAndMerge(t *testing.T) {
	testEnv(t)
	r := newRNG(t)
	s1 := "sk-proj-" + randFrom(r, alnum, 40)
	s2 := randFrom(r, alnum, 32)
	s3 := "xoxb-" + randFrom(r, alnum, 30)
	m, _ := matcherFor(t, map[string]string{"S1": s1, "S2": s2, "S3": s3})
	dir := newRepo(t)
	writeFile(t, dir, "f.txt", "one\ntwo\nthree\n")
	commit(t, dir, "base")
	git(t, dir, "checkout", "-q", "-b", "feature")
	writeFile(t, dir, "f.txt", "one\nfeature side\nthree\n")
	writeFile(t, dir, "feature.txt", "token "+s1+"\n")
	c1 := commit(t, dir, "feature: adds a token")
	git(t, dir, "checkout", "-q", "main")
	writeFile(t, dir, "f.txt", "one\nmain side\nthree\n")
	c2 := commit(t, dir, "main change, message mentions nothing")
	// The merge conflicts on f.txt; the resolution brings in a secret that exists in
	// neither parent, so only the combined diff shows it.
	cmd := exec.Command("git", "-C", dir, "merge", "--no-edit", "feature")
	if err := cmd.Run(); err == nil {
		t.Fatal("expected a conflict")
	}
	writeFile(t, dir, "f.txt", "one\nresolved with "+s2+"\nthree\n")
	git(t, dir, "add", "-A")
	git(t, dir, "commit", "-q", "--no-edit")
	merge := strings.TrimSpace(git(t, dir, "rev-parse", "HEAD"))
	writeFile(t, dir, "g.txt", "later "+s3+"\n")
	c3 := commit(t, dir, "adds s3")

	log := git(t, dir, "log", "-p", "--cc", "-U0", "--no-color", "--no-ext-diff", "--reverse")
	got := m.MatchDiff([]byte(log))
	type hit struct {
		commit, path, name string
		line               int
	}
	var seen []hit
	for _, l := range got {
		seen = append(seen, hit{l.Commit, l.Path, l.Name, l.Line})
	}
	want := []hit{
		{c1, "feature.txt", "S1", 1},
		{merge, "f.txt", "S2", 2},
		{c3, "g.txt", "S3", 1},
	}
	if fmt.Sprint(seen) != fmt.Sprint(want) {
		t.Errorf("log -p --cc:\n got  %v\n want %v\n(main commit %s is clean)", seen, want, c2)
	}
	// Without --cc a merge shows nothing, which is why the reference-transaction hook uses it.
	plain := git(t, dir, "log", "-p", "-U0", "--no-color", "--reverse")
	for _, l := range m.MatchDiff([]byte(plain)) {
		if l.Name == "S2" {
			t.Error("plain log -p unexpectedly showed the merge resolution")
		}
	}
	// git show of the merge, and a range diff, work the same way.
	show := git(t, dir, "show", "--cc", "-U0", "--no-color", merge)
	if got := whereAll(m.MatchDiff([]byte(show))); len(got) != 1 || got[0] != "f.txt:2 S2" {
		t.Errorf("show --cc: %v", got)
	}
	rng := git(t, dir, "diff", "-U0", "--no-color", c2+".."+c3)
	if got := whereAll(m.MatchDiff([]byte(rng))); len(got) != 3 {
		// the range from main's commit to the tip adds the feature file, the resolution and g.txt
		t.Errorf("range diff: %v", got)
	}
}

func TestMatchDiffNeverPanicsOnGarbage(t *testing.T) {
	r := newRNG(t)
	s := "sk-proj-" + randFrom(r, alnum, 40)
	m, _ := matcherFor(t, map[string]string{"S": s})
	hunks := []string{"@@ -1,2 +1,2 @@\n", "@@@ -1 -1 +1,2 @@@\n", "@@ -a +b @@\n", "@@\n", "@@@@ -1 -1 -1 +1 @@@@\n", "@@ -1,99999999999999999999 +1 @@\n"}
	for i := 0; i < 3000; i++ {
		var sb strings.Builder
		for j := r.IntN(30); j >= 0; j-- {
			switch r.IntN(6) {
			case 0:
				sb.WriteString(hunks[r.IntN(len(hunks))])
			case 1:
				sb.WriteString("+" + s + "\n")
			case 2:
				sb.WriteString("diff --git a/x b/x\n+++ b/x\n")
			case 3:
				sb.WriteString("commit " + randFrom(r, hexchars, 40) + "\n")
			case 4:
				sb.WriteString(string(noise(r, r.IntN(80), true)) + "\n")
			default:
				sb.WriteString(" ctx " + s + "\n-\\ No newline\n\\ No newline at end of file\n")
			}
		}
		for _, lm := range m.MatchDiff([]byte(sb.String())) {
			if lm.Line < 0 || lm.Offset < 0 || strings.Contains(lm.Context, s[10:30]) {
				t.Fatalf("bad line match %+v", lm)
			}
		}
	}
}

func FuzzMatchDiff(f *testing.F) {
	r := newRNG(f)
	s := "sk-proj-" + randFrom(r, alnum, 40)
	m, _ := matcherFor(f, map[string]string{"S": s})
	f.Add([]byte("diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -0,0 +1,2 @@\n+a\n+" + s + "\n"))
	f.Add([]byte("@@@ -1 -1 +1 @@@\n++" + s + "\n"))
	f.Add([]byte("commit abcdef0\n\n    msg\n\ndiff --cc f\n+++ b/f\n@@@ -1 -1 +1 @@@\n +" + s + "\n"))
	f.Fuzz(func(t *testing.T, diff []byte) {
		for _, lm := range m.MatchDiff(diff) {
			if lm.Line < 0 || lm.Offset < 0 || lm.Len <= 0 || strings.Contains(lm.Context, s[10:30]) {
				t.Fatalf("bad line match %+v", lm)
			}
		}
	})
}
