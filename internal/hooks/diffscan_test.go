package hooks

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"keyguard/internal/core"
)

type found struct {
	commit, path string
	line         int
	ctx          string
}

func scanText(t *testing.T, diff string, m core.KnownMatcher, maxCommits int) (res []found, commits int, capped bool) {
	t.Helper()
	commits, capped, err := scanAdded(strings.NewReader(diff), m, maxCommits, func(dm diffMatch) {
		res = append(res, found{dm.Commit, dm.Path, dm.Line, dm.Ctx})
	})
	if err != nil {
		t.Fatal(err)
	}
	return res, commits, capped
}

// fileDiff renders the diff of a file gaining lines at a position, as git would for -U0.
func fileDiff(path string, start int, lines ...string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "diff --git a/%[1]s b/%[1]s\nindex 0000000..1111111 100644\n--- a/%[1]s\n+++ b/%[1]s\n@@ -%[2]d,0 +%[3]d,%[4]d @@\n", path, max(start-1, 0), start, len(lines))
	for _, l := range lines {
		b.WriteString("+" + l + "\n")
	}
	return b.String()
}

func TestScanAddedAgainstRealGitDiff(t *testing.T) {
	e := newTenv(t)
	e.activate()
	repo := e.initRepo("r")
	key := fakeGitHub()
	m := newSubMatcher([]string{"K=" + key})

	// A base commit, then staged changes of every awkward kind.
	e.quietCommit(repo, "mod.txt", "a\nb\nc\nd\ne\n", "base")
	e.quietCommit(repo, "old name.txt", "keep me\nline2\nline3\nline4\nline5\n", "base2")
	e.quietCommit(repo, "gone.txt", "bye\n", "base3")
	e.write(repo, "mod.txt", "a\nb\nTOKEN="+key+"\nc\nd\ne\nlast="+key+"\n") // lines 3 and 7
	e.write(repo, "sp ace.txt", "x\n"+key+"\n")                              // name with a space
	e.write(repo, "tab\tname.txt", key+"\n")                                 // name git quotes
	e.write(repo, "é.txt", "ü\n\n"+key+"\n")                                 // non-ASCII name, blank line
	e.write(repo, "marks.txt", "++ plus\n-- minus\n+++ looks like a header\n--- also\n@@ -1 +1 @@\n"+key+"\n")
	e.write(repo, "crlf.txt", "one\r\n"+key+"\r\n")
	e.write(repo, "nonl.txt", "only line "+key)         // no trailing newline
	e.write(repo, "bin.dat", "\x00\x01\x02"+key+"\x00") // NULs make it binary; --text shows the bytes all the same
	e.must(repo, "mv", "old name.txt", "renamed.txt")
	e.write(repo, "renamed.txt", "keep me\nline2\nline3\nNEW="+key+"\nline4\nline5\n") // rename + edit
	e.must(repo, "rm", "-q", "gone.txt")
	e.must(repo, "add", "-A")

	h := newHook(context.Background(), Deps{Dir: repo}, NamePreCommit, preCommitTimeout)
	defer h.cancel()
	st, err := h.g.cachedPatch(h.ctx)
	if err != nil {
		t.Fatal(err)
	}
	var res []found
	_, _, serr := scanAdded(st.r, m, 0, func(dm diffMatch) { res = append(res, found{dm.Commit, dm.Path, dm.Line, dm.Ctx}) })
	if err := st.finish(false); serr == nil {
		serr = err
	}
	if serr != nil {
		t.Fatal(serr)
	}

	want := map[string][]int{
		"mod.txt":       {3, 7},
		"sp ace.txt":    {2},
		"tab\tname.txt": {1},
		"é.txt":         {3},
		"marks.txt":     {6},
		"crlf.txt":      {2},
		"nonl.txt":      {1},
		"renamed.txt":   {4},
		"bin.dat":       {1}, // a key in a binary file is found now (STEAL P0-05, --text); it was skipped as "Binary files differ"
	}
	got := map[string][]int{}
	for _, f := range res {
		got[f.path] = append(got[f.path], f.line)
		if f.commit != "" {
			t.Errorf("staged diff has no commit, got %q", f.commit)
		}
		if strings.Contains(f.ctx, key) || !strings.Contains(f.ctx, "«ghp_…") {
			t.Errorf("%s: context must show the shape and never the key: %q", f.path, f.ctx)
		}
	}
	for path, lines := range want {
		if fmt.Sprint(got[path]) != fmt.Sprint(lines) {
			t.Errorf("%s: matched at lines %v, want %v", path, got[path], lines)
		}
	}
	for path := range got {
		if _, ok := want[path]; !ok {
			t.Errorf("unexpected match in %s", path)
		}
	}
}

func TestScanAddedMultiLineValue(t *testing.T) {
	two := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1\nBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB2" // the head of a key: two lines
	m := newSubMatcher([]string{"HEAD=" + two})
	adjacent := fileDiff("k.pem", 1, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1", "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBB2")
	if res, _, _ := scanText(t, adjacent, m, 0); len(res) != 1 || res[0].line != 1 {
		t.Errorf("adjacent added lines: %+v", res)
	}
	apart := fileDiff("k.pem", 1, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1") + "@@ -5,0 +9,1 @@\n+BBBBBBBBBBBBBBBBBBBBBBBBBBBBBB2\n"
	if res, _, _ := scanText(t, apart, m, 0); len(res) != 0 {
		t.Errorf("lines in different hunks are not adjacent in the file: %+v", res)
	}
	// A removed line between them does not separate them in the new file.
	viaRemoval := fileDiff("k.pem", 1, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1") + "-gone\n+BBBBBBBBBBBBBBBBBBBBBBBBBBBBBB2\n"
	if res, _, _ := scanText(t, viaRemoval, m, 0); len(res) != 1 {
		t.Errorf("a removed line between added ones: %+v", res)
	}
}

func TestScanAddedCombinedDiff(t *testing.T) {
	key := fakeGitHub()
	m := newSubMatcher([]string{"K=" + key})
	// Two parents. "++" is new in the merge; " +" came from the second parent; "- " and " -"
	// are lines the result lacks. Only "++" lines are the merge's own; the rest is history
	// that is judged where it was committed.
	merge := "\x01KG 1111111111111111111111111111111111111111\n\n" +
		"diff --cc f.txt\nindex aaa,bbb..ccc\n--- a/f.txt\n+++ b/f.txt\n" +
		"@@@ -2,2 -2,2 +2,4 @@@\n" +
		"- old1\n" + // removed from parent 1
		" -old2\n" + // removed from parent 2
		" +from parent two " + key + "\n" +
		"++fresh " + key + "\n" +
		"  context line\n" +
		"++second fresh " + key + "\n"
	res, _, _ := scanText(t, merge, m, 0)
	if len(res) != 2 {
		t.Fatalf("want the two lines new in the merge, got %+v", res)
	}
	// result lines: " +from parent two" = 2, "++fresh" = 3, "  context" = 4, "++second" = 5
	if res[0].line != 3 || res[1].line != 5 || res[0].commit != strings.Repeat("1", 40) || res[0].path != "f.txt" {
		t.Errorf("combined diff positions: %+v", res)
	}
}

func TestScanAddedCommitCapStopsReading(t *testing.T) {
	key := fakeGitHub()
	m := newSubMatcher([]string{"K=" + key})
	var b strings.Builder
	for i := 1; i <= 5; i++ {
		fmt.Fprintf(&b, "\x01KG %040d\n\n%s", i, fileDiff(fmt.Sprintf("f%d.txt", i), 1, "k="+key))
	}
	res, commits, capped := scanText(t, b.String(), m, 3)
	if !capped || commits != 3 || len(res) != 3 {
		t.Errorf("cap of 3: capped=%v commits=%d matches=%d", capped, commits, len(res))
	}
	res, commits, capped = scanText(t, b.String(), m, 5)
	if capped || commits != 5 || len(res) != 5 {
		t.Errorf("cap of 5 over 5 commits: capped=%v commits=%d matches=%d", capped, commits, len(res))
	}
	res, commits, capped = scanText(t, b.String(), m, 0)
	if capped || commits != 5 || len(res) != 5 {
		t.Errorf("no cap: capped=%v commits=%d matches=%d", capped, commits, len(res))
	}
}

// A run of added lines longer than the chunk is matched in overlapping pieces. A key must
// be found wherever the cut falls, once, with the right line number.
func TestScanAddedHugeRunsAcrossChunkCuts(t *testing.T) {
	key := fakeGitHub()
	m := newSubMatcher([]string{"K=" + key})

	t.Run("one giant line", func(t *testing.T) {
		for _, off := range []int{0, 100, chunk - len(key) - 1, chunk - len(key), chunk - len(key) + 1, chunk - 10, chunk + 5, 2*chunk - overlap - 3, 2*chunk + 100, 3*chunk - 20} {
			line := strings.Repeat("x", off) + key + strings.Repeat("y", 3*chunk-off)
			res, _, _ := scanText(t, fileDiff("min.js", 1, line), m, 0)
			if len(res) != 1 || res[0].line != 1 {
				t.Errorf("key at offset %d of one giant line: %d matches %+v", off, len(res), res)
			}
		}
	})

	t.Run("many lines", func(t *testing.T) {
		const per = 99 // bytes of filler per line
		filler := strings.Repeat("z", per)
		total := 2*chunk/(per+1) + 500
		for _, at := range []int{1, chunk/(per+1) - 3, chunk / (per + 1), chunk/(per+1) + 3, total - 1, total} {
			lines := make([]string, total)
			for i := range lines {
				lines[i] = filler
			}
			lines[at-1] = "k=" + key
			res, _, _ := scanText(t, fileDiff("big.txt", 1, lines...), m, 0)
			if len(res) != 1 || res[0].line != at {
				t.Errorf("key on line %d of %d: %+v", at, total, res)
			}
		}
	})
}

func TestScanPositions(t *testing.T) {
	diff := fileDiff("a.txt", 3, "x", "y") + "-removed\n@@ -9,0 +12,1 @@\n+z\n" +
		"diff --cc m.txt\nindex a,b..c\n--- a/m.txt\n+++ b/m.txt\n@@@ -1 -1 +5,3 @@@\n++new\n +theirs\n++new2\n"
	var got []string
	if err := scanPositions(strings.NewReader(diff), func(path string, line int) { got = append(got, fmt.Sprintf("%s:%d", path, line)) }); err != nil {
		t.Fatal(err)
	}
	if want := "[a.txt:3 a.txt:4 a.txt:12 m.txt:5 m.txt:7]"; fmt.Sprint(got) != want {
		t.Errorf("positions %v, want %s", got, want)
	}
}

func TestMatchContext(t *testing.T) {
	key := fakeGitHub()
	neighbour := fakeAnthropic()
	m := newSubMatcher([]string{"K=" + key})
	res, _, _ := scanText(t, fileDiff("a.txt", 1, "header = 1", "other: "+neighbour[:40]+" url: https://x/y?token="+key+"&n=1 tail"), m, 0)
	if len(res) != 1 {
		t.Fatalf("%+v", res)
	}
	assertNoLeak(t, "context", res[0].ctx, key, neighbour[:40])
	if !strings.Contains(res[0].ctx, "«ghp_…") || !strings.Contains(res[0].ctx, "tail") || !strings.Contains(res[0].ctx, "«…»") {
		t.Errorf("context should keep the surrounding text, show the shape and mask a neighbouring secret: %q", res[0].ctx)
	}
	// A window of a megabyte-long line stays short and valid UTF-8.
	long := strings.Repeat("é", 500000) + key + strings.Repeat("ü", 500000)
	res, _, _ = scanText(t, fileDiff("min.js", 1, long), m, 0)
	if len(res) != 1 || len([]rune(res[0].ctx)) > 200 || !utf8.ValidString(res[0].ctx) {
		t.Errorf("context: %d runes, valid=%v; want <= 200 and valid", len([]rune(res[0].ctx)), utf8.ValidString(res[0].ctx))
	}
}

func TestParseHunk(t *testing.T) {
	for _, c := range []struct {
		in         string
		cols, line int
		ok         bool
	}{
		{"@@ -1,3 +4,5 @@", 1, 4, true},
		{"@@ -1 +7 @@ func (x) y", 1, 7, true},
		{"@@ -0,0 +1 @@", 1, 1, true},
		{"@@ -5,2 +0,0 @@", 1, 0, true},
		{"@@@ -1,2 -1,2 +1,3 @@@", 2, 1, true},
		{"@@@@ -1 -1 -1 +9 @@@@", 3, 9, true},
		{"@@ garbage @@", 0, 0, false},
		{"@ -1 +1 @", 0, 0, false},
	} {
		cols, line, ok := parseHunk([]byte(c.in))
		if cols != c.cols || line != c.line || ok != c.ok {
			t.Errorf("parseHunk(%q) = %d,%d,%v; want %d,%d,%v", c.in, cols, line, ok, c.cols, c.line, c.ok)
		}
	}
}

func TestParseNewPath(t *testing.T) {
	for in, want := range map[string]string{
		"b/dir/f.go":        "dir/f.go",
		"b/sp ace.txt\t":    "sp ace.txt",
		`"b/tab\tname.txt"`: "tab\tname.txt",
		`"b/\303\251.txt"`:  "é.txt",
		`"b/quote\"d.txt"`:  `quote"d.txt`,
		"/dev/null":         "",
		"b/":                "",
		`"b/unterminated`:   `"b/unterminated`,
	} {
		if got := parseNewPath(in); got != want {
			t.Errorf("parseNewPath(%q) = %q, want %q", in, got, want)
		}
	}
}

// nullMatcher costs nothing, so a benchmark with it measures the diff parser alone.
type nullMatcher struct{}

func (nullMatcher) Match([]byte) []core.KnownMatch { return nil }
func (nullMatcher) Len() int                       { return 1 }

// BenchmarkScanAdded is the diff parser's own speed (the matcher is a no-op): the floor
// under the known-secret pass on a big range. Run: go test -bench ScanAdded ./internal/hooks
func BenchmarkScanAdded(b *testing.B) {
	var sb strings.Builder
	line := strings.Repeat("some typical source line with identifiers and 12345 numbers; ", 1) // 61 bytes
	for f := 0; f < 200; f++ {
		lines := make([]string, 500)
		for i := range lines {
			lines[i] = line
		}
		sb.WriteString("\x01KG " + strings.Repeat("a", 40) + "\n\n" + fileDiff(fmt.Sprintf("dir/file%d.go", f), 1, lines...))
	}
	in := sb.String()
	b.SetBytes(int64(len(in)))
	b.ResetTimer()
	for range b.N {
		if _, _, err := scanAdded(strings.NewReader(in), nullMatcher{}, 0, func(diffMatch) {}); err != nil {
			b.Fatal(err)
		}
	}
}

// FuzzScanAdded throws arbitrary bytes at the diff scanner: whatever git (or a hostile
// repository) puts in a diff, the hook must not panic. `go test -fuzz=FuzzScanAdded`
// runs it for real; the seeds run as a normal test.
func FuzzScanAdded(f *testing.F) {
	f.Add("diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -0,0 +1,2 @@\n+one\n+two\n")
	f.Add("\x01KG abc\n\ndiff --cc f\n+++ b/f\n@@@ -1 -1 +1,2 @@@\n++a\n +b\n- c\n")
	f.Add("@@ -1 +1 @@\n+k=sekret-value-123\n\\ No newline at end of file\n")
	m := newSubMatcher([]string{"K=sekret-value-123", "M=line one\nline two"})
	f.Fuzz(func(t *testing.T, in string) {
		_, _, _ = scanAdded(strings.NewReader(in), m, 3, func(diffMatch) {})
		_, _, _ = scanAdded(strings.NewReader(in), m, 0, func(diffMatch) {})
	})
}

// Byte-level robustness: nothing in a diff stream may panic the scanner.
func TestScanAddedSurvivesGarbage(t *testing.T) {
	m := newSubMatcher([]string{"K=" + fakeGitHub()})
	for _, in := range []string{
		"", "\n", "@@", "@@@", "+", "+++", "+++ ", "\x01", "\x01KG", "diff", "diff --git",
		"@@ -1 +1 @@\n", "@@ -1 +1 @@\n\n\n", "@@ -1 +x @@\n+a\n", "@@@ -1 +1 @@@\n+a\n", "@@@ -1 -1 +1 @@@\n+\n",
		"@@ -1 +1 @@\n\\ No newline at end of file\n", "\x00\x00\x00", strings.Repeat("@@ -1 +1 @@\n+a\n", 1000),
		"diff --git a/x b/x\n+++ b/x\n@@ -0,0 +1 @@\n" + string(bytes.Repeat([]byte{0xff, 0xfe}, 100)) + "\n",
	} {
		scanText(t, in, m, 0)
	}
}
