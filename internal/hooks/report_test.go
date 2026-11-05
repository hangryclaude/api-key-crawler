package hooks

import (
	"fmt"
	"strings"
	"testing"

	"keyguard/internal/core"
	"keyguard/internal/fp"
)

func render(title string, hits []core.Hit) string {
	var b strings.Builder
	writeBlock(&b, title, hits)
	return b.String()
}

func TestWriteBlockLayout(t *testing.T) {
	key := fakeGitHub()
	hits := []core.Hit{
		{Engine: "betterleaks", Rule: "github-pat", Type: "github-pat", FP: testKeyring.FP(key), Shape: fp.Shape(key), Loc: core.Location{Path: "src/api.py", Line: 12}},
		{Engine: "filename", Rule: "env-file", Type: "env-file", FP: "00ff00ff00ff00ff00ff00ff00ff00ff", Context: "env file: holds real values", Loc: core.Location{Path: ".env"}},
		{Engine: "known", Rule: "known-secret", Type: "known", FP: "aabbccddaabbccddaabbccddaabbccdd", Shape: "sk-ant-api03-…AA", Known: "kgaabbcc OPENAI_API_KEY", Loc: core.Location{Path: "z.js", Line: 1204}},
	}
	out := render("commit blocked", hits)
	for _, want := range []string{
		"keyguard: commit blocked: 3 findings",
		"FILE", "LINE", "TYPE", "SECRET", "WHY",
		"src/api.py", "github-pat", fp.Shape(key), "(kg" + testKeyring.FP(key)[:6] + ")",
		".env", "env file: holds real values (kg00ff00)",
		"your learned key OPENAI_API_KEY (kgaabbcc)",
		"fix: move the value to a gitignored .env and read it from the environment.",
		"do not bypass with --no-verify", "blocked at the", "ref level", "re-scanned every minute",
		"keyguard allow <id from the WHY column>",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "COMMIT") {
		t.Errorf("no commit column expected when no hit has a commit:\n%s", out)
	}
	assertNoLeak(t, "block message", out, key)

	// The numbers sit in a column: right-aligned under LINE.
	lines := strings.Split(out, "\n")
	var col = -1
	for _, l := range lines {
		if i := strings.Index(l, "LINE"); i >= 0 {
			col = i + len("LINE")
		}
	}
	if col < 0 {
		t.Fatalf("no header:\n%s", out)
	}
	for _, l := range lines {
		for _, n := range []string{"12", "1204"} {
			if i := strings.Index(l, " "+n+" "); i >= 0 && i+1+len(n) != col {
				t.Errorf("line number %s ends at column %d, want %d:\n%s", n, i+1+len(n), col, out)
			}
		}
	}

	// A single id is named in the closing line.
	one := render("push blocked", hits[:1])
	if !strings.Contains(one, "keyguard allow kg"+testKeyring.FP(key)[:6]) || !strings.Contains(one, "1 finding\n") {
		t.Errorf("single finding:\n%s", one)
	}
	// Without any id there is nothing to allow.
	none := render("commit blocked", []core.Hit{{Engine: "filename", Rule: "netrc", Type: "netrc", Context: "netrc holds logins", Loc: core.Location{Path: ".netrc"}}})
	if strings.Contains(none, "keyguard allow") || !strings.Contains(none, "rename the file") {
		t.Errorf("no-id finding:\n%s", none)
	}
}

func TestWriteBlockCommitColumnAndTruncation(t *testing.T) {
	var hits []core.Hit
	for i := 1; i <= 40; i++ {
		hits = append(hits, core.Hit{Engine: "known", Rule: "known-secret", Type: "known", FP: fmt.Sprintf("%032x", i), Shape: "x…", Known: "kgx N",
			Loc: core.Location{Path: fmt.Sprintf("f%02d.txt", i), Line: i, Commit: "0123456789abcdef0123456789abcdef01234567"}})
	}
	out := render("ref update blocked", hits)
	if !strings.Contains(out, "COMMIT") || !strings.Contains(out, "0123456  f01.txt") {
		t.Errorf("commit column:\n%s", out)
	}
	if strings.Contains(out, "f26.txt") || !strings.Contains(out, "... and 15 more") || !strings.Contains(out, "40 findings") {
		t.Errorf("truncation at 25 rows:\n%s", out)
	}
}

func TestWriteBlockKeepsTheIDWhenTheReasonIsLong(t *testing.T) {
	h := core.Hit{Engine: "betterleaks", Rule: strings.Repeat("very-long-rule-name-", 10), Type: "t", FP: "abcdef0123456789abcdef0123456789", Shape: "x…", Loc: core.Location{Path: "a", Line: 1}}
	out := render("commit blocked", []core.Hit{h})
	if !strings.Contains(out, "(kgabcdef)") {
		t.Errorf("the id was cut off:\n%s", out)
	}
	for _, l := range strings.Split(out, "\n") {
		if n := len([]rune(l)); n > 130 {
			t.Errorf("line of %d runes:\n%s", n, l)
		}
	}
}

// Text that comes from a repository or an engine can carry terminal escapes.
func TestWriteBlockNeutralisesControlCharacters(t *testing.T) {
	h := core.Hit{Engine: "betterleaks", Rule: "r\x1b[31mred", Type: "t\x07", FP: "abcdef0123456789abcdef0123456789", Shape: "x\x1b…",
		Loc: core.Location{Path: "dir/\x1b]0;owned\x07/f.txt", Line: 3}}
	out := render("commit blocked", []core.Hit{h})
	if strings.ContainsAny(out, "\x1b\x07") {
		t.Errorf("control characters survive:\n%q", out)
	}
}

// A normalizer that forgets to call fp.Shape must not turn the block message into a leak.
func TestWriteBlockNeverPrintsMoreThanAShape(t *testing.T) {
	key := fakeGitHub()
	for name, shape := range map[string]string{
		"the raw value":        key,
		"raw with an ellipsis": key[:30] + "…" + key[30:],
		"long prefix":          key[:20] + "…" + key[36:],
		"long tail":            "ghp_…" + key[4:],
		"empty":                "",
		"just an ellipsis":     "…",
		"a real shape":         fp.Shape(key),
		"the PEM shape":        "-----BEGIN…KEY-----",
	} {
		out := render("commit blocked", []core.Hit{{Engine: "x", Rule: "r", Type: "t", FP: "abcdef0123456789abcdef0123456789", Shape: shape, Loc: core.Location{Path: "a", Line: 1}}})
		assertNoLeak(t, name, out, key)
	}
	if got := safeShape(fp.Shape(key)); got != fp.Shape(key) {
		t.Errorf("safeShape altered a real shape: %q -> %q", fp.Shape(key), got)
	}
	if got := safeShape("-----BEGIN…KEY-----"); got != "-----BEGIN…KEY-----" {
		t.Errorf("safeShape altered the PEM shape: %q", got)
	}
}

func TestErrTextScrubsAndShortens(t *testing.T) {
	key := fakeGitHub()
	got := errText(fmt.Errorf("git log: exit status 128: could not read %s\x1b[0m", key))
	if strings.Contains(got, key) || strings.ContainsAny(got, "\x1b") {
		t.Errorf("errText leaked: %q", got)
	}
	if long := errText(fmt.Errorf("%s", strings.Repeat("word ", 500))); len([]rune(long)) > 240 {
		t.Errorf("errText is %d runes", len([]rune(long)))
	}
}

func TestFinalize(t *testing.T) {
	h := &hook{d: Deps{Ignored: func(fp string) bool { return fp == "ignored" }}}
	hits := []core.Hit{
		{FP: "ignored", Loc: core.Location{Path: "a", Line: 1}},
		{FP: "dead", Verified: core.Dead, Loc: core.Location{Path: "a", Line: 2}},
		{FP: "same", Rule: "engine", Loc: core.Location{Path: "b", Line: 5}},
		{FP: "same", Rule: "known", Known: "kg1 NAME", Loc: core.Location{Path: "b", Line: 5}},
		{FP: "same", Rule: "trufflehog", Verified: core.Live, Loc: core.Location{Path: "b", Line: 5}},
		{FP: "same", Rule: "engine", Loc: core.Location{Path: "b", Line: 6}},
		{FP: "", Rule: "r1", Loc: core.Location{Path: "c", Line: 1}},
		{FP: "", Rule: "r2", Loc: core.Location{Path: "c", Line: 1}},
		{FP: "x", Loc: core.Location{Path: "a", Line: 9, Commit: "bbb"}},
		{FP: "x", Loc: core.Location{Path: "a", Line: 9, Commit: "aaa"}},
	}
	out := h.finalize(hits, "staged")
	var got []string
	for _, x := range out {
		got = append(got, fmt.Sprintf("%s:%d:%s:%s:%s:%s", x.Loc.Path, x.Loc.Line, x.Loc.Commit, x.Rule, x.Known, x.Verified))
	}
	// b:5 was seen by an engine and by the learned-key matcher: one row, with both facts,
	// and the provider's "live" from a third sighting survives too.
	want := []string{"a:9:aaa:::", "a:9:bbb:::", "b:5::engine:kg1 NAME:live", "b:6::engine::", "c:1::r1::", "c:1::r2::"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("finalize = %v\nwant       %v", got, want)
	}
	for _, x := range out {
		if x.Loc.Kind != "staged" || x.Loc.Visibility != core.Local || !strings.HasPrefix(x.Loc.Source, "local:") {
			t.Errorf("location defaults missing: %+v", x.Loc)
		}
	}
}
