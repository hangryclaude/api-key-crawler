package lin

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// flat is FindAllSubmatchIndex, flattened the way FindAll returns it.
func flat(re *regexp.Regexp, b []byte) []int {
	var out []int
	for _, m := range re.FindAllSubmatchIndex(b, -1) {
		out = append(out, m...)
	}
	return out
}

// agree runs the pattern both ways over the inputs and fails on any difference.
func agree(t *testing.T, expr string, inputs ...string) {
	t.Helper()
	re := regexp.MustCompile(expr)
	p, err := Compile(expr)
	if err != nil {
		t.Fatalf("%s: %v", expr, err)
	}
	if p.NumSubexp() != re.NumSubexp() {
		t.Fatalf("%s: %d groups, regexp says %d", expr, p.NumSubexp(), re.NumSubexp())
	}
	for _, in := range inputs {
		want := flat(re, []byte(in))
		got, ok := p.FindAll([]byte(in), nil)
		if !ok {
			t.Errorf("%s on %q: gave up", expr, in)
			continue
		}
		if !slices.Equal(want, got) {
			t.Errorf("%s on %q: got %v, regexp says %v", expr, in, got, want)
		}
	}
}

func TestAgreesWithRegexpOnPlainPatterns(t *testing.T) {
	agree(t, `a+b`, "aab", "b", "xaabyab", "aaaa")
	agree(t, `(a|ab)(c|bcd)(d*)`, "abcd", "acd", "abcdd", "xabcdx")
	agree(t, `\bfoo\b`, "foo", "a foo b", "foobar", "_foo", "foo_", "foo-foo")
	agree(t, `^abc`, "abc", "xabc", "abc\nabc")
	agree(t, `abc$`, "abc", "abcx", "abc\nabc")
	agree(t, `(?m)^x$`, "x\nx\nxx\nx", "x", "\nx\n")
	agree(t, `(?i)key=`, "KEY=", "kEy=", "KEY=K", "k=", "Key=", "Key=Key=")
	agree(t, `(?i)[a-z]+1`, "abc1", "ABC1", "K1", "ſ1", "s1", "ſſ1")
	agree(t, `[^a]+b`, "xyb", "\xff\xfeb", "\xe2\x82b", "aab", "é€b", "\xe2\x82\xacb")
	agree(t, `.+x`, "abx", "ab\nx", "é€x", "\xffx")
	agree(t, `(?s).{0,3}?y`, "y", "xxy", "xxxxy", "\n\ny")
	agree(t, `a.*?b`, "aXXbYYb", "ab", "a\nb")
	agree(t, `a.*b`, "aXXbYYb", "ab", "a\nb")
	agree(t, `(a)|(b)`, "ab", "ba", "c", "bb")
	agree(t, `(?:ab)?c`, "abc", "c", "ac", "ababc")
	agree(t, `(?:ab){2,3}c`, "ababc", "abababc", "ababababc", "abc", "xababcx")
	agree(t, `(?:ab){2,3}?c`, "ababc", "abababc")
	agree(t, `x([a-c]{2,4})([a-c]*)z`, "xabcz", "xabcabcz", "xaz", "xabcabcabcz")
	agree(t, `[a-c]{2,3}c`, "abcc", "abc", "cccc", "ccccc")
	agree(t, `\d{3}-\d{4}`, "555-1234", "5555-12345", "55-123")
	agree(t, `(?:\\.|[^"\\]){1,20}"`, `ab\"c"`, `ab"`, `\`, `"`)
}

func TestAgreesOnBoundariesAndEncodings(t *testing.T) {
	agree(t, `\b\w+\b`, "héllo wörld", "a_b c-d", "日本語 text")
	agree(t, `[a-z]\B[a-z]`, "ab a b", "éa")
	agree(t, `é+`, "ééé", "e\xcc\x81", "\xc3")
	agree(t, `[é]+x`, "ééx", "\xc3x", "\xa9x")
	agree(t, `[^x]y`, "\x80y", "é y", "\xe2\x82y")
	agree(t, `.y`, "\xe2\x82\xacy", "\x80\x80y", "\xe2\x82y")
	agree(t, `(?i)straße`, "STRASSE", "straße", "STRAẞE")
}

func TestRefusesWhatItCannotDo(t *testing.T) {
	for _, expr := range []string{
		`a*`,          // can match the empty string
		`(?:ab)*c`,    // an unbounded repeat of a group
		`(?:(a))+b`,   // a capture group inside a repeat
		`(?:a*){2}b`,  // a repeated group that can be empty
		`(?:ab|cd)+e`, // an unbounded repeat of a group
		`\x{fffd}x`,   // a literal that regexp also reads out of a byte that is not UTF-8
	} {
		if _, err := Compile(expr); err == nil {
			t.Errorf("%s was accepted", expr)
		}
	}
}

// A walk that runs out of budget says so, and does not report a wrong answer.
func TestGivesUpRatherThanGuess(t *testing.T) {
	p, err := Compile(`(?:a|aa){1,40}b`)
	if err != nil {
		t.Fatal(err)
	}
	in := []byte(strings.Repeat("a", 60))
	if _, ok := p.findAll(in, nil, 200); ok {
		t.Fatal("a tiny budget was enough")
	}
	re := regexp.MustCompile(`(?:a|aa){1,40}b`)
	got, ok := p.FindAll(in, nil)
	if ok && !slices.Equal(got, flat(re, in)) {
		t.Fatal("the default budget gave a wrong answer")
	}
}
