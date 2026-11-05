package pattern

import (
	"regexp"
	"regexp/syntax"
	"slices"
	"sort"
	"strings"
	"testing"

	"keyguard/internal/pattern/rules"
)

func parse(t testing.TB, expr string) *syntax.Regexp {
	t.Helper()
	re, err := syntax.Parse(expr, syntax.Perl)
	if err != nil {
		t.Fatalf("%s: %v", expr, err)
	}
	return re
}

func TestExtentOfSimpleExpressions(t *testing.T) {
	for _, c := range []struct {
		expr string
		want span
	}{
		{`abc`, span{3, 0}},
		{`ab?c`, span{3, 0}},
		{`[a-f0-9]{32}`, span{32, 0}},
		{`x[a-z]{2,5}y`, span{7, 0}},
		{`a\s{0,3}b`, span{5, 3}},
		{`a[^"]*b`, span{-1, -1}},
		{`a\w+b`, span{-1, 0}},
		{`a.+b`, span{-1, 0}},
		{`(?s)a.b`, span{6, 1}},
		{`(?i)k`, span{1, 0}},        // the Kelvin sign, which (?i) folds onto k, is not counted
		{`(?i)as`, span{2, 0}},       // nor is the long s
		{`(?i)[a-z]{4}`, span{4, 0}}, // so a folded class is not three bytes a letter
		{`\bfoo$`, span{3, 0}},
		{`(?:ab|cde)f`, span{4, 0}},
		{`é`, span{2, 0}},
	} {
		if got := extent(parse(t, c.expr)); got != c.want {
			t.Errorf("extent(%s) = %+v, want %+v", c.expr, got, c.want)
		}
	}
}

func TestFiniteAndPrefixes(t *testing.T) {
	for _, c := range []struct {
		expr   string
		finite []string
		prefix []string
	}{
		{`(?i)Abc`, []string{"abc"}, []string{"abc"}},
		{`(?:sk|rk)_(?:test|live)_`, []string{"sk_test_", "sk_live_", "rk_test_", "rk_live_"}, nil},
		{`ab?`, []string{"a", "ab"}, nil},
		{`x:{1,3}=`, []string{"x:=", "x::=", "x:::="}, nil},
		{`[Aa]pi`, []string{"api"}, nil},
		{`[a-z]{3}`, nil, []string{""}},
		{`foo[a-z]+`, nil, []string{"foo"}},
		{`(?:ab[0-9a-z]{3}|cd)x`, nil, []string{"ab", "cd"}},
	} {
		re := parse(t, c.expr)
		f, ok := finite(re)
		if c.finite == nil {
			if ok {
				t.Errorf("finite(%s) = %v, want not finite", c.expr, f)
			}
		} else {
			slices.Sort(f)
			want := slices.Clone(c.finite)
			slices.Sort(want)
			if !ok || !slices.Equal(f, want) {
				t.Errorf("finite(%s) = %v %v, want %v", c.expr, f, ok, want)
			}
		}
		if c.prefix != nil {
			p := prefixes(re)
			slices.Sort(p)
			want := slices.Clone(c.prefix)
			slices.Sort(want)
			if !slices.Equal(p, want) {
				t.Errorf("prefixes(%s) = %v, want %v", c.expr, p, want)
			}
		}
	}
}

func TestPlanAnchor(t *testing.T) {
	for _, c := range []struct {
		name     string
		expr     string
		keywords []string
		ok       bool
		before   span // checked only when ok
		after    span
	}{
		{"keyword is the whole prefix", `(?i)(?:abc)[\s'"]{0,3}=([a-z0-9]{12})`, []string{"abc"}, true, span{0, 0}, span{3 + 3 + 1 + 12*1, 3}},
		{"keyword inside an alternation of the prefix", `\b((?:sk|rk)_(?:test|live)_[a-z0-9]{10,99})`, []string{"sk_test", "sk_live", "rk_test", "rk_live"}, true, span{0, 0}, span{8 + 99, 0}},
		{"keyword after a gap", `(?i)lob[ \t]{0,20}=((live|test)_[a-f0-9]{35})`, []string{"live_", "test_"}, true, span{3 + 20 + 1, 0}, span{1 + 4 + 1 + 35, 0}}, // the run starts at the "=" before live_
		{"an unbounded gap before the keyword", `ab\s+cd[0-9]{4}`, []string{"cd"}, false, span{}, span{}},
		{"an unbounded run after the keyword stays on its line", `abc[a-z]+=`, []string{"abc"}, true, span{0, 0}, span{-1, 0}},
		{"keyword is not in the match", `ab[0-9]{4}`, []string{"zzz"}, false, span{}, span{}},
		{"a longer keyword than the match carries", `ey[a-z]{17}`, []string{"eyj"}, false, span{}, span{}},
		{"one branch has no keyword", `(?:abc[0-9]|xyz[0-9])`, []string{"abc"}, false, span{}, span{}},
		{"every branch has one", `(?:abc[0-9]|xyz[0-9])`, []string{"abc", "xyz"}, true, span{0, 0}, span{4, 0}},
		{"no keywords", `abc`, nil, false, span{}, span{}},
	} {
		a := planAnchor(parse(t, c.expr), c.keywords)
		if a.ok != c.ok {
			t.Errorf("%s: anchored = %v, want %v", c.name, a.ok, c.ok)
			continue
		}
		if c.ok && (a.before != c.before || a.after != c.after) {
			t.Errorf("%s: before %+v after %+v, want %+v %+v", c.name, a.before, a.after, c.before, c.after)
		}
	}
}

// What the analysis says about the real table, pinned loosely: the generic rules and the common shapes
// are anchored and bounded; the few whose keyword is only a gate are not.
func TestAnchorsOfTheTable(t *testing.T) {
	gated := map[string]bool{}
	anchored := 0
	for i := range rules.All {
		r := &rules.All[i]
		if r.Re == "" || len(r.Keywords) == 0 {
			continue
		}
		var kws []string
		for _, k := range r.Keywords {
			kws = append(kws, strings.ToLower(k))
		}
		a := planAnchor(parse(t, r.Re), kws)
		if a.ok {
			anchored++
		} else {
			gated[r.ID] = true
		}
		if a.ok && a.before.bytes < 0 && a.before.lines != 0 {
			t.Errorf("%s: unbounded text before the keyword spanning lines", r.ID)
		}
	}
	var names []string
	for id := range gated {
		names = append(names, id)
	}
	sort.Strings(names)
	t.Logf("%d anchored, %d gated: %v", anchored, len(gated), names)
	if anchored < 400 {
		t.Errorf("only %d rules anchored", anchored)
	}
	for _, id := range []string{"generic-api-key", "stripe-access-token", "lob-api-key", "generic-credential-uri", "aws-access-token", "slack-legacy-token"} {
		if gated[id] {
			t.Errorf("%s should be anchored", id)
		}
	}
	for _, id := range []string{"twilio-api-key", "jwt", "generic-password"} {
		if !gated[id] {
			t.Errorf("%s should be gated: its keyword is not in every match", id)
		}
	}
	// The assignment grammar is the one that matters: the keyword is the start of the match.
	r := ruleByID(t, "generic-api-key")
	a := planAnchor(parse(t, r.Re), []string{"access", "api", "auth", "key", "credential", "creds", "secret", "token"})
	if !a.ok || a.before.bytes != 0 || a.before.lines != 0 || a.after.lines < 1 {
		t.Errorf("generic-api-key: %+v", a)
	}
}

func ruleByID(t testing.TB, id string) *rules.Rule {
	t.Helper()
	for i := range rules.All {
		if rules.All[i].ID == id {
			return &rules.All[i]
		}
	}
	t.Fatalf("no rule %s", id)
	return nil
}

// The bounds are upper bounds on real matches: for random strings drawn from a regex's own language
// (here sampled by mutation of known matches), no match is longer than extent says.
func TestExtentBoundsRealMatches(t *testing.T) {
	for _, expr := range []string{
		`(?i)(?:abc)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([\w.=-]{10,150})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`,
		`ab\s{0,3}cd[^x]{2,4}`,
	} {
		re := regexp.MustCompile(expr)
		ext := extent(parse(t, expr))
		text := "abc  :\n\n\n =\n\n'  abcdefghij0123456789\"\nab \n\n cd..z\n"
		for _, m := range re.FindAllStringIndex(text, -1) {
			s := text[m[0]:m[1]]
			if ext.bytes >= 0 && len(s) > ext.bytes {
				t.Errorf("%s: a match of %d bytes exceeds %d", expr, len(s), ext.bytes)
			}
			if n := strings.Count(s, "\n"); ext.lines >= 0 && n > ext.lines {
				t.Errorf("%s: a match with %d newlines exceeds %d", expr, n, ext.lines)
			}
		}
	}
}
