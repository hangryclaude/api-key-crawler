package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"keyguard/internal/pattern/rules"
)

func root(t *testing.T) string {
	t.Helper()
	r, err := repoRoot("")
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// The committed table is what the generator writes from the committed data. This is the test that
// keeps rules_gen.go from drifting from rules/src and rules/keyguard.toml.
func TestRulesGenIsCurrent(t *testing.T) {
	r := root(t)
	out, err := generate(r)
	if err != nil {
		t.Fatal(err)
	}
	have, err := os.ReadFile(filepath.Join(r, genFile))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(have, out.source) {
		t.Errorf("%s is not what rulegen writes; run go run ./internal/pattern/rulegen", genFile)
	}
	if len(out.table) != 475 || out.upstream != 463 {
		t.Errorf("%d rules, %d from betterleaks", len(out.table), out.upstream)
	}
}

func TestGenerationIsDeterministic(t *testing.T) {
	r := root(t)
	a, err := generate(r)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := generate(r)
	if !bytes.Equal(a.source, b.source) {
		t.Error("two runs wrote different files")
	}
}

func TestTheOwnRulesAreRead(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(root(t), "rules", "keyguard.toml"))
	if err != nil {
		t.Fatal(err)
	}
	top, rs, err := parseTOML(string(b))
	if err != nil {
		t.Fatal(err)
	}
	if top["title"] != "keyguard" || len(rs) != 12 {
		t.Fatalf("title %v, %d rules", top["title"], len(rs))
	}
	for _, r := range rs {
		id := str(r["id"])
		if !strings.HasPrefix(id, "kg-") || str(r["regex"]) == "" || str(r["description"]) == "" {
			t.Errorf("rule %q: %v", id, r)
		}
	}
	// the multi-line literal keeps its text, and a regex containing quotes is not cut
	if f := str(rs[0]["filter"]); f != "entropy(finding[\"secret\"]) <= 3.5\n" {
		t.Errorf("filter %q", f)
	}
	if re := str(rs[0]["regex"]); !strings.Contains(re, `(?:\\?['"\x60]|`) {
		t.Errorf("regex %q", re)
	}
}

func TestTheTOMLReaderRefusesWhatItDoesNotKnow(t *testing.T) {
	for name, src := range map[string]string{
		"an unknown table":       "[[other]]\nid = 'x'\n",
		"a triple-quoted string": "[[rules]]\nid = \"\"\"x\"\"\"\n",
		"an unclosed literal":    "[[rules]]\nfilter = '''\nentropy\n",
		"a repeated key":         "[[rules]]\nid = 'a'\nid = 'b'\n",
		"a bare word":            "[[rules]]\nid = nope\n",
		"an unknown escape":      "[[rules]]\nid = \"a\\qb\"\n",
		"text after a string":    "[[rules]]\nid = 'a' 'b'\n",
		"an array of numbers":    "[[rules]]\nkeywords = [1, 2]\n",
	} {
		if _, _, err := parseTOML(src); err == nil {
			t.Errorf("%s was read", name)
		}
	}
	top, rs, err := parseTOML("title = \"t\"\nn = 3\nok = true\n[extend]\nuseDefault = true\n[[rules]]\nid = 'a'  # comment\nkeywords = [\"x\", 'y']\nfilter = '''one'''\n")
	if err != nil || top["title"] != "t" || top["n"] != int64(3) || top["ok"] != true || len(rs) != 1 {
		t.Fatalf("%v %v %v", top, rs, err)
	}
	if kw := rs[0]["keywords"].([]string); len(kw) != 2 || kw[1] != "y" || rs[0]["filter"] != "one" || rs[0]["id"] != "a" {
		t.Errorf("rule %v", rs[0])
	}
	if _, ok := top["useDefault"]; ok {
		t.Error("a key under [extend] leaked into the top level")
	}
}

func TestOwnFiltersAreReadOrRefused(t *testing.T) {
	f, err := parseOwnFilter("entropy(finding[\"secret\"]) <= 3.0\n|| matchesAny(finding[\"secret\"], [`.+EXAMPLE$`, `plain`])")
	if err != nil {
		t.Fatal(err)
	}
	if f.Entropy != (rules.Floor{Min: 3, Strict: true}) || len(f.DropRegex) != 1 || f.DropRegex[0] != ".+EXAMPLE$" || len(f.DropWords) != 1 || f.DropWords[0] != "plain" {
		t.Errorf("%+v", f)
	}
	if f, err := parseOwnFilter("entropy(finding[\"secret\"]) < 2.8"); err != nil || f.Entropy != (rules.Floor{Min: 2.8}) {
		t.Errorf("%+v %v", f, err)
	}
	if f, err := parseOwnFilter(""); err != nil || f.Entropy.Min != 0 {
		t.Errorf("an empty filter: %+v %v", f, err)
	}
	for _, bad := range []string{"entropy(finding[\"secret\"]) > 3", "len(finding[\"secret\"]) == 8", "entropy(finding[\"secret\"]) <= 3 && x"} {
		if _, err := parseOwnFilter(bad); err == nil {
			t.Errorf("%q was read", bad)
		}
	}
}

func TestSourcesLockRefusesTruffleHogAndUnknownLicences(t *testing.T) {
	const good = "betterleaks\tbetterleaks\thttps://example.invalid/b\tv1\t0123456789abcdef0123456789abcdef01234567\tMIT\t2026-01-01\t2026-01-02\n"
	write := func(body string) string {
		p := filepath.Join(t.TempDir(), "SOURCES.lock")
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if _, err := readLock(write("# comment\n" + good)); err != nil {
		t.Fatalf("a good lock is refused: %v", err)
	}
	for name, body := range map[string]string{
		"trufflehog":        strings.Replace(good, "betterleaks\tbetterleaks", "trufflehog\ttrufflehog", 1),
		"an AGPL licence":   strings.Replace(good, "\tMIT\t", "\tAGPL-3.0\t", 1),
		"an unknown family": strings.Replace(good, "betterleaks\tbetterleaks", "x\tsecrets-patterns-db", 1),
		"a short line":      "betterleaks\tbetterleaks\tMIT\n",
		"a lineage twice":   good + good,
	} {
		if _, err := readLock(write(body)); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestEmittedLiterals(t *testing.T) {
	for in, want := range map[string]string{
		"plain":       `"plain"`,
		`plain \d+`:   "`plain \\d+`",
		`say "hi" \n`: "`say \"hi\" \\n`",
		"has `tick":   `"has ` + "`" + `tick"`,
		"line\rbreak": `"line\rbreak"`,
		"bell\x07":    `"bell\a"`,
		"tab\tkept":   "`tab\tkept`",
	} {
		if got := quote(in); got != want {
			t.Errorf("quote(%q) = %s, want %s", in, got, want)
		}
	}
	for id, want := range map[string]string{
		"aws-access-token":         "aws",
		"1password-secret-key":     "1password",
		"abuseipdb-api-key.1":      "abuseipdb",
		"kg-anthropic-oauth-token": "anthropic",
		"jwt":                      "jwt",
	} {
		if got := providerOf(id); got != want {
			t.Errorf("providerOf(%q) = %q, want %q", id, got, want)
		}
	}
}

func TestEmitWritesCompilableSortedSource(t *testing.T) {
	const commit = "0123456789abcdef0123456789abcdef01234567"
	table := []rules.Rule{
		{ID: "a-one", Provider: "a", Re: `x(\d)`, Keywords: []string{"x"}, Filter: rules.Filter{Entropy: rules.Floor{Min: 3.5, Strict: true}, DropWords: []string{"w"}},
			Src: rules.Src{Lineage: "betterleaks", UpstreamID: "a-one", Commit: commit, Licence: "MIT", Rewrite: "none"}},
		{ID: "kg-b", Provider: "b", Re: "y", Src: rules.Src{Lineage: "own", Licence: "own"}},
	}
	a, err := emit(table, rules.Filter{DropWords: []string{"z"}}, map[string]string{"betterleaks": commit})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := emit(table, rules.Filter{DropWords: []string{"z"}}, map[string]string{"betterleaks": commit})
	if !bytes.Equal(a, b) {
		t.Error("emit is not deterministic")
	}
	s := string(a)
	for _, want := range []string{"Code generated", "DO NOT EDIT", "Modified for keyguard", "commitBetterleaks = " + `"` + commit + `"`,
		"Commit: commitBetterleaks", "Strict: true", `Lineage: "own"`} {
		if !strings.Contains(s, want) {
			t.Errorf("the source lacks %q", want)
		}
	}
	if strings.Contains(s, `Commit: ""`) {
		t.Error("an own rule carries an empty commit")
	}
}
