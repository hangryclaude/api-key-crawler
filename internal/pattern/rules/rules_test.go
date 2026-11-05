package rules_test

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"keyguard/internal/pattern/rules"
	"keyguard/internal/pattern/rules/fidelity"
	"keyguard/internal/testkit"
)

// 463 rules of betterleaks v1.9.0 and the 12 kg- rules of rules/keyguard.toml.
const (
	upstreamRules = 463
	ownRules      = 12
	pinnedVersion = "1.9.0"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if b, err := os.ReadFile(filepath.Join(dir, "go.mod")); err == nil && bytes.HasPrefix(b, []byte("module keyguard")) {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod for module keyguard above the test's directory")
		}
		dir = parent
	}
}

func TestTheTableHasEveryRule(t *testing.T) {
	var own, upstream int
	for _, r := range rules.All {
		switch r.Src.Lineage {
		case "own":
			own++
		case "betterleaks":
			upstream++
		default:
			t.Errorf("%s: lineage %q", r.ID, r.Src.Lineage)
		}
	}
	if len(rules.All) != upstreamRules+ownRules || upstream != upstreamRules || own != ownRules {
		t.Errorf("%d rules (%d betterleaks, %d own), want %d (%d, %d)", len(rules.All), upstream, own, upstreamRules+ownRules, upstreamRules, ownRules)
	}
	if !sort.SliceIsSorted(rules.All, func(i, j int) bool { return rules.All[i].ID < rules.All[j].ID }) {
		t.Error("the table is not sorted by id")
	}
}

// 475 of 475: Go's regexp compiles every pattern the table holds, so a rule never fails to start.
func TestEveryRuleCompiles(t *testing.T) {
	compiled := 0
	try := func(who, what, re string) bool {
		if _, err := regexp.Compile(re); err != nil {
			t.Errorf("%s: %s does not compile: %v", who, what, err)
			return false
		}
		return true
	}
	for _, r := range rules.All {
		ok := true
		if r.Re == "" && r.Path == "" {
			t.Errorf("%s: no regex and no path", r.ID)
			continue
		}
		if r.Re != "" {
			ok = try(r.ID, "its regex", r.Re) && ok
		}
		if r.Path != "" {
			ok = try(r.ID, "its path pattern", r.Path) && ok
		}
		for _, list := range [][]string{r.Filter.DropRegex, r.Filter.DropPath} {
			for _, re := range list {
				ok = try(r.ID, "a filter pattern", re) && ok
			}
		}
		for _, g := range r.Filter.Require {
			for _, re := range g {
				ok = try(r.ID, "a required pattern", re) && ok
			}
		}
		if r.Group < 0 {
			t.Errorf("%s: secret group %d", r.ID, r.Group)
			ok = false
		} else if r.Re != "" {
			if re, err := regexp.Compile(r.Re); err == nil && r.Group > re.NumSubexp() {
				t.Errorf("%s: secret group %d, but the regex has %d groups", r.ID, r.Group, re.NumSubexp())
				ok = false
			}
		}
		if ok {
			compiled++
		}
	}
	for _, re := range append(append([]string{}, rules.Global.DropRegex...), rules.Global.DropPath...) {
		try("the global filter", "a pattern", re)
	}
	if compiled != len(rules.All) || compiled != upstreamRules+ownRules {
		t.Errorf("%d of %d rules compile", compiled, len(rules.All))
	}
	t.Logf("%d of %d rules compile as they are", compiled, len(rules.All))
}

// The rule ids are betterleaks's own list: what `betterleaks config show` prints for the default
// rules plus rules/keyguard.toml, id for id.
func TestIDsAreBetterleaksOwnList(t *testing.T) {
	bin := testkit.EnginePath(t, "betterleaks")
	run := func(args ...string) string {
		cmd := exec.Command(bin, args...)
		cmd.Dir = t.TempDir()
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("betterleaks %v: %v\n%s", args, err, out)
		}
		return string(out)
	}
	if v := strings.TrimSpace(run("version")); v != pinnedVersion {
		t.Skipf("the table is pinned to betterleaks %s and %s is installed", pinnedVersion, v)
	}
	shown := run("config", "show", "-c", filepath.Join(repoRoot(t), "rules", "keyguard.toml"))
	want := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)^id = ['"]([^'"]+)['"]$`).FindAllStringSubmatch(shown, -1) {
		want[m[1]] = true
	}
	got := map[string]bool{}
	for _, r := range rules.All {
		got[r.ID] = true
	}
	var missing, extra []string
	for id := range want {
		if !got[id] {
			missing = append(missing, id)
		}
	}
	for id := range got {
		if !want[id] {
			extra = append(extra, id)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	if len(want) != upstreamRules+ownRules || len(missing) > 0 || len(extra) > 0 {
		t.Errorf("betterleaks lists %d rules, the table %d; missing from the table %v, not in betterleaks %v", len(want), len(got), missing, extra)
	}
}

// The fidelity digest: every rule that has upstream examples does with them what it did when the
// golden was written, which is what upstream expects of it: its true positives fire, its false
// positives do not. The examples are in a cache that only someone who ran extract.mjs has.
func TestFidelityDigest(t *testing.T) {
	corpus := exampleCache(t)
	got, err := fidelity.Build(corpus, rules.All, rules.Global, pinnedCommit(t))
	if err != nil {
		t.Fatal(err)
	}
	want := readGolden(t)
	match := 0
	for id, e := range want.Rules {
		if got.Rules[id] == e {
			match++
			continue
		}
		t.Errorf("%s: digest %s over %d+%d examples, the golden has %s over %d+%d", id, got.Rules[id].Digest,
			got.Rules[id].Positives, got.Rules[id].Negatives, e.Digest, e.Positives, e.Negatives)
	}
	for id := range got.Rules {
		if _, ok := want.Rules[id]; !ok {
			t.Errorf("%s has examples and no entry in the golden", id)
		}
	}
	t.Logf("fidelity: %d of %d rules match their digest (%.1f%%), %d examples; %d rules have no upstream examples",
		match, len(want.Rules), 100*float64(match)/float64(len(want.Rules)), got.Examples, len(got.WithoutExamples))
	if match != len(want.Rules) {
		t.Errorf("fidelity is %d of %d", match, len(want.Rules))
	}
}

func pinnedCommit(t *testing.T) string {
	t.Helper()
	for _, r := range rules.All {
		if r.Src.Lineage == "betterleaks" {
			return r.Src.Commit
		}
	}
	t.Fatal("no betterleaks rule in the table")
	return ""
}

func readGolden(t *testing.T) *fidelity.Golden {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "fidelity.golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	var g fidelity.Golden
	if err := json.Unmarshal(b, &g); err != nil {
		t.Fatal(err)
	}
	return &g
}

// Without the cache the golden can still be checked against the table: every rule is accounted
// for, once, and it was written at the commit the table is pinned to.
func TestTheGoldenAccountsForTheTable(t *testing.T) {
	g := readGolden(t)
	if want := "betterleaks@" + pinnedCommit(t)[:12]; g.Source != want {
		t.Errorf("the golden is for %s, the table is pinned at %s", g.Source, want)
	}
	seen := map[string]bool{}
	for id := range g.Rules {
		seen[id] = true
	}
	for _, id := range g.WithoutExamples {
		if seen[id] {
			t.Errorf("%s is in the golden with and without examples", id)
		}
		seen[id] = true
	}
	for _, r := range rules.All {
		if !seen[r.ID] {
			t.Errorf("%s is neither in the golden nor listed as having no examples", r.ID)
		}
		delete(seen, r.ID)
	}
	for id := range seen {
		t.Errorf("the golden names %s, which is not in the table", id)
	}
	for id, e := range g.Rules {
		if len(e.Digest) != 16 || e.Positives+e.Negatives == 0 {
			t.Errorf("%s: a golden entry %+v", id, e)
		}
	}
}

func TestTheTableLintsClean(t *testing.T) {
	if bad := rules.Lint(rules.All); len(bad) > 0 {
		t.Errorf("%d problems:\n  %s", len(bad), strings.Join(bad, "\n  "))
	}
	rewritten := 0
	for _, r := range rules.All {
		if r.Src.Lineage == "betterleaks" && (r.Src.UpstreamID != r.ID || (r.Src.Rewrite != "none" && r.Src.Rewrite != "split")) {
			t.Errorf("%s: provenance %+v", r.ID, r.Src)
		}
		if r.Src.Rewrite == "split" {
			rewritten++
		}
	}
	if rewritten != 5 {
		t.Errorf("%d rules have a rewritten regex, extract.mjs rewrites 5 (3 long token prefixes, 2 key-like classes)", rewritten)
	}
}

// The lint is the wall against copying what must not be copied.
func TestLintRefusesTruffleHogAndUnknownLicences(t *testing.T) {
	commit := strings.Repeat("ab", 20)
	ok := func(id string) rules.Rule {
		return rules.Rule{ID: id, Re: "x", Src: rules.Src{Lineage: "betterleaks", UpstreamID: id, Commit: commit, Licence: "MIT", Rewrite: "none"}}
	}
	if bad := rules.Lint([]rules.Rule{ok("a")}); len(bad) != 0 {
		t.Fatalf("a good rule is refused: %v", bad)
	}
	for name, mutate := range map[string]func(*rules.Rule){
		"trufflehog lineage":          func(r *rules.Rule) { r.Src.Lineage = "trufflehog" },
		"TruffleHog by another case":  func(r *rules.Rule) { r.Src.Lineage = "TruffleHog" },
		"an AGPL licence":             func(r *rules.Rule) { r.Src.Licence = "AGPL-3.0" },
		"a licence nobody listed":     func(r *rules.Rule) { r.Src.Licence = "WTFPL" },
		"no licence":                  func(r *rules.Rule) { r.Src.Licence = "" },
		"a lineage nobody checked":    func(r *rules.Rule) { r.Src.Lineage = "secrets-patterns-db" },
		"a licence its lineage lacks": func(r *rules.Rule) { r.Src.Licence = "Apache-2.0" },
		"no commit":                   func(r *rules.Rule) { r.Src.Commit = "" },
		"a short commit":              func(r *rules.Rule) { r.Src.Commit = "0123456" },
		"no upstream id":              func(r *rules.Rule) { r.Src.UpstreamID = "" },
		"an unknown rewrite":          func(r *rules.Rule) { r.Src.Rewrite = "magic" },
		"a rule that matches nothing": func(r *rules.Rule) { r.Re = "" },
		"an own rule without kg-":     func(r *rules.Rule) { r.Src = rules.Src{Lineage: "own", Licence: "own"} },
	} {
		r := ok("a")
		mutate(&r)
		if bad := rules.Lint([]rules.Rule{r}); len(bad) == 0 {
			t.Errorf("%s was accepted", name)
		}
	}
	if bad := rules.Lint([]rules.Rule{ok("a"), ok("a")}); len(bad) == 0 {
		t.Error("a repeated id was accepted")
	}
	if bad := rules.Lint([]rules.Rule{{ID: "kg-x", Re: "x", Src: rules.Src{Lineage: "own", Licence: "own"}}}); len(bad) != 0 {
		t.Errorf("our own rule is refused: %v", bad)
	}
	// the message names TruffleHog, so a person who trips it learns why
	r := ok("a")
	r.Src.Lineage = "trufflehog"
	if bad := rules.Lint([]rules.Rule{r}); !strings.Contains(strings.Join(bad, " "), "TruffleHog") {
		t.Errorf("the refusal does not say why: %v", bad)
	}
}

// The sources the data is read from are the ones the lint allows: SOURCES.lock, and the lineage and
// licence each rules/src file claims.
func TestTheSourcesAreAllowed(t *testing.T) {
	root := repoRoot(t)
	lock, err := os.ReadFile(filepath.Join(root, "rules", "SOURCES.lock"))
	if err != nil {
		t.Fatal(err)
	}
	pinned := map[string]string{}
	for _, line := range strings.Split(string(lock), "\n") {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 8 {
			t.Fatalf("SOURCES.lock: %d fields in %q", len(f), line)
		}
		if bad := rules.CheckSource(f[1], f[5]); len(bad) > 0 {
			t.Errorf("SOURCES.lock: %s: %v", f[0], bad)
		}
		pinned[f[1]] = f[4]
	}
	files, _ := filepath.Glob(filepath.Join(root, "rules", "src", "*.json"))
	if len(files) < 100 {
		t.Fatalf("%d files in rules/src", len(files))
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var head struct{ Lineage, Licence string }
		if err := json.Unmarshal(b, &head); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if bad := rules.CheckSource(head.Lineage, head.Licence); len(bad) > 0 {
			t.Errorf("%s: %v", filepath.Base(f), bad)
		}
		if _, ok := pinned[head.Lineage]; !ok {
			t.Errorf("%s: lineage %q has no line in SOURCES.lock", filepath.Base(f), head.Lineage)
		}
	}
	for _, r := range rules.All {
		if r.Src.Lineage != "own" && r.Src.Commit != pinned[r.Src.Lineage] {
			t.Errorf("%s: commit %s, SOURCES.lock pins %s", r.ID, r.Src.Commit, pinned[r.Src.Lineage])
			break
		}
	}
}

// go build works with no network and an empty go.sum, because the module has no dependency:
// no require line, and every package any of it imports is the standard library or its own. The
// rule data is Go source in the repository; nothing is fetched to read it.
func TestBuildNeedsNothingFromTheNetwork(t *testing.T) {
	root := repoRoot(t)
	mod, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(mod), "\n") {
		if f := strings.Fields(line); len(f) > 0 && (f[0] == "require" || f[0] == "replace" || f[0] == "exclude" || f[0] == "toolchain") {
			t.Errorf("go.mod has a %q line", f[0])
		}
	}
	if sum, err := os.ReadFile(filepath.Join(root, "go.sum")); err == nil && len(bytes.TrimSpace(sum)) > 0 {
		t.Error("go.sum is not empty")
	}
	if strings.Contains(strings.ToLower(string(mod)), "trufflesecurity") {
		t.Error("go.mod mentions trufflesecurity")
	}
	env := append(os.Environ(), "GOPROXY=off", "GOFLAGS=-mod=readonly", "GOTOOLCHAIN=local")
	build := exec.Command("go", "build", "./...")
	build.Dir, build.Env = root, env
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build ./... offline: %v\n%s", err, out)
	}
	list := exec.Command("go", "list", "-deps", "-f", "{{if not .Standard}}{{.ImportPath}}{{end}}", "./...")
	list.Dir, list.Env = root, env
	out, err := list.Output()
	if err != nil {
		t.Fatalf("go list -deps: %v", err)
	}
	for _, p := range strings.Fields(string(out)) {
		if p != "keyguard" && !strings.HasPrefix(p, "keyguard/") {
			t.Errorf("a package outside the standard library and this module is built: %s", p)
		}
	}
}
