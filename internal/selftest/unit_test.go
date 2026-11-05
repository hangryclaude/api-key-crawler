package selftest

import (
	"encoding/base64"
	"math"
	"slices"
	"strings"
	"testing"
	"time"

	"keyguard/internal/fp"
)

func TestPercentileIsNearestRank(t *testing.T) {
	ten := []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	for _, tc := range []struct {
		in   []float64
		p    float64
		want float64
	}{
		{ten, 50, 5}, // the lower middle of an even count
		{ten, 95, 10},
		{ten, 100, 10},
		{ten, 1, 1},
		{[]float64{7}, 50, 7},
		{[]float64{3, 9, 12}, 50, 9},
		{nil, 50, 0},
	} {
		if got := percentile(tc.in, tc.p); got != tc.want {
			t.Errorf("percentile(%v, %v) = %v, want %v", tc.in, tc.p, got, tc.want)
		}
	}
	p50, p95, max := stats([]time.Duration{50 * time.Millisecond, 10 * time.Millisecond, 30 * time.Millisecond, 20 * time.Millisecond, 40 * time.Millisecond})
	if p50 != 30 || p95 != 50 || max != 50 {
		t.Errorf("stats: %v %v %v", p50, p95, max)
	}
	if a, b, c := stats(nil); a != 0 || b != 0 || c != 0 {
		t.Error("stats of nothing")
	}
}

func TestFmtMs(t *testing.T) {
	for in, want := range map[float64]string{0.4: "0.4 ms", 9.96: "10.0 ms", 23.6: "24 ms", 150: "150 ms", 999.4: "999 ms", 1000: "1.00 s", 2500: "2.50 s"} {
		if got := fmtMs(in); got != want {
			t.Errorf("fmtMs(%v) = %q, want %q", in, got, want)
		}
	}
}

// The children get a whitelist, not a filtered copy of the caller's environment: a key
// exported in the shell that runs the selftest must not be able to reach a check.
func TestChildEnvIsAWhitelist(t *testing.T) {
	environ := []string{
		"PATH=/usr/bin:/opt/homebrew/bin", "TMPDIR=/tmp/x", "USER=someone", "LOGNAME=someone",
		"HOME=/Users/real", "KEYGUARD_HOME=/Users/real/.keyguard", "GIT_CONFIG_GLOBAL=/Users/real/.gitconfig",
		"GIT_DIR=/somewhere", "GIT_INDEX_FILE=/somewhere/index", "GIT_WORK_TREE=/somewhere", "GIT_CONFIG_PARAMETERS='x=y'",
		"OPENAI_API_KEY=not-really", "GH_TOKEN=not-really", "GITHUB_TOKEN=not-really", "ANTHROPIC_AUTH_TOKEN=not-really",
		"XDG_CONFIG_HOME=/Users/real/.config", "SSH_AUTH_SOCK=/tmp/agent", "AWS_SECRET_ACCESS_KEY=not-really",
	}
	env := childEnv(environ, "/m/home", "/m/home/.keyguard", "/m/gitconfig")
	has := func(kv string) bool { return slices.Contains(env, kv) }
	for _, want := range []string{"PATH=/usr/bin:/opt/homebrew/bin", "TMPDIR=/tmp/x", "HOME=/m/home", "KEYGUARD_HOME=/m/home/.keyguard",
		"GIT_CONFIG_GLOBAL=/m/gitconfig", "GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0", "GIT_EDITOR=true"} {
		if !has(want) {
			t.Errorf("the environment lacks %s", want)
		}
	}
	for _, kv := range env {
		name, _, _ := strings.Cut(kv, "=")
		switch name {
		case "PATH", "TMPDIR", "USER", "LOGNAME", "HOME", "KEYGUARD_HOME", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_NOSYSTEM",
			"GIT_TERMINAL_PROMPT", "GIT_EDITOR", "GIT_ADVICE", "LC_ALL", "LANG":
		default:
			t.Errorf("%s got through to the children", name)
		}
	}
	for _, kv := range env {
		if strings.Contains(kv, "/Users/real") || strings.Contains(kv, "not-really") {
			t.Errorf("something of the caller's got through: %s", kv)
		}
	}
	// No PATH at all still leaves a PATH with git on it.
	if env := childEnv(nil, "/h", "/r", "/g"); !slices.ContainsFunc(env, func(kv string) bool { return strings.HasPrefix(kv, "PATH=") }) {
		t.Error("no PATH")
	}
}

func TestFakesAreRandomShapedLikeKeysAndRemembered(t *testing.T) {
	s := &suite{}
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		v := s.fake("ghp_", 36)
		if !strings.HasPrefix(v, "ghp_") || len(v) != 40 || seen[v] {
			t.Fatalf("a fake of the wrong shape or a repeat: %s, %d long", fp.Shape(v), len(v))
		}
		if fp.Entropy(v[4:]) < 4.4 {
			t.Fatalf("%s is not random enough to survive an entropy gate", fp.Shape(v))
		}
		for _, c := range v[4:] {
			if !strings.ContainsRune(alnum, c) {
				t.Fatalf("%s has a character outside the alphabet", fp.Shape(v))
			}
		}
		seen[v] = true
	}
	if len(s.fakes) != 100 {
		t.Errorf("only %d of 100 fakes were remembered", len(s.fakes))
	}
}

func TestLeaksFindsEveryKnownSpelling(t *testing.T) {
	s := &suite{}
	a, b := s.fake("sk-proj-", 48), s.fake("ghp_", 36)
	if s.leaks("nothing at all") != 0 || s.leaks("sk-proj-…abcd and ghp_…wxyz") != 0 {
		t.Error("a shape is not a leak")
	}
	for _, text := range []string{
		"x " + a + " y",
		base64.StdEncoding.EncodeToString([]byte(a)),
		base64.RawStdEncoding.EncodeToString([]byte(a)),
		base64.URLEncoding.EncodeToString([]byte(a)),
		base64.RawURLEncoding.EncodeToString([]byte(a)),
	} {
		if s.leaks(text) != 1 {
			t.Errorf("a leak was missed in a spelling of %d characters", len(text))
		}
	}
	if s.leaks(a+" "+b) != 2 {
		t.Error("two leaks counted as fewer")
	}
	// One character short is not the secret.
	if s.leaks(a[:len(a)-1]) != 0 {
		t.Error("a prefix of a fake counted as the fake")
	}
}

func TestLineIsShortSafeAndOneLine(t *testing.T) {
	s := &suite{dir: "/var/folders/xx/T/keyguard-gates-1"}
	got := s.line("git failed in /var/folders/xx/T/keyguard-gates-1/work/r:\n\tfatal: nope  \n" + strings.Repeat("x", 400))
	if strings.ContainsAny(got, "\n\t") || strings.Contains(got, "keyguard-gates-1") || !strings.HasPrefix(got, "git failed in <machine>/work/r: fatal: nope") {
		t.Errorf("line: %q", got)
	}
	if n := len([]rune(got)); n > 240 {
		t.Errorf("%d runes", n)
	}
	// A secret-looking token in an error is masked: the one place a raw value could slip out.
	tok := (&suite{}).fake("ghp_", 36)
	if strings.Contains(s.line("hook said "+tok), tok) {
		t.Error("a secret-looking token got into a detail line")
	}
}

func TestLabelNeverCarriesLateArguments(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"git", []string{"commit", "-q", "-m", "msg"}, "git commit -q"},
		{"/opt/homebrew/bin/git", []string{"-c", "core.hooksPath=/dev/null", "commit"}, "git core.hooksPath=/dev/null commit"},
		{"sh", []string{"-c", "script", "name"}, "sh script name"},
	} {
		if got := label(tc.name, tc.args); got != tc.want {
			t.Errorf("label(%s %v) = %q, want %q", tc.name, tc.args, got, tc.want)
		}
	}
}

func TestCatalogIsConsistent(t *testing.T) {
	all, groupIDs := Catalog()
	if len(all) < 30 {
		t.Errorf("only %d checks", len(all))
	}
	ids := map[string]bool{}
	names := map[string]bool{}
	used := map[string]bool{}
	var order []string
	for _, c := range all {
		if ids[c.ID] || names[c.Name] {
			t.Errorf("%s is listed twice", c.ID)
		}
		ids[c.ID], names[c.Name] = true, true
		used[c.Group] = true
		if !slices.Contains(groupIDs, c.Group) {
			t.Errorf("%s is in the unknown group %q", c.ID, c.Group)
		}
		order = append(order, c.Group)
	}
	for _, g := range groupIDs {
		if !used[g] {
			t.Errorf("the group %q has no checks", g)
		}
	}
	// Groups run in the order they are listed: the audits only mean something after the
	// checks they audit, and the speed checks are best alone at the end.
	last := -1
	for _, g := range order {
		i := slices.Index(groupIDs, g)
		if i < last {
			t.Errorf("%s comes after a later group", g)
		}
		last = i
	}
	if all[0].ID != "machine" {
		t.Errorf("the machine check must come first, not %s", all[0].ID)
	}
	// The things PLAN.md asks for by name are there.
	for _, id := range []string{"precommit-known", "precommit-names", "reftx-noverify", "push-unknown", "push-clean", "quiet-clone",
		"quiet-fetch", "quiet-pull", "quiet-rebase", "quiet-stash", "quiet-branch", "mirror-skip", "speed-precommit", "speed-reftx"} {
		if !ids[id] {
			t.Errorf("no check %s", id)
		}
	}
}

func TestSelectionTakesGroupsAndIDs(t *testing.T) {
	sel, err := selection([]string{"reftx", "quiet-clone"})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, ck := range checks() {
		if sel(ck) {
			got = append(got, ck.id)
		}
	}
	if want := "reftx-noverify,reftx-ways,quiet-clone"; strings.Join(got, ",") != want {
		t.Errorf("selected %v, want %s", got, want)
	}
	all, err := selection([]string{"gates"})
	if err != nil {
		t.Fatal(err)
	}
	for _, ck := range checks() {
		if !all(ck) {
			t.Errorf("gates leaves out %s", ck.id)
		}
	}
	every, _ := selection(nil)
	if !every(checks()[3]) {
		t.Error("an empty list selects everything")
	}
	if _, err := selection([]string{"precommit", "nope"}); err == nil || !strings.Contains(err.Error(), `"nope"`) {
		t.Errorf("unknown name: %v", err)
	}
}

func TestGroupsFoldTheChecksOfEachSection(t *testing.T) {
	rep := &Report{
		Checks: []Check{
			{ID: "machine", Group: "machine", Name: "m", OK: true, Seconds: 0.5},
			{ID: "precommit-known", Group: "precommit", Name: "a", OK: true, Seconds: 1},
			{ID: "precommit-scanner", Group: "precommit", Name: "b", OK: false, Detail: "it was not blocked", Seconds: 2},
			{ID: "speed-reftx", Group: "speed", Name: "r", OK: true, Seconds: 0.25},
		},
		Latency: []Latency{{Hook: "reference-transaction", P50ms: 23.6, BudgetMs: 40}},
	}
	g := rep.Groups()
	if len(g) != 3 {
		t.Fatalf("groups: %+v", g)
	}
	if !g[0].OK || g[0].Detail != "1 check passed" {
		t.Errorf("machine: %+v", g[0])
	}
	if g[1].OK || g[1].Checks != 2 || g[1].Seconds != 3 || !strings.HasPrefix(g[1].Detail, "FAILED precommit-scanner (it was not blocked)") || strings.Contains(g[1].Detail, "precommit-known") {
		t.Errorf("precommit: %+v", g[1])
	}
	if !g[2].OK || g[2].Detail != "reference-transaction p50 24 ms of 40 ms" {
		t.Errorf("speed: %+v", g[2])
	}
	if len(rep.Failed()) != 1 || rep.Failed()[0].ID != "precommit-scanner" {
		t.Errorf("Failed: %+v", rep.Failed())
	}
}

func TestTableLinesUpAndSaysWhatFailed(t *testing.T) {
	rep := &Report{
		Binary: "/x/keyguard", Git: "2.55.0", Seconds: 12.34,
		Checks: []Check{
			{ID: "machine", Group: "machine", Name: "wired", OK: true, Seconds: 0.2, Detail: "fine"},
			{ID: "precommit-known", Group: "precommit", Name: "blocks a learned key", OK: true, Seconds: 12.5, Detail: "refused"},
			{ID: "precommit-scanner", Group: "precommit", Name: "blocks a token", OK: false, Seconds: 0.01, Detail: "was not blocked"},
		},
	}
	out := table(rep)
	for _, want := range []string{"git gates: the hooks of /x/keyguard", "(git 2.55.0)", "\nthe throwaway machine\n", "\npre-commit\n",
		"  ok    wired" + strings.Repeat(" ", 18) + "0.20 s  fine\n", "  ok    blocks a learned key  12.50 s  refused\n",
		"  FAIL  blocks a token" + strings.Repeat(" ", 9) + "0.01 s  was not blocked\n",
		"1 of 3 checks FAILED: precommit-scanner (12.3 s)", "keyguard selftest --only precommit-scanner"} {
		if !strings.Contains(out, want) {
			t.Errorf("the table lacks %q:\n%s", want, out)
		}
	}
	rep.Checks[2].OK = true
	if out := table(rep); !strings.Contains(out, "3 of 3 checks passed (12.3 s)") || strings.Contains(out, "FAIL") {
		t.Errorf("a passing table:\n%s", out)
	}
}

func TestPercentileDoesNotPanicOnOneRun(t *testing.T) {
	if got := percentile([]float64{4}, 95); got != 4 || math.IsNaN(got) {
		t.Errorf("%v", got)
	}
}
