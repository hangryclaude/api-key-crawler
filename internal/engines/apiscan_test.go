package engines

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"

	"keyguard/internal/core"
)

// ----- P0-22: API resources by exact URL -----

func TestScanAPI(t *testing.T) {
	f := getFixture(t)
	token := register("ghp_" + tok(alnumCS, 36))
	leaked := register(fake("stripe"))
	const issue = "https://github.com/someowner/somerepo/issues/12"
	report := leakJSON(t,
		map[string]any{"RuleID": "stripe-access-token", "File": "issues/12", "StartLine": 3, "Secret": leaked, "Match": "k=" + leaked,
			"Attributes": map[string]any{"url": issue + "#issue-1", "resource": "github.issue", "confidence": "high"}},
		map[string]any{"RuleID": "stripe-access-token", "File": "issues/12/comments/9", "StartLine": 1, "Secret": leaked, "Match": "k=" + leaked,
			"Attributes": map[string]any{"url": issue + "#issuecomment-9", "resource": "github.issue_comment"}},
	)
	e, calls := recordingEngine(t, "betterleaks", f.kr, report, "", 0)
	api, ok := e.(core.APIScanner)
	if !ok {
		t.Fatal("betterleaks is not a core.APIScanner")
	}
	o := testOpts()
	o.Env = []string{"GITHUB_TOKEN=" + token, "TMPDIR=/somewhere/else", "GIT_CONFIG_GLOBAL=/etc/gitconfig"}
	var hits []core.Hit
	if err := api.ScanAPI(context.Background(), issue, o, func(h core.Hit) { hits = append(hits, h) }); err != nil {
		t.Fatal(err)
	}
	assertSafe(t, "api", hits)
	cs := calls()
	if len(cs) != 1 {
		t.Fatalf("%d starts", len(cs))
	}
	c := cs[0]
	if !hasArgs(c.args, "github", issue) || !slices.Contains(c.args, "--exclude=release-assets") {
		t.Errorf("args %v", c.args)
	}
	for _, a := range c.args {
		if strings.Contains(a, token) || a == "--token" || strings.HasPrefix(a, "--token=") {
			t.Errorf("the token is in argv: %v", a == "--token")
		}
	}
	if c.env["GITHUB_TOKEN"] != token {
		t.Error("the token did not reach the engine by environment")
	}
	// The caller's extras cannot undo the environment the engine runs in.
	if strings.HasPrefix(c.env["TMPDIR"], "/somewhere") || c.env["GIT_CONFIG_GLOBAL"] != "/dev/null" {
		t.Errorf("caller env overrode a protective variable: TMPDIR=%q GIT_CONFIG_GLOBAL=%q", c.env["TMPDIR"], c.env["GIT_CONFIG_GLOBAL"])
	}
	if len(hits) != 2 {
		t.Fatalf("%d hits", len(hits))
	}
	byURL := map[string]string{}
	for _, h := range hits {
		byURL[h.Loc.URL] = h.Loc.Kind
		if h.FP != f.kr.FP(leaked) || h.Loc.Source != "github.com/x/y" || h.Loc.Commit != "" {
			t.Errorf("hit %+v", h.Loc)
		}
	}
	if byURL[issue+"#issue-1"] != "issue" || byURL[issue+"#issuecomment-9"] != "comment" {
		t.Errorf("kinds by url: %v", byURL)
	}
	b, _ := json.Marshal(hits)
	if strings.Contains(string(b), token) {
		t.Error("the token is in a hit")
	}

	// The deep run takes release assets too.
	o.ReleaseAssets = true
	if err := api.ScanAPI(context.Background(), "https://github.com/someowner/somerepo/releases/tag/v1.0", o, func(core.Hit) {}); err != nil {
		t.Fatal(err)
	}
	if last := calls()[1]; slices.Contains(last.args, "--exclude=release-assets") || !hasArgs(last.args, "github", "https://github.com/someowner/somerepo/releases/tag/v1.0") {
		t.Errorf("deep run args %v", last.args)
	}
}

func TestScanAPITakesOnlyExactURLs(t *testing.T) {
	f := getFixture(t)
	e, calls := recordingEngine(t, "betterleaks", f.kr, "[]", "", 0)
	api := e.(core.APIScanner)
	for _, ok := range []string{
		"https://github.com/o/r/issues/1", "https://github.com/o/r/pull/20", "https://github.com/o/r/releases/tag/v1.2.3",
		"https://github.com/o/r/actions/runs/1234567",
	} {
		if err := api.ScanAPI(context.Background(), ok, testOpts(), func(core.Hit) {}); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	n := len(calls())
	for _, bad := range []string{
		"https://github.com/o", "https://github.com/o/r", "https://github.com/o/r/issues", "https://github.com/o/r/issues/x",
		"https://github.com/o/r/issues/1?since=2020", "http://github.com/o/r/issues/1", "https://evil.example/o/r/issues/1",
		"https://github.com/o/r/actions/runs", "https://github.com/o/r/releases", "-https://github.com/o/r/issues/1", "",
	} {
		if err := api.ScanAPI(context.Background(), bad, testOpts(), func(core.Hit) {}); err == nil {
			t.Errorf("%q was accepted: it would make betterleaks list everything below it", bad)
		}
	}
	if len(calls()) != n {
		t.Error("a refused URL started the engine")
	}
	g, _ := New("gitleaks", "/bin/true", f.kr)
	if err := g.(core.APIScanner).ScanAPI(context.Background(), "https://github.com/o/r/issues/1", testOpts(), func(core.Hit) {}); !errors.Is(err, core.ErrUnsupported) {
		t.Errorf("gitleaks has no GitHub source: %v", err)
	}
	for _, name := range []string{"trufflehog", "titus"} {
		e, _ := New(name, "/bin/true", f.kr)
		if _, ok := e.(core.APIScanner); ok {
			t.Errorf("%s claims an API source it does not have", name)
		}
	}
}

// ----- P0-07: warming what an engine builds on first use -----

func TestPrewarmBuildsTheTitusCacheUnderTheDataRoot(t *testing.T) {
	f := getFixture(t)
	needEngine(t, "titus")
	home := t.TempDir() + "/kg"
	t.Setenv("KEYGUARD_HOME", home)
	e := newEngine(t, "titus", f.kr)
	if err := Prewarm(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	entries, err := readDirNames(home + "/cache/titus")
	if err != nil || len(entries) == 0 {
		t.Fatalf("no titus cache under the data root after Prewarm: %v %v", entries, err)
	}
}

func readDirNames(dir string) ([]string, error) {
	es, err := os.ReadDir(dir)
	var out []string
	for _, e := range es {
		out = append(out, e.Name())
	}
	return out, err
}
