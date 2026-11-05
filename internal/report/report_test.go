package report

import (
	"html"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"keyguard/internal/core"
	"keyguard/internal/fp"
)

// --- helpers --------------------------------------------------------------------------

var (
	h1Re    = regexp.MustCompile(`(?s)<h1>(.*?)</h1>`)
	styleRe = regexp.MustCompile(`(?s)<style>(.*?)</style>`)
	tagRe   = regexp.MustCompile(`<(/?)([a-zA-Z][a-zA-Z0-9]*)([^>]*)>`)
)

func h1(t *testing.T, doc string) string {
	t.Helper()
	m := h1Re.FindStringSubmatch(doc)
	if m == nil {
		t.Fatal("page has no <h1>")
	}
	return html.UnescapeString(m[1])
}

func section(t *testing.T, doc, id string) string {
	t.Helper()
	i := strings.Index(doc, `<section id="`+id+`"`)
	if i < 0 {
		t.Fatalf("no section %q", id)
	}
	j := strings.Index(doc[i:], "</section>")
	if j < 0 {
		t.Fatalf("section %q is not closed", id)
	}
	return doc[i : i+j]
}

// balanced fails when a tag is left open or closed out of order. html/template does not
// check the markup it is given, and a stray </div> reflows a whole page.
func balanced(t *testing.T, doc string) {
	t.Helper()
	void := map[string]bool{"meta": true, "link": true, "br": true, "hr": true, "img": true, "input": true, "base": true, "col": true}
	doc = styleRe.ReplaceAllString(doc, "<style></style>")
	var stack []string
	for _, m := range tagRe.FindAllStringSubmatch(doc, -1) {
		name := strings.ToLower(m[2])
		switch {
		case void[name]:
		case m[1] == "/":
			if len(stack) == 0 || stack[len(stack)-1] != name {
				t.Fatalf("closing </%s> with stack %v", name, stack)
			}
			stack = stack[:len(stack)-1]
		default:
			stack = append(stack, name)
		}
	}
	if len(stack) != 0 {
		t.Fatalf("unclosed tags: %v", stack)
	}
}

// strayTokens is a second opinion on "no key-like string on the page", independent of
// maskRuns: any 20+ character stretch of letters and digits (dashes and underscores split
// it too) with real variety in it. Static markup and CSS must pass it as well.
func strayTokens(doc string) []string {
	var out []string
	for i := 0; i < len(doc); {
		c := doc[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
			i++
			continue
		}
		j := i
		for j < len(doc) && (doc[j] >= 'a' && doc[j] <= 'z' || doc[j] >= 'A' && doc[j] <= 'Z' || doc[j] >= '0' && doc[j] <= '9') {
			j++
		}
		if tok := doc[i:j]; len(tok) >= 20 && fp.Entropy(tok) >= 3.0 {
			out = append(out, fp.Shape(tok))
		}
		i = j
	}
	return out
}

func noKeyLike(t *testing.T, doc string) {
	t.Helper()
	if s := strayTokens(doc); len(s) > 0 {
		t.Fatalf("key-like tokens on the page (shown as shapes): %v", s)
	}
	// The production rule with its own alphabet, so URLs and paths are judged the way
	// the page judges them.
	if hasSecretLike(doc) {
		t.Fatal("hasSecretLike finds a key-like run on the page")
	}
}

func noRaw(t *testing.T, doc string, f *fixture) {
	t.Helper()
	for i, raw := range f.raws {
		if strings.Contains(doc, raw) {
			t.Fatalf("raw secret #%d (%s) is on the page", i, leakShape(raw))
		}
		// A 10-character window of the random part is far longer than the 4-character tail
		// a shape shows. The constant prefix is shown on purpose, so it is not searched.
		if at, ok := hasWindow(doc, f.rands[i], 10); ok {
			t.Fatalf("raw secret #%d (%s) leaks a window starting %d characters into its random part", i, leakShape(raw), at)
		}
	}
	for _, s := range f.secrets {
		if strings.Contains(doc, s.FP) {
			t.Fatalf("fingerprint of %s is on the page; show the short id only", s.ID)
		}
	}
	for i, c := range f.commits {
		if strings.Contains(doc, c) {
			t.Fatalf("full 40-character commit #%d is on the page", i)
		}
	}
}

func inputOf(secrets []core.Secret, run core.RunStats, layers []core.LayerStatus) input {
	return input{secrets: secrets, run: run, layers: layers, now: fixedNow, zone: time.UTC, stale: 2 * time.Hour}
}

// --- tests ----------------------------------------------------------------------------

func TestRenderZeroSecrets(t *testing.T) {
	f := newFixture(t)
	doc := mustRender(t, reporter(""), f, healthyRun(), healthyLayers())

	if got := h1(t, doc); got != "No live keys exposed" {
		t.Fatalf("status sentence = %q", got)
	}
	if !strings.Contains(doc, `class="hero k-ok"`) {
		t.Fatal("a clean report should use the ok hero")
	}
	for _, want := range []string{
		`<title>No live keys exposed · keyguard</title>`,
		`<h2 id="h-rotate">Rotate now <span class="count">0</span></h2>`,
		`<h2 id="h-layers">Layers</h2>`, `<h2 id="h-coverage">Coverage</h2>`, `<h2 id="h-engines">Engines</h2>`,
		`id="rotate"`, `id="layers"`, `id="coverage"`, `id="engines"`, `id="lower"`, `id="ignored"`,
		"Nothing to rotate.", "Lower severity: none", "Ignored: none",
		"470 sources checked.", "All 8 layers working.",
		"https://github.com/settings/security_analysis",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("page is missing %q", want)
		}
	}
	if strings.Contains(doc, "<details") {
		t.Error("with nothing to review there is nothing to fold")
	}
	for _, e := range []string{"betterleaks", "gitleaks", "trufflehog", "titus", "known"} {
		if !strings.Contains(section(t, doc, "engines"), e) {
			t.Errorf("engine %s missing from the Engines section", e)
		}
	}
	for _, landmark := range []string{"<header ", "<main>", "<nav ", "<footer>"} {
		if strings.Count(doc, landmark) != 1 {
			t.Errorf("want exactly one %s landmark", landmark)
		}
	}
	balanced(t, doc)
	noKeyLike(t, doc)
}

func TestRenderMixed30(t *testing.T) {
	f := mixed30(t)
	if len(f.secrets) != 30 {
		t.Fatalf("fixture has %d secrets, want 30", len(f.secrets))
	}
	r := reporter("")
	r.Coverage = Coverage{Repos: 439, Wikis: 29, Gists: 2, Public: 5, Refs: 18204, Commits: 41330, Blobs: 99120, APIItems: 812}
	layers := healthyLayers()
	layers[5].OK, layers[5].Detail = false, "launchd job io.github.hangryclaude.keyguard.poll has not run for 3 hours"
	run := healthyRun()
	run.Skipped = 2
	run.Failed = 2
	run.Notes = []string{"2 sources skipped: clone timed out (will retry next poll)"}
	doc := mustRender(t, r, f, run, layers)

	// Hero: three critical, one of them without a verifier, so "live" is not claimed.
	if got := h1(t, doc); got != "3 keys exposed — rotate now" {
		t.Fatalf("status sentence = %q", got)
	}
	v := build(inputOf(f.secrets, run, layers))
	wantLevels := map[string]string{"Critical": "3", "High": "4", "Medium": "4", "Low": "7", "Not rated": "1", "Ignored": "11"}
	for _, l := range v.Levels {
		if wantLevels[l.Name] != l.N {
			t.Errorf("level %s = %s, want %s", l.Name, l.N, wantLevels[l.Name])
		}
		delete(wantLevels, l.Name)
	}
	if len(wantLevels) != 0 {
		t.Errorf("levels missing: %v", wantLevels)
	}

	rot := section(t, doc, "rotate")
	if n := strings.Count(rot, "<tr>") - 2; n != 7 { // two tables, one header row each
		t.Errorf("Rotate now has %d rows, want 7", n)
	}
	if !strings.Contains(rot, `<span class="count">7</span>`) {
		t.Error("Rotate now heading should count 7")
	}
	// Critical group first, live keys before the unverified one.
	order := []string{f.secrets[0].ID, f.secrets[1].ID, f.secrets[2].ID}
	last := -1
	for _, id := range order {
		at := strings.Index(rot, id)
		if at <= last {
			t.Fatalf("critical rows out of order near %s", id)
		}
		last = at
	}
	if strings.Index(rot, "Critical: strangers can read these") > strings.Index(rot, "High: private, but still yours") {
		t.Error("critical group must come before high")
	}
	for _, want := range []string{
		"Rotate at Anthropic", "https://platform.claude.com/settings/keys",
		"Rotate at GitHub", "https://github.com/settings/tokens",
		"Rotate at Stripe", "https://dashboard.stripe.com/apikeys",
		"Rotate at AWS", "Rotate at Groq", "Rotate at Hugging Face",
		">Public</span>", ">Secret gist</span>", ">Private</span>", ">This Mac</span>",
		"Your OPENAI_API_KEY", "Your GROQ_API_KEY",
		"3 more places",
	} {
		if !strings.Contains(rot, want) {
			t.Errorf("Rotate now is missing %q", want)
		}
	}
	// Numbers that matter are bold; the Places column is right-aligned.
	if !strings.Contains(rot, `<th scope="col" class="num">Places</th>`) || !strings.Contains(rot, `class="num"><div class="cell"><strong>4</strong>`) {
		t.Error("Places column should be a bold, right-aligned number (the gist secret has 4 places)")
	}

	// Strips tell the reader what the green parts of the page do not cover.
	for _, want := range []string{"1 protection layer of 8 is down.", "2 sources failed in the last run and were not scanned."} {
		if !strings.Contains(doc, want) {
			t.Errorf("missing strip %q", want)
		}
	}
	if !strings.Contains(section(t, doc, "layers"), `<span class="chip state-alert">Down</span>`) {
		t.Error("the down layer should be marked Down")
	}
	if strings.Index(section(t, doc, "layers"), "Poller") > strings.Index(section(t, doc, "layers"), "Commit gate") {
		t.Error("a broken layer should be listed before the working ones")
	}
	cov := section(t, doc, "coverage")
	for _, want := range []string{"18,204", "41,330", "99,120", "812", "439", ">29<", "Public sources", "Skipped", "2 sources skipped: clone timed out"} {
		if !strings.Contains(cov, want) {
			t.Errorf("Coverage is missing %q", want)
		}
	}
	// Lower and Ignored fold away, closed.
	if n := strings.Count(doc, `<details class="fold">`); n != 2 {
		t.Errorf("want 2 closed folds, got %d", n)
	}
	if !strings.Contains(doc, "Lower severity: 12 to review (4 medium, 7 low, 1 not rated)") {
		t.Error("lower severity summary is wrong")
	}
	if !strings.Contains(doc, "Ignored: 11 (3 marked by you, 3 resolved, 5 need no action)") {
		t.Error("ignored summary is wrong")
	}
	// Every secret is somewhere on the page, none of them raw.
	for _, s := range f.secrets {
		if !strings.Contains(doc, s.ID) {
			t.Errorf("secret %s is missing from the page", s.ID)
		}
	}
	// Resolved and ignored criticals must not show up under Rotate now.
	for _, s := range f.secrets {
		if s.Status != "open" && strings.Contains(rot, s.ID) {
			t.Errorf("%s secret %s is listed under Rotate now", s.Status, s.ID)
		}
	}
	noRaw(t, doc, f)
	noKeyLike(t, doc)
	balanced(t, doc)
}

// A key that is verified live, or learned from the user's own files, is not a false positive,
// so the page must not hand the reader the command that would hide it.
func TestAllowCommandIsNeverOfferedForKeysKnownToBeReal(t *testing.T) {
	f := newFixture(t)
	live := f.add(t, spec{kind: 0, sev: core.Critical, verified: core.Live, vis: core.Public})
	known := f.add(t, spec{kind: 1, sev: core.Critical, verified: core.Unverified, vis: core.Public, known: "kg1a2b3c OPENAI_API_KEY"})
	unverified := f.add(t, spec{kind: 2, sev: core.Critical, verified: core.Unverified, vis: core.Public})
	doc := mustRender(t, reporter(""), f, healthyRun(), healthyLayers())
	for _, s := range []core.Secret{live, known} {
		if strings.Contains(doc, "keyguard allow "+s.ID) {
			t.Errorf("the page offers an allow command for %s, a key known to be real", s.ID)
		}
	}
	if !strings.Contains(doc, "keyguard allow "+unverified.ID) {
		t.Error("an unverified, unknown key should come with its allow command")
	}
}

func TestHeroStates(t *testing.T) {
	f := newFixture(t)
	live := func(v core.Verified, sevv core.Severity, status string) core.Secret {
		return f.add(t, spec{kind: 0, sev: sevv, verified: v, vis: core.Public, status: status})
	}
	run := healthyRun()
	stale := healthyRun()
	stale.Finished = fixedNow.Add(-5 * time.Hour).Format(time.RFC3339)
	running := core.RunStats{Kind: "poll", Started: fixedNow.Add(-30 * time.Minute).Format(time.RFC3339)}
	errRun := healthyRun()
	errRun.Engines = map[string]core.EngineStats{"titus": {Seconds: 1, Errors: 2}}
	down := healthyLayers()
	down[0].OK = false

	cases := []struct {
		name    string
		secrets []core.Secret
		run     core.RunStats
		layers  []core.LayerStatus
		kind    string
		head    string
		sub     string // substring of the sub line
		strip   string // substring of some strip, "" for none
	}{
		{"clean", nil, run, healthyLayers(), "ok", "No live keys exposed", "470 sources checked", ""},
		{"never scanned", nil, core.RunStats{}, nil, "unknown", "Not scanned yet", "not an all-clear", ""},
		{"scan running or dead", nil, running, nil, "unknown", "Not scanned yet", "started 30 minutes ago", ""},
		{"stale and clean", nil, stale, healthyLayers(), "warn", "No live keys exposed at the last scan", "5 hours ago", ""},
		{"one live critical", []core.Secret{live(core.Live, core.Critical, "open")}, run, healthyLayers(), "alert",
			"1 live key exposed — rotate now", "Anyone could read it. Rotate it below.", ""},
		{"two live critical", []core.Secret{live(core.Live, core.Critical, "open"), live(core.Live, core.Critical, "open")},
			run, healthyLayers(), "alert", "2 live keys exposed — rotate now", "Rotate each one below.", ""},
		{"one live one known", []core.Secret{live(core.Live, core.Critical, "open"), live(core.Unverified, core.Critical, "open")},
			run, healthyLayers(), "alert", "2 keys exposed — rotate now", "", ""},
		{"high only", []core.Secret{live(core.Live, core.High, "open")}, run, healthyLayers(), "warn",
			"1 live key in private places — rotate now", "Nobody outside can read it today.", ""},
		{"critical beats high", []core.Secret{live(core.Live, core.High, "open"), live(core.Live, core.Critical, "open")},
			run, healthyLayers(), "alert", "1 live key exposed — rotate now", "", ""},
		{"resolved critical is not news", []core.Secret{live(core.Dead, core.Critical, "resolved")}, run, healthyLayers(),
			"ok", "No live keys exposed", "", ""},
		{"ignored critical is not news", []core.Secret{live(core.Live, core.Critical, "ignored")}, run, healthyLayers(),
			"ok", "No live keys exposed", "", ""},
		{"empty status counts as open", []core.Secret{live(core.Live, core.Critical, "")}, run, healthyLayers(),
			"alert", "1 live key exposed — rotate now", "", ""},
		{"layer down", nil, run, down, "ok", "No live keys exposed", "", "1 protection layer of 8 is down."},
		{"engine errors", nil, errRun, healthyLayers(), "ok", "No live keys exposed", "", "2 engine errors in the last run."},
		{"stale with a critical", []core.Secret{live(core.Live, core.Critical, "open")}, stale, healthyLayers(), "alert",
			"1 live key exposed — rotate now", "", "The last scan finished 5 hours ago."},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// f.add recorded these under f.secrets too; the case lists are what render.
			v := build(inputOf(c.secrets, c.run, c.layers))
			if v.Hero.Kind != c.kind || v.Hero.Headline != c.head {
				t.Fatalf("hero = %s %q, want %s %q", v.Hero.Kind, v.Hero.Headline, c.kind, c.head)
			}
			if !strings.Contains(v.Hero.Sub, c.sub) {
				t.Errorf("sub = %q, want it to contain %q", v.Hero.Sub, c.sub)
			}
			var strips []string
			for _, s := range v.Strips {
				strips = append(strips, s.Text)
			}
			joined := strings.Join(strips, " | ")
			if c.strip == "" && len(strips) != 0 {
				t.Errorf("unexpected strips: %s", joined)
			}
			if c.strip != "" && !strings.Contains(joined, c.strip) {
				t.Errorf("strips = %s, want %q", joined, c.strip)
			}
			if c.kind != "ok" && v.Hero.Kind == "ok" {
				t.Error("a page with something to do must not be green")
			}
		})
	}
}

// An empty list under a grey or amber hero must not turn into a green "all clear".
func TestEmptyListNeverContradictsTheHero(t *testing.T) {
	stale := healthyRun()
	stale.Finished = fixedNow.Add(-30 * time.Hour).Format(time.RFC3339)
	stale.Started = fixedNow.Add(-31 * time.Hour).Format(time.RFC3339)
	for name, c := range map[string]struct {
		run  core.RunStats
		want string
		kind string
	}{
		"fresh scan":    {healthyRun(), "Nothing to rotate.", "k-ok"},
		"stale scan":    {stale, "Nothing to rotate at the last scan.", "k-warn"},
		"never scanned": {core.RunStats{}, "No result yet. Nothing has been scanned.", "k-unknown"},
	} {
		doc := mustRender(t, reporter(""), newFixture(t), c.run, healthyLayers())
		want := `<p class="empty ` + c.kind + `">` + c.want + `</p>`
		if !strings.Contains(doc, want) {
			t.Errorf("%s: want %s", name, want)
		}
		if name != "fresh scan" && strings.Contains(doc, ">Nothing to rotate.<") {
			t.Errorf("%s: says an unqualified all-clear", name)
		}
	}
}

// A run whose stamps run backwards must not print a negative or dashed duration.
func TestBackwardsRunStampsSayNothing(t *testing.T) {
	run := healthyRun()
	run.Started, run.Finished = run.Finished, run.Started
	doc := mustRender(t, reporter(""), newFixture(t), run, healthyLayers())
	if strings.Contains(doc, "took") || strings.Contains(doc, "Run time") || strings.Contains(doc, "took —") {
		t.Error("bad run stamps produced a duration")
	}
}

func TestEscapesEverything(t *testing.T) {
	const xss = `<script>window.pwned=1</script>`
	const attr = `"><img src=x onerror=alert(1)>`
	const js = `javascript:alert(1)`
	f := newFixture(t)
	evil := f.add(t, spec{kind: 0, sev: core.Critical, verified: core.Live, locs: []core.Location{{
		Source: "github.com/evil/" + xss, Kind: attr, Visibility: core.Public,
		Ref: "refs/heads/" + attr, Commit: "abc1234" + xss, Path: xss + "/a.py", Line: 7,
		Author: xss, Date: attr, URL: js,
	}, {
		Source: "github.com/hangryclaude/ok", Kind: "repo", Visibility: core.Public, Path: attr, URL: "https://evil.example/" + xss,
	}}})
	_ = evil
	f.secrets[0].Type = xss
	f.secrets[0].Known = "kg000000 " + xss
	f.secrets[0].TriageWhy = xss
	f.secrets[0].ID = attr
	f.add(t, spec{kind: 1, sev: core.Low, verified: core.Unverified, vis: core.Private, why: xss})
	f.secrets[1].Type = attr
	f.secrets[1].TriageWhy = attr
	f.add(t, spec{kind: 2, sev: core.Info, verified: core.Unverified, vis: core.Private, why: xss})

	run := healthyRun()
	run.Kind = xss
	run.Notes = []string{xss, attr}
	run.Engines = map[string]core.EngineStats{xss: {Seconds: 1, Hits: 1, Errors: 1}}
	run.Started, run.Finished = xss, attr
	layers := []core.LayerStatus{{Name: xss, OK: false, Detail: attr, CheckedAt: xss}}
	doc := mustRender(t, reporter(""), f, run, layers)

	lower := strings.ToLower(doc)
	for _, bad := range []string{"<script", "<img", "<iframe", "javascript:", "pwned=1</", "evil.example"} {
		if strings.Contains(lower, bad) {
			t.Errorf("page contains %q", bad)
		}
	}
	// Escaped, not dropped: the reader still sees what the field said.
	text := html.UnescapeString(doc)
	if !strings.Contains(text, "window.pwned=1") {
		t.Error("hostile text should still be readable, escaped")
	}
	if !strings.Contains(doc, "&lt;script&gt;") {
		t.Error("hostile text should arrive as &lt;script&gt;")
	}
	for _, m := range regexp.MustCompile(`href="([^"]*)"`).FindAllStringSubmatch(doc, -1) {
		if !(strings.HasPrefix(m[1], "#") || strings.HasPrefix(m[1], "https://")) {
			t.Errorf("href %q is neither an anchor nor https", m[1])
		}
	}
	balanced(t, doc)
}

func TestNoRawEvenWhenUpstreamLeaks(t *testing.T) {
	f := mixed30(t)
	// Break every promise the contract makes about display fields, one way per secret.
	// AWS key ids (20 characters) are too short for any heuristic to separate from prose,
	// and by themselves are not a credential; they get only the correct-shape treatment.
	for i := range f.secrets {
		s := &f.secrets[i]
		if s.Type == "aws" {
			continue
		}
		raw := f.raws[i]
		switch i % 5 {
		case 0:
			s.Shape = raw
		case 1:
			s.TriageWhy = "matched value " + raw + " in a comment"
		case 2:
			s.Locations[0].Path = "config/" + raw + ".txt"
		case 3:
			s.Known = "kgaaaaaa " + raw
		case 4:
			s.Locations[0].Ref = "refs/heads/" + raw
			s.Locations[0].Source += "/" + raw
		}
	}
	run := healthyRun()
	run.Notes = []string{"capped at 2000 commits while reading " + f.raws[0]}
	run.Engines[f.raws[2]] = core.EngineStats{Seconds: 1, Hits: 1} // an engine named by a bug
	layers := healthyLayers()
	layers[0].Detail = "token " + f.raws[1] + " in the hook"
	doc := mustRender(t, reporter(""), f, run, layers)
	noRaw(t, doc, f)
	noKeyLike(t, doc)
}

func TestLightOnly(t *testing.T) {
	doc := mustRender(t, reporter(""), mixed30(t), healthyRun(), healthyLayers())
	css := styleRe.FindStringSubmatch(doc)
	if css == nil {
		t.Fatal("no inline style")
	}
	if !strings.Contains(css[1], "color-scheme: light;") || !strings.Contains(doc, `<meta name="color-scheme" content="light">`) {
		t.Error("page must declare color-scheme light in CSS and in a meta tag")
	}
	lower := strings.ToLower(doc)
	for _, bad := range []string{"prefers-color-scheme", "color-scheme: dark", "color-scheme: light dark", "dark"} {
		if strings.Contains(strings.ToLower(css[1]), bad) || strings.Contains(lower[:strings.Index(lower, "<body")], bad) {
			t.Errorf("head or CSS mentions %q", bad)
		}
	}
	// Every colour in the stylesheet is a light-theme colour: backgrounds are bright.
	vars := cssVars(t, css[1])
	for _, name := range []string{"paper", "card", "crit-bg", "warn-bg", "ok-bg", "unk-bg"} {
		if l := luminance(vars[name]); l < 0.6 {
			t.Errorf("--%s (%s) is too dark for a light page (luminance %.2f)", name, vars[name], l)
		}
	}
}

func TestNoScriptNoNetwork(t *testing.T) {
	doc := mustRender(t, reporter(""), mixed30(t), healthyRun(), healthyLayers())
	lower := strings.ToLower(doc)
	for _, bad := range []string{"<script", "<link", "<img", "<iframe", "<form", "<object", "<embed", "<video", "<audio",
		" src=", "url(", "@import", "http://", "xmlhttprequest", "fetch("} {
		if strings.Contains(lower, bad) {
			t.Errorf("page contains %q", bad)
		}
	}
	csp := regexp.MustCompile(`http-equiv="Content-Security-Policy" content="([^"]*)"`).FindStringSubmatch(doc)
	if csp == nil || !strings.HasPrefix(html.UnescapeString(csp[1]), "default-src 'none';") || strings.Contains(csp[1], "script-src") {
		t.Fatalf("CSP must start from default-src 'none' and allow no script, got %v", csp)
	}
	for _, m := range regexp.MustCompile(`<a [^>]*href="https://[^>]*>`).FindAllString(doc, -1) {
		if !strings.Contains(m, `rel="noopener noreferrer"`) {
			t.Errorf("external link without noopener: %s", m)
		}
	}
	for _, name := range []string{"width=device-width", `lang="en"`, `<meta charset="utf-8">`} {
		if !strings.Contains(doc, name) {
			t.Errorf("missing %s", name)
		}
	}
}

func TestPhoneWidthRules(t *testing.T) {
	css := styleCSS
	for _, want := range []string{"@media (max-width: 940px)", "@media (max-width: 760px)", "attr(data-label)", "table.stack", "overflow-wrap: anywhere", "minmax(0, 1fr)"} {
		if !strings.Contains(css, want) {
			t.Errorf("stylesheet lacks %q, so a phone would scroll sideways", want)
		}
	}
	doc := mustRender(t, reporter(""), mixed30(t), healthyRun(), healthyLayers())
	// Every cell of a stacked table needs its label, or the phone layout shows bare values.
	for _, tbl := range regexp.MustCompile(`(?s)<table class="stack">.*?</table>`).FindAllString(doc, -1) {
		for _, td := range regexp.MustCompile(`<td( [^>]*)?>`).FindAllString(tbl, -1) {
			if !strings.Contains(td, "data-label=") {
				t.Errorf("stacked cell without data-label: %s", td)
			}
		}
	}
}

func TestDyslexiaRules(t *testing.T) {
	css := styleCSS
	for _, want := range []string{
		"font-variant-numeric: tabular-nums", "text-align: right",
		"line-height", "letter-spacing", "Verdana",
	} {
		if !strings.Contains(css, want) {
			t.Errorf("stylesheet lacks %q", want)
		}
	}
	for _, bad := range []string{"italic", "text-align: justify", "text-transform: uppercase", "font-variant: small-caps"} {
		if strings.Contains(css, bad) {
			t.Errorf("stylesheet uses %q; italics, justification and capitals slow dyslexic reading", bad)
		}
	}
	doc := mustRender(t, reporter(""), mixed30(t), healthyRun(), healthyLayers())
	// The status sentence is the first thing in the body and the only <h1>.
	if strings.Count(doc, "<h1>") != 1 || strings.Index(doc, "<h1>") > strings.Index(doc, "<nav") {
		t.Error("exactly one <h1>, before the navigation")
	}
	// Short lines: no table cell or note carries a paragraph.
	for _, m := range regexp.MustCompile(`(?s)<td[^>]*>(.*?)</td>`).FindAllStringSubmatch(doc, -1) {
		if n := len(strings.Fields(regexp.MustCompile(`<[^>]*>`).ReplaceAllString(m[1], " "))); n > 40 {
			t.Errorf("a table cell holds %d words", n)
		}
	}
}

func TestContrast(t *testing.T) {
	vars := cssVars(t, styleCSS)
	pair := func(s string) string {
		if strings.HasPrefix(s, "#") {
			return s
		}
		if v, ok := vars[s]; ok {
			return v
		}
		t.Fatalf("no colour %q in the stylesheet", s)
		return ""
	}
	// Minimum 7:1 (WCAG AAA) for text people have to read; 4.5:1 for bold chips.
	checks := []struct {
		fg, bg string
		min    float64
	}{
		{"ink", "paper", 7}, {"ink", "card", 7}, {"muted", "card", 7}, {"muted", "paper", 7},
		{"link", "card", 7}, {"link", "paper", 7}, {"#ffffff", "link", 7}, {"#ffffff", "#083a85", 7},
		{"crit-ink", "crit-bg", 7}, {"warn-ink", "warn-bg", 7}, {"ok-ink", "ok-bg", 7}, {"unk-ink", "unk-bg", 7},
		{"#ffffff", "crit-edge", 4.5}, {"#ffffff", "warn-edge", 4.5}, {"crit-edge", "card", 4.5},
		{"warn-ink", "warn-bg", 4.5}, {"#ffffff", "ink", 7}, {"ink", "#f0eee6", 7},
	}
	for _, c := range checks {
		if got := contrast(pair(c.fg), pair(c.bg)); got < c.min {
			t.Errorf("%s on %s = %.2f:1, want at least %.1f:1", c.fg, c.bg, got, c.min)
		}
	}
}

var varRe = regexp.MustCompile(`--([a-z-]+):\s*(#[0-9a-fA-F]{6});`)

func cssVars(t *testing.T, css string) map[string]string {
	t.Helper()
	m := map[string]string{}
	for _, x := range varRe.FindAllStringSubmatch(css, -1) {
		m[x[1]] = x[2]
	}
	if len(m) < 10 {
		t.Fatalf("parsed only %d colour variables", len(m))
	}
	return m
}

func luminance(hex string) float64 {
	ch := func(s string) float64 {
		v, _ := strconv.ParseUint(s, 16, 8)
		c := float64(v) / 255
		if c <= 0.03928 {
			return c / 12.92
		}
		return math.Pow((c+0.055)/1.055, 2.4)
	}
	return 0.2126*ch(hex[1:3]) + 0.7152*ch(hex[3:5]) + 0.0722*ch(hex[5:7])
}

func contrast(a, b string) float64 {
	la, lb := luminance(a), luminance(b)
	if la < lb {
		la, lb = lb, la
	}
	return (la + 0.05) / (lb + 0.05)
}

func TestDeterministicAndOrderIndependent(t *testing.T) {
	f := mixed30(t)
	run, layers := healthyRun(), healthyLayers()
	a := mustRender(t, reporter(""), f, run, layers)
	if b := mustRender(t, reporter(""), f, run, layers); a != b {
		t.Fatal("same input rendered two different pages")
	}
	rev := &fixture{kr: f.kr, raws: f.raws}
	for i := len(f.secrets) - 1; i >= 0; i-- {
		rev.secrets = append(rev.secrets, f.secrets[i])
	}
	if b := mustRender(t, reporter(""), rev, run, layers); a != b {
		t.Fatal("input order changed the page; sorting is not fully determined")
	}
	if len(f.secrets) != 30 || f.secrets[0].ID == rev.secrets[0].ID {
		t.Fatal("test did not reverse anything")
	}
}

func TestInputNotMutated(t *testing.T) {
	f := mixed30(t)
	before := make([]string, len(f.secrets))
	for i, s := range f.secrets {
		before[i] = s.ID + s.Locations[0].Key()
	}
	mustRender(t, reporter(""), f, healthyRun(), healthyLayers())
	for i, s := range f.secrets {
		if before[i] != s.ID+s.Locations[0].Key() {
			t.Fatal("Render reordered the caller's slice")
		}
	}
}

func TestWriteIsAtomicAndPrivate(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "report")
	path := filepath.Join(dir, "index.html")
	r := reporter(path)
	f := mixed30(t)

	got, err := r.Write(f.secrets, healthyRun(), healthyLayers())
	if err != nil || got != path {
		t.Fatalf("Write = %q, %v", got, err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("report mode %v, want 0600", st.Mode().Perm())
	}
	if d, _ := os.Stat(dir); d.Mode().Perm() != 0o700 {
		t.Errorf("report dir mode %v, want 0700", d.Mode().Perm())
	}
	want, _ := r.Render(f.secrets, healthyRun(), healthyLayers())
	have, _ := os.ReadFile(path)
	if string(have) != string(want) {
		t.Error("file differs from Render output")
	}

	// A second write replaces the first and leaves no temp files behind.
	if _, err := r.Write(nil, healthyRun(), healthyLayers()); err != nil {
		t.Fatal(err)
	}
	have, _ = os.ReadFile(path)
	if h1(t, string(have)) != "No live keys exposed" {
		t.Error("second write did not replace the file")
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		t.Errorf("%d entries in report dir, want only index.html", len(ents))
	}

	// Failures are loud and leave nothing half-written.
	if _, err := New("").Write(nil, core.RunStats{}, nil); err == nil {
		t.Error("an empty path must be an error")
	}
	blocked := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocked, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(filepath.Join(blocked, "index.html")).Write(nil, core.RunStats{}, nil); err == nil {
		t.Error("writing under a regular file must fail")
	}
}

// New, and a bare Reporter literal, must work with the real clock and the Mac's zone: the
// other tests pin both, which would hide a broken default.
func TestDefaultsUseTheRealClock(t *testing.T) {
	now := time.Now()
	run := core.RunStats{
		Kind: "poll", Sources: 3, Started: now.Add(-3 * time.Minute).UTC().Format(time.RFC3339),
		Finished: now.Add(-2 * time.Minute).UTC().Format(time.RFC3339),
	}
	for name, r := range map[string]*Reporter{"New": New(filepath.Join(t.TempDir(), "r", "index.html")), "literal": {Path: filepath.Join(t.TempDir(), "i.html")}} {
		path, err := r.Write(nil, run, nil)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		b, _ := os.ReadFile(path)
		doc := string(b)
		if got := h1(t, doc); got != "No live keys exposed" {
			t.Errorf("%s: a scan from two minutes ago was judged stale or unscanned: %q", name, got)
		}
		if !strings.Contains(doc, "2 minutes ago") || !strings.Contains(doc, "Quick check took 1 min 0 s") {
			t.Errorf("%s: freshness line wrong in the default zone: %s", name, regexp.MustCompile(`class="fresh">([^<]*)`).FindString(doc))
		}
	}
}

// A key committed in many places lists the first few and says how many it left out.
func TestManyPlacesAreCountedNotSilentlyCut(t *testing.T) {
	f := newFixture(t)
	var locs []core.Location
	for i := 0; i < 20; i++ {
		locs = append(locs, core.Location{
			Source: "github.com/hangryclaude/demo", Kind: "repo", Visibility: core.Public, Ref: "refs/heads/main",
			Commit: randStr(t, hexa, 40), Path: "src/config/" + strconv.Itoa(i) + ".py", Line: i + 1,
		})
	}
	f.add(t, spec{kind: 0, sev: core.Critical, verified: core.Live, locs: locs})
	doc := mustRender(t, reporter(""), f, healthyRun(), healthyLayers())
	row := build(inputOf(f.secrets, healthyRun(), nil)).Rotate[0].Rows[0]
	if row.Places != "20" || row.MoreN != "19 more places" || len(row.More) != 8 || row.MoreHidden != "11 more places not listed here" {
		t.Fatalf("places = %s, more = %q, listed = %d, hidden = %q", row.Places, row.MoreN, len(row.More), row.MoreHidden)
	}
	for _, want := range []string{"<strong>20</strong>", "19 more places", "11 more places not listed here"} {
		if !strings.Contains(doc, want) {
			t.Errorf("page is missing %q", want)
		}
	}
	noRaw(t, doc, f)
}

func TestRowCapIsAnnounced(t *testing.T) {
	var ss []core.Secret
	for i := 0; i < rowCap+500; i++ {
		ss = append(ss, core.Secret{
			ID: "kg" + strconv.FormatInt(int64(0x100000+i), 16), Type: "generic", Shape: "…",
			Severity: core.Low, Status: "open", Verified: core.Unverified, Triage: "unreviewed",
			FirstSeen: fixedNow.Format(time.RFC3339),
		})
	}
	r := reporter("")
	b, err := r.Render(ss, healthyRun(), healthyLayers())
	if err != nil {
		t.Fatal(err)
	}
	doc := string(b)
	if !strings.Contains(doc, "Showing 2,000 of 2,500. The rest are in findings.json.") {
		t.Error("a capped table must say it is capped")
	}
	if !strings.Contains(doc, "Lower severity: 2,500 to review") {
		t.Error("the summary must count every secret, not only the ones shown")
	}
	if n := strings.Count(doc, `<td data-label="Level">`); n != rowCap {
		t.Errorf("%d rows shown, want %d", n, rowCap)
	}
}

func TestEngineAndCoverageHonesty(t *testing.T) {
	// A run that reports no refs, commits, files or API items must show dashes: a zero
	// would read as "looked, found nothing".
	run := healthyRun()
	doc := mustRender(t, reporter(""), newFixture(t), run, nil)
	cov := section(t, doc, "coverage")
	if n := strings.Count(cov, "not reported"); n != 5 { // repos+wikis+gists row, refs, commits, files, API items
		t.Errorf("%d 'not reported' notes, want 5", n)
	}
	if strings.Contains(doc, "All 0 layers") {
		t.Error("no layers must not read as all layers working")
	}
	if !strings.Contains(doc, "No layer check has run yet.") {
		t.Error("missing layers must be said out loud")
	}
	run.Engines = nil
	if !strings.Contains(mustRender(t, reporter(""), newFixture(t), run, nil), "No engine timing was recorded") {
		t.Error("missing engine stats must be said out loud")
	}
}

func TestSampleReport(t *testing.T) {
	f := mixed30(t)
	path := filepath.Join(t.TempDir(), "report", "index.html")
	r := reporter(path)
	r.Coverage = Coverage{Repos: 439, Wikis: 29, Gists: 2, Public: 5, Refs: 18204, Commits: 41330, Blobs: 99120, APIItems: 812}
	layers := healthyLayers()
	layers[5].OK, layers[5].Detail = false, "launchd job io.github.hangryclaude.keyguard.poll has not run for 3 hours"
	run := healthyRun()
	run.Skipped = 2
	run.Notes = []string{"2 sources skipped: clone timed out (will retry next poll)", "titus: 3 blobs over 50 MB were not scanned"}
	if _, err := r.Write(f.secrets, run, layers); err != nil {
		t.Fatal(err)
	}
	doc, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("sample report: %d bytes (%.1f KB) for 30 secrets", len(doc), float64(len(doc))/1024)
	noRaw(t, string(doc), f)
}

func TestSortingKeepsTheWorstFirst(t *testing.T) {
	f := newFixture(t)
	old := f.add(t, spec{kind: 0, sev: core.High, verified: core.Live, vis: core.Private, age: 100 * day24})
	live := f.add(t, spec{kind: 1, sev: core.Critical, verified: core.Live, vis: core.Public, age: 2 * day24})
	unv := f.add(t, spec{kind: 2, sev: core.Critical, verified: core.Unverified, vis: core.Public, age: 50 * day24})
	older := f.add(t, spec{kind: 3, sev: core.Critical, verified: core.Live, vis: core.Public, age: 30 * day24})
	v := build(inputOf(f.secrets, healthyRun(), nil))
	var got []string
	for _, g := range v.Rotate {
		for _, r := range g.Rows {
			got = append(got, r.ID)
		}
	}
	want := []string{older.ID, live.ID, unv.ID, old.ID} // live first, longest exposed first, critical before high
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("rotate order %v, want %v", got, want)
	}
}

func TestUnknownTypeAndOddInputsDoNotCrash(t *testing.T) {
	f := newFixture(t)
	f.add(t, spec{kind: 0, sev: core.Critical, verified: core.Live, vis: core.Public})
	f.secrets[0].Type = "some-new-engine-rule"
	f.secrets[0].Locations = nil
	f.secrets[0].Severity = core.Severity(99) // a corrupt DB must not panic core.Severity.String
	f.secrets[0].ID = ""
	f.secrets[0].Shape = ""
	f.secrets[0].FirstSeen = "yesterday"
	f.add(t, spec{kind: 1, sev: core.Severity(-3), verified: core.Verified("???"), vis: core.Visibility("moon")})
	f.secrets[1].Locations[0].Visibility = core.Visibility("moon")
	doc := mustRender(t, reporter(""), f, core.RunStats{Finished: "last tuesday", Started: "?"}, []core.LayerStatus{{Name: "x", CheckedAt: "never"}})
	if !strings.Contains(doc, "Rotate it where it was issued.") || !strings.Contains(doc, "no location recorded") {
		t.Error("unknown type and missing location should say so")
	}
	if got := h1(t, doc); got != "1 live key exposed — rotate now" {
		t.Errorf("h1 = %q", got)
	}
	balanced(t, doc)
}

// --- the sanitizers -------------------------------------------------------------------

func TestMaskRuns(t *testing.T) {
	f := newFixture(t)
	for _, k := range []struct {
		name, prefix, charset string
		n                     int
	}{
		{"alnum 40", "", alnum, 40}, {"anthropic style", "sk-ant-api03-", b64url, 90},
		{"hex 40", "", hexa, 40}, {"github style", "ghp_", alnum, 36}, {"jwt body", "eyJ", b64url, 120},
	} {
		raw := k.prefix + randStr(t, k.charset, k.n)
		if got := maskRuns("see " + raw + " here"); strings.Contains(got, raw[len(k.prefix):len(k.prefix)+10]) || !strings.Contains(got, "«…»") {
			t.Errorf("%s was not masked: %s", k.name, fp.Shape(got))
		}
	}
	_ = f
	for _, ok := range []string{
		"internal/engines/titus_normalizer_test.go",
		"docs/2026-11-03-meeting-notes-final-v2.md",
		"static/chunks/pages/_app-3f2c1ab9d4e5f6a7.js",
		"123e4567-e89b-12d3-a456-426614174000",
		"hangryclaude/shop-factory-2026-11-final",
		"node_modules/.pnpm/@babel+helper-validator-identifier@7.19.1/node_modules/@babel/helper-validator-identifier/lib/index.js",
		"AuthenticationMiddlewareConfigurationFactory",
		"https://console.twilio.com/us1/account/keys-credentials/api-keys",
		"refs/heads/feature/add-the-new-login-flow-for-mobile-clients",
		"scripts/bootstrap_mirrors_v2.py",
		"kg3f9a1c", "sk-ant-api03-…AbCd",
	} {
		if got := maskRuns(ok); got != ok {
			t.Errorf("legitimate text was changed: %q -> %q", ok, got)
		}
	}
}

// strideToken is n distinct letters and digits, so its entropy is log2(n): deterministic,
// and not random, so it is never mistaken for a real key by a scanner reading this file.
func strideToken(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = alnum[(i*7+3)%len(alnum)]
	}
	return string(b)
}

func TestMaskRunsLengthBoundary(t *testing.T) {
	for _, n := range []int{20, 24, 31, 64} {
		if tok := strideToken(n); !hasSecretLike(tok) || strings.Contains(maskRuns("x "+tok+" y"), tok[:8]) {
			t.Errorf("a %d-character mixed token was not masked", n)
		}
	}
	if tok := strideToken(19); hasSecretLike(tok) {
		t.Error("19 characters is below the floor; shorter words must be left alone")
	}
}

func TestCleanStripsWhatCouldDisguiseText(t *testing.T) {
	for in, want := range map[string]string{
		"a\u202eb":       "ab",  // right-to-left override: reverses how a file name displays
		"a\u200bb":       "ab",  // zero-width space
		"\ufeffabc":      "abc", // byte-order mark
		"tab\there":      "tab here",
		"line1\nline2\r": "line1 line2 ",
		"nul\x00byte":    "nul byte",
		"del\x7fx":       "del x",
		"c1\u0085x":      "c1 x",
		"bad\xffutf8":    "bad\ufffdutf8",
		"plain é ✓ 日本語":  "plain é ✓ 日本語",
	} {
		if got := clean(in); got != want {
			t.Errorf("clean(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSafeShape(t *testing.T) {
	for _, ok := range []string{"sk-ant-api03-…AbCd", "AKIA…", "…", "-----BEGIN…KEY-----", "ghp_…Zz9a", "sk_live_…q7Kp", "eyJ…"} {
		if got := safeShape(ok); got != ok {
			t.Errorf("shape %q was altered to %q", ok, got)
		}
	}
	for _, c := range []struct{ prefix, charset string }{{"sk-ant-api03-", b64url}, {"ghp_", alnum}, {"", alnum}, {"-----BEGIN", alnum}} {
		raw := c.prefix + randStr(t, c.charset, 60)
		got := safeShape(raw)
		if got != fp.Shape(raw) {
			t.Errorf("a raw value was not reduced to fp.Shape: %q", got)
		}
		if _, leaked := hasWindow(got, raw[len(c.prefix):], 6); leaked {
			t.Errorf("shape of %s still shows part of the value", leakShape(raw))
		}
	}
	// Looks like a shape but shows too much of the value.
	if got := safeShape("abc…defghij"); got == "abc…defghij" {
		t.Error("a 7-character tail is not a shape")
	}
	if got := safeShape("sk-ant-api03-…AbCd and more words"); strings.Contains(got, "words") {
		t.Error("a shape with spaces is prose, not a shape")
	}
}

func TestShortSHAAndLinks(t *testing.T) {
	sha := randStr(t, hexa, 40)
	if got := shortSHA(sha); got != sha[:10] {
		t.Errorf("shortSHA = %q", got)
	}
	if shortSHA("main") != "" || shortSHA("abc") != "" || shortSHA("") != "" {
		t.Error("non-hex or too-short commits must not be shown")
	}
	for in, want := range map[string]string{
		"https://github.com/hangryclaude/foo/blob/" + sha + "/src/a.py#L12": "https://github.com/hangryclaude/foo/blob/" + sha[:10] + "/src/a.py#L12",
		"https://github.com/hangryclaude/foo":                               "https://github.com/hangryclaude/foo",
	} {
		if got := safeLink(in); got != want {
			t.Errorf("safeLink(%q) = %q, want %q", in, got, want)
		}
	}
	for _, bad := range []string{
		"javascript:alert(1)", "http://github.com/a/b", "https://evil.example/github.com", "https://user" + ":pw@github.com/a/b",
		"https://github.com/a/b?token=" + randStr(t, alnum, 40), "//github.com/a", "", "ftp://github.com/x",
	} {
		if got := safeLink(bad); got != "" {
			t.Errorf("safeLink(%q) = %q, want no link", bad, got)
		}
	}
	// A gist id (32 hex) must show as 8 characters, and its link must be the owner's list.
	gid := randStr(t, hexa, 32)
	l := core.Location{Source: "gist.github.com/hangryclaude/" + gid, Kind: "gist", Visibility: core.SecretGist}
	if got := sourceName(l.Source); got != "gist hangryclaude/"+gid[:8]+"…" {
		t.Errorf("gist name = %q", got)
	}
	if got := locHref(l); got != "https://gist.github.com/hangryclaude" {
		t.Errorf("gist link = %q", got)
	}
	l = core.Location{Source: "github.com/hangryclaude/foo", Commit: sha, Path: "a b/ü.py", Line: 7}
	if got := locHref(l); got != "https://github.com/hangryclaude/foo/blob/"+sha[:10]+"/a%20b/%C3%BC.py#L7" {
		t.Errorf("blob link = %q", got)
	}
	if got := locHref(core.Location{Source: "github.com/hangryclaude/foo.wiki"}); got != "https://github.com/hangryclaude/foo/wiki" {
		t.Errorf("wiki link = %q", got)
	}
	if got := locHref(core.Location{Source: "local:/Users/me/dev/foo"}); got != "" {
		t.Errorf("a local path must not link, got %q", got)
	}
	if got := sourceName("local:/Users/me/dev/foo"); got != "this Mac: ~/dev/foo" {
		t.Errorf("local name = %q", got)
	}
}

func TestFormatting(t *testing.T) {
	for in, want := range map[int]string{0: "0", 7: "7", 999: "999", 1000: "1,000", 41330: "41,330", 1234567: "1,234,567", -4200: "-4,200"} {
		if got := num(in); got != want {
			t.Errorf("num(%d) = %q, want %q", in, got, want)
		}
	}
	if plural(1, "key", "keys") != "1 key" || plural(2, "key", "keys") != "2 keys" || plural(0, "key", "keys") != "0 keys" {
		t.Error("plural")
	}
	for d, want := range map[time.Duration]string{
		0: "just now", 59 * time.Second: "just now", time.Minute: "1 minute ago", 22 * time.Minute: "22 minutes ago",
		time.Hour: "1 hour ago", 47 * time.Hour: "47 hours ago", 48 * time.Hour: "2 days ago", 89 * 24 * time.Hour: "89 days ago",
		200 * 24 * time.Hour: "6 months ago", -time.Hour: "just now",
	} {
		if got := ago(d); got != want {
			t.Errorf("ago(%v) = %q, want %q", d, got, want)
		}
	}
	for d, want := range map[time.Duration]string{
		360 * time.Millisecond: "0.36 s", 38 * time.Second: "38 s", 38500 * time.Millisecond: "38.5 s", 134 * time.Second: "2 min 14 s", 63 * time.Minute: "1 h 3 min",
	} {
		if got := dur(d); got != want {
			t.Errorf("dur(%v) = %q, want %q", d, got, want)
		}
	}
	if n, w := days(36 * time.Hour); n != 1 || w != "day" {
		t.Errorf("days(36h) = %d %s", n, w)
	}
	if n, w := days(3 * time.Hour); n != 0 || w != "today" {
		t.Errorf("days(3h) = %d %s", n, w)
	}
	for _, in := range []string{"2026-11-03T19:52:00Z", "2026-11-03T19:52:00.123456789+02:00", "2026-11-03T19:52:00", "2026-11-03 19:52:00", "2026-11-03"} {
		if _, ok := parseTime(in, time.UTC); !ok {
			t.Errorf("parseTime(%q) failed", in)
		}
	}
	if _, ok := parseTime("yesterday", time.UTC); ok {
		t.Error("parseTime accepted nonsense")
	}
	if got := stamp(time.Date(2026, 11, 3, 19, 52, 0, 0, time.UTC), time.UTC); got != "3 Nov 2026, 19:52" {
		t.Errorf("stamp = %q", got)
	}
}

func TestCoverageFromSources(t *testing.T) {
	c := CoverageFromSources([]core.Source{
		{Kind: "repo", Visibility: core.Public}, {Kind: "repo", Visibility: core.Private}, {Kind: "wiki", Visibility: core.Public},
		{Kind: "gist", Visibility: core.SecretGist}, {Kind: "gist", Visibility: core.Public},
	})
	if c.Repos != 2 || c.Wikis != 1 || c.Gists != 2 || c.Public != 3 {
		t.Errorf("coverage = %+v", c)
	}
}

// --- speed ----------------------------------------------------------------------------

func benchRender(b *testing.B, n int) {
	f := newFixture(b)
	for i := 0; i < n; i++ {
		sv := []core.Severity{core.Low, core.Medium, core.Info, core.High, core.Critical}[i%5]
		f.add(b, spec{kind: i, sev: sv, verified: core.Unverified, vis: core.Public, age: time.Duration(i%400) * day24})
	}
	r := reporter("")
	run, layers := healthyRun(), healthyLayers()
	b.ReportAllocs()
	b.ResetTimer()
	var size int
	for i := 0; i < b.N; i++ {
		out, err := r.Render(f.secrets, run, layers)
		if err != nil {
			b.Fatal(err)
		}
		size = len(out)
	}
	b.ReportMetric(float64(size)/1024, "KB/page")
}

func BenchmarkRender30(b *testing.B)   { benchRender(b, 30) }
func BenchmarkRender5000(b *testing.B) { benchRender(b, 5000) }
