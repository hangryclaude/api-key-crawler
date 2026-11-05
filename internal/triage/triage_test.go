package triage

import (
	"slices"
	"strings"
	"testing"

	"keyguard/internal/core"
	"keyguard/internal/fp"
)

func loc(src string, vis core.Visibility, path string) core.Location {
	return core.Location{Source: src, Kind: "repo", Visibility: vis, Path: path, Line: 3}
}

// sec is a plausible unverified secret in a private repo; tests change what they care about.
func sec(mods ...func(*core.Secret)) core.Secret {
	s := core.Secret{
		FP: "fp-under-test", ID: "kg0test0", Type: "openai", Shape: "sk-…k7Qz", Len: 51,
		Engines: []string{"betterleaks"}, Rules: []string{"openai-api-key"},
		Locations: []core.Location{loc("github.com/o/a", core.Private, "src/app.ts")},
		Verified:  core.Unverified, Triage: Unreviewed, Status: "open",
	}
	for _, m := range mods {
		m(&s)
	}
	return s
}

func vis(v core.Visibility) func(*core.Secret) {
	return func(s *core.Secret) { s.Locations = []core.Location{loc("github.com/o/a", v, "src/app.ts")} }
}
func verdict(v core.Verified) func(*core.Secret) { return func(s *core.Secret) { s.Verified = v } }
func typ(t string) func(*core.Secret)            { return func(s *core.Secret) { s.Type = t } }
func shape(sh string) func(*core.Secret)         { return func(s *core.Secret) { s.Shape = sh } }
func engines(e ...string) func(*core.Secret)     { return func(s *core.Secret) { s.Engines = e } }
func paths(p ...string) func(*core.Secret) {
	return func(s *core.Secret) {
		s.Locations = nil
		for _, x := range p {
			s.Locations = append(s.Locations, loc("github.com/o/a", core.Private, x))
		}
	}
}

func classify(t *testing.T, tr *Triager, s core.Secret) core.Secret {
	t.Helper()
	tr.Classify(&s)
	return s
}

func TestSeverityTable(t *testing.T) {
	tr := New()
	cases := []struct {
		name string
		s    core.Secret
		want core.Severity
		lab  string
	}{
		{"live + public", sec(verdict(core.Live), vis(core.Public)), core.Critical, Real},
		{"live + secret gist", sec(verdict(core.Live), vis(core.SecretGist)), core.Critical, Real},
		{"live + unknown visibility counts as exposed", sec(verdict(core.Live), vis(core.Unknown)), core.Critical, Real},
		{"live + private", sec(verdict(core.Live), vis(core.Private)), core.High, Real},
		{"live + local only", sec(verdict(core.Live), vis(core.Local)), core.High, Real},
		{"live: one public place among private ones is enough", sec(verdict(core.Live), func(s *core.Secret) {
			s.Locations = []core.Location{loc("a", core.Private, "x"), loc("b", core.Public, "y")}
		}), core.Critical, Real},
		{"known + public", sec(func(s *core.Secret) { s.Known = "kgabc123 OPENAI_API_KEY" }, vis(core.Public)), core.Critical, Real},
		{"known + private repo", sec(func(s *core.Secret) { s.Known = "kgabc123 OPENAI_API_KEY" }), core.High, Real},
		{"dead + public", sec(verdict(core.Dead), vis(core.Public)), core.Info, Real},
		{"dead + known", sec(verdict(core.Dead), func(s *core.Secret) { s.Known = "kgabc123 X" }, vis(core.Public)), core.Info, Real},
		{"resolved status", sec(func(s *core.Secret) { s.Status = "resolved" }, vis(core.Public)), core.Info, Real},
		{"real by agreement + exposed", sec(engines("betterleaks", "trufflehog"), vis(core.Public), typ("generic")), core.Medium, Real},
		{"real by agreement + private", sec(engines("betterleaks", "trufflehog"), typ("generic")), core.Low, Real},
		{"real by format + exposed", sec(vis(core.Public)), core.Medium, Real},
		{"test fixture, exposed or not", sec(paths("tests/fixtures/k.json"), vis(core.Public), func(s *core.Secret) {
			s.Locations[0].Path = "tests/fixtures/k.json"
		}), core.Low, Test},
		{"unreviewed residue", sec(typ("generic")), core.Low, Unreviewed},
		{"unreviewed residue, exposed", sec(typ("generic"), vis(core.Public)), core.Low, Unreviewed},
		{"placeholder", sec(shape("sk-…xxxx"), vis(core.Public)), core.Info, Placeholder},
		{"public by design", sec(shape("pk_live_…k7Qz"), typ("stripe"), vis(core.Public)), core.Info, PublicByDesign},
		{"google AIza is low, not info", sec(shape("AIza…k7Qz"), typ("google"), vis(core.Public)), core.Low, PublicByDesign},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := classify(t, tr, c.s)
			if got.Severity != c.want || got.Triage != c.lab {
				t.Fatalf("severity=%v triage=%s (%s); want %v %s", got.Severity, got.Triage, got.TriageWhy, c.want, c.lab)
			}
			if got.TriageWhy == "" {
				t.Fatal("no reason given")
			}
		})
	}
}

func TestLiveOverridesEveryNotRealLabel(t *testing.T) {
	tr := New()
	cases := map[string]core.Secret{
		"placeholder":      sec(shape("sk-…xxxx")),
		"public-by-design": sec(shape("pk_live_…k7Qz"), typ("stripe")),
		"test (path)":      sec(paths("test/data.json")),
		"google AIza":      sec(shape("AIza…k7Qz"), typ("google")),
		"false-positive by an LLM": sec(func(s *core.Secret) {
			s.Triage, s.TriageBy, s.TriageWhy = FalsePositive, ByClaude, "looked like a hash"
		}),
		"test by a human": sec(func(s *core.Secret) { s.Triage, s.TriageBy, s.TriageWhy = Test, ByHuman, "my fixture" }),
	}
	for name, s := range cases {
		t.Run(name, func(t *testing.T) {
			before := classify(t, tr, s)
			if !notReal(before.Triage) {
				t.Fatalf("setup: expected a not-real label, got %s", before.Triage)
			}
			s.Verified = core.Live
			s.Locations[0].Visibility = core.Public
			got := classify(t, tr, s)
			if got.Triage != Real || got.TriageBy != ByRule || got.Severity != core.Critical {
				t.Fatalf("live secret kept the %s label: %s / %s / %v", before.Triage, got.Triage, got.TriageBy, got.Severity)
			}
			if !strings.Contains(got.TriageWhy, "overrides the "+before.Triage+" label") {
				t.Fatalf("reason does not say what was overridden: %q", got.TriageWhy)
			}
		})
	}
}

func TestDeadBeatsKnownAndKeepsTheLabel(t *testing.T) {
	tr := New()
	got := classify(t, tr, sec(verdict(core.Dead), shape("sk-…xxxx"), vis(core.Public)))
	if got.Severity != core.Info || got.Triage != Placeholder || !strings.Contains(got.TriageWhy, "rejects it") {
		t.Fatalf("%v %s %q", got.Severity, got.Triage, got.TriageWhy)
	}
}

func TestIgnoredIsFinalAndKeepsTheHumansWords(t *testing.T) {
	tr := New()
	s := sec(verdict(core.Live), vis(core.Public), func(s *core.Secret) {
		s.Status, s.Triage, s.TriageBy, s.TriageWhy = "ignored", FalsePositive, ByHuman, "ignored by a human: fixture"
	})
	got := classify(t, tr, s)
	if got.Severity != core.Info || got.Triage != FalsePositive || got.TriageWhy != "ignored by a human: fixture" {
		t.Fatalf("ignored secret reclassified: %v %s %q", got.Severity, got.Triage, got.TriageWhy)
	}
	// An ignored secret with no label yet (the store only partially filled it) still reads as the human's call.
	bare := classify(t, tr, sec(func(s *core.Secret) { s.Status = "ignored" }))
	if bare.Triage != FalsePositive || bare.TriageBy != ByHuman || bare.Severity != core.Info || bare.TriageWhy == "" {
		t.Fatalf("%+v", bare)
	}
}

func TestReviewerLabelsAreKeptUnlessProvenOtherwise(t *testing.T) {
	tr := New()
	label := func(l, by string) func(*core.Secret) {
		return func(s *core.Secret) { s.Triage, s.TriageBy, s.TriageWhy = l, by, "because" }
	}
	cases := []struct {
		name string
		s    core.Secret
		want core.Severity
		lab  string
	}{
		{"human test", sec(typ("generic"), label(Test, ByHuman)), core.Low, Test},
		{"human real, exposed", sec(typ("generic"), vis(core.Public), label(Real, ByHuman)), core.Medium, Real},
		{"claude placeholder", sec(label(Placeholder, ByClaude)), core.Info, Placeholder},
		{"codex public-by-design", sec(label(PublicByDesign, ByCodex)), core.Info, PublicByDesign},
		{"claude false positive beats a format match", sec(label(FalsePositive, ByClaude)), core.Info, FalsePositive},
		{"an unreviewed label by a reviewer means nothing", sec(label(Unreviewed, ByClaude)), core.Medium - 1, Real},
		{"known beats an LLM's placeholder", sec(label(Placeholder, ByClaude), func(s *core.Secret) { s.Known = "kg1 X" }), core.High, Real},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := classify(t, tr, c.s)
			if got.Severity != c.want || got.Triage != c.lab {
				t.Fatalf("%v %s (%s) %s; want %v %s", got.Severity, got.Triage, got.TriageBy, got.TriageWhy, c.want, c.lab)
			}
		})
	}
	kept := classify(t, tr, sec(label(Placeholder, ByClaude)))
	if kept.TriageBy != ByClaude || kept.TriageWhy != "because" {
		t.Fatalf("the reviewer's attribution was lost: %s %q", kept.TriageBy, kept.TriageWhy)
	}
}

func TestClassifyIsIdempotentAndRecomputesItsOwnLabels(t *testing.T) {
	ev := map[string]Evidence{}
	tr := New(WithEvidence(func(fp string) (Evidence, bool) { e, ok := ev[fp]; return e, ok }))
	s := sec(typ("generic"))
	first := classify(t, tr, s)
	if first.Triage != Unreviewed || first.TriageBy != "" {
		t.Fatalf("setup: %+v", first)
	}
	if again := classify(t, tr, first); !sameDecision(again, first) {
		t.Fatalf("second pass changed the decision: %+v vs %+v", again, first)
	}
	// New evidence arrives: a rule-made label is recomputed, not locked in.
	ev[s.FP] = Evidence{Contexts: []string{"api_key = «sk-…k7Qz»  # dummy value"}}
	second := classify(t, tr, first)
	if second.Triage != Placeholder {
		t.Fatalf("new evidence ignored: %s", second.Triage)
	}
	delete(ev, s.FP)
	third := classify(t, tr, second)
	if third.Triage != Unreviewed {
		t.Fatalf("a rule's label outlived its evidence: %s", third.Triage)
	}
}

func sameDecision(a, b core.Secret) bool {
	return a.Triage == b.Triage && a.TriageBy == b.TriageBy && a.TriageWhy == b.TriageWhy && a.Severity == b.Severity
}

func TestAgreementCountsFamiliesNotEngines(t *testing.T) {
	tr := New()
	cases := []struct {
		eng  []string
		want string
	}{
		{[]string{"betterleaks"}, Unreviewed},
		{[]string{"betterleaks", "gitleaks"}, Unreviewed}, // one lineage, shared rules
		{[]string{"betterleaks", "trufflehog"}, Real},
		{[]string{"gitleaks", "titus"}, Real},
		{[]string{"trufflehog", "titus", "betterleaks"}, Real},
		{[]string{"betterleaks", "known"}, Unreviewed}, // the matcher is not a detector of this kind
		{[]string{"betterleaks", "filename"}, Unreviewed},
		{[]string{"betterleaks", "github-alerts"}, Real},
	}
	for _, c := range cases {
		got := classify(t, tr, sec(typ("generic"), engines(c.eng...)))
		if got.Triage != c.want {
			t.Errorf("%v: %s, want %s (%s)", c.eng, got.Triage, c.want, got.TriageWhy)
		}
	}
}

func TestFormatAloneNeedsAStrongTypeAndRealisticEntropy(t *testing.T) {
	ev := Evidence{}
	tr := New(WithEvidence(func(string) (Evidence, bool) { return ev, true }))
	for _, weak := range []string{"generic", "", "jwt", "google", "password", "url", "generic-api-key"} {
		if got := classify(t, tr, sec(typ(weak))); got.Triage != Unreviewed {
			t.Errorf("type %q judged %s on format alone", weak, got.Triage)
		}
	}
	if got := classify(t, tr, sec(typ("anthropic"))); got.Triage != Real {
		t.Errorf("a provider format should be real: %s", got.Triage)
	}
	ev = Evidence{Entropy: 2.8}
	if got := classify(t, tr, sec(typ("anthropic"))); got.Triage == Real {
		t.Errorf("an entropy of 2.8 should not pass for a provider key: %s", got.Triage)
	}
	ev = Evidence{Entropy: 5.2}
	if got := classify(t, tr, sec(typ("anthropic"))); got.Triage != Real {
		t.Errorf("a random-looking value of a provider format: %s", got.Triage)
	}
}

func TestPlaceholderRules(t *testing.T) {
	ev := Evidence{}
	tr := New(WithEvidence(func(string) (Evidence, bool) { return ev, true }))
	tails := map[string]bool{
		"sk-…xxxx": true, "sk-…0000": true, "sk-…AAAA": true, "sk-…1234": true, "sk-…abcd": true, "sk-…dcba": true,
		"sk-…9876": true, "sk-…TEST": true, "sk-…here": true, "sk-…FAKE": true, "sk-…DEMO": true,
		"sk-…k7Qz": false, "sk-…ab12": false, "sk-…12": false, "sk-…": false, "sk-…xxx": false, "sk-…12ab": false,
	}
	for sh, want := range tails {
		ev = Evidence{}
		got := classify(t, tr, sec(shape(sh)))
		if (got.Triage == Placeholder) != want {
			t.Errorf("shape %q: %s (%s), want placeholder=%v", sh, got.Triage, got.TriageWhy, want)
		}
	}
	ev = Evidence{Entropy: 1.1}
	if got := classify(t, tr, sec()); got.Triage != Placeholder {
		t.Errorf("a 51-character value with 1.1 bits of entropy: %s", got.Triage)
	}
	if got := classify(t, tr, sec(func(s *core.Secret) { s.Len = 10 })); got.Triage == Placeholder {
		t.Errorf("short values are not judged on entropy: %s", got.Triage)
	}
	ev = Evidence{Tags: []string{TagPlaceholder}}
	if got := classify(t, tr, sec()); got.Triage != Placeholder {
		t.Errorf("the placeholder tag: %s", got.Triage)
	}
	for _, line := range []string{
		`OPENAI_API_KEY="«sk-…k7Qz»" # placeholder`, `api_key: <your-api-key-here> «…»`, `token = «…» # changeme`,
		`key=«…» # replace_me before deploy`, `# dummy «…»`,
	} {
		ev = Evidence{Contexts: []string{line}}
		if got := classify(t, tr, sec()); got.Triage != Placeholder {
			t.Errorf("%q judged %s", line, got.Triage)
		}
	}
	// Words that merely sit near secrets must not make one a placeholder.
	for _, line := range []string{`host = "example.com" key = «sk-…k7Qz»`, `from examples import client; key = «…»`, `// production key «…»`} {
		ev = Evidence{Contexts: []string{line}}
		if got := classify(t, tr, sec()); got.Triage == Placeholder {
			t.Errorf("%q judged a placeholder", line)
		}
	}
}

func TestPublicByDesignRules(t *testing.T) {
	ev := Evidence{}
	tr := New(WithEvidence(func(string) (Evidence, bool) { return ev, true }))
	cases := []struct {
		name string
		s    core.Secret
		ev   Evidence
		want bool
	}{
		{"stripe publishable live", sec(shape("pk_live_…k7Qz"), typ("stripe")), Evidence{}, true},
		{"stripe publishable test", sec(shape("pk_test_…k7Qz"), typ("stripe")), Evidence{}, true},
		{"stripe secret", sec(shape("sk_live_…k7Qz"), typ("stripe")), Evidence{}, false},
		{"stripe restricted", sec(shape("rk_live_…k7Qz"), typ("stripe")), Evidence{}, false},
		{"posthog project key", sec(shape("phc_…k7Qz"), typ("posthog")), Evidence{}, true},
		{"posthog personal key is secret", sec(shape("phx_…k7Qz"), typ("posthog")), Evidence{}, false},
		{"mapbox public", sec(shape("pk.…k7Qz"), typ("mapbox")), Evidence{}, true},
		{"mapbox secret", sec(shape("sk.…k7Qz"), typ("mapbox")), Evidence{}, false},
		{"jwt tagged anon", sec(shape("eyJ…k7Qz"), typ("jwt")), Evidence{Tags: []string{TagJWTAnon}}, true},
		{"jwt tagged service role", sec(shape("eyJ…k7Qz"), typ("jwt")), Evidence{Tags: []string{TagJWTServiceRole}}, false},
		{"supabase anon by name", sec(shape("eyJ…k7Qz"), typ("supabase")), Evidence{Contexts: []string{"NEXT_PUBLIC_SUPABASE_ANON_KEY=«eyJ…k7Qz»"}}, true},
		{"supabase anon in js", sec(shape("eyJ…k7Qz"), typ("generic")), Evidence{Contexts: []string{"const supabaseAnonKey = «eyJ…k7Qz»"}}, true},
		{"supabase service role by name", sec(shape("eyJ…k7Qz"), typ("supabase")), Evidence{Contexts: []string{"SUPABASE_SERVICE_ROLE_KEY=«eyJ…k7Qz»"}}, false},
		{"anon and service_role on one line is not safe", sec(shape("eyJ…k7Qz"), typ("supabase")), Evidence{Contexts: []string{"anon_key=«…» service_role=«…»"}}, false},
		{"sentry dsn by context", sec(typ("generic")), Evidence{Contexts: []string{"Sentry.init({ dsn: «https://…@o4.ingest.sentry.io/1» })"}}, true},
		{"sentry dsn by rule", sec(typ("sentry"), func(s *core.Secret) { s.Rules = []string{"sentry-dsn"} }), Evidence{}, true},
		{"sentry auth token is secret", sec(shape("sntrys_…k7Qz"), typ("sentry")), Evidence{Contexts: []string{"SENTRY_AUTH_TOKEN=«…»"}}, false},
		{"algolia search-only key", sec(typ("algolia")), Evidence{Contexts: []string{"ALGOLIA_SEARCH_API_KEY=«…k7Qz»"}}, true},
		{"algolia admin key", sec(typ("algolia")), Evidence{Contexts: []string{"ALGOLIA_ADMIN_API_KEY=«…k7Qz»"}}, false},
		{"algolia unnamed", sec(typ("algolia")), Evidence{Contexts: []string{"ALGOLIA_API_KEY=«…k7Qz»"}}, false},
		{"recaptcha site key", sec(typ("generic")), Evidence{Contexts: []string{`<div class="g-recaptcha" data-sitekey="«…k7Qz»">`}}, true},
		{"recaptcha secret", sec(typ("generic")), Evidence{Contexts: []string{"RECAPTCHA_SECRET_KEY=«…k7Qz»"}}, false},
		{"google key", sec(shape("AIza…k7Qz"), typ("google")), Evidence{}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ev = c.ev
			got := classify(t, tr, c.s)
			if (got.Triage == PublicByDesign) != c.want {
				t.Fatalf("%s (%s); want public-by-design=%v", got.Triage, got.TriageWhy, c.want)
			}
		})
	}
}

func TestTestPaths(t *testing.T) {
	yes := []string{
		"tests/a.py", "src/__tests__/a.js", "pkg/foo_test.go", ".env.example", ".env.sample", "config/.env.template",
		"a/b/fixtures/k.json", "testdata/key.pem", "app/config.sample.json", "settings.dist", "src/api.test.ts",
		"src/api.spec.js", "test_client.py", "conftest.py", "spec/models/user_spec.rb", "examples/basic/main.go",
		"example.env", "docs/demo/app.js", "mocks/api.json", "Tests/Client.swift", "e2e/login.ts", ".env.test",
		"src\\tests\\a.js", "tests/../tests/a.py", "defaults.test.json", "app.config.example.yml",
	}
	no := []string{
		"src/app.ts", "dist/bundle.js", ".env", "latest.js", "contest/a.go", "README.md", "config/production.json",
		"src/contest.py", "lib/attest.rb", "specification.md", "id_rsa", "src/dist/app.js", "testing.js", "protest/a.js",
		"templates/index.html", "docs/guide.md", "",
	}
	for _, p := range yes {
		if !testPath(p) {
			t.Errorf("%q should be a test path", p)
		}
	}
	for _, p := range no {
		if testPath(p) {
			t.Errorf("%q should not be a test path", p)
		}
	}
}

func TestTestLabelNeedsEveryLocationToBeTestLike(t *testing.T) {
	tr := New()
	if got := classify(t, tr, sec(typ("generic"), paths("tests/a.py", "src/app.ts"))); got.Triage == Test {
		t.Fatalf("a secret that also lives in src/ is not a test fixture: %s", got.Triage)
	}
	if got := classify(t, tr, sec(typ("generic"), paths("tests/a.py", "fixtures/b.json"))); got.Triage != Test {
		t.Fatalf("all places are fixtures: %s", got.Triage)
	}
	issue := sec(typ("generic"), func(s *core.Secret) {
		s.Locations = []core.Location{{Source: "github.com/o/a", Kind: "issue", Visibility: core.Public}}
	})
	if got := classify(t, tr, issue); got.Triage == Test {
		t.Fatalf("an issue comment has no path and is never a fixture: %s", got.Triage)
	}
	none := sec(typ("generic"), func(s *core.Secret) { s.Locations = nil })
	if got := classify(t, tr, none); got.Triage == Test {
		t.Fatalf("no locations at all: %s", got.Triage)
	}
}

// uri builds a connection string the way a redacted context shows one: the password already
// replaced by its shape. It is assembled so the test file holds no credential-bearing URI.
func uri(scheme, user, host string) string { return scheme + "://" + user + ":«…ab»@" + host }

func TestLocalServiceCredentials(t *testing.T) {
	ev := Evidence{}
	tr := New(WithEvidence(func(string) (Evidence, bool) { return ev, true }))
	yes := []string{
		"DATABASE_URL=" + uri("postgres", "app", "localhost:5432/app"),
		uri("redis", "default", "127.0.0.1:6379"),
		uri("mongodb", "root", "mongo:27017/admin"),
		uri("amqp", "u", "rabbitmq/"),
		uri("mysql", "u", "host.docker.internal:3306/x"),
		uri("postgres", "u", "db/prod"),
		uri("POSTGRES", "U", "LOCALHOST:5432/x"),
	}
	no := []string{
		"DATABASE_URL=" + uri("postgres", "app", "prod-db.internal.example.com:5432/app"),
		uri("redis", "default", "redis-12345.c1.us-east-1-2.ec2.cloud.redislabs.com:12345"),
		uri("postgres", "u", "dbhost.example.com/x"),
		"user@localhost is just an email-looking string «…»",
	}
	for _, line := range yes {
		ev = Evidence{Contexts: []string{line}}
		if got := classify(t, tr, sec(typ("generic"))); got.Triage != Test {
			t.Errorf("%q judged %s", line, got.Triage)
		}
	}
	for _, line := range no {
		ev = Evidence{Contexts: []string{line}}
		if got := classify(t, tr, sec(typ("generic"))); got.Triage == Test {
			t.Errorf("%q judged test", line)
		}
	}
}

func TestStripeTestModeKeysAreTestNotReal(t *testing.T) {
	tr := New()
	for _, p := range []string{"sk_test_", "rk_test_"} {
		if got := classify(t, tr, sec(shape(p+"…k7Qz"), typ("stripe"), vis(core.Public))); got.Triage != Test || got.Severity != core.Low {
			t.Errorf("%s: %s %v", p, got.Triage, got.Severity)
		}
	}
	ev := Evidence{Tags: []string{TagTestMode}}
	tr = New(WithEvidence(func(string) (Evidence, bool) { return ev, true }))
	if got := classify(t, tr, sec(typ("generic"))); got.Triage != Test {
		t.Errorf("test-mode tag: %s", got.Triage)
	}
}

type fakeStore struct{ ctx []string }

func (f fakeStore) Evidence(fpv string) ([]string, float64, []string, bool) {
	if fpv != "fp-under-test" {
		return nil, 0, nil, false
	}
	return f.ctx, 4.2, nil, true
}

func TestStoreEvidenceFeedsTheRules(t *testing.T) {
	tr := New(WithStoreEvidence(fakeStore{ctx: []string{"recaptcha sitekey=«…»"}}))
	if got := classify(t, tr, sec(typ("generic"))); got.Triage != PublicByDesign {
		t.Fatalf("evidence from a store was not used: %s", got.Triage)
	}
	other := sec(typ("generic"), func(s *core.Secret) { s.FP = "someone-else" })
	if got := classify(t, tr, other); got.Triage != Unreviewed {
		t.Fatalf("another secret's evidence leaked in: %s", got.Triage)
	}
}

func TestDocumentationExamplesNeedTheKeyring(t *testing.T) {
	kr := fp.NewEphemeral()
	tr := New(WithFingerprinter(kr))
	for _, e := range documentationExamples() {
		s := sec(typ("aws"), func(s *core.Secret) { s.FP = kr.FP(e.value); s.Shape = fp.Shape(e.value) })
		got := classify(t, tr, s)
		if got.Triage != Placeholder || !strings.Contains(got.TriageWhy, e.what) {
			t.Errorf("%s: %s (%s)", e.what, got.Triage, got.TriageWhy)
		}
	}
	// Without a keyring there is nothing to match against, and a different keyring does not match.
	e := documentationExamples()[0]
	plain := sec(typ("aws"), func(s *core.Secret) { s.FP = kr.FP(e.value); s.Shape = fp.Shape(e.value) })
	if got := classify(t, New(), plain); got.Triage == Placeholder {
		t.Errorf("no keyring but still matched: %s", got.Triage)
	}
	if got := classify(t, New(WithFingerprinter(fp.NewEphemeral())), plain); got.Triage == Placeholder {
		t.Errorf("a different salt still matched")
	}
}

// The JWT sample is built, not written down; check that the build is the famous one by its
// first characters (not enough to be a secret, enough to be the right token).
func TestJWTSampleIsTheJwtIoOne(t *testing.T) {
	var tok string
	for _, e := range documentationExamples() {
		if strings.HasPrefix(e.value, "eyJ") {
			tok = e.value
		}
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 || parts[0][:12] != "eyJhbGciOiJI" || parts[1][:12] != "eyJzdWIiOiIx" || parts[2][:8] != "SflKxwRJ" {
		t.Fatal("the jwt.io sample was not rebuilt correctly")
	}
}

func TestTailLooksFakeBoundaries(t *testing.T) {
	for tail, want := range map[string]bool{"": false, "abc": false, "abcde": false, "aaaa": true, "AaAa": false, "1234": true, "4321": true,
		"1235": false, "ab1c": false, "zyxw": true, "9012": false, "Test": true} {
		if got := tailLooksFake(tail); got != want {
			t.Errorf("tailLooksFake(%q) = %v, want %v", tail, got, want)
		}
	}
}

func TestShapeParts(t *testing.T) {
	c := newCtx(&core.Secret{Shape: "-----BEGIN…KEY-----"}, Evidence{})
	if c.prefix != "-----BEGIN" || c.tail != "KEY-----" {
		t.Fatalf("%q %q", c.prefix, c.tail)
	}
	c = newCtx(&core.Secret{Shape: "…"}, Evidence{})
	if c.prefix != "" || c.tail != "" {
		t.Fatalf("%q %q", c.prefix, c.tail)
	}
	c = newCtx(&core.Secret{Shape: "no ellipsis"}, Evidence{})
	if c.prefix != "" || c.tail != "" {
		t.Fatalf("%q %q", c.prefix, c.tail)
	}
}

func TestEveryDecisionExplainsItselfWithoutLeakingMore(t *testing.T) {
	tr := New()
	raw := "sk-" + strings.Repeat("Qz7", 16)
	s := sec(func(s *core.Secret) { s.Shape = fp.Shape(raw) })
	for _, v := range []core.Verified{core.Live, core.Dead, core.Unverified, core.VerifyError} {
		s.Verified = v
		got := classify(t, tr, s)
		if got.TriageWhy == "" || strings.Contains(got.TriageWhy, raw[3:]) {
			t.Errorf("%s: why = %q", v, got.TriageWhy)
		}
	}
	if !slices.Contains([]string{ByRule, ByHuman, ByClaude, ByCodex, ""}, classify(t, tr, s).TriageBy) {
		t.Fatal("unknown TriageBy")
	}
}

func TestUnsignedLabelsAreHonoredAndRuleSignedOnesAreNot(t *testing.T) {
	tr := New()
	// Somebody outside the rules set "real" without saying who: keep it, and price it by the table.
	got := classify(t, tr, sec(typ("generic"), vis(core.Public), func(s *core.Secret) { s.Triage = Real }))
	if got.Triage != Real || got.TriageBy != "" || got.Severity != core.Medium {
		t.Fatalf("%s by %q: %v", got.Triage, got.TriageBy, got.Severity)
	}
	got = classify(t, tr, sec(typ("generic"), func(s *core.Secret) { s.Triage = Test }))
	if got.Triage != Test || got.Severity != core.Low {
		t.Fatalf("%s: %v", got.Triage, got.Severity)
	}
	// The rules sign what they decide, so what they decided is theirs to change.
	got = classify(t, tr, sec(typ("generic"), func(s *core.Secret) { s.Triage, s.TriageBy = Real, ByRule }))
	if got.Triage != Unreviewed {
		t.Fatalf("a stale rule label survived: %s", got.Triage)
	}
}

func TestProviderPrefixOutranksTheTailGuess(t *testing.T) {
	tr := New()
	for _, c := range []struct {
		shape string
		typ   string
		sev   core.Severity
	}{
		{"pk_live_…abcd", "stripe", core.Info},
		{"pk_test_…1234", "stripe", core.Info},
		{"phc_…xxxx", "posthog", core.Info},
		{"AIza…abcd", "google", core.Low}, // a Google key stays low even when its tail looks fake
	} {
		got := classify(t, tr, sec(shape(c.shape), typ(c.typ), vis(core.Public)))
		if got.Triage != PublicByDesign || got.Severity != c.sev {
			t.Errorf("%s: %s / %v (%s)", c.shape, got.Triage, got.Severity, got.TriageWhy)
		}
	}
}
