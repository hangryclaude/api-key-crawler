package report

import (
	"crypto/rand"
	"math/big"
	"strings"
	"testing"
	"time"

	"keyguard/internal/core"
	"keyguard/internal/fp"
)

const (
	alnum  = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	hexa   = "0123456789abcdef"
	b64url = alnum + "-_"
	upperD = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
)

func randStr(t testing.TB, charset string, n int) string {
	t.Helper()
	b := make([]byte, n)
	for i := range b {
		x, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			t.Fatal(err)
		}
		b[i] = charset[x.Int64()]
	}
	return string(b)
}

// fakeKinds are built at runtime from a constant prefix plus random characters, so no
// secret-shaped literal exists in this repo.
var fakeKinds = []struct {
	typ, prefix, charset string
	n                    int
}{
	{"anthropic", "sk-ant-api03-", b64url, 93},
	{"openai", "sk-proj-", b64url, 80},
	{"github", "ghp_", alnum, 36},
	{"aws", "AKIA", upperD, 16},
	{"stripe", "sk_live_", alnum, 99},
	{"slack", "xoxb-", alnum, 50},
	{"google", "AIza", b64url, 35},
	{"huggingface", "hf_", alnum, 34},
	{"groq", "gsk_", alnum, 52},
	{"xai", "xai-", alnum, 80},
	{"replicate", "r8_", alnum, 37},
	{"sendgrid", "SG.", b64url, 66},
	{"npm", "npm_", alnum, 36},
	{"digitalocean", "dop_v1_", hexa, 64},
	{"supabase", "eyJ", b64url, 190},
	{"vercel", "", alnum, 32},
	{"cloudflare", "", b64url, 40},
	{"twilio", "SK", hexa, 32},
	{"postgres", "", alnum, 32},
	{"private-key", "-----BEGIN", alnum, 200},
	{"generic", "", alnum, 44},
}

var fixedNow = time.Date(2026, 11, 3, 20, 0, 0, 0, time.UTC)

// fixture is a set of secrets plus the raw values behind them. The raws stay in the test
// so it can prove none of them reaches the page; secrets never carry them.
type fixture struct {
	kr      *fp.Keyring
	secrets []core.Secret
	raws    []string
	rands   []string // raws without their constant prefix: what a shape must never show
	commits []string
}

func newFixture(t testing.TB) *fixture { return &fixture{kr: fp.NewEphemeral()} }

type spec struct {
	kind     int // index into fakeKinds
	sev      core.Severity
	status   string
	verified core.Verified
	vis      core.Visibility
	locs     []core.Location
	known    string
	triage   string
	why      string
	age      time.Duration
}

func (f *fixture) add(t testing.TB, sp spec) core.Secret {
	t.Helper()
	k := fakeKinds[sp.kind%len(fakeKinds)]
	raw := k.prefix + randStr(t, k.charset, k.n)
	if k.typ == "aws" { // 20 characters: make sure a digit is in there like real key ids have
		raw = raw[:12] + randStr(t, "234567", 1) + raw[13:]
	}
	commit := randStr(t, hexa, 40)
	f.raws = append(f.raws, raw)
	f.rands = append(f.rands, raw[len(k.prefix):])
	f.commits = append(f.commits, commit)
	locs := sp.locs
	if locs == nil {
		locs = []core.Location{{
			Source: "github.com/hangryclaude/demo-" + k.typ, Kind: "repo", Visibility: sp.vis,
			Ref: "refs/heads/main", Commit: commit, Path: "src/config/" + k.typ + ".py", Line: 12 + len(f.raws),
			Date: fixedNow.Add(-sp.age).Format(time.RFC3339),
		}}
	}
	if sp.status == "" {
		sp.status = "open"
	}
	s := core.Secret{
		FP: f.kr.FP(raw), Type: k.typ, Shape: fp.Shape(raw), Len: len(raw),
		Engines: []string{"betterleaks", "trufflehog"}, Rules: []string{k.typ + "-key"},
		Locations: locs, Verified: sp.verified, Known: sp.known,
		Triage: sp.triage, TriageBy: "rule", TriageWhy: sp.why,
		Severity: sp.sev, Status: sp.status,
		FirstSeen: fixedNow.Add(-sp.age).Format(time.RFC3339), LastSeen: fixedNow.Format(time.RFC3339),
	}
	s.ID = fp.ID(s.FP)
	if sp.verified == core.Live || sp.verified == core.Dead {
		s.VerifiedAt = fixedNow.Add(-time.Hour).Format(time.RFC3339)
	}
	if s.Triage == "" {
		s.Triage = "real"
	}
	f.secrets = append(f.secrets, s)
	return s
}

const day24 = 24 * time.Hour

// mixed30 is the shape of a real report: a few things on fire, a tail of noise.
func mixed30(t testing.TB) *fixture {
	f := newFixture(t)
	pub, priv := core.Public, core.Private
	// critical: live and public
	f.add(t, spec{kind: 0, sev: core.Critical, verified: core.Live, vis: pub, age: 3 * day24})
	f.add(t, spec{kind: 2, sev: core.Critical, verified: core.Live, age: 9 * time.Hour, locs: []core.Location{
		{Source: "gist.github.com/hangryclaude/" + randStr(t, hexa, 32), Kind: "gist", Visibility: core.SecretGist,
			Commit: randStr(t, hexa, 40), Path: "notes.md", Line: 4},
		{Source: "github.com/hangryclaude/notes", Kind: "repo", Visibility: core.Public, Ref: "refs/heads/main",
			Commit: randStr(t, hexa, 40), Path: "docs/setup.md", Line: 31},
		{Source: "github.com/hangryclaude/notes.wiki", Kind: "wiki", Visibility: core.Public, Path: "Home.md", Line: 2},
		{Source: "local:/Users/me/dev/notes", Kind: "unpushed", Visibility: core.Local, Path: ".env", Line: 1},
	}})
	// critical: a learned local key found in public, no verifier for it
	f.add(t, spec{kind: 1, sev: core.Critical, verified: core.Unverified, vis: pub, age: 40 * day24,
		known: "kg1a2b3c OPENAI_API_KEY"})
	// high: live, private
	f.add(t, spec{kind: 4, sev: core.High, verified: core.Live, vis: priv, age: 120 * day24})
	f.add(t, spec{kind: 3, sev: core.High, verified: core.Live, vis: priv, age: 2 * day24})
	f.add(t, spec{kind: 8, sev: core.High, verified: core.Unverified, vis: priv, age: 6 * day24, known: "kgfeed01 GROQ_API_KEY"})
	// medium and low: the review queue
	for i := 0; i < 3; i++ {
		f.add(t, spec{kind: 5 + i, sev: core.Medium, verified: core.Unverified, vis: pub, age: time.Duration(i+1) * day24,
			triage: "unreviewed"})
	}
	for i := 0; i < 5; i++ {
		f.add(t, spec{kind: 9 + i, sev: core.Low, verified: core.Unverified, vis: priv, age: time.Duration(10+i) * day24,
			triage: "test", why: "path contains tests/fixtures"})
	}
	f.add(t, spec{kind: 20, sev: core.None, verified: core.Unverified, vis: priv, triage: "unreviewed"})
	// info: dead, placeholder, public by design
	f.add(t, spec{kind: 6, sev: core.Info, verified: core.Dead, vis: pub, age: 200 * day24, triage: "real", why: "provider rejected it"})
	f.add(t, spec{kind: 14, sev: core.Info, verified: core.Unverified, vis: pub, triage: "public-by-design", why: "Supabase anon key"})
	f.add(t, spec{kind: 17, sev: core.Info, verified: core.Unverified, vis: priv, triage: "placeholder", why: "your_key_here style value"})
	f.add(t, spec{kind: 18, sev: core.Info, verified: core.Unverified, vis: priv, triage: "placeholder"})
	f.add(t, spec{kind: 19, sev: core.Info, verified: core.Unverified, vis: priv, triage: "false-positive"})
	// resolved: rotated keys keep their history but leave the to-do list
	for i := 0; i < 3; i++ {
		f.add(t, spec{kind: i, sev: core.Critical, status: "resolved", verified: core.Dead, vis: pub, age: 300 * day24})
	}
	// ignored by a human
	for i := 0; i < 3; i++ {
		f.add(t, spec{kind: 10 + i, sev: core.Medium, status: "ignored", verified: core.Unverified, vis: priv, triage: "false-positive"})
	}
	// more of each so the tables have weight
	f.add(t, spec{kind: 7, sev: core.High, verified: core.Live, vis: priv, age: 15 * day24})
	f.add(t, spec{kind: 11, sev: core.Medium, verified: core.VerifyError, vis: pub, age: day24, triage: "unreviewed"})
	f.add(t, spec{kind: 12, sev: core.Low, verified: core.Unverified, vis: priv, age: 80 * day24})
	f.add(t, spec{kind: 13, sev: core.Low, verified: core.Unverified, vis: priv, age: 90 * day24})
	return f
}

func healthyRun() core.RunStats {
	return core.RunStats{
		Kind: "poll", Started: fixedNow.Add(-6 * time.Minute).Format(time.RFC3339),
		Finished: fixedNow.Add(-5*time.Minute - 22*time.Second).Format(time.RFC3339),
		Sources:  470, Scanned: 12, Skipped: 0, NewFPs: 1,
		Engines: map[string]core.EngineStats{
			"betterleaks": {Seconds: 0.36, Hits: 58},
			"gitleaks":    {Seconds: 0.65, Hits: 57},
			"trufflehog":  {Seconds: 1.38, Hits: 2},
			"titus":       {Seconds: 3.37, Hits: 70},
			"known":       {Seconds: 0.02, Hits: 3},
		},
	}
}

func healthyLayers() []core.LayerStatus {
	at := fixedNow.Add(-3 * time.Minute).Format(time.RFC3339)
	return []core.LayerStatus{
		{Name: "Commit gate", OK: true, Detail: "pre-commit hook loads and blocks a planted fake", CheckedAt: at},
		{Name: "Push gate", OK: true, Detail: "pre-push hook blocks a planted fake", CheckedAt: at},
		{Name: "Ref guard", OK: true, Detail: "reference-transaction aborts --no-verify commits", CheckedAt: at},
		{Name: "Agent guard", OK: true, Detail: "Claude Code guard blocks --no-verify", CheckedAt: at},
		{Name: "GitHub settings", OK: true, Detail: "push protection on for 5 of 5 public repos", CheckedAt: at},
		{Name: "Poller", OK: true, Detail: "launchd job io.github.hangryclaude.keyguard.poll ran 4 min ago", CheckedAt: at},
		{Name: "Deep scan", OK: true, Detail: "last full rescan 2 days ago", CheckedAt: at},
		{Name: "Self-test", OK: true, Detail: "all layers caught their planted fake", CheckedAt: at},
	}
}

func reporter(path string) *Reporter {
	r := New(path)
	r.Now = func() time.Time { return fixedNow }
	r.Zone = time.UTC
	return r
}

func mustRender(t testing.TB, r *Reporter, f *fixture, run core.RunStats, layers []core.LayerStatus) string {
	t.Helper()
	b, err := r.Render(f.secrets, run, layers)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// leak names a raw value by its shape only: a failing test must not print the secret.
func leakShape(raw string) string { return fp.Shape(raw) }

func hasWindow(html, raw string, w int) (int, bool) {
	for i := 0; i+w <= len(raw); i++ {
		if strings.Contains(html, raw[i:i+w]) {
			return i, true
		}
	}
	return 0, false
}

// stressed is mixed30 with one long word, with nowhere to break, in every free-text field
// that reaches a cell: real data is not tidy. Letters only, so nothing is masked and the
// word really reaches the page.
func stressed(t testing.TB) (*fixture, core.RunStats, []core.LayerStatus) {
	f := mixed30(t)
	long := strings.Repeat("unbreakable", 12)
	for i := 0; i < 6; i++ {
		s := &f.secrets[i]
		s.Locations[0].Path = "src/" + long + ".py"
		s.Locations[0].Source = "github.com/hangryclaude/" + long
		s.Locations[0].Ref = "refs/heads/" + long
		s.TriageWhy = long
		s.Known = "kg000000 " + strings.ToUpper(long)
	}
	f.secrets[5].Type = long // an engine rule nobody has mapped yet
	run := healthyRun()
	run.Kind = long // reaches the hero's freshness line and a Coverage note
	run.Notes = []string{"2 sources skipped: clone timed out (will retry next poll)", long}
	run.Skipped = 2
	run.Engines[long] = core.EngineStats{Seconds: 1.5, Hits: 3}
	layers := healthyLayers()
	layers[1].OK = false
	layers[2].Name, layers[2].Detail = long, long
	return f, run, layers
}
