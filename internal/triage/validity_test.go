package triage

import (
	"crypto/rand"
	"math/big"
	"strings"
	"testing"
	"time"

	"keyguard/internal/core"
	"keyguard/internal/fp"
)

var vt0 = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)

// vstep is one verification outcome arriving `min` minutes after vt0.
type vstep struct {
	v   core.Verified
	why core.VerifyReason
	min int
}

// verified runs the outcomes through the same merge rules the store uses, so these tests
// start from states the system can actually reach, not ones typed in by hand.
func verified(steps ...vstep) func(*core.Secret) {
	return func(s *core.Secret) {
		for _, st := range steps {
			s.RecordVerification(st.v, st.why, vt0.Add(time.Duration(st.min)*time.Minute))
		}
	}
}

func exposedEver(s *core.Secret) { s.ExposedEver = true }

func randAlnum(t *testing.T, n int) string {
	t.Helper()
	const set = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		x, err := rand.Int(rand.Reader, big.NewInt(int64(len(set))))
		if err != nil {
			t.Fatal(err)
		}
		b[i] = set[x.Int64()]
	}
	return string(b)
}

var allReasons = []core.VerifyReason{
	core.ReasonNone, core.ReasonTimeout, core.ReasonRateLimited, core.ReasonDNS, core.ReasonDial, core.ReasonStatus, core.ReasonOverlap,
}

// STEAL P0-09: "Only a clean invalid/revoked may downgrade; error and TH overlap keep severity."
func TestAFailedCheckNeverLowersSeverity(t *testing.T) {
	tr := New()
	for _, reason := range allReasons {
		t.Run("reason="+string(reason), func(t *testing.T) {
			// Never verified: a check that could not decide is the same as no check.
			base := classify(t, tr, sec(vis(core.Public)))
			errd := classify(t, tr, sec(vis(core.Public), verified(vstep{core.VerifyError, reason, 0})))
			if errd.Severity != base.Severity || errd.Triage != base.Triage || base.Severity < core.Medium {
				t.Fatalf("errored check: %v %s, unchecked: %v %s", errd.Severity, errd.Triage, base.Severity, base.Triage)
			}
			if !strings.Contains(errd.TriageWhy, "could not decide") {
				t.Fatalf("the reason does not say the check failed: %q", errd.TriageWhy)
			}
			if reason != core.ReasonNone && !strings.Contains(errd.TriageWhy, "("+string(reason)+")") {
				t.Fatalf("the reason does not name the failure class: %q", errd.TriageWhy)
			}

			// A key that was live stays live through a failed re-check, public or private.
			for vv, want := range map[core.Visibility]core.Severity{core.Public: core.Critical, core.Private: core.High} {
				live := classify(t, tr, sec(vis(vv), verified(vstep{core.Live, core.ReasonNone, 0}, vstep{core.VerifyError, reason, 60})))
				if live.Severity != want || live.Triage != Real {
					t.Fatalf("live key, %s, after a failed re-check: %v %s (%s)", vv, live.Severity, live.Triage, live.TriageWhy)
				}
				if !strings.Contains(live.TriageWhy, "verdict stands") {
					t.Fatalf("a failed re-check is not explained: %q", live.TriageWhy)
				}
			}

			// A dead key stays retired: a failed re-check neither resurrects nor escalates it.
			dead := classify(t, tr, sec(vis(core.Public), verified(vstep{core.Dead, core.ReasonNone, 0}, vstep{core.VerifyError, reason, 60})))
			if dead.Severity != core.Info {
				t.Fatalf("dead key after a failed re-check: %v (%s)", dead.Severity, dead.TriageWhy)
			}
		})
	}
}

// "An unreachable endpoint is not dead": a Dead that carries a failure reason is no verdict,
// so the secret keeps the severity of an unchecked one instead of being retired.
func TestDeadWithAFailureReasonDoesNotRetireAnAlert(t *testing.T) {
	tr := New()
	for _, reason := range allReasons[1:] {
		got := classify(t, tr, sec(vis(core.Public), verified(vstep{core.Dead, reason, 0})))
		if got.Severity < core.Medium {
			t.Errorf("%s: a failed check retired the alert (%v)", reason, got.Severity)
		}
		live := classify(t, tr, sec(vis(core.Public), verified(vstep{core.Live, core.ReasonNone, 0}, vstep{core.Dead, reason, 5})))
		if live.Severity != core.Critical {
			t.Errorf("%s: a failed check lowered a live key to %v", reason, live.Severity)
		}
	}
	// The clean rejection still retires it.
	if got := classify(t, tr, sec(vis(core.Public), verified(vstep{core.Dead, core.ReasonNone, 0}))); got.Severity != core.Info {
		t.Errorf("a clean rejection must retire the alert, got %v", got.Severity)
	}
}

func TestSeverityFollowsExposureAsItEverWas(t *testing.T) {
	tr := New()
	for name, c := range map[string]struct {
		mods []func(*core.Secret)
		want core.Severity
	}{
		"live, public then private again":        {[]func(*core.Secret){verdict(core.Live), vis(core.Private), exposedEver}, core.Critical},
		"live, private all along":                {[]func(*core.Secret){verdict(core.Live), vis(core.Private)}, core.High},
		"known, public then private again":       {[]func(*core.Secret){func(s *core.Secret) { s.Known = "kgabc123 X" }, vis(core.Private), exposedEver}, core.Critical},
		"unchecked real, public then private":    {[]func(*core.Secret){vis(core.Private), exposedEver}, core.Medium},
		"unchecked real, private all along":      {[]func(*core.Secret){vis(core.Private)}, core.Low},
		"dead stays info however it was exposed": {[]func(*core.Secret){verdict(core.Dead), vis(core.Private), exposedEver}, core.Info},
		"a secret gist counts as exposed":        {[]func(*core.Secret){verdict(core.Live), vis(core.SecretGist)}, core.Critical},
	} {
		if got := classify(t, tr, sec(c.mods...)); got.Severity != c.want {
			t.Errorf("%s: %v, want %v (%s)", name, got.Severity, c.want, got.TriageWhy)
		}
	}
}

func TestSecretTagsReachTheRules(t *testing.T) {
	tr := New()
	anon := sec(typ("jwt"), shape("eyJ…k7Qz"), vis(core.Public), func(s *core.Secret) { s.Tags = []string{TagJWTAnon} })
	got := classify(t, tr, anon)
	if got.Triage != PublicByDesign || got.Severity != core.Info {
		t.Fatalf("a Supabase anon JWT tagged by the normalizer: %s / %v (%s)", got.Triage, got.Severity, got.TriageWhy)
	}
	anon.Tags = nil
	if got := classify(t, tr, anon); got.Triage == PublicByDesign {
		t.Fatalf("without the tag a JWT says nothing about its role, yet: %s", got.Triage)
	}

	ph := classify(t, tr, sec(vis(core.Public), func(s *core.Secret) { s.Tags = []string{TagPlaceholder} }))
	if ph.Triage != Placeholder {
		t.Fatalf("placeholder tag on the secret: %s", ph.Triage)
	}

	// Evidence tags and the secret's own are read together, and the store's slice is never written to.
	spare := make([]string, 1, 8)
	spare[0] = TagTestMode
	both := New(WithEvidence(func(string) (Evidence, bool) { return Evidence{Tags: spare}, true }))
	if got := classify(t, both, sec(typ("jwt"), shape("eyJ…k7Qz"), vis(core.Public), func(s *core.Secret) { s.Tags = []string{TagJWTAnon} })); got.Triage != PublicByDesign {
		t.Fatalf("secret tag next to an evidence tag: %s", got.Triage)
	}
	for i, x := range spare[:cap(spare)][1:] {
		if x != "" {
			t.Fatalf("Classify wrote into the evidence slice's spare capacity at %d", i+1)
		}
	}
}

// The prefixes below only exist in a Shape since fp learned them, and the rules are written
// against Shape, so these run through fp.Shape rather than a hand-typed shape.
func TestMapboxPublicTokenIsShippableAndTheSecretOneIsNot(t *testing.T) {
	tr := New()
	pub := classify(t, tr, sec(shape(fp.Shape("pk."+randAlnum(t, 60))), typ("mapbox"), vis(core.Public)))
	if pub.Triage != PublicByDesign || pub.Severity != core.Info {
		t.Fatalf("Mapbox public token: %s / %v (%s)", pub.Triage, pub.Severity, pub.TriageWhy)
	}
	secret := classify(t, tr, sec(shape(fp.Shape("sk."+randAlnum(t, 60))), typ("mapbox"), vis(core.Public)))
	if secret.Triage == PublicByDesign || secret.Severity < core.Medium {
		t.Fatalf("Mapbox secret token: %s / %v (%s)", secret.Triage, secret.Severity, secret.TriageWhy)
	}
}

func TestSentryAuthTokenIsNotADSN(t *testing.T) {
	ctxLine := Evidence{Contexts: []string{"SENTRY_DSN_ENV = «…»  # sentry dsn for the web client"}}
	tr := New(WithEvidence(func(string) (Evidence, bool) { return ctxLine, true }))

	token := classify(t, tr, sec(shape(fp.Shape("sntrys_"+randAlnum(t, 64))), typ("sentry"), vis(core.Public)))
	if token.Triage == PublicByDesign {
		t.Fatalf("a Sentry auth token on a line that mentions the DSN was called public by design: %s", token.TriageWhy)
	}
	user := classify(t, tr, sec(shape(fp.Shape("sntryu_"+randAlnum(t, 64))), typ("sentry"), vis(core.Public)))
	if user.Triage == PublicByDesign {
		t.Fatalf("a Sentry user token was called public by design: %s", user.TriageWhy)
	}
	// Control: a DSN really is meant to ship.
	dsn := classify(t, tr, sec(shape(fp.Shape("https://"+randAlnum(t, 32)+"@o1.ingest.sentry.io/2")), typ("sentry"), vis(core.Public)))
	if dsn.Triage != PublicByDesign {
		t.Fatalf("a Sentry DSN: %s (%s)", dsn.Triage, dsn.TriageWhy)
	}
}

// core.Hit documents that a filename-rule hit has no Shape or Len; the store keeps what the
// hit had, so triage meets such secrets and must classify them without help from the shape.
func TestFilenameRuleSecretsWithNoShapeAreClassified(t *testing.T) {
	tr := New()
	for _, st := range []string{"", core.StatusOpen} {
		s := core.Secret{
			FP: "kgfilerule", ID: "kgfile", Type: "env-file", Engines: []string{"filename"}, Rules: []string{"env-file"},
			Locations: []core.Location{{Source: "local:/work/app", Kind: "staged", Visibility: core.Local, Path: ".env"}},
			Verified:  core.Unverified, Status: st,
		}
		got := classify(t, tr, s)
		if got.Triage == "" || got.TriageWhy == "" || got.Severity < core.Info {
			t.Errorf("status %q: %q %q %v", st, got.Triage, got.TriageWhy, got.Severity)
		}
	}
}

func TestTheJudgeListStaysClaudeCodexHuman(t *testing.T) {
	if ByClaude != "claude" || ByCodex != "codex" || ByHuman != "human" || ByRule != "rule" {
		t.Fatalf("the judge words changed: %q %q %q %q", ByRule, ByClaude, ByCodex, ByHuman)
	}
	if Real != core.TriageReal || Unreviewed != core.TriageUnreviewed || ByHuman != core.TriageByHuman {
		t.Fatal("triage's vocabulary drifted from core's")
	}
	// A label some judge gave is kept as that judge's, whichever of the three it was.
	tr := New()
	for _, by := range []string{ByClaude, ByCodex, ByHuman} {
		got := classify(t, tr, sec(func(s *core.Secret) { s.Triage, s.TriageBy = Placeholder, by }))
		if got.TriageBy != by || got.Triage != Placeholder {
			t.Errorf("%s: label %s by %q", by, got.Triage, got.TriageBy)
		}
	}
}

// TriageWhy is stored in findings.json and shown in the report. A reason that did not come
// through RecordVerification (a record from an older build, another writer) can be anything,
// and an engine's error text can quote the credential it was checking: only a class is printed.
func TestTriageWhyNamesAFailureClassNeverText(t *testing.T) {
	tr := New()
	quoted := core.VerifyReason("Post https://" + "user" + ":" + "hunter2" + "@db.example/ping: i/o timeout")
	for name, mod := range map[string]func(*core.Secret){
		"never decided": func(s *core.Secret) { s.Verified, s.VerifyReason = core.VerifyError, quoted },
		"live, then a re-check failed": func(s *core.Secret) {
			s.Verified, s.VerifyReason, s.VerifyErrors = core.Live, quoted, 1
		},
	} {
		got := classify(t, tr, sec(vis(core.Public), mod))
		if strings.Contains(got.TriageWhy, "hunter2") || strings.Contains(got.TriageWhy, "example") {
			t.Errorf("%s: the reason text reached TriageWhy: %q", name, got.TriageWhy)
		}
		if !strings.Contains(got.TriageWhy, "could not decide") {
			t.Errorf("%s: a failed check is not explained: %q", name, got.TriageWhy)
		}
	}
	// A real class is still named.
	got := classify(t, tr, sec(vis(core.Public), func(s *core.Secret) { s.Verified, s.VerifyReason = core.VerifyError, core.ReasonDNS }))
	if !strings.Contains(got.TriageWhy, "(dns)") {
		t.Errorf("the class is not named: %q", got.TriageWhy)
	}
}
