// Package triage turns what is known about a Secret into a label, a reason and a severity.
//
// The order of trust, strongest first, is PLAN.md's accuracy chain: a human's ignore, the
// provider's verdict (verified live overrides every "not real" label; dead is revoked), a
// learned local key (zero false positives), a reviewer's earlier label (human, claude,
// codex), and last the rules here. Severity then follows the table in PLAN.md "Core data
// model" from the label, the verdict and whether a stranger can read a location.
//
// Classify is a pure function of the Secret and its evidence, so running it again on every
// sweep is safe: a decision made by the rules is recomputed from scratch, and a decision a
// human or an LLM made is kept.
//
// The rules read what core.Secret carries (type, rules, engines, shape, length, locations,
// known, verified, tags) plus Evidence, which a Store can supply from the hits it has seen:
// the redacted lines a secret appeared on, its entropy, and more tags. Without evidence the
// rules still run, with less to go on.
//
// Verification follows the validity model (STEAL P0-09, core.Secret.RecordVerification).
// Only a verdict from the provider moves severity: live raises it, dead lowers it to info. A
// check that could not decide (core.VerifyError, whatever the reason: timeout, 429, dns,
// dial, status, overlap) is treated as no check at all, so it can neither retire an alert nor
// lower one, and a key that was live stays live through any number of failed re-checks.
// Severity follows exposure as it ever was (Secret.WasExposed), not as it is now: a key that
// was public stays compromised when its repo goes private again.
//
// The judge list is claude|codex|human. Claude Opus 5.5 is the only judge in use; the others
// stay valid so labels already stored keep reading.
//
// Four calls made on purpose, confirmed in the hardening pass. A human's ignore stays info even
// if the key later verifies live: an ignored key is one the user judged not a leak (a valid but
// public browser key is the usual case), and alerting it every sweep would make ignoring useless.
// Every other not-real label, a human's included, gives way to a live verdict. A place that is
// only on this Mac (core.Local) counts as private. A live key that is public by design goes
// critical; that may be noisy, and the bench is where to tune it. A label with no author counts
// as a reviewer's; only labels signed by the rules are recomputed.
package triage

import (
	"cmp"
	"slices"
	"strings"

	"keyguard/internal/core"
)

// Labels for Secret.Triage.
const (
	Real           = core.TriageReal
	Test           = core.TriageTest
	Placeholder    = core.TriagePlaceholder
	PublicByDesign = core.TriagePublicByDesign
	FalsePositive  = core.TriageFalsePositive
	Unreviewed     = core.TriageUnreviewed
)

// Values for Secret.TriageBy.
const (
	ByRule   = core.TriageByRule
	ByClaude = core.TriageByClaude
	ByCodex  = core.TriageByCodex
	ByHuman  = core.TriageByHuman
)

// Tags are facts a normalizer can compute from the raw value, which is gone by the time
// triage runs. They are the contract between an engine and these rules.
const (
	TagPlaceholder    = "placeholder"           // the value matches a placeholder pattern (your_*, changeme, xxx...)
	TagJWTAnon        = "jwt.role=anon"         // a JWT whose payload says role=anon (Supabase's public key)
	TagJWTServiceRole = "jwt.role=service_role" // a JWT whose payload says role=service_role
	TagTestMode       = "test-mode"             // a provider's test-mode key
)

const (
	statusResolved = core.StatusResolved
	statusIgnored  = core.StatusIgnored
)

// Evidence is what a Secret does not carry but its hits did. Tags here and core.Secret.Tags
// are read together.
type Evidence struct {
	Contexts []string // redacted lines the secret was seen on, with the value replaced by its shape
	Entropy  float64  // bits per character of the raw value; 0 means unknown
	Tags     []string // see the Tag constants
}

// StoreEvidence is what *db.Store offers; it is spelled out here so the two packages need
// not import each other.
type StoreEvidence interface {
	Evidence(fp string) (contexts []string, entropy float64, tags []string, ok bool)
}

// Option configures a Triager.
type Option func(*Triager)

// WithEvidence supplies evidence by fingerprint.
func WithEvidence(f func(fp string) (Evidence, bool)) Option {
	return func(t *Triager) { t.evidence = f }
}

// WithStoreEvidence reads evidence from a findings store.
func WithStoreEvidence(s StoreEvidence) Option {
	return WithEvidence(func(fp string) (Evidence, bool) {
		c, e, tags, ok := s.Evidence(fp)
		return Evidence{Contexts: c, Entropy: e, Tags: tags}, ok
	})
}

// WithFingerprinter lets the rules recognise well-known documentation values (the AWS
// docs keys, the jwt.io sample token) by fingerprint. It must be the keyring the engines
// use, or the fingerprints will not match.
func WithFingerprinter(f core.Fingerprinter) Option {
	return func(t *Triager) {
		t.examples = make(map[string]string, 8)
		for _, e := range documentationExamples() {
			t.examples[f.FP(e.value)] = e.what
		}
	}
}

// Triager implements core.Triager. It is safe for concurrent use.
type Triager struct {
	evidence func(fp string) (Evidence, bool)
	examples map[string]string // fingerprint -> what the documentation value is
}

var _ core.Triager = (*Triager)(nil)

// New builds a Triager.
func New(opts ...Option) *Triager {
	t := &Triager{}
	for _, o := range opts {
		o(t)
	}
	return t
}

type decision struct {
	label, by, why string
	sev            core.Severity
}

// Classify sets Triage, TriageBy, TriageWhy and Severity.
func (t *Triager) Classify(s *core.Secret) {
	var ev Evidence
	if t.evidence != nil {
		ev, _ = t.evidence(s.FP)
	}
	if len(s.Tags) > 0 {
		ev.Tags = append(slices.Clip(ev.Tags), s.Tags...) // never write into the store's slice
	}
	d := t.decide(s, ev)
	s.Triage, s.TriageBy, s.TriageWhy, s.Severity = d.label, d.by, d.why, d.sev
}

func (t *Triager) decide(s *core.Secret, ev Evidence) decision {
	exposed := s.WasExposed()

	// A human's ignore is the last word in the chain: nothing below can undo it.
	if s.Status == statusIgnored {
		d := decision{s.Triage, s.TriageBy, s.TriageWhy, core.Info}
		if d.label == "" || d.label == Unreviewed {
			d.label, d.by = FalsePositive, ByHuman
		}
		d.why = cmp.Or(d.why, "ignored by a human")
		return d
	}

	d := t.label(s, ev)
	switch {
	case s.Verified == core.Dead || s.Status == statusResolved:
		if s.Known != "" {
			d = decision{label: Real, by: ByRule, why: "learned local secret " + s.Known}
		}
		d.sev = core.Info
		if s.Verified == core.Dead {
			d.why = joinWhy(d.why, "the provider rejects it (revoked, rotated or never valid)")
		} else {
			d.why = joinWhy(d.why, "marked resolved")
		}
	case s.Verified == core.Live:
		why := "the provider accepted it (verified live)"
		if notReal(d.label) {
			why += "; this overrides the " + d.label + " label"
		}
		d = decision{Real, ByRule, why, liveSeverity(exposed)}
	case s.Known != "":
		d = decision{Real, ByRule, "learned local secret " + s.Known, liveSeverity(exposed)}
	default:
		d.sev = severityFor(d.label, s, exposed)
		if s.Verified == core.VerifyError {
			d.why = joinWhy(d.why, "the last check could not decide"+reasonSuffix(s.VerifyReason)+", so it counts as unchecked, not as dead")
		}
	}
	if s.Verified.Decisive() && s.VerifyErrors > 0 {
		d.why = joinWhy(d.why, "the latest re-check could not decide"+reasonSuffix(s.VerifyReason)+"; the verdict stands")
	}
	return d
}

// reasonSuffix names the failure class. Only a class is ever printed: TriageWhy is stored and
// shown, and a reason that arrived as text from somewhere outside RecordVerification could
// quote the credential that was being checked.
func reasonSuffix(r core.VerifyReason) string {
	if r = r.Class(); r == core.ReasonNone {
		return ""
	}
	return " (" + string(r) + ")"
}

func joinWhy(a, b string) string {
	if a == "" {
		return b
	}
	return a + "; " + b
}

func notReal(label string) bool {
	switch label {
	case Test, Placeholder, PublicByDesign, FalsePositive:
		return true
	}
	return false
}

// liveSeverity is the table's top two rows: a key that works is critical when a stranger can
// read it and high when only a private place holds it. Local places count as private.
func liveSeverity(exposed bool) core.Severity {
	if exposed {
		return core.Critical
	}
	return core.High
}

// severityFor is the rest of the table, for a secret nobody has proven live or dead.
func severityFor(label string, s *core.Secret, exposed bool) core.Severity {
	switch label {
	case Real:
		if exposed {
			return core.Medium
		}
		return core.Low
	case Test:
		return core.Low
	case PublicByDesign:
		if isGoogleKey(s) {
			return core.Low // a Google key is often meant to ship, but an unrestricted one still bills its owner
		}
		return core.Info
	case Placeholder, FalsePositive:
		return core.Info
	}
	return core.Low // unreviewed, or a label this build does not know: it still needs a look
}

// label is the reviewer's earlier verdict if somebody other than the rules gave one, else the
// rules'. A label with no author counts as a reviewer's: the rules always sign theirs, so an
// unsigned one came from outside. An LLM saw redacted context only, so its label yields to
// proof (live, known) in decide.
func (t *Triager) label(s *core.Secret, ev Evidence) decision {
	if s.Triage != "" && s.Triage != Unreviewed && s.TriageBy != ByRule {
		return decision{label: s.Triage, by: s.TriageBy, why: s.TriageWhy}
	}
	return t.byRules(s, ev)
}

// byRules evaluates the label rules in order of how sure each is that a hit is not a leak:
// a value meant to be public, a placeholder, then a test or fixture. What survives is real if
// the evidence says so and unreviewed otherwise. Public-by-design goes first because it
// matches on a provider's own prefix, which is more reliable than the placeholder rules'
// guesses about a value's last characters, and because a Google key must stay low, not info.
func (t *Triager) byRules(s *core.Secret, ev Evidence) decision {
	c := newCtx(s, ev)
	if why, ok := publicByDesign(c); ok {
		return decision{label: PublicByDesign, by: ByRule, why: why}
	}
	if why, ok := t.placeholder(c); ok {
		return decision{label: Placeholder, by: ByRule, why: why}
	}
	if why, ok := testLike(c); ok {
		return decision{label: Test, by: ByRule, why: why}
	}
	if why, ok := realByRule(c); ok {
		return decision{label: Real, by: ByRule, why: why}
	}
	return decision{label: Unreviewed, why: "no verifier result and no second detector; needs a human or an LLM look"}
}

func has(list []string, v string) bool { return slices.Contains(list, v) }

func hasAny(s string, subs ...string) bool {
	for _, x := range subs {
		if strings.Contains(s, x) {
			return true
		}
	}
	return false
}
