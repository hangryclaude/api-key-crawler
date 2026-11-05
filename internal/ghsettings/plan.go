package ghsettings

import (
	"fmt"

	"keyguard/internal/core"
)

// Support says what the plan allows for one feature, from the plan alone.
type Support int

const (
	// Unsupported: the plan cannot do it, so nothing is asked and nothing is written.
	Unsupported Support = iota
	// Supported: the plan can, so Apply switches it on.
	Supported
	// Probe: GitHub documents it loosely, so it is asked once on one public repo and the answer
	// is kept for a month (ProbePlan).
	Probe
)

// PlanSupport is the plan-gate matrix for a free personal account, hard-coded (STEAL P0-18).
// On Free, secret scanning and push protection exist on public repos only; a private repo reads
// `security_and_analysis: null`, its alerts answer 404 and its rulesets 403, on both of the user's
// accounts. The matrix is a fact about the plan, so nothing is written to a private repo to learn
// it: enabling a paid feature there can cost money, and 448 of 461 repos are private.
//
// The two optional features are not in GitHub's free tier as far as its documentation says, but
// that wording is loose, so they are probed (once, on a public repo) instead of assumed.
func PlanSupport(vis core.Visibility, f Feature) Support {
	switch {
	case vis != core.Public:
		return Unsupported
	case f == SecretScanning || f == PushProtection:
		return Supported
	}
	return Probe
}

// Class is where one repo stands with GitHub's own protection.
type Class string

const (
	// Protected: secret scanning and push protection are both on.
	Protected Class = "protected"
	// Gap: GitHub scans the repo but at least one of the two is off. Apply fixes it on a public repo.
	Gap Class = "gap"
	// Unreadable: GitHub would not say, or the read failed. The token lacks admin rights there.
	Unreadable Class = "unreadable"
	// Unavailable: a private repo on a plan that cannot scan it. GitHub cannot protect it, so
	// the hooks and keyguard's own scans are the only protection it has.
	Unavailable Class = "unavailable"
)

// ClassOf classifies a repo from the one GET that read it, with no write and no alerts call
// (P0-18). A private repo on a free plan reads `security_and_analysis: null`, which is how it
// lands in Unavailable.
func ClassOf(a AuditResult) Class {
	scanning := a.State[SecretScanning]
	switch {
	case a.Err != nil:
		return Unreadable
	case !a.Reported || scanning == Unreported:
		if a.Source.Visibility == core.Private {
			return Unavailable
		}
		return Unreadable
	case scanning == Enabled && a.State[PushProtection] == Enabled:
		return Protected
	}
	return Gap
}

// Protected reports whether GitHub's own protection is fully on for the repo as it was read. A
// publish-check asks it of a repo that just turned public: if it is still false a minute later,
// the flip went unprotected (STEAL P0-17).
func (a AuditResult) Protected() bool { return ClassOf(a) == Protected }

// Counts tallies a survey for the report.
type Counts struct {
	Repos       int
	Public      int
	Private     int
	Protected   int
	Gap         int
	Unreadable  int
	Unavailable int
}

// Headline is the line the report leads with: how much of what the user owns GitHub itself
// protects. On a free plan that is the public repos and little else, and the number should
// say so (STEAL P0-18: "GitHub protects 13 of 461 repos").
func (c Counts) Headline() string {
	return fmt.Sprintf("GitHub protects %d of %d repos", c.Protected, c.Repos)
}
