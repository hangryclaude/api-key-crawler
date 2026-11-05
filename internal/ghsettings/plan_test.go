package ghsettings

import (
	"errors"
	"strings"
	"testing"
	"time"

	"keyguard/internal/core"
	"keyguard/internal/fp"
	"keyguard/internal/inventory/ghcli"
)

func optionalWrites(g *ghub) (npp, vc int) {
	for _, p := range g.patches() {
		switch {
		case strings.Contains(p, "non_provider"):
			npp++
		case strings.Contains(p, "validity"):
			vc++
		}
	}
	return npp, vc
}

func TestProbePlanAsksOnceOnOnePublicRepoAndRemembersForAMonth(t *testing.T) {
	for name, skew := range skews {
		t.Run(name, func(t *testing.T) {
			g := newGhub()
			g.add("o/r", hrepo{sa: on(), refuse: map[string]string{"secret_scanning_non_provider_patterns": "Non-provider patterns require GitHub Secret Protection."}})
			fx := newFixtureSkew(t, g, skew, nil)
			src := repoSrc("o", "r", core.Public)

			plan, err := fx.s.ProbePlan(bg(), src, false)
			if err != nil {
				t.Fatal(err)
			}
			if n, v := optionalWrites(g); n != 1 || v != 1 {
				t.Fatalf("writes: %d non-provider, %d validity; want one each", n, v)
			}
			if p := plan[NonProviderPatterns]; !p.Unavailable || !strings.Contains(p.Message, "GitHub Secret Protection") {
				t.Errorf("non-provider patterns = %+v: a 422 says the plan lacks it, in GitHub's words", p)
			}
			if p := plan[ValidityChecks]; p.Unavailable || p.Probed == "" {
				t.Errorf("validity checks = %+v: a 200 says the plan has it", p)
			}
			if _, has := plan[SecretScanning]; has {
				t.Error("a required feature was probed; those are Apply's and the matrix's")
			}
			if p := fx.pauses(); len(p) != 1 || p[0] != time.Second {
				t.Errorf("pauses = %v: one second between the two writes", p)
			}
			// Each answer is stamped with GitHub's clock at the moment GitHub gave it, which is the
			// Mac's minus its skew, and the second is the pause later.
			saved := fx.readSaved(t).Plan["o"]
			if got := saved["secret_scanning_non_provider_patterns"]; !got.Unavailable || got.Probed != github.Format(time.RFC3339) {
				t.Errorf("non-provider patterns in state = %+v, want unavailable_on_plan stamped %s", got, github.Format(time.RFC3339))
			}
			if got := saved["secret_scanning_validity_checks"]; got.Probed != github.Add(time.Second).Format(time.RFC3339) {
				t.Errorf("validity checks in state = %+v, want the stamp GitHub's clock had a second later", got)
			}

			// Within the month nothing is asked, and the answer comes from the state file.
			before := len(g.log)
			fx.ck.Advance(29 * 24 * time.Hour)
			again, err := fx.s.ProbePlan(bg(), src, false)
			if err != nil || len(g.log) != before || !again[NonProviderPatterns].Unavailable {
				t.Errorf("29 days on: err=%v new requests=%q plan=%+v", err, g.log[before:], again)
			}
			// After it, both are asked again.
			fx.ck.Advance(2 * 24 * time.Hour)
			if _, err := fx.s.ProbePlan(bg(), src, false); err != nil {
				t.Fatal(err)
			}
			if n, v := optionalWrites(g); n != 2 || v != 2 {
				t.Errorf("31 days on: %d non-provider, %d validity writes in all; want a second probe of each", n, v)
			}
			// Force asks regardless.
			if _, err := fx.s.ProbePlan(bg(), src, true); err != nil {
				t.Fatal(err)
			}
			if n, _ := optionalWrites(g); n != 3 {
				t.Errorf("force: %d non-provider writes in all, want 3", n)
			}
			assertNoParameterFlags(t, fx)
		})
	}
}

// The plan belongs to an owner: an org can be on a different one from the account that reads it.
func TestProbePlanKeepsOneAnswerPerOwner(t *testing.T) {
	g := newGhub()
	g.add("free/r", hrepo{sa: on(), refuse: map[string]string{"secret_scanning_non_provider_patterns": "not on this plan"}})
	g.add("team/r", hrepo{sa: on()})
	fx := newFixture(t, g, nil)
	freePlan, err := fx.s.ProbePlan(bg(), repoSrc("free", "r", core.Public), false)
	if err != nil {
		t.Fatal(err)
	}
	teamPlan, err := fx.s.ProbePlan(bg(), repoSrc("team", "r", core.Public), false)
	if err != nil {
		t.Fatal(err)
	}
	if !freePlan[NonProviderPatterns].Unavailable || teamPlan[NonProviderPatterns].Unavailable {
		t.Errorf("free %+v team %+v: one owner's answer was taken for the other's", freePlan, teamPlan)
	}
	if n, _ := optionalWrites(g); n != 2 {
		t.Errorf("%d non-provider writes, want one for each owner", n)
	}
}

func TestProbePlanTreatsForbiddenAsAMissingPlanAndAnythingElseAsNoAnswer(t *testing.T) {
	g := newGhub()
	g.add("o/r", hrepo{sa: on(),
		refuse:       map[string]string{"secret_scanning_non_provider_patterns": "Advanced Security must be enabled."},
		refuseStatus: 403,
	})
	g.add("x/gone", hrepo{missing: true})
	fx := newFixture(t, g, nil)
	plan, err := fx.s.ProbePlan(bg(), repoSrc("o", "r", core.Public), false)
	if err != nil || !plan[NonProviderPatterns].Unavailable {
		t.Errorf("403: plan=%+v err=%v", plan, err)
	}
	plan, err = fx.s.ProbePlan(bg(), repoSrc("x", "gone", core.Public), false)
	if err == nil || !strings.Contains(err.Error(), "inconclusive") {
		t.Errorf("404: err = %v, want an inconclusive probe", err)
	}
	if len(plan) != 0 {
		t.Errorf("an answer that is not an answer was recorded: %+v", plan)
	}
	if st := fx.readSaved(t).Plan; len(st) != 1 || len(st["o"]) != 2 {
		t.Errorf("state plan = %v: only the first owner's two answers", st)
	}
}

// A process whose first call is a probe has not heard GitHub's clock yet; it asks the one
// request that costs nothing before it stamps or compares anything with a date.
func TestProbePlanLearnsGitHubsTimeBeforeItStampsAnything(t *testing.T) {
	for name, skew := range skews {
		t.Run(name, func(t *testing.T) {
			g := newGhub()
			g.add("o/r", hrepo{sa: on()})
			fx := newFixtureSkew(t, g, skew, nil)
			if fx.s.cl.Clock().Known() {
				t.Fatal("the clock knew GitHub's time before any request")
			}
			if _, err := fx.s.ProbePlan(bg(), repoSrc("o", "r", core.Public), false); err != nil {
				t.Fatal(err)
			}
			if first := fx.f.Calls()[0].Path; first != "rate_limit" {
				t.Errorf("first request = %s, want rate_limit", first)
			}
			ok := map[string]bool{github.Format(time.RFC3339): true, github.Add(time.Second).Format(time.RFC3339): true}
			for f, p := range fx.readSaved(t).Plan["o"] {
				if !ok[p.Probed] {
					t.Errorf("%s was stamped %s; GitHub's clock read %s, and the Mac's %s", f, p.Probed, github.Format(time.RFC3339), github.Add(skew).Format(time.RFC3339))
				}
			}
		})
	}
}

func TestProbePlanIsRefusedForARepoThatIsNotPublicOrNotARepo(t *testing.T) {
	g := newGhub()
	fx := newFixture(t, g, nil)
	for _, src := range []core.Source{
		repoSrc("o", "r", core.Private),
		{ID: "github.com/o/r.wiki", Kind: "wiki", Owner: "o", Name: "r.wiki", Visibility: core.Public},
		repoSrc("o", "x/../y", core.Public),
	} {
		if _, err := fx.s.ProbePlan(bg(), src, false); err == nil {
			t.Errorf("%s was probed", src.ID)
		}
	}
	if len(g.log) != 0 {
		t.Errorf("GitHub was contacted: %q", g.log)
	}
}

func TestProbePlanStopsAtARateLimit(t *testing.T) {
	g := newGhub()
	g.add("o/r", hrepo{sa: on()})
	g.rateLimitAfter, g.resetIn = 1, 45*time.Second
	fx := newFixtureSkew(t, g, 2*time.Hour, nil)
	plan, err := fx.s.ProbePlan(bg(), repoSrc("o", "r", core.Public), false)
	var rl *ghcli.RateLimitError
	if !errors.As(err, &rl) {
		t.Fatalf("err = %v, want the rate limit", err)
	}
	if rl.Wait(fx.s.githubNow()) != 47*time.Second {
		t.Errorf("Wait = %v", rl.Wait(fx.s.githubNow()))
	}
	if len(plan) != 0 || g.patchCount != 1 {
		t.Errorf("plan %+v after %d writes: it must stop at the limit and record nothing", plan, g.patchCount)
	}
}

// The probe of a private repo used to PATCH it, which on a paid plan switches a paid feature on.
func TestProbeReadsAPrivateRepoAndNeverWritesToIt(t *testing.T) {
	g := newGhub()
	g.add("o/free", hrepo{null: true})
	g.add("o/empty", hrepo{}) // a block with no secret scanning in it
	g.add("o/paid", hrepo{sa: map[string]string{"secret_scanning": "disabled"}})
	fx := newFixture(t, g, nil)

	for _, name := range []string{"free", "empty"} {
		r := fx.s.Probe(bg(), repoSrc("o", name, core.Private))
		if r.Err != nil || r.Available || r.Status != 200 || !strings.Contains(r.Message, "not available") {
			t.Errorf("%s: %+v", name, r)
		}
	}
	if r := fx.s.Probe(bg(), repoSrc("o", "paid", core.Private)); r.Err != nil || !r.Available || r.Status != 200 {
		t.Errorf("paid plan: %+v", r)
	}
	if r := fx.s.Probe(bg(), repoSrc("o", "paid", core.Public)); r.Err == nil || r.Available {
		t.Errorf("a public repo is Apply's business: %+v", r)
	}
	if r := fx.s.Probe(bg(), repoSrc("o", "ghost", core.Private)); r.Err != nil || r.Available || r.Status != 404 {
		t.Errorf("missing repo: %+v", r)
	}
	if n := len(g.patches()); n != 0 {
		t.Errorf("%d writes: a probe of a private repo is a read (STEAL P0-18)", n)
	}
	assertNoParameterFlags(t, fx)
}

func TestNewRejectsNegativePauses(t *testing.T) {
	kr := fp.NewEphemeral()
	if _, err := New(Config{FP: kr, Gap: -time.Second}); err == nil {
		t.Error("a negative gap between writes was accepted")
	}
	if _, err := New(Config{FP: kr, ReprobeEvery: -time.Hour}); err == nil {
		t.Error("a negative re-probe interval was accepted")
	}
	s, err := New(Config{FP: kr})
	if err != nil || s.gap != time.Second || s.reprobe != 30*24*time.Hour {
		t.Errorf("defaults: gap %v re-probe %v err %v, want a second and a month", s.gap, s.reprobe, err)
	}
}
