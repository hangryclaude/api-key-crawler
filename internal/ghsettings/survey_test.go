package ghsettings

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"keyguard/internal/core"
)

// ownerRepos adds n private repos for owner, each as a free plan shows them: no
// security_and_analysis at all, just null.
func (g *ghub) ownerRepos(owner string, n int, vis core.Visibility) []core.Source {
	var out []core.Source
	for i := range n {
		name := fmt.Sprintf("%s%d", map[core.Visibility]string{core.Private: "priv", core.Public: "pub"}[vis], i)
		if vis == core.Private {
			g.add(owner+"/"+name, hrepo{null: true})
		} else {
			g.add(owner+"/"+name, hrepo{sa: on()})
		}
		out = append(out, repoSrc(owner, name, vis))
	}
	return out
}

func gets(g *ghub) (reads, writes, alerts int) {
	for _, l := range g.log {
		switch {
		case strings.HasPrefix(l, "PATCH "):
			writes++
		case strings.HasPrefix(l, "GET "):
			reads++
		}
	}
	return reads, writes, alerts
}

func TestSurveyReadsEveryNonPrivateRepoAndOnePrivateRepoPerOwner(t *testing.T) {
	g := newGhub()
	var srcs []core.Source
	srcs = append(srcs, g.ownerRepos("o", 2, core.Public)...)
	g.repos["o/pub1"].sa = map[string]string{"secret_scanning": "enabled", "secret_scanning_push_protection": "disabled"}
	srcs = append(srcs, g.ownerRepos("o", 5, core.Private)...)
	srcs = append(srcs, g.ownerRepos("p", 2, core.Private)...)
	fx := newFixture(t, g, nil)

	sv, err := fx.s.Survey(bg(), srcs)
	if err != nil {
		t.Fatal(err)
	}
	reads, writes, _ := gets(g)
	if reads != 4 || writes != 0 {
		t.Errorf("%d reads and %d writes, want 2 public + 1 sample for each of 2 owners = 4, and none written", reads, writes)
	}
	for _, c := range fx.f.Calls() {
		if strings.Contains(c.Path, "/secret-scanning/alerts") {
			t.Errorf("alerts were polled: %s", c.Path)
		}
	}

	if sv.Classes["github.com/o/pub0"] != Protected || sv.Classes["github.com/o/pub1"] != Gap {
		t.Errorf("public classes = %v", sv.Classes)
	}
	inferred := 0
	for _, s := range srcs {
		if s.Visibility != core.Private {
			continue
		}
		if sv.Classes[s.ID] != Unavailable {
			t.Errorf("%s is %s, want unavailable", s.ID, sv.Classes[s.ID])
		}
		if sv.Inferred[s.ID] {
			inferred++
		}
	}
	if inferred != 5 {
		t.Errorf("%d private repos classified without a request of their own, want 5 of 7", inferred)
	}
	want := Counts{Repos: 9, Public: 2, Private: 7, Protected: 1, Gap: 1, Unavailable: 7}
	if sv.Counts != want {
		t.Errorf("counts = %+v, want %+v", sv.Counts, want)
	}
	if got := sv.Headline(); got != "GitHub protects 1 of 9 repos" {
		t.Errorf("headline = %q", got)
	}
	assertNoParameterFlags(t, fx)
}

// The figures in STEAL P0-18: 13 public repos, 448 private ones, one free plan. Reading 461 repos
// would cost 461 calls and one more for every private repo's alerts; the survey costs 15.
func TestSurveyOfAFreePlanCostsOneCallPerPublicRepoAndOnePerOwner(t *testing.T) {
	g := newGhub()
	var srcs []core.Source
	srcs = append(srcs, g.ownerRepos("hangryclaude", 5, core.Public)...)
	srcs = append(srcs, g.ownerRepos("alt-builds", 8, core.Public)...)
	srcs = append(srcs, g.ownerRepos("hangryclaude", 439-5, core.Private)...)
	srcs = append(srcs, g.ownerRepos("alt-builds", 14, core.Private)...)
	fx := newFixture(t, g, nil)
	sv, err := fx.s.Survey(bg(), srcs)
	if err != nil {
		t.Fatal(err)
	}
	if len(srcs) != 461 || sv.Headline() != "GitHub protects 13 of 461 repos" {
		t.Errorf("%d repos, headline %q", len(srcs), sv.Headline())
	}
	if reads, writes, _ := gets(g); reads != 15 || writes != 0 {
		t.Errorf("%d reads, %d writes: want 13 public + 2 samples = 15, none written", reads, writes)
	}
	if sv.Counts.Unavailable != 448 {
		t.Errorf("unavailable = %d, want 448", sv.Counts.Unavailable)
	}
}

func TestSurveyReadsEveryPrivateRepoOfAnOwnerWhoseSampleShowsThePlanHasTheFeature(t *testing.T) {
	g := newGhub()
	paid := map[string]string{"secret_scanning": "enabled", "secret_scanning_push_protection": "enabled"}
	g.add("org/a", hrepo{sa: paid})
	g.add("org/b", hrepo{sa: map[string]string{"secret_scanning": "enabled", "secret_scanning_push_protection": "disabled"}})
	g.add("org/c", hrepo{null: true}) // a repo of a paid org that GHAS was never enabled on
	srcs := []core.Source{repoSrc("org", "a", core.Private), repoSrc("org", "b", core.Private), repoSrc("org", "c", core.Private)}
	fx := newFixture(t, g, nil)
	sv, err := fx.s.Survey(bg(), srcs)
	if err != nil {
		t.Fatal(err)
	}
	if reads, _, _ := gets(g); reads != 3 {
		t.Errorf("%d reads: once the plan has the feature the private repos can differ, so each is read", reads)
	}
	if sv.Classes["github.com/org/a"] != Protected || sv.Classes["github.com/org/b"] != Gap || sv.Classes["github.com/org/c"] != Unavailable {
		t.Errorf("classes = %v", sv.Classes)
	}
	if len(sv.Inferred) != 0 {
		t.Errorf("inferred = %v, want none", sv.Inferred)
	}
}

// A sample that could not be read says nothing about the plan, so the repos behind it are
// unreadable and not "GitHub cannot protect them".
func TestSurveyDoesNotCallARepoUnavailableBecauseItsSampleFailed(t *testing.T) {
	g := newGhub()
	g.add("o/p0", hrepo{missing: true})
	g.add("o/p1", hrepo{null: true})
	fx := newFixture(t, g, nil)
	sv, _ := fx.s.Survey(bg(), []core.Source{repoSrc("o", "p0", core.Private), repoSrc("o", "p1", core.Private)})
	if sv.Classes["github.com/o/p0"] != Unreadable || sv.Classes["github.com/o/p1"] != Unreadable {
		t.Errorf("classes = %v", sv.Classes)
	}
	if sv.Counts.Unavailable != 0 || sv.Counts.Unreadable != 2 {
		t.Errorf("counts = %+v", sv.Counts)
	}
}

func TestSurveySamplesAnArchivedRepoOnlyAsALastResort(t *testing.T) {
	g := newGhub()
	g.add("o/old", hrepo{null: true})
	g.add("o/live", hrepo{null: true})
	old := repoSrc("o", "old", core.Private)
	old.Archived = true
	fx := newFixture(t, g, nil)
	if _, err := fx.s.Survey(bg(), []core.Source{old, repoSrc("o", "live", core.Private)}); err != nil {
		t.Fatal(err)
	}
	saved := fx.readSaved(t)
	if got := saved.Samples["o"].Repo; got != "github.com/o/live" {
		t.Errorf("sample = %q, want the repo that is not archived", got)
	}
}

func TestSurveyIgnoresWikisAndGistsAndReadsUnknownVisibilityLikeAPublicRepo(t *testing.T) {
	g := newGhub()
	g.add("o/r", hrepo{sa: on()})
	fx := newFixture(t, g, nil)
	srcs := []core.Source{
		repoSrc("o", "r", core.Unknown),
		{ID: "github.com/o/r.wiki", Kind: "wiki", Owner: "o", Name: "r.wiki", Visibility: core.Public},
		{ID: "gist.github.com/o/abc", Kind: "gist", Owner: "o", Name: "abc", Visibility: core.SecretGist},
	}
	sv, err := fx.s.Survey(bg(), srcs)
	if err != nil {
		t.Fatal(err)
	}
	if sv.Counts.Repos != 1 || sv.Classes["github.com/o/r"] != Protected || len(g.log) != 1 {
		t.Errorf("counts %+v classes %v requests %q", sv.Counts, sv.Classes, g.log)
	}
}

func TestSurveyReportsAFeatureThatWentFromOnToOff(t *testing.T) {
	for name, skew := range skews {
		t.Run(name, func(t *testing.T) {
			g := newGhub()
			g.add("o/a", hrepo{sa: on()})
			g.add("o/b", hrepo{sa: on()})
			g.add("o/c", hrepo{sa: off()}) // off from the start is a gap, not a drift
			fx := newFixtureSkew(t, g, skew, nil)
			srcs := []core.Source{repoSrc("o", "a", core.Public), repoSrc("o", "b", core.Public), repoSrc("o", "c", core.Public)}

			first, err := fx.s.Survey(bg(), srcs)
			if err != nil || len(first.Drift) != 0 {
				t.Fatalf("first survey: %v drift %v", err, first.Drift)
			}
			// Someone with an admin token turns scanning off on one repo and the repo b goes dark.
			g.repos["o/a"].sa["secret_scanning"] = "disabled"
			g.repos["o/b"].hidden = true
			fx.ck.Advance(10 * time.Minute)
			second, err := fx.s.Survey(bg(), srcs)
			if err != nil {
				t.Fatal(err)
			}
			if len(second.Drift) != 1 || second.Drift[0] != (Drift{Source: "github.com/o/a", Feature: SecretScanning, Was: Enabled, Now: Disabled}) {
				t.Errorf("drift = %+v, want secret scanning on o/a, and nothing for o/b which was not seen", second.Drift)
			}
			if second.Classes["github.com/o/b"] != Unreadable {
				t.Errorf("b = %s", second.Classes["github.com/o/b"])
			}
			// The drift is reported once: the next survey compares with the state this one left.
			third, _ := fx.s.Survey(bg(), srcs)
			if len(third.Drift) != 0 {
				t.Errorf("the same drift was reported twice: %+v", third.Drift)
			}
		})
	}
}

func TestSurveyStateHoldsWhatWasReadAndNoMoreAndSurvivesARestart(t *testing.T) {
	g := newGhub()
	var srcs []core.Source
	srcs = append(srcs, g.ownerRepos("o", 2, core.Public)...)
	srcs = append(srcs, g.ownerRepos("o", 4, core.Private)...)
	fx := newFixture(t, g, nil)
	if _, err := fx.s.Survey(bg(), srcs); err != nil {
		t.Fatal(err)
	}
	st := fx.readSaved(t)
	if len(st.Repos) != 3 {
		t.Errorf("repos in state = %v: the two public ones and the sample, not the 3 repos nobody asked GitHub about", keysOf(st.Repos))
	}
	if s := st.Samples["o"]; s.Class != Unavailable || s.Checked == "" {
		t.Errorf("sample = %+v", s)
	}
	// A new Settings over the same file sees it.
	again := newFixtureSkew(t, g, 0, func(c *Config) { c.StatePath = fx.state })
	got, err := again.s.Saved()
	if err != nil || len(got.Repos) != 3 {
		t.Errorf("restart: %v %v", err, got)
	}
}

func TestSurveyOfACorruptStateFileSaysSoAndStartsAgain(t *testing.T) {
	g := newGhub()
	g.add("o/r", hrepo{sa: on()})
	fx := newFixture(t, g, nil)
	if err := os.MkdirAll(filepath.Dir(fx.state), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fx.state, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	sv, err := fx.s.Survey(bg(), []core.Source{repoSrc("o", "r", core.Public)})
	if err == nil || !strings.Contains(err.Error(), "unreadable") {
		t.Fatalf("err = %v, want the state file named as unreadable", err)
	}
	if sv.Classes["github.com/o/r"] != Protected {
		t.Errorf("the survey itself was lost with its state: %+v", sv)
	}
	if st := fx.readSaved(t); len(st.Repos) != 1 {
		t.Errorf("state was not repaired: %+v", st)
	}
}

func TestClassOfCoversEveryShapeOfAnswer(t *testing.T) {
	src := func(v core.Visibility) core.Source { return core.Source{ID: "github.com/o/r", Visibility: v} }
	both := map[Feature]State{SecretScanning: Enabled, PushProtection: Enabled}
	for _, tc := range []struct {
		name string
		a    AuditResult
		want Class
	}{
		{"public, both on", AuditResult{Source: src(core.Public), Reported: true, State: both}, Protected},
		{"public, push protection off", AuditResult{Source: src(core.Public), Reported: true, State: map[Feature]State{SecretScanning: Enabled, PushProtection: Disabled}}, Gap},
		{"public, everything off", AuditResult{Source: src(core.Public), Reported: true, State: map[Feature]State{SecretScanning: Disabled, PushProtection: Disabled}}, Gap},
		{"public, GitHub shows nothing", AuditResult{Source: src(core.Public)}, Unreadable},
		{"public, block present but empty", AuditResult{Source: src(core.Public), Reported: true, State: map[Feature]State{}}, Unreadable},
		{"public, the read failed", AuditResult{Source: src(core.Public), Err: os.ErrNotExist}, Unreadable},
		{"private on a free plan", AuditResult{Source: src(core.Private)}, Unavailable},
		{"private, empty block", AuditResult{Source: src(core.Private), Reported: true, State: map[Feature]State{}}, Unavailable},
		{"private, the read failed", AuditResult{Source: src(core.Private), Err: os.ErrNotExist}, Unreadable},
		{"private on a plan that has it", AuditResult{Source: src(core.Private), Reported: true, State: both}, Protected},
	} {
		if got := ClassOf(tc.a); got != tc.want {
			t.Errorf("%s: %s, want %s", tc.name, got, tc.want)
		}
		if got := tc.a.Protected(); got != (tc.want == Protected) {
			t.Errorf("%s: Protected() = %v", tc.name, got)
		}
	}
}

func TestPlanSupportIsTheHardCodedMatrix(t *testing.T) {
	for _, vis := range []core.Visibility{core.Private, core.Unknown, core.SecretGist, core.Local} {
		for _, f := range Features {
			if got := PlanSupport(vis, f); got != Unsupported {
				t.Errorf("%s %s = %v: nothing is written to a repo that is not public", vis, f, got)
			}
		}
	}
	for f, want := range map[Feature]Support{SecretScanning: Supported, PushProtection: Supported, NonProviderPatterns: Probe, ValidityChecks: Probe} {
		if got := PlanSupport(core.Public, f); got != want {
			t.Errorf("public %s = %v, want %v", f, got, want)
		}
	}
}
