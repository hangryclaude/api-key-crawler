package ghsettings

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"keyguard/internal/core"
	"keyguard/internal/fp"
)

func bg() context.Context { return context.Background() }

func TestAuditReadsEachReposSecurityAndAnalysis(t *testing.T) {
	g := newGhub()
	g.add("o/full", hrepo{sa: map[string]string{
		"secret_scanning": "enabled", "secret_scanning_push_protection": "enabled",
		"secret_scanning_non_provider_patterns": "disabled", "secret_scanning_validity_checks": "enabled",
	}})
	g.add("o/partial", hrepo{sa: map[string]string{"secret_scanning": "enabled", "secret_scanning_push_protection": "disabled"}})
	g.add("o/blind", hrepo{hidden: true})
	g.add("o/gone", hrepo{missing: true})
	fx := newFixture(t, g, nil)

	srcs := []core.Source{
		repoSrc("o", "full", core.Public), repoSrc("o", "partial", core.Public), repoSrc("o", "blind", core.Private),
		repoSrc("o", "gone", core.Public), {ID: "github.com/o/full.wiki", Kind: "wiki", Owner: "o", Name: "full.wiki"},
		{ID: "github.com/o/ev il", Kind: "repo", Owner: "o", Name: "ev il"},
	}
	got := fx.s.Audit(bg(), srcs)
	if len(got) != len(srcs) {
		t.Fatalf("%d results for %d sources", len(got), len(srcs))
	}
	for i, r := range got {
		if r.Source.ID != srcs[i].ID {
			t.Errorf("result %d is for %s, want input order (%s)", i, r.Source.ID, srcs[i].ID)
		}
	}
	if r := got[0]; r.Err != nil || !r.Reported || r.State[SecretScanning] != Enabled || r.State[PushProtection] != Enabled ||
		r.State[NonProviderPatterns] != Disabled || r.State[ValidityChecks] != Enabled {
		t.Errorf("full = %+v", r)
	}
	if r := got[1]; r.State[SecretScanning] != Enabled || r.State[PushProtection] != Disabled || r.State[ValidityChecks] != Unreported {
		t.Errorf("partial = %+v", r)
	}
	if r := got[2]; r.Err != nil || r.Reported {
		t.Errorf("blind (no admin): err=%v reported=%v; unreported is not an error", r.Err, r.Reported)
	}
	if r := got[3]; r.Err == nil || !strings.Contains(r.Err.Error(), "404") {
		t.Errorf("missing repo: %v", r.Err)
	}
	if r := got[4]; !errors.Is(r.Err, ErrNotRepo) {
		t.Errorf("wiki: %v, want ErrNotRepo", r.Err)
	}
	if r := got[5]; r.Err == nil {
		t.Error("a repo name that would escape the URL path was queried")
	}
	for _, l := range g.log {
		if strings.Contains(l, "ev il") {
			t.Errorf("request made for the unusable name: %s", l)
		}
	}
}

func TestApplyDoesNotTryDependentFeaturesWhenSecretScanningIsRefused(t *testing.T) {
	g := newGhub()
	g.add("o/r", hrepo{
		sa:     map[string]string{"secret_scanning": "disabled"},
		refuse: map[string]string{"secret_scanning": "Secret scanning is not available for this repository."},
	})
	fx := newFixture(t, g, nil)
	res := fx.s.Apply(bg(), []core.Source{repoSrc("o", "r", core.Public)})
	if got := g.patches(); len(got) != 1 {
		t.Fatalf("PATCHes = %q, want only the refused first one", got)
	}
	f := res[0].Fields
	if f[0].Status != 422 || !strings.Contains(f[0].Message, "not available") {
		t.Errorf("first = %+v", f[0])
	}
	for _, x := range f[1:] {
		if x.Sent || x.Message != reasonNeedsScan {
			t.Errorf("dependent %s = %+v", x.Feature, x)
		}
	}
}

func TestApplyNeverTouchesPrivateReposOrWikisOrUnusableNames(t *testing.T) {
	g := newGhub()
	g.add("o/priv", hrepo{sa: map[string]string{"secret_scanning": "disabled"}})
	fx := newFixture(t, g, nil)
	res := fx.s.Apply(bg(), []core.Source{
		repoSrc("o", "priv", core.Private),
		repoSrc("o", "priv", core.SecretGist), // visibility that is not public in any form
		repoSrc("o", "priv", core.Unknown),
		{ID: "github.com/o/priv.wiki", Kind: "wiki", Owner: "o", Name: "priv.wiki", Visibility: core.Public},
		repoSrc("o", "x/../y", core.Public),
	})
	for i, r := range res {
		if r.Err == nil || len(r.Fields) != 0 {
			t.Errorf("result %d = %+v: must be refused", i, r)
		}
	}
	if !strings.Contains(res[0].Err.Error(), "can cost money") {
		t.Errorf("reason not given: %v", res[0].Err)
	}
	if len(g.log) != 0 {
		t.Errorf("GitHub was contacted: %q", g.log)
	}
}

func TestApplyWritesAreSerial(t *testing.T) {
	g := newGhub()
	var srcs []core.Source
	for i := range 5 {
		name := fmt.Sprintf("r%d", i)
		g.add("o/"+name, hrepo{sa: map[string]string{"secret_scanning": "disabled", "secret_scanning_push_protection": "disabled"}})
		srcs = append(srcs, repoSrc("o", name, core.Public))
	}
	fx := newFixture(t, g, func(c *Config) { c.Workers = 8 })
	for _, r := range fx.s.Apply(bg(), srcs) {
		if r.Err != nil || !r.Fields[0].Done() || !r.Fields[1].Done() {
			t.Fatalf("%+v", r)
		}
	}
	if m := g.maxPatch.Load(); m != 1 {
		t.Errorf("%d PATCHes were in flight at once; GitHub treats concurrent writes as abuse", m)
	}
}

func TestApplyStopsWhenTheContextEnds(t *testing.T) {
	g := newGhub()
	g.add("o/r", hrepo{sa: map[string]string{"secret_scanning": "disabled"}})
	fx := newFixture(t, g, nil)
	ctx, cancel := context.WithCancel(bg())
	cancel()
	res := fx.s.Apply(ctx, []core.Source{repoSrc("o", "r", core.Public)})
	if !errors.Is(res[0].Err, context.Canceled) {
		t.Fatalf("err = %v", res[0].Err)
	}
	if len(g.patches()) != 0 {
		t.Error("a cancelled Apply still wrote")
	}
}

func TestSettingsCalleeUsesTheSourcesOwnAccountToken(t *testing.T) {
	g := newGhub()
	g.add("o/r", hrepo{sa: map[string]string{"secret_scanning": "enabled"}})
	fx := newFixture(t, g, nil)
	src := repoSrc("o", "r", core.Public)
	src.Account = "alt-builds"
	fx.s.Audit(bg(), []core.Source{src})
	fx.s.Apply(bg(), []core.Source{src})
	if _, err := fx.s.Alerts(bg(), src); err != nil {
		t.Fatal(err)
	}
	calls := fx.f.Calls()
	if len(calls) == 0 {
		t.Fatal("no calls")
	}
	for _, c := range calls {
		if c.Acct != "alt-builds" {
			t.Errorf("%s %s ran as %s", c.Method, c.Path, c.Acct)
		}
	}
	for _, cmd := range fx.f.Commands() {
		if cmd[0] == "auth" && cmd[1] != "token" {
			t.Errorf("gh %v", cmd)
		}
	}
}

func TestNewRequiresAFingerprinter(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Error("no fingerprinter accepted: alerts would be stored unkeyed")
	}
	if _, err := New(Config{FP: fp.NewEphemeral(), PerPage: 101}); err == nil {
		t.Error("per-page above GitHub's maximum accepted")
	}
	if _, err := New(Config{FP: fp.NewEphemeral(), Workers: -1}); err == nil {
		t.Error("negative workers accepted")
	}
}
