//go:build live

// Live survey of the real accounts. Read-only: Survey issues GETs and nothing else, and the state
// file it writes is in a temp directory. It prints counts and no names.
//
//	KEYGUARD_LIVE_ACCOUNTS=alt-builds go test -tags live -run TestLiveSurvey -v ./internal/ghsettings
package ghsettings

import (
	"context"
	"crypto/sha256"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"keyguard/internal/core"
	"keyguard/internal/fp"
	"keyguard/internal/inventory"
	"keyguard/internal/inventory/ghcli"
)

func TestLiveSurvey(t *testing.T) {
	before := func() [32]byte {
		out, err := exec.Command("gh", "auth", "token").Output()
		if err != nil {
			t.Fatalf("gh auth token: %v", err)
		}
		return sha256.Sum256(out)
	}
	active := before()

	cfg := inventory.DefaultConfig(t.TempDir())
	cfg.NoDefaultBranch = true
	// the accounts and orgs a first install writes into config.json
	out, err := exec.Command("gh", ghcli.AuthStatusArgs...).Output()
	if cfg.Accounts = ghcli.Logins(out); err != nil || len(cfg.Accounts) == 0 {
		t.Fatalf("gh auth status: no account (%v)", err)
	}
	out, err = exec.Command("gh", ghcli.OrgsArgs...).Output()
	if err != nil {
		t.Fatalf("gh api user/memberships/orgs: %v", err)
	}
	for _, o := range ghcli.Logins(out) {
		cfg.Orgs = append(cfg.Orgs, inventory.Org{Login: o, Via: cfg.Accounts[0]})
	}
	if only := os.Getenv("KEYGUARD_LIVE_ACCOUNTS"); only != "" {
		accounts := strings.Split(only, ",")
		cfg.Accounts = slices.DeleteFunc(cfg.Accounts, func(a string) bool { return !slices.Contains(accounts, a) })
		cfg.Orgs = slices.DeleteFunc(cfg.Orgs, func(o inventory.Org) bool { return !slices.Contains(accounts, o.Via) })
	}
	inv, err := inventory.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 110*time.Second)
	defer cancel()
	all, err := inv.List(ctx)
	if err != nil {
		t.Logf("List: %v", err)
	}
	var repos []core.Source
	for _, s := range all {
		if s.Kind == "repo" {
			repos = append(repos, s)
		}
	}

	state := filepath.Join(t.TempDir(), "ghsettings.json")
	s, err := New(Config{FP: fp.NewEphemeral(), StatePath: state})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	sv, err := s.Survey(ctx, repos)
	took := time.Since(start)
	load, _ := exec.Command("sysctl", "-n", "vm.loadavg").Output()
	t.Logf("Survey of %d repos: %s wall, %d GETs (the rest classified from a sample), err=%v, load average %s",
		sv.Counts.Repos, took.Round(time.Millisecond), len(sv.Results), err, strings.TrimSpace(string(load)))
	t.Logf("counts: public=%d private=%d protected=%d gap=%d unreadable=%d unavailable=%d inferred=%d",
		sv.Counts.Public, sv.Counts.Private, sv.Counts.Protected, sv.Counts.Gap, sv.Counts.Unreadable, sv.Counts.Unavailable, len(sv.Inferred))
	t.Logf("headline: %s", sv.Headline())

	// What GitHub reports for the public repos, by feature: how many are on, off, or not said.
	for _, f := range Features {
		var on, off, unsaid int
		for _, a := range sv.Results {
			if a.Err != nil || a.Source.Visibility != core.Public {
				continue
			}
			switch a.State[f] {
			case Enabled:
				on++
			case Disabled:
				off++
			default:
				unsaid++
			}
		}
		t.Logf("public repos, %s: on=%d off=%d not reported=%d", f, on, off, unsaid)
	}
	// And what a private repo reads like on this plan: the GET behind P0-18.
	n := 0
	for _, a := range sv.Results {
		if a.Source.Visibility == core.Private {
			n++
			t.Logf("private sample %d: reported security_and_analysis=%v, class=%s, err=%v", n, a.Reported, ClassOf(a), a.Err)
		}
	}
	if sv.Counts.Repos > 0 && len(sv.Results) >= sv.Counts.Repos && sv.Counts.Private > 5 {
		t.Errorf("%d reads for %d repos: the private repos were not classified from a sample", len(sv.Results), sv.Counts.Repos)
	}
	if before() != active {
		t.Fatal("the active gh account changed during the run")
	}
}
