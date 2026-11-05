//go:build live

// Live smoke against the real accounts. Read-only, prints counts only, and is kept out of the
// default test run by its build tag: go test -tags live -run TestLive -v ./internal/inventory
package inventory

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"keyguard/internal/core"
	"keyguard/internal/inventory/ghcli"
)

// activeToken fingerprints the token of whichever gh account is active. It is compared before
// and after, never printed: if the active account flipped, the digest would change.
func activeToken(t *testing.T) [32]byte {
	t.Helper()
	out, err := exec.Command("gh", "auth", "token").Output()
	if err != nil {
		t.Fatalf("gh auth token: %v", err)
	}
	return sha256.Sum256(out)
}

// liveAccounts are what a first install writes into config.json: the accounts gh is logged
// in to, and the orgs of the active one.
func liveAccounts(t *testing.T) ([]string, []Org) {
	t.Helper()
	out, err := exec.Command("gh", ghcli.AuthStatusArgs...).Output()
	accts := ghcli.Logins(out)
	if err != nil || len(accts) == 0 {
		t.Fatalf("gh auth status: no account (%v)", err)
	}
	out, err = exec.Command("gh", ghcli.OrgsArgs...).Output()
	if err != nil {
		t.Fatalf("gh api user/memberships/orgs: %v", err)
	}
	var orgs []Org
	for _, o := range ghcli.Logins(out) {
		orgs = append(orgs, Org{Login: o, Via: accts[0]})
	}
	return accts, orgs
}

func TestLiveListAndIdlePoll(t *testing.T) {
	active := activeToken(t)
	cfg := DefaultConfig(t.TempDir())
	cfg.Accounts, cfg.Orgs = liveAccounts(t)
	inv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()

	start := time.Now()
	all, err := inv.List(ctx)
	listTime := time.Since(start)
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	perOwner := map[string]int{}
	var public, wikis, gistsSecret, gistsPublic, unknown, forks, archived int
	for _, s := range all {
		switch s.Kind {
		case "repo":
			perOwner[s.Owner]++
			forks += b2i(s.Fork)
			archived += b2i(s.Archived)
		case "wiki":
			wikis++
		case "gist":
			if s.Visibility == core.SecretGist {
				gistsSecret++
			} else {
				gistsPublic++
			}
		}
		if s.Kind == "repo" && s.Visibility == core.Public {
			public++
		}
		if s.Visibility == core.Unknown {
			unknown++
		}
	}
	t.Logf("List: %d sources in %s", len(all), listTime.Round(time.Millisecond))
	t.Logf("repos per owner: hangryclaude=%d alt-builds=%d Loony-Labs-Video=%d acme-apps=%d",
		perOwner["hangryclaude"], perOwner["alt-builds"], perOwner["Loony-Labs-Video"], perOwner["acme-apps"])
	t.Logf("public repos=%d wikis=%d secret gists=%d public gists=%d forks=%d archived=%d unknown-visibility=%d",
		public, wikis, gistsSecret, gistsPublic, forks, archived, unknown)

	if perOwner["hangryclaude"] < 400 || perOwner["alt-builds"] < 20 || perOwner["Loony-Labs-Video"]+perOwner["acme-apps"] != 6 {
		t.Errorf("repo counts are far from the expected ~439 + 22 + 6")
	}
	if gistsSecret+gistsPublic != 2 {
		t.Errorf("gists = %d, expected 2", gistsSecret+gistsPublic)
	}
	if unknown != 0 {
		t.Errorf("%d sources have unknown visibility", unknown)
	}

	// The same listing without the per-repo default-branch lookup.
	fastCfg := cfg
	fastCfg.NoDefaultBranch = true
	fastInv, err := New(fastCfg)
	if err != nil {
		t.Fatal(err)
	}
	start = time.Now()
	fast, err := fastInv.List(ctx)
	t.Logf("List without default branches: %d sources in %s (err=%v)", len(fast), time.Since(start).Round(time.Millisecond), err)
	if len(fast) != len(all) {
		t.Errorf("the fast listing disagrees with the full one: %d vs %d", len(fast), len(all))
	}

	// The idle poll against the list just taken.
	start = time.Now()
	changed, events, err := inv.Changed(ctx, Index(all))
	pollTime := time.Since(start)
	var rl *ghcli.RateLimitError
	switch {
	case err == nil:
	case errors.As(err, &rl):
		t.Logf("events were rate limited (quota spent by other sessions): %v", rl)
	default:
		t.Fatalf("Changed: %v", err)
	}
	t.Logf("idle Changed: %d changed, %d events in %s", len(changed), len(events), pollTime.Round(time.Millisecond))
	if len(changed) > 5 {
		t.Errorf("%d sources changed in the seconds between List and Changed", len(changed))
	}

	// A second poll finds the saved ETags and should be cheaper still.
	if err == nil {
		start = time.Now()
		_, _, err := inv.Changed(ctx, Index(all))
		t.Logf("second idle Changed (304s): %s err=%v", time.Since(start).Round(time.Millisecond), err)
	}

	if activeToken(t) != active {
		t.Fatal("the active gh account changed during the run")
	}
	if strings.Contains(strings.Join(ids(all), "\n"), "\x00") {
		t.Fatal("garbage in source ids")
	}
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// liveConfig is the CLI's configuration over a throwaway state directory. KEYGUARD_LIVE_ACCOUNTS
// (comma separated) narrows it to some accounts, and to the orgs those accounts read, for a day
// when another account's quota is spent.
func liveConfig(t *testing.T) Config {
	t.Helper()
	cfg := DefaultConfig(t.TempDir())
	cfg.NoDefaultBranch = true // the CLI's setting: nothing in the scan path reads the default branch
	cfg.Accounts, cfg.Orgs = liveAccounts(t)
	only := strings.Split(os.Getenv("KEYGUARD_LIVE_ACCOUNTS"), ",")
	if len(only) == 1 && only[0] == "" {
		return cfg
	}
	cfg.Accounts = slices.DeleteFunc(cfg.Accounts, func(a string) bool { return !slices.Contains(only, a) })
	cfg.Orgs = slices.DeleteFunc(cfg.Orgs, func(o Org) bool { return !slices.Contains(only, o.Via) })
	return cfg
}

// TestLiveCheapPoll is the live check of the cheap poll: a listing, a cold poll, a second poll
// that is all conditional, and the REST lists against the GraphQL listing. Read-only; it prints
// counts, times and the load they were taken under, and no names.
//
//	KEYGUARD_LIVE_ACCOUNTS=alt-builds go test -tags live -run TestLiveCheapPoll -v ./internal/inventory
func TestLiveCheapPoll(t *testing.T) {
	active := activeToken(t)
	cfg := liveConfig(t)
	inv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 110*time.Second)
	defer cancel()
	load := func() string {
		b, _ := exec.Command("sysctl", "-n", "vm.loadavg").Output()
		return strings.TrimSpace(string(b))
	}
	t.Logf("accounts=%v orgs=%d load average %s", cfg.Accounts, len(cfg.Orgs), load())

	if skew, err := inv.Skew(ctx); err == nil {
		t.Logf("clock: this Mac is %s ahead of GitHub (Date header)", skew.Round(time.Second))
	} else {
		t.Logf("clock: %v", err)
	}

	start := time.Now()
	all, err := inv.List(ctx)
	t.Logf("List: %d sources in %s (err=%v)", len(all), time.Since(start).Round(time.Millisecond), err)
	sum := Summarize(all)
	t.Logf("repos=%d public=%d private=%d unknown=%d exposed wikis=%d secret gists=%d public gists=%d scan set=%d",
		sum.Repos, sum.PublicRepos, sum.PrivateRepos, sum.UnknownRepos, sum.Wikis, sum.SecretGists, sum.PublicGists, sum.Scan)
	t.Logf("repos by owner %v; public by owner %v", sum.ReposByOwner, sum.PublicByOwner)
	prev := Index(all)

	for i, name := range []string{"pass 1 (no ETags yet)", "pass 2 (conditional)"} {
		start := time.Now()
		p, err := inv.Poll(ctx, prev)
		took := time.Since(start)
		st := p.Stats
		t.Logf("%s: %s wall; %d REST requests, %d answered 304, %d GraphQL; full poll ran=%v; changed=%d events=%d flips=%d activity=%d; interval=%s; err=%v",
			name, took.Round(time.Millisecond), st.Requests, st.NotModified, st.GraphQL, st.Refreshed, len(p.Changed), len(p.Events), len(p.Flips), len(p.Activity), p.Interval, err)
		t.Logf("%s: events usable per account %v; cursors %v; GitHub now %s", name, p.EventsUsable, p.Cursor, p.Now.Format(time.RFC3339))
		if i == 1 && err == nil && st.NotModified != st.Requests {
			t.Errorf("pass 2: %d of %d REST requests were not 304", st.Requests-st.NotModified, st.Requests)
		}
		if i == 1 && st.Refreshed {
			t.Error("pass 2 ran the full poll")
		}
	}

	// The REST lists the detector reads against the GraphQL listing: do they say the same thing
	// about every exposed source? Counts only.
	byID := Index(all)
	var checked, missing, extra, vis, pushed, fork, archived, size int
	for _, g := range inv.groups() {
		w := inv.watchGroup(ctx, g, nil)
		if len(w.errs) > 0 {
			t.Errorf("watch %s: %v", g.via, w.errs)
		}
		seen := map[string]bool{}
		for _, s := range w.view {
			seen[s.ID] = true
			g, ok := byID[s.ID]
			if !ok {
				extra++
				continue
			}
			checked++
			vis += b2i(s.Visibility != g.Visibility)
			pushed += b2i(newer(s.PushedAt, g.PushedAt) || newer(g.PushedAt, s.PushedAt))
			fork += b2i(s.Fork != g.Fork)
			archived += b2i(s.Archived != g.Archived)
			size += b2i(s.SizeKB != g.SizeKB)
		}
		for _, s := range ScanSet(all) {
			if (s.Account == g.via) && !seen[s.ID] {
				missing++
			}
		}
	}
	t.Logf("REST lists vs GraphQL listing: %d exposed sources compared; %d in the lists but not the listing, %d in the listing but not the lists; differing visibility=%d pushed=%d fork=%d archived=%d size=%d",
		checked, extra, missing, vis, pushed, fork, archived, size)

	if activeToken(t) != active {
		t.Fatal("the active gh account changed during the run")
	}
}
