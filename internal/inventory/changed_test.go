package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"keyguard/internal/core"
	"keyguard/internal/inventory/ghcli"
	"keyguard/internal/inventory/ghcli/ghclitest"
)

// baseline is the "last full inventory" a poll compares against.
func baseline(t *testing.T, fx *fixture) map[string]core.Source {
	t.Helper()
	all, err := fx.inv.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return Index(all)
}

func poll(t *testing.T, fx *fixture, prev map[string]core.Source) ([]core.Source, []core.Event) {
	t.Helper()
	ch, ev, err := fx.inv.Changed(context.Background(), prev)
	if err != nil {
		t.Fatalf("Changed: %v", err)
	}
	return ch, ev
}

// queryOf returns the GraphQL text of every call as one account, in order.
func queryOf(t *testing.T, f *ghclitest.Fake, acct string) []string {
	t.Helper()
	var out []string
	for _, c := range f.Calls() {
		if c.Path != "graphql" || c.Acct != acct {
			continue
		}
		var b struct {
			Query string `json:"query"`
		}
		if err := json.Unmarshal(c.Body, &b); err != nil {
			t.Fatal(err)
		}
		out = append(out, b.Query)
	}
	return out
}

// noBranchSince fails if any GraphQL call after the first n asked for defaultBranchRef.
func noBranchSince(t *testing.T, f *ghclitest.Fake, n int) {
	t.Helper()
	for _, c := range f.Calls()[n:] {
		if strings.Contains(string(c.Body), "defaultBranchRef") {
			t.Errorf("a poll-time request selects defaultBranchRef: %.120s", c.Body)
		}
	}
}

// pollsOf is queryOf narrowed to the poll operation.
func pollsOf(t *testing.T, f *ghclitest.Fake, acct string) []string {
	t.Helper()
	var out []string
	for _, q := range queryOf(t, f, acct) {
		if strings.HasPrefix(q, "query Poll(") {
			out = append(out, q)
		}
	}
	return out
}

func TestChangedIdlePollIsOneRequestPerTokenPlusEvents(t *testing.T) {
	w := standardWorld()
	// Both feeds work (they hold events, if old ones). An empty feed beside recent pushes would
	// be read as broken and cost a GraphQL fallback request each: see the P0-21 tests.
	w.feeds["hangryclaude"] = feed(2, 1, "WatchEvent", "someone/else", "2026-09-01")
	w.feeds["alt-builds"] = feed(2, 1, "WatchEvent", "someone/else", "2026-09-01")
	fx := newFixture(t, w, nil)
	prev := baseline(t, fx)

	// First poll has no ETag yet, so it pays for the feed once; the second is the idle case.
	poll(t, fx, prev)
	w.resetOps()
	before := len(fx.f.Calls())
	changed, events := poll(t, fx, prev)
	if len(changed) != 0 || len(events) != 0 {
		t.Fatalf("idle poll reported work: %v %v", ids(changed), events)
	}
	calls := fx.f.Calls()[before:]
	if len(calls) != 4 {
		t.Fatalf("idle poll made %d API calls, want 2 GraphQL + 2 events: %+v", len(calls), calls)
	}
	if n := w.opCount("Poll"); n != 2 || len(w.ops) != 2 {
		t.Fatalf("GraphQL operations = %v", w.ops)
	}
	hq := pollsOf(t, fx.f, "hangryclaude")
	last := hq[len(hq)-1]
	if strings.Contains(strings.Join(hq, "\n")+strings.Join(pollsOf(t, fx.f, "alt-builds"), "\n"), "defaultBranchRef") {
		t.Error("the idle poll asks for defaultBranchRef, a git lookup per repo that adds seconds")
	}
	if !strings.Contains(last, "first:$n") {
		t.Errorf("poll page size is not a variable: %s", last)
	}
	for _, org := range []string{`organization(login:"acme-apps")`, `organization(login:"Loony-Labs-Video")`} {
		if !strings.Contains(last, org) {
			t.Errorf("hangryclaude's poll does not read %s: %s", org, last)
		}
	}
	aq := pollsOf(t, fx.f, "alt-builds")
	if strings.Contains(aq[len(aq)-1], "organization(") {
		t.Errorf("alt-builds' poll reads orgs it has no token for")
	}
	for _, acct := range []string{"hangryclaude", "alt-builds"} {
		p := w.polls[acct]
		if len(p) != 2 || p[0] != "" || p[1] == "" {
			t.Errorf("%s feed If-None-Match history = %q: second poll must send the first one's ETag", acct, p)
		}
	}
	fx.assertNoTokenAnywhere()
}

func TestChangedPushFindsOnlyThatRepoAndStopsAtTheFirstUnchangedPage(t *testing.T) {
	w := standardWorld()
	fx := newFixture(t, w, func(c *Config) { c.PageSize = 2 })
	prev := baseline(t, fx)
	w.find("hangryclaude", "bravo").pushed = "2026-11-03T11:00:00Z"
	w.resetOps()

	changed, _ := poll(t, fx, prev)
	if got := ids(changed); !slices.Equal(got, []string{"github.com/hangryclaude/bravo"}) {
		t.Fatalf("changed = %v", got)
	}
	if changed[0].PushedAt != "2026-11-03T11:00:00Z" {
		t.Errorf("changed source must carry the new push time: %+v", changed[0])
	}
	if changed[0].DefaultBranch != "main" {
		t.Errorf("the poll must carry the default branch List recorded, got %q", changed[0].DefaultBranch)
	}
	if n := w.opCount("Repos"); n != 0 {
		t.Errorf("walked %d extra pages for one push", n)
	}
}

func TestChangedWalksOnWhileTheLastRepoOfAPageIsStillChanged(t *testing.T) {
	w := standardWorld()
	fx := newFixture(t, w, func(c *Config) { c.PageSize = 2 })
	prev := baseline(t, fx)
	w.find("hangryclaude", "bravo").pushed = "2026-11-03T11:00:00Z"
	w.find("hangryclaude", "charlie").pushed = "2026-11-03T11:01:00Z"
	w.find("hangryclaude", "delta").pushed = "2026-11-03T11:02:00Z"
	w.resetOps()
	calls := len(fx.f.Calls())

	changed, _ := poll(t, fx, prev)
	noBranchSince(t, fx.f, calls)
	want := []string{"github.com/hangryclaude/bravo", "github.com/hangryclaude/charlie", "github.com/hangryclaude/delta"}
	if got := ids(changed); !slices.Equal(got, want) {
		t.Fatalf("changed = %v, want %v", got, want)
	}
	// Order is delta, charlie | bravo, alpha | echo: page 2 ends on unchanged alpha, so page 3 is never fetched.
	if n := w.opCount("Repos"); n != 1 {
		t.Errorf("follow-up pages = %d, want 1", n)
	}
}

func TestChangedNewRepoWithAnOldPushTimeStillFound(t *testing.T) {
	w := standardWorld()
	fx := newFixture(t, w, func(c *Config) { c.PageSize = 2 })
	prev := baseline(t, fx)
	// An import or a transfer keeps the original push time, so it sorts to the end.
	w.add(wrepo{owner: "hangryclaude", name: "zulu", pushed: "2025-01-01T00:00:00Z"})
	w.resetOps()
	calls := len(fx.f.Calls())

	changed, _ := poll(t, fx, prev)
	noBranchSince(t, fx.f, calls)
	if got := ids(changed); !slices.Equal(got, []string{"github.com/hangryclaude/zulu"}) {
		t.Fatalf("changed = %v", got)
	}
	if changed[0].DefaultBranch != "" {
		t.Errorf("a repo new to the poll has no recorded branch yet (List fills it): %q", changed[0].DefaultBranch)
	}
	if n := w.opCount("Repos"); n != 2 {
		t.Errorf("a grown repo count must walk the rest of the list: %d follow-up pages", n)
	}
}

func TestChangedCatchesPrivateToPublicFlipOfAnOldRepo(t *testing.T) {
	w := standardWorld()
	fx := newFixture(t, w, func(c *Config) { c.PageSize = 2 })
	prev := baseline(t, fx)
	// charlie is third in push order, off the first page, and a flip does not move pushedAt.
	w.find("hangryclaude", "charlie").vis = "PUBLIC"
	w.resetOps()

	changed, _ := poll(t, fx, prev)
	want := []string{"github.com/hangryclaude/charlie", "github.com/hangryclaude/charlie.wiki"}
	if got := ids(changed); !slices.Equal(got, want) {
		t.Fatalf("changed = %v, want repo and its wiki", got)
	}
	for _, s := range changed {
		if s.Visibility != core.Public {
			t.Errorf("%s reported as %s", s.ID, s.Visibility)
		}
	}
	if w.opCount("Repos") != 0 || w.opCount("ReposByName") != 1 {
		t.Errorf("ops = %v: want one targeted lookup and no page walk", w.ops)
	}
	q := strings.Join(queryOf(t, fx.f, "hangryclaude"), "\n")
	if !strings.Contains(q, `name:"charlie"`) || strings.Contains(q, `name:"bravo"`) || strings.Contains(q, `name:"delta"`) {
		t.Errorf("lookup should name only the flipped repo: %s", q)
	}
}

func TestChangedCatchesPublicToPrivateAndIgnoresDeletion(t *testing.T) {
	w := standardWorld()
	w.add(wrepo{owner: "hangryclaude", name: "kilo", vis: "PUBLIC", pushed: "2026-01-01T00:00:00Z"})
	w.add(wrepo{owner: "hangryclaude", name: "lima", vis: "PUBLIC", pushed: "2026-01-02T00:00:00Z"})
	fx := newFixture(t, w, func(c *Config) { c.PageSize = 2 })
	prev := baseline(t, fx)

	w.find("hangryclaude", "kilo").vis = "PRIVATE"
	w.drop("hangryclaude", "lima")
	w.resetOps()

	changed, _ := poll(t, fx, prev)
	if got := ids(changed); !slices.Equal(got, []string{"github.com/hangryclaude/kilo"}) || changed[0].Visibility != core.Private {
		t.Fatalf("changed = %+v: kilo went private, lima was deleted and is just gone", changed)
	}
	if w.opCount("ReposByName") != 1 {
		t.Errorf("ops = %v", w.ops)
	}
}

func TestChangedFlipDetectionLeavesForeignScopesAlone(t *testing.T) {
	w := standardWorld()
	fx := newFixture(t, w, nil)
	prev := baseline(t, fx)
	// An org repo flipping must be noticed through the org selection, not the account's.
	w.find("acme-apps", "india").vis = "PUBLIC"
	w.resetOps()
	changed, _ := poll(t, fx, prev)
	want := []string{"github.com/acme-apps/india", "github.com/acme-apps/india.wiki"}
	if got := ids(changed); !slices.Equal(got, want) {
		t.Fatalf("changed = %v", got)
	}
	if changed[0].Account != "hangryclaude" {
		t.Errorf("org repo read as %s", changed[0].Account)
	}
}

func TestChangedNoticesAWikiSwitchedOn(t *testing.T) {
	w := standardWorld()
	fx := newFixture(t, w, func(c *Config) { c.PageSize = 2 })
	prev := baseline(t, fx)
	// bravo is the last repo of page one; its wiki is new but the repo itself is unchanged,
	// so nothing justifies fetching page two.
	w.find("hangryclaude", "bravo").wiki = true
	w.resetOps()
	changed, _ := poll(t, fx, prev)
	if got := ids(changed); !slices.Equal(got, []string{"github.com/hangryclaude/bravo.wiki"}) {
		t.Fatalf("changed = %v: the repo itself did not change", got)
	}
	if n := w.opCount("Repos"); n != 0 {
		t.Errorf("a new wiki alone fetched %d more repo pages", n)
	}
}

func TestChangedOrgPushGoesThroughTheOwningToken(t *testing.T) {
	w := standardWorld()
	fx := newFixture(t, w, nil)
	prev := baseline(t, fx)
	w.find("acme-apps", "hotel").pushed = "2026-11-03T11:30:00Z"
	changed, _ := poll(t, fx, prev)
	if got := ids(changed); !slices.Equal(got, []string{"github.com/acme-apps/hotel"}) || changed[0].Account != "hangryclaude" {
		t.Fatalf("changed = %+v", changed)
	}
}

func TestChangedGistsNewUpdatedAndPaged(t *testing.T) {
	w := standardWorld()
	fx := newFixture(t, w, nil)
	prev := baseline(t, fx)

	w.gists["hangryclaude"][1].updated = "2026-11-03T11:00:00Z" // pushed to
	w.gists["hangryclaude"] = append(w.gists["hangryclaude"], wgist{id: "3d4e5f60718293a4b5c6d7e8f9a0b1c2", updated: "2026-11-03T11:30:00Z"})
	changed, _ := poll(t, fx, prev)
	want := []string{
		"gist.github.com/hangryclaude/1b2c3d4e5f60718293a4b5c6d7e8f9a0",
		"gist.github.com/hangryclaude/3d4e5f60718293a4b5c6d7e8f9a0b1c2",
	}
	if got := ids(changed); !slices.Equal(got, want) {
		t.Fatalf("changed = %v", got)
	}
	if changed[1].Visibility != core.SecretGist {
		t.Errorf("new gist visibility = %s", changed[1].Visibility)
	}

	// More new gists than one poll page: the walk continues while the last one on a page is new.
	prev = baseline(t, fx)
	for i := range 35 {
		w.gists["hangryclaude"] = append(w.gists["hangryclaude"], wgist{
			id: fmt.Sprintf("%032x", i+1), updated: fmt.Sprintf("2026-11-03T12:%02d:00Z", i+10),
		})
	}
	w.resetOps()
	changed, _ = poll(t, fx, prev)
	if len(changed) != 35 {
		t.Fatalf("changed %d gists, want 35", len(changed))
	}
	if w.opCount("Gists") != 1 {
		t.Errorf("ops = %v: want exactly one follow-up gist page", w.ops)
	}
}

func TestChangedIdleGistsDoNotFetchASecondPage(t *testing.T) {
	w := standardWorld()
	for i := range 35 {
		w.gists["hangryclaude"] = append(w.gists["hangryclaude"], wgist{id: fmt.Sprintf("%032x", i+1), updated: fmt.Sprintf("2026-09-01T00:%02d:00Z", i)})
	}
	fx := newFixture(t, w, nil)
	prev := baseline(t, fx)
	w.resetOps()
	changed, _ := poll(t, fx, prev)
	if len(changed) != 0 {
		t.Fatalf("idle poll changed %v", ids(changed))
	}
	if n := w.opCount("Gists"); n != 0 {
		t.Errorf("fetched %d extra gist pages although the newest 30 were unchanged", n)
	}
}

func TestChangedWithoutBaselineReportsEverything(t *testing.T) {
	w := standardWorld()
	fx := newFixture(t, w, func(c *Config) { c.PageSize = 2 })
	all, err := fx.inv.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	changed, _ := poll(t, fx, nil)
	if !slices.Equal(ids(changed), ids(all)) {
		t.Fatalf("first poll with no baseline:\n got %v\nwant %v", ids(changed), ids(all))
	}
	// Everything but the default branch, which only List fetches.
	for i := range changed {
		want := all[i]
		want.DefaultBranch = ""
		if changed[i] != want {
			t.Errorf("%s differs from List's:\n got %+v\nwant %+v", changed[i].ID, changed[i], want)
		}
	}
}

func TestChangedFirstPageIsSmallerThanAListPage(t *testing.T) {
	w := standardWorld()
	fx := newFixture(t, w, nil) // default page size 100
	prev := baseline(t, fx)
	poll(t, fx, prev)
	var sizes []float64
	for _, c := range fx.f.Calls() {
		var b struct {
			Query     string         `json:"query"`
			Variables map[string]any `json:"variables"`
		}
		if json.Unmarshal(c.Body, &b) == nil && strings.HasPrefix(b.Query, "query Poll(") {
			sizes = append(sizes, b.Variables["n"].(float64))
		}
	}
	if len(sizes) != 2 || sizes[0] != pollPageSize || sizes[1] != pollPageSize {
		t.Fatalf("poll first-page sizes = %v, want %d", sizes, pollPageSize)
	}
}

func TestChangedKeepsGoodResultsWhenOneTokenFails(t *testing.T) {
	w := standardWorld()
	fx := newFixture(t, w, nil)
	prev := baseline(t, fx)
	w.find("hangryclaude", "bravo").pushed = "2026-11-03T11:00:00Z"
	w.feeds["hangryclaude"] = []wevent{{id: "100", typ: "IssuesEvent", repo: "hangryclaude/bravo", at: "2026-11-03T11:55:00Z"}}
	w.fail["alt-builds Poll"] = ghclitest.JSON(502, map[string]string{"message": "Bad Gateway"})

	changed, events, err := fx.inv.Changed(context.Background(), prev)
	if err == nil || !strings.Contains(err.Error(), "poll as alt-builds") {
		t.Fatalf("err = %v", err)
	}
	if got := ids(changed); !slices.Equal(got, []string{"github.com/hangryclaude/bravo"}) {
		t.Errorf("changed = %v", got)
	}
	if len(events) != 1 || events[0].Source != "github.com/hangryclaude/bravo" {
		t.Errorf("events = %+v", events)
	}
	fx.assertNoTokenAnywhere(err)
}

func TestChangedReportsAnUnreadableOrgWithoutLosingTheAccount(t *testing.T) {
	w := standardWorld()
	fx := newFixture(t, w, nil)
	prev := baseline(t, fx)
	delete(w.orgs, "Loony-Labs-Video")
	w.find("hangryclaude", "bravo").pushed = "2026-11-03T11:00:00Z"
	changed, _, err := fx.inv.Changed(context.Background(), prev)
	if err == nil || !strings.Contains(err.Error(), "Loony-Labs-Video") {
		t.Fatalf("err = %v", err)
	}
	if got := ids(changed); !slices.Equal(got, []string{"github.com/hangryclaude/bravo"}) {
		t.Errorf("changed = %v", got)
	}
}

func TestChangedRateLimitIsInspectable(t *testing.T) {
	w := standardWorld()
	fx := newFixture(t, w, nil)
	prev := baseline(t, fx)
	r := ghclitest.JSON(403, map[string]string{"message": "API rate limit exceeded for user ID 1."})
	r.Header = map[string]string{"X-Ratelimit-Remaining": "0", "X-Ratelimit-Reset": "1793747131"}
	w.fail["hangryclaude events"] = r
	_, _, err := fx.inv.Changed(context.Background(), prev)
	var rl *ghcli.RateLimitError
	if !errors.As(err, &rl) || rl.Reset.Unix() != 1793747131 {
		t.Fatalf("a spent REST quota must stay inspectable through the join: %v", err)
	}
}

func TestChangedDefinition(t *testing.T) {
	prev := map[string]core.Source{
		"a": {ID: "a", Visibility: core.Private, PushedAt: "2026-11-03T10:00:00Z"},
		"w": {ID: "w", Kind: "wiki", Visibility: core.Private},
		"e": {ID: "e", Visibility: core.Private},
	}
	for name, tc := range map[string]struct {
		s    core.Source
		want bool
	}{
		"unseen":                   {core.Source{ID: "new"}, true},
		"same":                     {core.Source{ID: "a", Visibility: core.Private, PushedAt: "2026-11-03T10:00:00Z"}, false},
		"same instant, other zone": {core.Source{ID: "a", Visibility: core.Private, PushedAt: "2026-11-03T05:00:00-05:00"}, false},
		"pushed":                   {core.Source{ID: "a", Visibility: core.Private, PushedAt: "2026-11-03T10:00:01Z"}, true},
		"older push":               {core.Source{ID: "a", Visibility: core.Private, PushedAt: "2026-11-03T09:59:59Z"}, false},
		"flipped":                  {core.Source{ID: "a", Visibility: core.Public, PushedAt: "2026-11-03T10:00:00Z"}, true},
		"wiki untouched":           {core.Source{ID: "w", Kind: "wiki", Visibility: core.Private}, false},
		"wiki flipped":             {core.Source{ID: "w", Kind: "wiki", Visibility: core.Public}, true},
		"first push after none":    {core.Source{ID: "e", Visibility: core.Private, PushedAt: "2026-11-03T10:00:00Z"}, true},
		"still empty":              {core.Source{ID: "e", Visibility: core.Private}, false},
	} {
		if got := changedVs(prev, tc.s); got != tc.want {
			t.Errorf("%s: changedVs = %v, want %v", name, got, tc.want)
		}
	}
}
