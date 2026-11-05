package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"keyguard/internal/core"
	"keyguard/internal/inventory/ghcli"
	"keyguard/internal/inventory/ghcli/ghclitest"
)

// watchFixture is a fixture with the cheap detector on and its state on disk.
func watchFixture(t *testing.T, w *world, mod func(*Config)) *fixture {
	t.Helper()
	return watchFixtureSkew(t, w, 0, mod)
}

func watchFixtureSkew(t *testing.T, w *world, skew time.Duration, mod func(*Config)) *fixture {
	t.Helper()
	return newFixtureSkew(t, w, w.handler(t), skew, func(c *Config) {
		c.NoWatch = false
		c.StateDir = filepath.Join(c.StateDir, "state")
		if mod != nil {
			mod(c)
		}
	})
}

// usableFeeds gives both accounts a feed with events in it, old ones, so that no test of the
// detector pays for the empty-feed fallback by accident.
func usableFeeds(w *world) {
	w.feeds["hangryclaude"] = feed(2, 1, "WatchEvent", "someone/else", "2026-09-01")
	w.feeds["alt-builds"] = feed(2, 1, "WatchEvent", "someone/else", "2026-09-01")
}

func (fx *fixture) pollOK(prev map[string]core.Source) PollResult {
	fx.t.Helper()
	p, err := fx.inv.Poll(context.Background(), prev)
	if err != nil {
		fx.t.Fatalf("Poll: %v", err)
	}
	return p
}

// advance lets d go by on GitHub's clock, and so on this Mac's, which keeps its skew.
func (fx *fixture) advance(d time.Duration) { fx.now = fx.now.Add(d) }

// conditionalCalls counts the REST requests of the cheap poll and how many carried If-None-Match.
func conditionalCalls(f *ghclitest.Fake, from int) (total, conditional int) {
	for _, c := range f.Calls()[from:] {
		if c.Path == "graphql" {
			continue
		}
		total++
		if c.Header["If-None-Match"] != "" {
			conditional++
		}
	}
	return total, conditional
}

func exposedIDs(srcs []core.Source) []string {
	var out []string
	for _, s := range srcs {
		if Exposed(s) {
			out = append(out, s.ID)
		}
	}
	return out
}

func TestWatchColdPollRefreshesAndAWarmOneIsAllNotModified(t *testing.T) {
	w := standardWorld()
	usableFeeds(w)
	fx := watchFixture(t, w, nil)
	prev := baseline(t, fx)

	cold := fx.pollOK(prev)
	if !cold.Stats.Refreshed || cold.Stats.GraphQL < 2 || cold.Stats.NotModified != 0 {
		t.Errorf("cold poll stats = %+v: no ETags yet, so the full poll runs and nothing can be 304", cold.Stats)
	}

	fx.advance(time.Minute)
	from := len(fx.f.Calls())
	warm := fx.pollOK(prev)
	// hangryclaude: its repos, its gists, two orgs, its events. alt-builds: repos, gists, events.
	if warm.Stats.Requests != 8 || warm.Stats.NotModified != 8 || warm.Stats.GraphQL != 0 || warm.Stats.Refreshed {
		t.Errorf("warm poll stats = %+v, want 8 requests, all 304, no GraphQL", warm.Stats)
	}
	if len(warm.Changed) != 0 || len(warm.Events) != 0 {
		t.Errorf("an idle world reported work: %v %v", ids(warm.Changed), warm.Events)
	}
	if total, cond := conditionalCalls(fx.f, from); total != 8 || cond != 8 {
		t.Errorf("%d requests, %d conditional: every request of the cheap poll must carry If-None-Match", total, cond)
	}
	if n := w.opCount("Poll"); n != 2 {
		t.Errorf("GraphQL polls = %d in all: the cold poll's two, none since", n)
	}
	fx.assertNoTokenAnywhere()
	assertNoParameterFlags(t, fx.f)
}

// A 304 carries no body, so the answer has to come from what the 200 left behind. Here the
// sweep never scanned alpha's last push, so prev is behind GitHub, and a quiet poll must still
// say so: the cached view is compared with prev, not with the last poll.
func TestWatchAnswersA304FromTheCachedBodyAndStillReportsWhatPrevLacks(t *testing.T) {
	w := standardWorld()
	usableFeeds(w)
	fx := watchFixture(t, w, nil)
	prev := baseline(t, fx)
	alpha := prev["github.com/hangryclaude/alpha"]
	alpha.PushedAt = "2026-11-02T00:00:00Z" // what the last successful scan saw
	prev["github.com/hangryclaude/alpha"] = alpha

	first := fx.pollOK(prev)
	if !slices.Contains(ids(first.Changed), "github.com/hangryclaude/alpha") {
		t.Fatalf("first poll = %v", ids(first.Changed))
	}
	fx.advance(time.Minute)
	second := fx.pollOK(prev) // the scan failed again; prev did not move
	if second.Stats.GraphQL != 0 || second.Stats.NotModified != 8 {
		t.Fatalf("second poll stats = %+v: it should be all 304", second.Stats)
	}
	if got := ids(second.Changed); !slices.Equal(got, []string{"github.com/hangryclaude/alpha"}) {
		t.Fatalf("second poll = %v: a source whose scan failed is reported again, from the cached body", got)
	}
	if second.Changed[0].PushedAt != "2026-11-03T10:00:00Z" || second.Changed[0].Visibility != core.Public {
		t.Errorf("cached source = %+v", second.Changed[0])
	}
	// Once the sweep catches prev up, the same cached body reports nothing.
	prev["github.com/hangryclaude/alpha"] = second.Changed[0]
	if third := fx.pollOK(prev); len(third.Changed) != 0 {
		t.Errorf("third poll = %v", ids(third.Changed))
	}
}

func TestWatchStateSurvivesARestartSoTheFirstPollOfANewProcessIsQuiet(t *testing.T) {
	w := standardWorld()
	usableFeeds(w)
	fx := watchFixture(t, w, nil)
	prev := baseline(t, fx)
	fx.pollOK(prev)
	fx.advance(10 * time.Minute) // the next launchd run

	fresh := fx.fresh()
	from := len(fx.f.Calls())
	p, err := fresh.Poll(context.Background(), prev)
	if err != nil {
		t.Fatal(err)
	}
	if p.Stats.NotModified != 8 || p.Stats.GraphQL != 0 || p.Stats.Refreshed {
		t.Errorf("a new process over the same state: %+v, want 8 requests, all 304, no GraphQL", p.Stats)
	}
	if total, cond := conditionalCalls(fx.f, from); total != 8 || cond != 8 {
		t.Errorf("%d requests, %d conditional: the ETags must come from disk", total, cond)
	}
}

func TestWatchSeesAPushToAPublicRepoWithoutGraphQL(t *testing.T) {
	w := standardWorld()
	usableFeeds(w)
	fx := watchFixture(t, w, nil)
	prev := baseline(t, fx)
	fx.pollOK(prev)

	fx.advance(time.Minute)
	w.find("hangryclaude", "alpha").pushed = "2026-11-03T12:00:30Z"
	p := fx.pollOK(prev)
	if got := ids(p.Changed); !slices.Equal(got, []string{"github.com/hangryclaude/alpha"}) {
		t.Fatalf("changed = %v", got)
	}
	if p.Changed[0].PushedAt != "2026-11-03T12:00:30Z" || p.Changed[0].DefaultBranch != "main" {
		t.Errorf("source = %+v: the new push time, and the branch List recorded", p.Changed[0])
	}
	if p.Stats.GraphQL != 0 || p.Stats.NotModified != 7 {
		t.Errorf("stats = %+v: one list moved (200), the other seven are 304, and no GraphQL ran", p.Stats)
	}
}

// A push to a private repo moves the answer of no public list. That is the point of not
// watching private repos: they are metadata, and a refresh picks them up.
func TestWatchLeavesPrivateRepoMetadataToTheRefresh(t *testing.T) {
	w := standardWorld()
	usableFeeds(w)
	fx := watchFixture(t, w, nil)
	prev := baseline(t, fx)
	fx.pollOK(prev)

	w.find("hangryclaude", "bravo").pushed = "2026-11-03T12:01:00Z"
	fx.advance(10 * time.Minute)
	quiet := fx.pollOK(prev)
	if len(quiet.Changed) != 0 || quiet.Stats.GraphQL != 0 {
		t.Fatalf("a private push on a quiet poll: changed %v, stats %+v", ids(quiet.Changed), quiet.Stats)
	}
	fx.advance(21 * time.Minute) // 31 minutes since the cold poll: the refresh is due
	refresh := fx.pollOK(prev)
	if !refresh.Stats.Refreshed || !slices.Contains(ids(refresh.Changed), "github.com/hangryclaude/bravo") {
		t.Errorf("after RefreshEvery: changed %v, stats %+v", ids(refresh.Changed), refresh.Stats)
	}
}

func TestWatchRefreshesWhenTheConfigSaysSo(t *testing.T) {
	w := standardWorld()
	usableFeeds(w)
	fx := watchFixture(t, w, func(c *Config) { c.RefreshEvery = 2 * time.Minute })
	prev := baseline(t, fx)
	fx.pollOK(prev)
	fx.advance(time.Minute)
	if p := fx.pollOK(prev); p.Stats.Refreshed {
		t.Error("refreshed after one minute with RefreshEvery at two")
	}
	fx.advance(90 * time.Second)
	if p := fx.pollOK(prev); !p.Stats.Refreshed {
		t.Error("did not refresh after two and a half minutes")
	}
}

func TestWatchReportsAPrivateToPublicFlipFirstAndAsAFlip(t *testing.T) {
	for name, skew := range map[string]time.Duration{"clocks in step": 0, "mac 2h fast": 2 * time.Hour, "mac 2h slow": -2 * time.Hour} {
		t.Run(name, func(t *testing.T) {
			w := standardWorld()
			usableFeeds(w)
			fx := watchFixtureSkew(t, w, skew, func(c *Config) { c.PageSize = 2 })
			prev := baseline(t, fx)
			fx.pollOK(prev)

			fx.advance(time.Minute)
			w.find("hangryclaude", "alpha").pushed = "2026-11-03T12:00:10Z" // an ordinary push, sorting before the flip
			w.find("hangryclaude", "charlie").vis = "PUBLIC"                // charlie is old, with a wiki, and a flip moves no pushedAt
			p := fx.pollOK(prev)

			want := []string{"github.com/hangryclaude/charlie", "github.com/hangryclaude/charlie.wiki", "github.com/hangryclaude/alpha"}
			if got := ids(p.Changed); !slices.Equal(got, want) {
				t.Fatalf("changed = %v, want the flipped repo and its wiki ahead of everything else", got)
			}
			if len(p.Flips) != 2 || !p.Flips[0].Opened() || p.Flips[0].Was != core.Private || p.Flips[0].Now != core.Public || p.Flips[0].Source.ID != "github.com/hangryclaude/charlie" {
				t.Fatalf("flips = %+v", p.Flips)
			}
			var pub []core.Event
			for _, e := range p.Events {
				if e.Type == "PublicEvent" {
					pub = append(pub, e)
				}
			}
			// The event is stamped with GitHub's clock whatever this Mac says.
			if len(pub) != 1 || pub[0].Source != "github.com/hangryclaude/charlie" || pub[0].At != "2026-11-03T12:01:00Z" {
				t.Errorf("PublicEvents = %+v: one, for the repo, stamped 2026-11-03T12:01:00Z by GitHub's clock", pub)
			}
			if p.Stats.GraphQL != 0 {
				t.Errorf("a flip cost %d GraphQL requests; the public list shows it", p.Stats.GraphQL)
			}
			assertNoParameterFlags(t, fx.f)
		})
	}
}

func TestWatchDoesNotAddAPublicEventTheFeedAlreadyDelivered(t *testing.T) {
	w := standardWorld()
	usableFeeds(w)
	fx := watchFixture(t, w, nil)
	prev := baseline(t, fx)
	fx.pollOK(prev)
	fx.advance(time.Minute)
	w.find("hangryclaude", "charlie").vis = "PUBLIC"
	w.feeds["hangryclaude"] = append([]wevent{{id: "50", typ: "PublicEvent", repo: "hangryclaude/charlie", at: "2026-11-03T12:00:40Z"}}, w.feeds["hangryclaude"]...)
	p := fx.pollOK(prev)
	n := 0
	for _, e := range p.Events {
		if e.Type == "PublicEvent" && e.Source == "github.com/hangryclaude/charlie" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("%d PublicEvents for the flipped repo, want GitHub's own and no second", n)
	}
}

func TestWatchLooksUpARepoThatLeftThePublicListByName(t *testing.T) {
	w := standardWorld()
	w.add(wrepo{owner: "hangryclaude", name: "kilo", vis: "PUBLIC", pushed: "2026-01-01T00:00:00Z"})
	w.add(wrepo{owner: "hangryclaude", name: "lima", vis: "PUBLIC", pushed: "2026-01-02T00:00:00Z"})
	usableFeeds(w)
	fx := watchFixture(t, w, nil)
	prev := baseline(t, fx)
	fx.pollOK(prev)

	fx.advance(time.Minute)
	w.find("hangryclaude", "kilo").vis = "PRIVATE"
	w.drop("hangryclaude", "lima")
	w.resetOps()
	p := fx.pollOK(prev)
	if got := ids(p.Changed); !slices.Equal(got, []string{"github.com/hangryclaude/kilo"}) || p.Changed[0].Visibility != core.Private {
		t.Fatalf("changed = %+v: kilo went private; lima was deleted and is just gone", p.Changed)
	}
	if len(p.Flips) != 1 || p.Flips[0].Opened() || p.Flips[0].Was != core.Public {
		t.Errorf("flips = %+v: a repo closing is a flip too, but not an opened one", p.Flips)
	}
	if w.opCount("ReposByName") != 1 || len(w.ops) != 1 {
		t.Errorf("GraphQL operations = %v, want one lookup by name", w.ops)
	}
	for _, e := range p.Events {
		if e.Type == "PublicEvent" {
			t.Errorf("a repo that went private got %+v", e)
		}
	}
}

func TestWatchPaginatesAndOnlyThePageThatMovedIsFetchedAgain(t *testing.T) {
	w := newWorld()
	for i := range 5 {
		w.add(wrepo{owner: "hangryclaude", name: fmt.Sprintf("pub%d", i), vis: "PUBLIC", pushed: fmt.Sprintf("2026-10-1%dT00:00:00Z", 9-i)})
	}
	w.add(wrepo{owner: "alt-builds", name: "x", vis: "PUBLIC", pushed: "2026-10-01T00:00:00Z"})
	w.orgs["acme-apps"] = []string{"hangryclaude"}
	w.orgs["Loony-Labs-Video"] = []string{"hangryclaude"}
	usableFeeds(w)
	fx := watchFixture(t, w, func(c *Config) { c.PageSize = 2 })
	all, err := fx.inv.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	prev := Index(all)

	cold := fx.pollOK(prev)
	if got := w.restCalls["repos"]; got != 4 { // 5 repos at 2 a page is three pages, and the other account has one
		t.Fatalf("repo list requests = %d, want 3 pages for hangryclaude and 1 for alt-builds", got)
	}
	if len(cold.Changed) != 0 {
		t.Fatalf("cold poll changed %v: prev already has everything", ids(cold.Changed))
	}
	fx.advance(time.Minute)
	before, before304 := w.restCalls["repos"], w.rest304["repos"]
	fx.pollOK(prev)
	if got, n304 := w.restCalls["repos"]-before, w.rest304["repos"]-before304; got != 4 || n304 != 4 {
		t.Errorf("warm poll: %d repo list requests, %d answered 304; want all 4", got, n304)
	}

	// A repo that sorts after all the others fills the last page and starts a fourth: the first two
	// pages are untouched, and say so with a 304.
	w.add(wrepo{owner: "hangryclaude", name: "pub5", vis: "PUBLIC", pushed: "2026-10-01T00:00:00Z"})
	fx.advance(time.Minute)
	before, before304 = w.restCalls["repos"], w.rest304["repos"]
	p := fx.pollOK(prev)
	if got, n304 := w.restCalls["repos"]-before, w.rest304["repos"]-before304; got != 5 || n304 != 3 {
		t.Errorf("after a new oldest repo: %d requests, %d 304s; want 5 and 3 (the first two pages and the other account)", got, n304)
	}
	if got := ids(p.Changed); !slices.Equal(got, []string{"github.com/hangryclaude/pub5"}) {
		t.Errorf("changed = %v", got)
	}
}

func TestWatchSeesASecretGistPushedTo(t *testing.T) {
	w := standardWorld()
	usableFeeds(w)
	fx := watchFixture(t, w, nil)
	prev := baseline(t, fx)
	fx.pollOK(prev)
	fx.advance(time.Minute)
	w.gists["hangryclaude"][1].updated = "2026-11-03T12:00:30Z"
	p := fx.pollOK(prev)
	if got := ids(p.Changed); !slices.Equal(got, []string{"gist.github.com/hangryclaude/1b2c3d4e5f60718293a4b5c6d7e8f9a0"}) || p.Changed[0].Visibility != core.SecretGist {
		t.Fatalf("changed = %+v", p.Changed)
	}
	if p.Stats.GraphQL != 0 {
		t.Errorf("a gist push cost %d GraphQL requests", p.Stats.GraphQL)
	}
}

func TestWatchFallsBackToTheFullPollWhenAListFailsAndSaysSo(t *testing.T) {
	w := standardWorld()
	usableFeeds(w)
	fx := watchFixture(t, w, nil)
	prev := baseline(t, fx)
	fx.pollOK(prev)
	fx.advance(time.Minute)

	w.fail["hangryclaude repos"] = ghclitest.JSON(502, map[string]string{"message": "Bad Gateway"})
	w.find("hangryclaude", "alpha").pushed = "2026-11-03T12:00:30Z"
	w.resetOps()
	p, err := fx.inv.Poll(context.Background(), prev)
	if err == nil || !strings.Contains(err.Error(), "user/repos") {
		t.Fatalf("err = %v, want the failed list named: a broken fast path must not hide", err)
	}
	if got := ids(p.Changed); !slices.Equal(got, []string{"github.com/hangryclaude/alpha"}) {
		t.Errorf("changed = %v: the full poll found the push the list could not show", got)
	}
	if w.opCount("Poll") != 1 || !p.Stats.Refreshed {
		t.Errorf("ops %v, refreshed %v: the fallback is the full poll, for that token only", w.ops, p.Stats.Refreshed)
	}
	// The failure did not cost the ETag: when the list answers again it can still say 304.
	delete(w.fail, "hangryclaude repos")
	prev[p.Changed[0].ID] = p.Changed[0]
	fx.advance(time.Minute)
	again := fx.pollOK(prev)
	if again.Stats.GraphQL != 0 || len(again.Changed) != 0 {
		t.Errorf("recovered poll: changed %v stats %+v", ids(again.Changed), again.Stats)
	}
}

func TestWatchRefusesATokenThatListsSomeoneElsesRepos(t *testing.T) {
	w := standardWorld()
	w.add(wrepo{owner: "mallory", name: "x", vis: "PUBLIC", pushed: "2026-11-03T10:00:00Z"})
	w.login["hangryclaude"] = "mallory"
	usableFeeds(w)
	fx := watchFixture(t, w, nil)
	p, err := fx.inv.Poll(context.Background(), nil)
	if err == nil || !strings.Contains(err.Error(), "lists repos of mallory") {
		t.Fatalf("err = %v", err)
	}
	for _, s := range p.Changed {
		if s.Account == "hangryclaude" && (s.Owner == "mallory" || s.Kind == "gist") {
			t.Errorf("a source read with the wrong account's token got through: %s", s.ID)
		}
	}
}

func TestWatchStateIsReadableByTheOldReaderAndHoldsNoText(t *testing.T) {
	w := standardWorld()
	usableFeeds(w)
	fx := watchFixture(t, w, nil)
	prev := baseline(t, fx)
	fx.pollOK(prev)

	file := filepath.Join(fx.cfg.StateDir, "events.json")
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	// What v1 wrote and v1's tests read is still there under the same keys.
	var accounts map[string]eventState
	if err := json.Unmarshal(raw, &accounts); err != nil || accounts["hangryclaude"].ETag == "" || accounts["hangryclaude"].LastID == 0 {
		t.Fatalf("the per-account state moved: %v %+v", err, accounts["hangryclaude"])
	}
	var top map[string]json.RawMessage
	_ = json.Unmarshal(raw, &top)
	for _, k := range []string{"_watch", "_refreshed", "hangryclaude", "alt-builds"} {
		if _, ok := top[k]; !ok {
			t.Errorf("state file lacks %q: %v", k, keys(top))
		}
	}
	for _, text := range []string{"free text that may hold a key"} {
		if strings.Contains(string(raw), text) {
			t.Errorf("the state file holds text a person wrote: %q", text)
		}
	}
	if fi, _ := os.Stat(file); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v", fi.Mode().Perm())
	}
	fx.assertNoTokenAnywhere()

	// The file name is the one core.Paths gives it.
	paths := core.PathsAt("/k")
	if filepath.Join(paths.State, eventsFile) != paths.Events {
		t.Errorf("events file %q is not core.Paths.Events %q", filepath.Join(paths.State, eventsFile), paths.Events)
	}
}

func keys[V any](m map[string]V) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func TestWatchReadsAnOldStateFileAndStartsTheListsCold(t *testing.T) {
	w := standardWorld()
	usableFeeds(w)
	fx := watchFixture(t, w, nil)
	prev := baseline(t, fx)
	if err := os.MkdirAll(fx.cfg.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	old := `{"hangryclaude":{"etag":"\"stale\"","last_id":150},"alt-builds":{"etag":"\"stale2\"","last_id":7}}`
	if err := os.WriteFile(filepath.Join(fx.cfg.StateDir, "events.json"), []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	p := fx.pollOK(prev)
	if !p.Stats.Refreshed || p.Stats.NotModified != 0 {
		t.Errorf("stats = %+v: no list has an ETag yet, so everything is read and the full poll runs", p.Stats)
	}
	var sent []string
	for _, c := range fx.f.Calls() {
		if strings.HasPrefix(c.Path, "users/hangryclaude/events") {
			sent = append(sent, c.Header["If-None-Match"])
		}
	}
	if len(sent) == 0 || sent[0] != `"stale"` {
		t.Errorf("events If-None-Match = %q: the old ETag must still be used", sent)
	}
}

// The cheap poll and the full poll must agree about everything a stranger can read, through
// every kind of change, whether or not the sweep scans what it is told about. Private repos are
// the one difference, by design.
func TestWatchAgreesWithTheFullPollAboutWhatIsExposed(t *testing.T) {
	mutations := []struct {
		name string
		do   func(w *world)
	}{
		{"nothing", func(w *world) {}},
		{"push to a public repo", func(w *world) { w.find("hangryclaude", "alpha").pushed = "2026-11-03T12:10:00Z" }},
		{"push to an org repo", func(w *world) { w.find("acme-apps", "hotel").pushed = "2026-11-03T12:11:00Z" }},
		{"flip an old private repo public", func(w *world) { w.find("hangryclaude", "delta").vis = "PUBLIC" }},
		{"a new public repo with an old push time", func(w *world) {
			w.add(wrepo{owner: "alt-builds", name: "zulu", vis: "PUBLIC", pushed: "2025-01-01T00:00:00Z", wiki: true})
		}},
		{"a gist is pushed to", func(w *world) { w.gists["hangryclaude"][0].updated = "2026-11-03T12:12:00Z" }},
		{"a new gist", func(w *world) {
			w.gists["hangryclaude"] = append(w.gists["hangryclaude"], wgist{id: "4e5f60718293a4b5c6d7e8f9a0b1c2d3", updated: "2026-11-03T12:13:00Z"})
		}},
		{"a wiki is switched on", func(w *world) {
			w.find("hangryclaude", "alpha").wiki = true
			w.find("alt-builds", "foxtrot").wiki = true
		}},
		{"a public repo goes private", func(w *world) { w.find("alt-builds", "foxtrot").vis = "PRIVATE" }},
		{"a public repo is deleted", func(w *world) { w.drop("Loony-Labs-Video", "juliet") }},
		{"a private repo is pushed to (the one difference)", func(w *world) { w.find("hangryclaude", "bravo").pushed = "2026-11-03T12:14:00Z" }},
	}
	for _, scansSucceed := range []bool{true, false} {
		t.Run(fmt.Sprintf("scans succeed=%v", scansSucceed), func(t *testing.T) {
			wFull, wCheap := standardWorld(), standardWorld()
			usableFeeds(wFull)
			usableFeeds(wCheap)
			full := newFixture(t, wFull, nil) // NoWatch: the full poll every time
			cheap := watchFixture(t, wCheap, func(c *Config) { c.RefreshEvery = 7 * 24 * time.Hour })
			prevFull, prevCheap := baseline(t, full), baseline(t, cheap)
			reported := 0 // a comparison of two empty lists would prove nothing
			for step, m := range mutations {
				m.do(wFull)
				m.do(wCheap)
				full.advance(time.Minute)
				cheap.advance(time.Minute)
				a, b := full.pollOK(prevFull), cheap.pollOK(prevCheap)
				if want, got := summarizeExposed(a.Changed), summarizeExposed(b.Changed); !slices.Equal(want, got) {
					t.Fatalf("step %d (%s):\n full poll: %v\ncheap poll: %v", step, m.name, want, got)
				}
				reported += len(summarizeExposed(a.Changed))
				if scansSucceed {
					for _, s := range a.Changed {
						prevFull[s.ID] = s
					}
					for _, s := range b.Changed {
						prevCheap[s.ID] = s
					}
				}
			}
			if reported < 8 {
				t.Errorf("only %d exposed changes were compared across %d steps", reported, len(mutations))
			}
		})
	}
}

// summarizeExposed is what the sweep acts on: the exposed sources of a poll, with what makes
// them worth scanning.
func summarizeExposed(srcs []core.Source) []string {
	var out []string
	for _, s := range srcs {
		if Exposed(s) {
			out = append(out, fmt.Sprintf("%s %s %s", s.ID, s.Visibility, s.PushedAt))
		}
	}
	slices.Sort(out)
	return out
}

// STEAL P0-16. The refresh timer is read on GitHub's clock. A stamp written by one process is
// compared with the time another one hears from GitHub, so a Mac that is hours off in either
// direction must not make the refresh come early or late.
func TestWatchRefreshTimerFollowsGitHubsClockNotTheMacs(t *testing.T) {
	for name, skew := range map[string]time.Duration{"mac 2h fast": 2 * time.Hour, "mac 2h slow": -2 * time.Hour} {
		t.Run(name, func(t *testing.T) {
			for _, tc := range []struct {
				name    string
				age     time.Duration // since the last refresh, on GitHub's clock
				wantDue bool
			}{{"5 minutes ago", 5 * time.Minute, false}, {"45 minutes ago", 45 * time.Minute, true}} {
				w := standardWorld()
				usableFeeds(w)
				fx := watchFixtureSkew(t, w, skew, nil)
				prev := baseline(t, fx)
				if err := os.MkdirAll(fx.cfg.StateDir, 0o700); err != nil {
					t.Fatal(err)
				}
				at := fx.now.Add(-tc.age).UTC().Format(time.RFC3339)
				seed := fmt.Sprintf(`{"_refreshed":{"hangryclaude":%q,"alt-builds":%q}}`, at, at)
				if err := os.WriteFile(filepath.Join(fx.cfg.StateDir, "events.json"), []byte(seed), 0o600); err != nil {
					t.Fatal(err)
				}
				p := fx.pollOK(prev)
				if p.Stats.Refreshed != tc.wantDue {
					t.Errorf("%s: refreshed=%v, want %v (the Mac reads %s, GitHub %s)", tc.name, p.Stats.Refreshed, tc.wantDue,
						fx.now.Add(skew).Format(time.RFC3339), fx.now.Format(time.RFC3339))
				}
			}
		})
	}
}

func TestWatchStampsAndCursorsAreGitHubsTime(t *testing.T) {
	for name, skew := range map[string]time.Duration{"mac 2h fast": 2 * time.Hour, "mac 2h slow": -2 * time.Hour} {
		t.Run(name, func(t *testing.T) {
			w := standardWorld()
			w.feeds["hangryclaude"] = []wevent{{id: "30", typ: "WatchEvent", repo: "someone/else", at: "2026-11-03T11:30:00Z"}}
			w.feeds["alt-builds"] = feed(2, 1, "WatchEvent", "someone/else", "2026-09-01")
			fx := watchFixtureSkew(t, w, skew, nil)
			prev := baseline(t, fx)
			p := fx.pollOK(prev)

			// hangryclaude's newest timestamp is alpha's push at 10:00; its newest event is 11:30.
			if want := time.Date(2026, 11, 3, 11, 20, 0, 0, time.UTC); !p.Cursor["hangryclaude"].Equal(want) {
				t.Errorf("cursor = %s, want the newest thing seen less ten minutes, %s", p.Cursor["hangryclaude"], want)
			}
			if !p.Now.Equal(fx.now) {
				t.Errorf("poll time = %s, want GitHub's %s (the Mac says %s)", p.Now, fx.now, fx.now.Add(skew))
			}
			raw, _ := os.ReadFile(filepath.Join(fx.cfg.StateDir, "events.json"))
			var top map[string]json.RawMessage
			_ = json.Unmarshal(raw, &top)
			var refreshed map[string]string
			_ = json.Unmarshal(top["_refreshed"], &refreshed)
			if refreshed["hangryclaude"] != fx.now.Format(time.RFC3339) {
				t.Errorf("refresh stamp = %q, want GitHub's %s", refreshed["hangryclaude"], fx.now.Format(time.RFC3339))
			}
		})
	}
}

func TestCursorIsTheNewestSeenLessTenMinutes(t *testing.T) {
	newest := time.Date(2026, 11, 3, 23, 31, 37, 0, time.UTC)
	if got := Cursor(newest); !got.Equal(newest.Add(-10 * time.Minute)) {
		t.Errorf("Cursor = %s", got)
	}
	// With nothing seen, the first poll looks back one event window from GitHub's now.
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	if got := cursorTime(eventState{}, now, 24*time.Hour); !got.Equal(now.Add(-24 * time.Hour)) {
		t.Errorf("empty cursor = %s", got)
	}
	if got := cursorTime(eventState{Seen: "2026-11-03T11:00:00Z"}, now, 24*time.Hour); !got.Equal(time.Date(2026, 11, 3, 10, 50, 0, 0, time.UTC)) {
		t.Errorf("cursor = %s", got)
	}
}

func TestSkewIsTheMacMinusGitHub(t *testing.T) {
	for name, skew := range map[string]time.Duration{"mac 2h fast": 2 * time.Hour, "mac 2h slow": -2 * time.Hour, "in step": 0} {
		t.Run(name, func(t *testing.T) {
			fx := newFixtureSkew(t, standardWorld(), standardWorld().handler(t), skew, nil)
			got, err := fx.inv.Skew(context.Background())
			if err != nil || got != skew {
				t.Fatalf("Skew = %v, %v, want %v", got, err, skew)
			}
			if c := fx.f.Calls(); len(c) != 1 || c[0].Path != "rate_limit" {
				t.Errorf("calls = %+v: the skew is read from the one request that costs no quota", c)
			}
		})
	}
	fx := newFixtureH(t, standardWorld(), func(ghclitest.Call) ghclitest.Reply {
		return ghclitest.JSON(500, map[string]string{"message": "down"})
	}, nil)
	fx.cfg.Client.MaxAttempts = 1
	if _, err := fx.inv.Skew(context.Background()); err == nil {
		t.Log("a 500 still carries a Date header, which is enough to measure")
	}
}

func TestPollStatsMatchTheRequestsThatWereMade(t *testing.T) {
	w := standardWorld()
	usableFeeds(w)
	fx := watchFixture(t, w, nil)
	prev := baseline(t, fx)
	from := len(fx.f.Calls())
	p := fx.pollOK(prev)
	var rest, gql int
	for _, c := range fx.f.Calls()[from:] {
		if c.Path == "graphql" {
			gql++
		} else {
			rest++
		}
	}
	if p.Stats.Requests != rest || p.Stats.GraphQL != gql || p.Stats.Duration <= 0 {
		t.Errorf("stats %+v, but the fake saw %d REST and %d GraphQL", p.Stats, rest, gql)
	}
}

// A refresh that failed has not been done: the next poll tries it again instead of waiting out
// RefreshEvery from a stamp that was never earned.
func TestWatchDoesNotCountAFailedRefreshAsDone(t *testing.T) {
	w := standardWorld()
	usableFeeds(w)
	fx := watchFixture(t, w, nil)
	prev := baseline(t, fx)
	w.fail["hangryclaude Poll"] = ghclitest.JSON(502, map[string]string{"message": "Bad Gateway"})
	if _, err := fx.inv.Poll(context.Background(), prev); err == nil {
		t.Fatal("the failed poll was not reported")
	}
	raw, _ := os.ReadFile(filepath.Join(fx.cfg.StateDir, "events.json"))
	var top map[string]json.RawMessage
	_ = json.Unmarshal(raw, &top)
	var refreshed map[string]string
	_ = json.Unmarshal(top["_refreshed"], &refreshed)
	if _, done := refreshed["hangryclaude"]; done || refreshed["alt-builds"] == "" {
		t.Fatalf("refreshed = %v: hangryclaude's failed, alt-builds' did not", refreshed)
	}
	delete(w.fail, "hangryclaude Poll")
	fx.advance(time.Minute)
	p := fx.pollOK(prev)
	if !p.Stats.Refreshed || w.opCount("Poll") < 3 {
		t.Errorf("a minute later: refreshed=%v, %d GraphQL polls in all; hangryclaude's refresh should be tried again", p.Stats.Refreshed, w.opCount("Poll"))
	}
}

// A list that fails keeps the ETag it had, so the poll that follows its recovery is quiet again.
func TestWatchKeepsAFailedListsETagForWhenItRecovers(t *testing.T) {
	w := standardWorld()
	usableFeeds(w)
	fx := watchFixture(t, w, nil)
	prev := baseline(t, fx)
	fx.pollOK(prev)
	fx.advance(time.Minute)

	w.fail["hangryclaude repos"] = ghclitest.JSON(502, map[string]string{"message": "Bad Gateway"})
	if _, err := fx.inv.Poll(context.Background(), prev); err == nil {
		t.Fatal("the failed list was not reported")
	}
	delete(w.fail, "hangryclaude repos")
	fx.advance(time.Minute)
	from := len(fx.f.Calls())
	p := fx.pollOK(prev)
	if p.Stats.NotModified != 8 || p.Stats.GraphQL != 0 {
		t.Errorf("after recovery: %+v, want all 8 requests answered 304", p.Stats)
	}
	if total, cond := conditionalCalls(fx.f, from); total != 8 || cond != 8 {
		t.Errorf("%d requests, %d conditional: the failed list must still carry its ETag", total, cond)
	}
}

// With the REST quota spent every list is refused, and GraphQL, which has a quota of its own,
// still answers. The poll goes on through it, the limit stays inspectable, and the time to wait
// is GitHub's reset against GitHub's clock whatever the Mac says (STEAL P0-16).
func TestWatchWhenTheRESTQuotaIsSpentTheFullPollStillRuns(t *testing.T) {
	for name, skew := range map[string]time.Duration{"mac 2h fast": 2 * time.Hour, "mac 2h slow": -2 * time.Hour} {
		t.Run(name, func(t *testing.T) {
			w := standardWorld()
			usableFeeds(w)
			fx := watchFixtureSkew(t, w, skew, nil)
			prev := baseline(t, fx)
			fx.pollOK(prev)
			fx.advance(time.Minute)

			reset := fx.now.Add(40 * time.Second)
			limit := ghclitest.JSON(403, map[string]string{"message": "API rate limit exceeded for user ID 1."})
			limit.Header = map[string]string{"X-Ratelimit-Remaining": "0", "X-Ratelimit-Reset": fmt.Sprint(reset.Unix())}
			for _, label := range []string{"repos", "gists", "org:acme-apps", "org:Loony-Labs-Video", "events"} {
				w.fail["hangryclaude "+label] = limit
			}
			w.find("hangryclaude", "alpha").pushed = "2026-11-03T12:00:30Z"
			p, err := fx.inv.Poll(context.Background(), prev)

			var rl *ghcli.RateLimitError
			if !errors.As(err, &rl) {
				t.Fatalf("err = %v, want the rate limit inside it", err)
			}
			if got := rl.Wait(fx.inv.Clock().Now()); got != 42*time.Second {
				t.Errorf("Wait = %v, want 42s: the reset 40 s ahead on GitHub's clock, plus the margin (Mac %v off)", got, skew)
			}
			if got := ids(p.Changed); !slices.Equal(got, []string{"github.com/hangryclaude/alpha"}) {
				t.Errorf("changed = %v: the full poll goes through GraphQL and found the push", got)
			}
			if !p.Stats.Refreshed {
				t.Error("the full poll did not stand in for the refused lists")
			}
		})
	}
}

// A poll every minute must not outrun what GitHub's events endpoint asks for. Its 304 does not
// repeat the header (a live run showed it), so the answer has to outlive the response it came
// with, and a new process must still know it.
func TestPollReportsTheIntervalGitHubAsksForEvenWhenAll304(t *testing.T) {
	w := standardWorld()
	usableFeeds(w)
	fx := watchFixture(t, w, nil)
	prev := baseline(t, fx)
	if p := fx.pollOK(prev); p.Interval != time.Minute {
		t.Errorf("Interval = %v on a 200, want the 60 s of X-Poll-Interval", p.Interval)
	}
	fx.advance(time.Minute)
	p := fx.pollOK(prev)
	if p.Stats.NotModified != p.Stats.Requests || p.Interval != time.Minute {
		t.Errorf("Interval = %v on a poll of all 304s (%+v): the last 200's value must carry over", p.Interval, p.Stats)
	}
	fx.advance(time.Minute)
	if p, err := fx.fresh().Poll(context.Background(), prev); err != nil || p.Interval != time.Minute {
		t.Errorf("Interval = %v, %v in a new process: it must come from the state file", p.Interval, err)
	}
}

// A repo with a name that cannot be used in a path is skipped and said so, once, when the list
// holding it is read; it is not a failed list, and it is not a reason to run the full poll.
func TestWatchReportsAnUnusableNameOnceWithoutFallingBackToTheFullPoll(t *testing.T) {
	w := standardWorld()
	usableFeeds(w)
	w.add(wrepo{owner: "hangryclaude", name: "ev il", vis: "PUBLIC", pushed: "2026-10-01T00:00:00Z"})
	fx := watchFixture(t, w, nil)
	all, _ := fx.inv.List(context.Background()) // List reports the skipped repo as well
	prev := Index(all)
	_, _ = fx.inv.Poll(context.Background(), prev) // cold: the full poll runs and reads every list

	// Same lists, new process: they are read again (a restart forgets nothing, so they are 304),
	// so a list read with a 200 is where the skipped repo is said. Force that with a push.
	fx.advance(time.Minute)
	w.find("hangryclaude", "alpha").pushed = "2026-11-03T12:00:30Z"
	p, err := fx.inv.Poll(context.Background(), prev)
	if err == nil || !strings.Contains(err.Error(), "unusable name") {
		t.Fatalf("err = %v, want the skipped repo reported", err)
	}
	if p.Stats.GraphQL != 0 || p.Stats.Refreshed {
		t.Errorf("stats = %+v: a skipped repo is not a failed list", p.Stats)
	}
	for _, s := range p.Changed {
		if strings.Contains(s.ID, " ") {
			t.Errorf("the unusable repo became a source: %q", s.ID)
		}
	}
	if got := ids(p.Changed); !slices.Equal(got, []string{"github.com/hangryclaude/alpha"}) {
		t.Errorf("changed = %v", got)
	}
}

// With the detector off, the entries it left are not thrown away: turning it back on is quiet.
func TestTurningTheDetectorOffAndOnAgainKeepsItsETags(t *testing.T) {
	w := standardWorld()
	usableFeeds(w)
	fx := watchFixture(t, w, nil)
	prev := baseline(t, fx)
	fx.pollOK(prev)
	fx.cfg.NoWatch = true
	off, err := New(fx.cfg)
	if err != nil {
		t.Fatal(err)
	}
	fx.advance(time.Minute)
	if _, err := off.Poll(context.Background(), prev); err != nil {
		t.Fatal(err)
	}
	fx.advance(time.Minute)
	fx.cfg.NoWatch = false
	on, _ := New(fx.cfg)
	got, err := on.Poll(context.Background(), prev)
	if err != nil || got.Stats.NotModified != 8 {
		t.Errorf("after off and on: %v, stats %+v, want all 8 lists still 304", err, got.Stats)
	}
}

func TestNewRejectsANegativeRefreshInterval(t *testing.T) {
	cfg := testConfig("")
	cfg.RefreshEvery = -time.Minute
	if _, err := New(cfg); err == nil {
		t.Error("a negative refresh interval was accepted")
	}
}
