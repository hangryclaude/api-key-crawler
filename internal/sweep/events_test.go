package sweep

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"keyguard/internal/core"
	"keyguard/internal/fp"
)

type apiCall struct {
	url  string
	opts core.ScanOpts
}

// fakeAPI is a core.APIScanner that records its calls and emits what a test tells it to.
type fakeAPI struct {
	mu    sync.Mutex
	calls []apiCall
	fail  map[string]error // by URL
	emit  func(c apiCall, emit core.Emit)
}

func (f *fakeAPI) ScanAPI(ctx context.Context, url string, o core.ScanOpts, emit core.Emit) error {
	c := apiCall{url: url, opts: o}
	f.mu.Lock()
	f.calls = append(f.calls, c)
	fn, err := f.emit, f.fail[url]
	f.mu.Unlock()
	if fn != nil {
		fn(c, emit)
	}
	return err
}

func (f *fakeAPI) list() []apiCall { f.mu.Lock(); defer f.mu.Unlock(); return slices.Clone(f.calls) }
func (f *fakeAPI) reset()          { f.mu.Lock(); f.calls = nil; f.mu.Unlock() }
func (f *fakeAPI) setFail(url string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail == nil {
		f.fail = map[string]error{}
	}
	f.fail[url] = err
}
func (f *fakeAPI) urls() []string {
	var out []string
	for _, c := range f.list() {
		out = append(out, c.url)
	}
	slices.Sort(out)
	return out
}

func apiHit(kr *fp.Keyring, raw string, c apiCall, kind, url string, v core.Verified) core.Hit {
	loc := c.opts.Loc
	loc.Kind, loc.URL = kind, url
	return core.Hit{
		Engine: "betterleaks", Rule: "github-pat", Type: "github", FP: kr.FP(raw), Shape: fp.Shape(raw), Len: len(raw),
		Entropy: fp.Entropy(raw), Verified: v, Context: fp.Context("token: "+raw, raw), Loc: loc,
	}
}

func TestEventsDriveExactURLScans(t *testing.T) {
	w := newWorld(t)
	api := &fakeAPI{}
	w.cfg.API = api
	a := w.addRepo("a", core.Private)
	a.commit("one", map[string]string{"f": "1\n"})
	r := w.runner()
	mustPoll(t, r)
	if len(api.list()) != 0 {
		t.Fatal("no events, no API scan")
	}

	rawC, rawS := fakeKey(t, "ghp_", 36), fakeKey(t, "ghp_", 36)
	api.emit = func(c apiCall, emit core.Emit) {
		switch c.url {
		case "https://github.com/o/a/issues/1":
			emit(apiHit(w.kr, rawC, c, "comment", "https://github.com/o/a/issues/1#issuecomment-9", core.Unverified))
		case "https://github.com/x/y/pull/3":
			emit(apiHit(w.kr, rawS, c, "pr", "https://github.com/x/y/pull/3", core.Unverified))
		}
	}
	w.inv.events = []core.Event{
		w.event(w.src("a"), "IssueCommentEvent", "2026-11-03T11:00:00Z", "https://github.com/o/a/issues/1#issuecomment-9"),
		w.event(w.src("a"), "IssuesEvent", "2026-11-03T11:00:02Z", "https://github.com/o/a/issues/1"), // the same page: read once
		w.event("github.com/x/y", "PullRequestReviewCommentEvent", "2026-11-03T11:00:01Z", "https://github.com/x/y/pull/3?x=1#discussion_r5"),
		w.event(w.src("a"), "ReleaseEvent", "2026-11-03T11:00:03Z", "https://github.com/o/a/releases/tag/v1.0.0"),
	}
	st := mustPoll(t, r)

	want := []string{"https://github.com/o/a/issues/1", "https://github.com/o/a/releases/tag/v1.0.0", "https://github.com/x/y/pull/3"}
	if got := api.urls(); !slices.Equal(got, want) {
		t.Fatalf("one scan per changed resource, each at its exact page:\n got %v\nwant %v", got, want)
	}
	for _, c := range api.list() {
		if !slices.Contains(c.opts.Env, "GITHUB_TOKEN="+w.token) || c.opts.ReleaseAssets || !c.opts.Verify {
			// Not %+v of the options: their environment holds the token, and a failure must not print it.
			t.Fatalf("%s: token must travel in the environment, release files only in a deep run, verification on (release files %v, verify %v, %d env entries)", c.url, c.opts.ReleaseAssets, c.opts.Verify, len(c.opts.Env))
		}
		wantSrc := w.src("a")
		if strings.Contains(c.url, "/x/y/") {
			wantSrc = "github.com/x/y"
		}
		if c.opts.Loc.Source != wantSrc {
			t.Fatalf("%s: location template %+v", c.url, c.opts.Loc)
		}
	}
	if st.APIResources != 3 {
		t.Fatalf("api_resources = %d, want 3", st.APIResources)
	}
	if es := st.Engines["api"]; es.Hits != 2 || es.Errors != 0 {
		t.Fatalf("api stats %+v", es)
	}
	sc := w.secret(rawC)
	if len(sc.Locations) != 1 || sc.Locations[0].Kind != "comment" || sc.Locations[0].URL == "" || sc.Locations[0].Source != w.src("a") {
		t.Fatalf("comment location: %+v", sc.Locations)
	}
	if ss := w.secret(rawS); !ss.Exposed() {
		t.Fatalf("a key in a repo keyguard does not own is unknown-visibility, which counts as exposed: %+v", ss.Locations)
	}
	state, _ := loadState(w.paths.Sources, w.src("a"))
	if state == nil || state.LastAPI == "" || len(state.ScannedWith) != 3 || len(state.APIPending) != 0 {
		t.Fatalf("the API scan must record its time without disturbing git progress: %+v", state)
	}

	api.reset()
	mustPoll(t, r)
	if len(api.list()) != 0 {
		t.Fatalf("a poll with no new events must not read anything again: %v", api.urls())
	}
}

func TestAPIEventsThatCannotBeScannedAreSaidOutLoud(t *testing.T) {
	w := newWorld(t)
	a := w.addRepo("a", core.Private)
	a.commit("one", map[string]string{"f": "1\n"})
	r := w.runner()
	mustPoll(t, r)
	url := "https://github.com/o/a/issues/1"

	// No engine has the capability.
	w.inv.events = []core.Event{
		w.event(w.src("a"), "IssueCommentEvent", "2026-11-03T11:00:00Z", url),
		{Source: w.src("a"), Type: "CommitCommentEvent"},
		{Source: w.src("a"), Type: "DiscussionEvent"},
		{Source: "github.com/o/ghost.wiki", Type: "GollumEvent"},
	}
	st := mustPoll(t, r)
	for _, want := range []string{"no API scanner is configured", "CommitCommentEvent x1, DiscussionEvent x1", "not in the inventory"} {
		if !hasNote(st, want) {
			t.Errorf("notes lack %q: %v", want, st.Notes)
		}
	}

	// A scanner, but the event names no page.
	api := &fakeAPI{}
	w.cfg.API = api
	r = w.runner()
	w.inv.events = []core.Event{{Source: w.src("a"), Type: "IssuesEvent", At: "2026-11-03T12:00:00Z"}}
	st = mustPoll(t, r)
	if !hasNote(st, "named no scannable resource URL") || len(api.list()) != 0 {
		t.Fatalf("an event with no URL cannot be scanned and must say so: %v", st.Notes)
	}

	// A scanner and a page, but no way to get a token.
	w.cfg.Token = nil
	r = w.runner()
	w.inv.events = []core.Event{w.event(w.src("a"), "IssuesEvent", "2026-11-03T13:00:00Z", url)}
	st = mustPoll(t, r)
	if !hasNote(st, "Config.Token is not set") || len(api.list()) != 0 {
		t.Fatalf("no token source, no scan, and a note: %v", st.Notes)
	}
	if state, _ := loadState(w.paths.Sources, w.src("a")); len(state.APIPending) != 0 {
		t.Fatalf("with no token source nothing can ever be retried, so nothing may pile up: %v", state.APIPending)
	}
}

func TestAFailedAPIScanIsRetriedUntilItWorks(t *testing.T) {
	w := newWorld(t)
	api := &fakeAPI{}
	w.cfg.API = api
	a := w.addRepo("a", core.Private)
	a.commit("one", map[string]string{"f": "1\n"})
	r := w.runner()
	mustPoll(t, r)

	bad, good := "https://github.com/o/a/issues/7", "https://github.com/o/a/pull/8"
	api.setFail(bad, errors.New("HTTP 502"))
	w.inv.events = []core.Event{
		w.event(w.src("a"), "IssuesEvent", "2026-11-03T11:00:00Z", bad),
		w.event(w.src("a"), "PullRequestEvent", "2026-11-03T11:00:01Z", good),
	}
	st := mustPoll(t, r)
	if !hasNote(st, "API scan of "+bad+" failed: HTTP 502") || st.Engines["api"].Errors != 1 {
		t.Fatalf("%+v", st)
	}
	if st.APIResources != 1 {
		t.Fatalf("only the page that was read counts: %d", st.APIResources)
	}
	state, _ := loadState(w.paths.Sources, w.src("a"))
	if !slices.Equal(state.APIPending, []apiTry{{URL: bad, Tries: 1}}) {
		t.Fatalf("events arrive once, so the failed page has to wait on the source's retry list: %v", state.APIPending)
	}

	// No new events. The page is tried again by itself, and still fails.
	api.reset()
	mustPoll(t, r)
	if got := api.urls(); !slices.Equal(got, []string{bad}) {
		t.Fatalf("the retry list is replayed without an event, and only it: %v", got)
	}
	if state, _ = loadState(w.paths.Sources, w.src("a")); !slices.Equal(state.APIPending, []apiTry{{URL: bad, Tries: 2}}) {
		t.Fatalf("still failing, still waiting, one try the older: %v", state.APIPending)
	}

	// GitHub recovers.
	api.reset()
	api.setFail(bad, nil)
	mustPoll(t, r)
	if got := api.urls(); !slices.Equal(got, []string{bad}) {
		t.Fatalf("%v", got)
	}
	if state, _ = loadState(w.paths.Sources, w.src("a")); len(state.APIPending) != 0 || state.LastAPI == "" {
		t.Fatalf("a page that was read leaves the list: %+v", state)
	}
	api.reset()
	mustPoll(t, r)
	if len(api.list()) != 0 {
		t.Fatalf("and is not read again: %v", api.urls())
	}
}

func TestOnlyGitHubPagesOfTheEventsRepoAreEverScanned(t *testing.T) {
	src := core.Source{ID: "github.com/Owner/Repo", Kind: "repo", Owner: "Owner", Name: "Repo"}
	for raw, want := range map[string]string{
		"https://github.com/Owner/Repo/issues/12":                        "https://github.com/Owner/Repo/issues/12",
		"https://github.com/owner/repo/issues/12#issuecomment-5":         "https://github.com/owner/repo/issues/12", // GitHub ids are case-blind
		"https://github.com/Owner/Repo/pull/3?diff=split":                "https://github.com/Owner/Repo/pull/3",
		"https://github.com/Owner/Repo/releases/tag/v1.2.3":              "https://github.com/Owner/Repo/releases/tag/v1.2.3",
		"https://github.com/Owner/Repo/releases/tag/feature/x":           "https://github.com/Owner/Repo/releases/tag/feature/x",
		"https://github.com/Owner/Repo/actions/runs/998877":              "https://github.com/Owner/Repo/actions/runs/998877",
		"https://github.com/Owner/Repo/issues/12/":                       "https://github.com/Owner/Repo/issues/12",
		"http://github.com/Owner/Repo/issues/12":                         "", // not https
		"https://api.github.com/Owner/Repo/issues/12":                    "", // another host would be sent the token
		"https://github.com.evil.example/Owner/Repo/issues/12":           "",
		"https://evil.example/Owner/Repo/issues/12":                      "",
		"https://github.com:8443/Owner/Repo/issues/12":                   "",
		"https://user@github.com/Owner/Repo/issues/12":                   "",
		"https://github.com/Other/Repo/issues/12":                        "", // not the repo the event is about
		"https://github.com/Owner/Elsewhere/pull/3":                      "",
		"https://github.com/Owner/Repo":                                  "", // a whole repo is the deep run's business
		"https://github.com/Owner/Repo/issues":                           "",
		"https://github.com/Owner/Repo/issues/abc":                       "",
		"https://github.com/Owner/Repo/blob/main/.env":                   "", // a file is git's, not the API's
		"https://github.com/Owner/Repo/issues/12/../../../../etc/passwd": "",
		"ftp://github.com/Owner/Repo/issues/12":                          "",
		"":                                                               "",
		"not a url":                                                      "",
	} {
		got, ok := resourceURL(src, raw)
		if ok != (want != "") || got != want {
			t.Errorf("resourceURL(%q) = %q, %v; want %q", raw, got, ok, want)
		}
	}
	if _, ok := resourceURL(core.Source{ID: "github.com/Owner/Repo.wiki", Kind: "wiki", Owner: "Owner", Name: "Repo.wiki"}, "https://github.com/Owner/Repo.wiki/issues/1"); ok {
		t.Error("a wiki has no issues")
	}
}

func TestAnEventPointingAtAnotherRepoNeverGetsAToken(t *testing.T) {
	w := newWorld(t)
	api := &fakeAPI{}
	w.cfg.API = api
	asked := 0
	w.cfg.Token = func(context.Context, string) (string, error) { asked++; return w.token, nil }
	a := w.addRepo("a", core.Private)
	a.commit("one", map[string]string{"f": "1\n"})
	r := w.runner()
	mustPoll(t, r)
	w.inv.events = []core.Event{
		w.event(w.src("a"), "IssuesEvent", "2026-11-03T11:00:00Z", "https://github.com/someone/else/issues/1"),
		w.event(w.src("a"), "IssuesEvent", "2026-11-03T11:00:01Z", "https://evil.example/o/a/issues/1"),
	}
	st := mustPoll(t, r)
	if len(api.list()) != 0 || asked != 0 {
		t.Fatalf("a URL the event's repo does not own must be dropped before anything is asked for: %d scans, %d token requests", len(api.list()), asked)
	}
	if !hasNote(st, "2 issue, pull request or release event(s) named no scannable resource URL") {
		t.Fatalf("%v", st.Notes)
	}
}

func TestTheTokenStaysInTheScannersEnvironment(t *testing.T) {
	w := newWorld(t)
	api := &fakeAPI{}
	w.cfg.API = api
	a := w.addRepo("a", core.Private)
	a.commit("one", map[string]string{"f": "1\n"})
	r := w.runner()
	mustPoll(t, r)
	url := "https://github.com/o/a/issues/1"
	// A careless tool that echoes the token it was given in its failure.
	api.setFail(url, errors.New("GET https://api.github.com/graphql: 401 Bad credentials for token "+w.token))
	w.inv.events = []core.Event{w.event(w.src("a"), "IssuesEvent", "2026-11-03T11:00:00Z", url)}
	st, err := r.Poll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(api.list()) != 1 {
		t.Fatalf("the scan did not run: %v", st.Notes)
	}
	everything := strings.Join(st.Notes, "\n") + w.allFiles()
	if strings.Contains(everything, w.token) || strings.Contains(everything, w.token[4:]) {
		t.Fatal("the GitHub token reached a note or a file under the keyguard home")
	}
	if !hasNote(st, "failed") {
		t.Fatalf("the failure itself must still be said: %v", st.Notes)
	}
}

func TestAMissingTokenKeepsTheResourcesForLater(t *testing.T) {
	w := newWorld(t)
	api := &fakeAPI{}
	w.cfg.API = api
	have := false
	w.cfg.Token = func(_ context.Context, acct string) (string, error) {
		if !have {
			return "", errors.New("gh: no oauth token found for " + acct)
		}
		return w.token, nil
	}
	a := w.addRepo("a", core.Private)
	a.commit("one", map[string]string{"f": "1\n"})
	r := w.runner()
	mustPoll(t, r)
	url := "https://github.com/o/a/issues/4"
	w.inv.events = []core.Event{w.event(w.src("a"), "IssuesEvent", "2026-11-03T11:00:00Z", url)}
	st := mustPoll(t, r)
	if !hasNote(st, "no GitHub token") || len(api.list()) != 0 {
		t.Fatalf("%v", st.Notes)
	}
	for range maxAPITries + 2 {
		mustPoll(t, r) // a day without a token is not the page's fault, and costs it no try
	}
	have = true
	mustPoll(t, r)
	if got := api.urls(); !slices.Equal(got, []string{url}) {
		t.Fatalf("once a token exists the page waiting for it is read: %v", got)
	}
}

func TestWikiPushEventScansTheWikiThoughPushedAtDidNotMove(t *testing.T) {
	w := newWorld(t)
	a := w.addRepo("a", core.Private)
	a.commit("one", map[string]string{"f": "1\n"})
	wiki := newRepo(t, filepath.Join(w.root, "origins", "a.wiki"))
	w.mir.origins["github.com/o/a.wiki"] = wiki.dir
	w.inv.list = append(w.inv.list, core.Source{ID: "github.com/o/a.wiki", Kind: "wiki", Owner: "o", Name: "a.wiki", Account: "o", Visibility: core.Private, PushedAt: w.pushedAt()})
	wiki.commit("Home", map[string]string{"Home.md": "hello\n"})
	r := w.runner()
	mustPoll(t, r)
	w.resetCalls()

	raw := fakeKey(t, "sk-", 48)
	w.plantAll(raw, "openai", core.Unverified)
	c2 := wiki.commit("oops", map[string]string{"Setup.md": "key: " + raw + "\n"})
	if st := mustPoll(t, r); st.Sources != 0 || w.engineCalls() != 0 {
		t.Fatalf("setup: without an event nothing tells the sweep the wiki changed: %+v", st)
	}
	w.inv.events = []core.Event{{Source: "github.com/o/a.wiki", Type: "GollumEvent"}}
	st := mustPoll(t, r)
	if st.Scanned != 1 {
		t.Fatalf("the wiki event did not trigger a scan: %+v", st)
	}
	for _, e := range w.engines {
		if c := e.callList(); len(c) != 1 || c[0].rng.All || commitsOf(c[0]) != c2[:7] {
			t.Fatalf("%s: %+v", e.name, c)
		}
	}
	s := w.secret(raw)
	if s.Locations[0].Source != "github.com/o/a.wiki" || s.Locations[0].Path != "Setup.md" || s.Locations[0].Kind != "wiki" {
		t.Fatalf("%+v", s.Locations)
	}
}

func TestGitEventForASourceAlreadyQueuedIsNotScannedTwice(t *testing.T) {
	w := newWorld(t)
	a := w.addRepo("a", core.Private)
	a.commit("one", map[string]string{"f": "1\n"})
	r := w.runner()
	mustPoll(t, r)
	a.commit("two", map[string]string{"g": "2\n"})
	w.pushed("a")
	w.resetCalls()
	w.inv.events = []core.Event{{Source: w.src("a"), Type: "CreateEvent"}, {Source: w.src("a"), Type: "PublicEvent"}}
	st := mustPoll(t, r)
	if st.Sources != 1 || w.mir.syncCount(w.src("a")) != 2 {
		t.Fatalf("%+v, %d syncs", st, w.mir.syncCount(w.src("a")))
	}
}

// pageListerFake is an inventory that can list every page of the repos it is given.
type pageListerFake struct {
	*fakeInventory
	mu    sync.Mutex
	asked [][]string
	pages []Activity
	err   error
}

func (p *pageListerFake) ListPages(_ context.Context, repos []core.Source) ([]Activity, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	var ids []string
	for _, r := range repos {
		ids = append(ids, r.ID)
	}
	p.asked = append(p.asked, ids)
	return p.pages, p.err
}

func TestDeepReadsEveryPageOfEachExposedRepoAndFullDoesNot(t *testing.T) {
	w := newWorld(t)
	w.cfg.ExposedOnly = true
	api := &fakeAPI{}
	w.cfg.API = api
	pl := &pageListerFake{fakeInventory: w.inv}
	w.cfg.Inventory = pl
	pub := w.addRepo("pub", core.Public)
	priv := w.addRepo("priv", core.Private)
	pub.commit("one", map[string]string{"f": "1\n"})
	priv.commit("one", map[string]string{"f": "1\n"})
	wiki := newRepo(t, filepath.Join(w.root, "origins", "pub.wiki"))
	wiki.commit("Home", map[string]string{"Home.md": "hi\n"})
	w.mir.origins["github.com/o/pub.wiki"] = wiki.dir
	w.inv.list = append(w.inv.list, core.Source{ID: "github.com/o/pub.wiki", Kind: "wiki", Owner: "o", Name: "pub.wiki", Account: "o", Visibility: core.Public, PushedAt: w.pushedAt()})
	pl.pages = []Activity{
		{Source: w.src("pub"), Kind: "issue", URL: "https://github.com/o/pub/issues/1"},
		{Source: w.src("pub"), Kind: "issue", URL: "https://github.com/o/pub/issues/2"},
		{Source: w.src("pub"), Kind: "release", URL: "https://github.com/o/pub/releases/tag/v1"},
		{Source: w.src("priv"), Kind: "issue", URL: "https://github.com/o/priv/issues/1"},      // not asked for, and private
		{Source: w.src("pub"), Kind: "issue", URL: "https://github.com/someone/else/issues/9"}, // not this repo's page
	}
	r := w.runner()
	mustPoll(t, r)
	api.reset()

	if _, err := r.Full(context.Background()); err != nil || len(api.list()) != 0 || len(pl.asked) != 0 {
		t.Fatalf("a full run is git only: %v, %d API calls, %d listings", err, len(api.list()), len(pl.asked))
	}
	st, err := r.Deep(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(pl.asked) != 1 || !slices.Equal(pl.asked[0], []string{w.src("pub")}) {
		t.Fatalf("the listing is asked about the exposed repos only, not wikis or private repos: %v", pl.asked)
	}
	want := []string{"https://github.com/o/pub/issues/1", "https://github.com/o/pub/issues/2", "https://github.com/o/pub/releases/tag/v1"}
	if got := api.urls(); !slices.Equal(got, want) {
		t.Fatalf("deep reads every page listed, each by its exact URL:\n got %v\nwant %v", got, want)
	}
	for _, c := range api.list() {
		if !c.opts.ReleaseAssets {
			t.Fatalf("the weekly run is the one that opens release files: %s", c.url)
		}
	}
	if st.APIResources != 3 || !hasNote(st, "2 page(s) the inventory listed are not pages of an exposed repo") {
		t.Fatalf("%+v", st)
	}
}

func TestDeepSaysSoWhenItCannotListOrScan(t *testing.T) {
	w := newWorld(t)
	w.addRepo("pub", core.Public).commit("one", map[string]string{"f": "1\n"})
	st, err := w.runner().Deep(context.Background())
	if err != nil || !hasNote(st, "deep run: no API scanner is configured") {
		t.Fatalf("%v %v", err, st.Notes)
	}
	w.cfg.API = &fakeAPI{}
	st, err = w.runner().Deep(context.Background())
	if err != nil || !hasNote(st, "the inventory cannot list every page of a repo") {
		t.Fatalf("a scanner, but nobody to list what to scan: %v %v", err, st.Notes)
	}
	// An inventory whose listing fails is a note, and the run goes on.
	pl := &pageListerFake{fakeInventory: w.inv, err: errors.New("HTTP 502")}
	w.cfg.Inventory = pl
	st, err = w.runner().Deep(context.Background())
	if err != nil || !hasNote(st, "listing the pages of the repos: HTTP 502") {
		t.Fatalf("%v %v", err, st.Notes)
	}
}

func TestAPageThatNeverWorksIsGivenUpOnAfterEightTries(t *testing.T) {
	w := newWorld(t)
	api := &fakeAPI{}
	w.cfg.API = api
	w.addRepo("a", core.Private).commit("one", map[string]string{"f": "1\n"})
	r := w.runner()
	mustPoll(t, r)
	bad := "https://github.com/o/a/issues/404"
	api.setFail(bad, errors.New("not found"))
	w.inv.events = []core.Event{w.event(w.src("a"), "IssuesEvent", "2026-11-03T11:00:00Z", bad)}
	var last core.RunStats
	for range maxAPITries {
		last = mustPoll(t, r)
	}
	if got := len(api.list()); got != maxAPITries {
		t.Fatalf("%d tries", got)
	}
	if !hasNote(last, "failed 8 times in a row and were given up on") {
		t.Fatalf("%v", last.Notes)
	}
	if state, _ := loadState(w.paths.Sources, w.src("a")); len(state.APIPending) != 0 {
		t.Fatalf("%v", state.APIPending)
	}
	api.reset()
	if mustPoll(t, r); len(api.list()) != 0 {
		t.Fatal("a page that was given up on is not tried again")
	}
}

func TestSourceFromID(t *testing.T) {
	for id, want := range map[string]core.Source{
		"github.com/x/y":        {ID: "github.com/x/y", Kind: "repo", Owner: "x", Name: "y", Visibility: core.Unknown},
		"github.com/x/y.wiki":   {ID: "github.com/x/y.wiki", Kind: "wiki", Owner: "x", Name: "y.wiki", Visibility: core.Unknown},
		"gist.github.com/x/abc": {ID: "gist.github.com/x/abc", Kind: "gist", Owner: "x", Name: "abc", Visibility: core.Unknown},
		"odd":                   {ID: "odd", Kind: "repo", Visibility: core.Unknown},
	} {
		if got := sourceFromID(id); got != want {
			t.Errorf("sourceFromID(%q) = %+v, want %+v", id, got, want)
		}
	}
}
