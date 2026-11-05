package inventory

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"keyguard/internal/core"
	"keyguard/internal/inventory/ghcli/ghclitest"
)

func failReply(status int) ghclitest.Reply {
	return ghclitest.JSON(status, map[string]string{"message": "Bad Gateway"})
}

// readAccounts reads the per-account block of the state file the way v1's tests do.
func readAccounts(t *testing.T, fx *fixture) map[string]eventState {
	t.Helper()
	return readState(t, fx)
}

// quietWorld is a world where nothing was pushed for weeks, so that an empty feed is not
// suspicious.
func quietWorld() *world {
	w := newWorld()
	w.add(wrepo{owner: "hangryclaude", name: "old", vis: "PUBLIC", pushed: "2026-09-01T00:00:00Z"})
	w.add(wrepo{owner: "alt-builds", name: "older", vis: "PUBLIC", pushed: "2026-08-01T00:00:00Z"})
	w.orgs["acme-apps"] = []string{"hangryclaude"}
	w.orgs["Loony-Labs-Video"] = []string{"hangryclaude"}
	return w
}

// STEAL P0-21: alt-builds' /events returns [] although three of its repos were pushed. An empty
// feed is not a quiet account.
func TestAnEmptyFeedBesideARecentPushIsMarkedUnusable(t *testing.T) {
	w := standardWorld()
	w.feeds["hangryclaude"] = feed(2, 1, "WatchEvent", "someone/else", "2026-09-01") // works
	// alt-builds' feed stays empty, and foxtrot was pushed on 2026-11-02, two days before.
	fx := watchFixture(t, w, nil)
	prev := baseline(t, fx)
	p := fx.pollOK(prev)

	if usable, known := p.EventsUsable["alt-builds"]; !known || usable {
		t.Errorf("EventsUsable = %v: alt-builds' feed is empty while its repo was pushed two days ago", p.EventsUsable)
	}
	if usable, known := p.EventsUsable["hangryclaude"]; !known || !usable {
		t.Errorf("EventsUsable = %v: hangryclaude's feed has events in it", p.EventsUsable)
	}
	st := readAccounts(t, fx)
	if st["alt-builds"].Usable != triNo || st["hangryclaude"].Usable != triYes {
		t.Errorf("state = %+v", st)
	}
	raw, _ := os.ReadFile(filepath.Join(fx.cfg.StateDir, "events.json"))
	if !strings.Contains(string(raw), `"events_usable": false`) || !strings.Contains(string(raw), `"events_usable": true`) {
		t.Errorf("events_usable must be a JSON boolean in the state file:\n%s", raw)
	}
}

func TestAnEmptyFeedOfAQuietAccountSaysNothingEitherWay(t *testing.T) {
	w := quietWorld()
	fx := watchFixture(t, w, nil)
	prev := baseline(t, fx)
	p := fx.pollOK(prev)
	if len(p.EventsUsable) != 0 {
		t.Errorf("EventsUsable = %v: no push in a week, so an empty feed proves nothing", p.EventsUsable)
	}
	if st := readAccounts(t, fx)["alt-builds"]; st.Usable != triUnknown || st.Checked == "" || st.Count != 0 {
		t.Errorf("state = %+v: read, empty, and not judged", st)
	}
	// Then the account is pushed to, and the same empty feed is a verdict.
	w.find("alt-builds", "older").pushed = "2026-11-03T11:00:00Z"
	fx.advance(time.Minute)
	p = fx.pollOK(prev)
	if usable, known := p.EventsUsable["alt-builds"]; !known || usable {
		t.Errorf("EventsUsable = %v after a push", p.EventsUsable)
	}
}

func TestAFeedThatCameBackToLifeIsUsableAgain(t *testing.T) {
	w := standardWorld()
	fx := watchFixture(t, w, nil)
	prev := baseline(t, fx)
	if p := fx.pollOK(prev); p.EventsUsable["alt-builds"] {
		t.Fatalf("setup: %v", p.EventsUsable)
	}
	w.feeds["alt-builds"] = feed(3, 1, "IssuesEvent", "alt-builds/foxtrot", "2026-11-03")
	fx.advance(time.Minute)
	if p := fx.pollOK(prev); !p.EventsUsable["alt-builds"] {
		t.Errorf("EventsUsable = %v after the feed filled", p.EventsUsable)
	}
}

// A 304 carries no list, so what the feed held has to be remembered with its ETag.
func TestAnUnusableVerdictSurvivesA304AndARestart(t *testing.T) {
	w := standardWorld()
	w.feeds["hangryclaude"] = feed(2, 1, "WatchEvent", "someone/else", "2026-09-01")
	fx := watchFixture(t, w, nil)
	prev := baseline(t, fx)
	fx.pollOK(prev)

	fx.advance(time.Minute)
	from := len(fx.f.Calls())
	again, err := fx.fresh().Poll(context.Background(), prev) // a new process: the verdict comes from disk
	if err != nil {
		t.Fatal(err)
	}
	var sentETag bool
	for _, c := range fx.f.Calls()[from:] {
		if strings.HasPrefix(c.Path, "users/alt-builds/events") && c.Header["If-None-Match"] != "" {
			sentETag = true
		}
	}
	if !sentETag {
		t.Fatal("the empty feed was asked without its ETag")
	}
	if usable, known := again.EventsUsable["alt-builds"]; !known || usable {
		t.Errorf("EventsUsable = %v: a 304 on an empty feed is still an empty feed", again.EventsUsable)
	}
}

func TestAFailedEventsReadLeavesTheVerdictAlone(t *testing.T) {
	w := standardWorld()
	fx := watchFixture(t, w, nil)
	prev := baseline(t, fx)
	fx.pollOK(prev)
	before := readAccounts(t, fx)
	w.fail["alt-builds events"] = failReply(502)
	fx.advance(time.Minute)
	if _, err := fx.inv.Poll(context.Background(), prev); err == nil {
		t.Fatal("a failed events request was not reported")
	}
	if after := readAccounts(t, fx); after["alt-builds"] != before["alt-builds"] {
		t.Errorf("a failed read moved the state: %+v -> %+v", before["alt-builds"], after["alt-builds"])
	}
}

func activityOf(p PollResult) []string {
	var out []string
	for _, a := range p.Activity {
		out = append(out, a.Kind+" "+a.URL)
	}
	return out
}

// The fallback finds, through GraphQL, what the feed would have said: issues and pull requests
// that involve the account, updated since the cursor, by exact page, and the newest releases.
func TestTheFallbackListsActivityByExactPageSinceTheCursor(t *testing.T) {
	w := standardWorld()
	w.feeds["hangryclaude"] = feed(2, 1, "WatchEvent", "someone/else", "2026-09-01")
	w.items = []witem{
		{login: "alt-builds", owner: "alt-builds", repo: "foxtrot", kind: "Issue", number: 7, updated: "2026-11-03T11:00:00Z"},
		{login: "alt-builds", owner: "alt-builds", repo: "foxtrot", kind: "PullRequest", number: 9, updated: "2026-11-03T11:30:00Z"},
		{login: "alt-builds", owner: "someone-else", repo: "their-repo", kind: "Issue", number: 3, updated: "2026-11-03T11:45:00Z"},
		{login: "alt-builds", owner: "alt-builds", repo: "foxtrot", kind: "Issue", number: 1, updated: "2026-10-01T00:00:00Z"},   // older than the cursor
		{login: "hangryclaude", owner: "hangryclaude", repo: "alpha", kind: "Issue", number: 5, updated: "2026-11-03T11:00:00Z"}, // its feed works: not asked
	}
	w.releases["alt-builds/foxtrot"] = []wrelease{{tag: "v1.2", updated: "2026-11-03T11:10:00Z"}, {tag: "v1.0", updated: "2026-09-01T00:00:00Z"}}
	fx := watchFixture(t, w, nil)
	prev := baseline(t, fx)
	p := fx.pollOK(prev)

	want := []string{
		"issue https://github.com/alt-builds/foxtrot/issues/7",
		"release https://github.com/alt-builds/foxtrot/releases/tag/v1.2",
		"pr https://github.com/alt-builds/foxtrot/pull/9",
		"issue https://github.com/someone-else/their-repo/issues/3",
	}
	if got := activityOf(p); !slices.Equal(got, want) {
		t.Fatalf("activity:\n got %v\nwant %v", got, want)
	}
	for _, a := range p.Activity {
		if a.At == "" || !strings.HasPrefix(a.URL, "https://github.com/") {
			t.Errorf("activity %+v", a)
		}
	}
	var body struct {
		Query     string         `json:"query"`
		Variables map[string]any `json:"variables"`
	}
	for _, c := range fx.f.Calls() {
		if c.Path == "graphql" && strings.Contains(string(c.Body), "query Activity") {
			if err := json.Unmarshal(c.Body, &body); err != nil {
				t.Fatal(err)
			}
		}
	}
	// Nothing has been listed yet, so the first listing reaches back one event window from
	// GitHub's now (2026-11-03T12:00:00Z).
	if got := body.Variables["q"]; got != "involves:alt-builds updated:>=2026-11-02T12:00:00Z" {
		t.Errorf("search = %q: it must be by the account and the cursor", got)
	}
	if strings.Contains(body.Query, "hangryclaude") || strings.Contains(fmt.Sprint(body.Variables), "hangryclaude") {
		t.Error("an account whose feed works was asked for a fallback")
	}
	assertNoParameterFlags(t, fx.f)
	// The cursor moved to the newest thing seen less ten minutes.
	if want := time.Date(2026, 11, 3, 11, 35, 0, 0, time.UTC); !p.Cursor["alt-builds"].Equal(want) {
		t.Errorf("cursor = %s, want %s", p.Cursor["alt-builds"], want)
	}

	// Next poll lists from there: only what moved since.
	w.items = append(w.items, witem{login: "alt-builds", owner: "alt-builds", repo: "foxtrot", kind: "Issue", number: 7, updated: "2026-11-03T11:58:00Z"})
	w.items = slices.DeleteFunc(w.items, func(it witem) bool { return it.number == 7 && it.updated == "2026-11-03T11:00:00Z" })
	fx.advance(time.Minute)
	p = fx.pollOK(prev)
	// The second listing starts ten minutes before the first began (11:50), so everything before
	// that is behind it, and the comment that moved the old issue 7 to 11:58 shows: a listing by
	// creation date would miss it.
	if got := activityOf(p); !slices.Equal(got, []string{"issue https://github.com/alt-builds/foxtrot/issues/7"}) {
		t.Errorf("second listing = %v", got)
	}
}

// What the listing covers is what was listed, not what else happened: a push or an event seen
// while nothing was listing must not move the point it resumes from, or an issue updated in the
// meantime is skipped for good.
func TestTheFallbackResumesFromWhatItListedNotFromWhatItSaw(t *testing.T) {
	w := standardWorld()
	w.feeds["hangryclaude"] = feed(2, 1, "WatchEvent", "someone/else", "2026-09-01")
	w.items = []witem{{login: "alt-builds", owner: "alt-builds", repo: "foxtrot", kind: "Issue", number: 7, updated: "2026-11-03T09:00:00Z"}}
	fx := watchFixture(t, w, nil)
	prev := baseline(t, fx)
	// The listing fails (GitHub is down for it); everything else works and sees a push at 11:59.
	w.fail["alt-builds Activity"] = failReply(502)
	w.find("alt-builds", "foxtrot").pushed = "2026-11-03T11:59:00Z"
	if _, err := fx.inv.Poll(context.Background(), prev); err == nil {
		t.Fatal("the failed listing was not reported")
	}
	st := readAccounts(t, fx)["alt-builds"]
	if st.Listed != "" || st.Pushed != "2026-11-03T11:59:00Z" {
		t.Fatalf("state = %+v: the push was seen, the listing was not made", st)
	}
	delete(w.fail, "alt-builds Activity")
	fx.advance(time.Minute)
	p := fx.pollOK(prev)
	if got := activityOf(p); !slices.Equal(got, []string{"issue https://github.com/alt-builds/foxtrot/issues/7"}) {
		t.Errorf("activity = %v: the issue updated at 09:00 must still be found, though a push at 11:59 was seen since", got)
	}
}

// The fallback lists from a cursor ten minutes behind the newest thing, so on a poll a minute it
// would hand out the same page ten times and have it scanned ten times. A page goes out once per
// time GitHub gives it, and again when it is written to again; and a new process remembers.
func TestTheFallbackHandsEachPageOutOncePerUpdate(t *testing.T) {
	w := standardWorld()
	w.feeds["hangryclaude"] = feed(2, 1, "WatchEvent", "someone/else", "2026-09-01")
	w.items = []witem{{login: "alt-builds", owner: "alt-builds", repo: "foxtrot", kind: "Issue", number: 7, updated: "2026-11-03T11:50:00Z"}}
	fx := watchFixture(t, w, nil)
	prev := baseline(t, fx)

	if first := fx.pollOK(prev); len(first.Activity) != 1 {
		t.Fatalf("first poll = %v", activityOf(first))
	}
	for i := 1; i <= 5; i++ { // five more minutes inside the overlap
		fx.advance(time.Minute)
		if p := fx.pollOK(prev); len(p.Activity) != 0 {
			t.Fatalf("minute %d: %v went out again", i, activityOf(p))
		}
	}
	fx.advance(time.Minute)
	if p, err := fx.fresh().Poll(context.Background(), prev); err != nil || len(p.Activity) != 0 {
		t.Errorf("a new process handed out %v again (err %v): the state must remember", activityOf(p), err)
	}
	w.items[0].updated = "2026-11-03T12:05:00Z" // a new comment
	fx.advance(time.Minute)
	if p := fx.pollOK(prev); len(p.Activity) != 1 || p.Activity[0].At != "2026-11-03T12:05:00Z" {
		t.Errorf("after a new comment: %v", activityOf(p))
	}
	raw, _ := os.ReadFile(filepath.Join(fx.cfg.StateDir, "events.json"))
	if !strings.Contains(string(raw), `"_delivered"`) {
		t.Errorf("the state file does not hold what was handed out:\n%s", raw)
	}
	// The cursor moves with activity and not with the clock, so on a quiet account the same page
	// is listed hours later, and must still not go out again.
	fx.advance(3 * time.Hour)
	if p := fx.pollOK(prev); len(p.Activity) != 0 {
		t.Errorf("three quiet hours later %v went out again", activityOf(p))
	}
	// Once something newer moves the cursor past a page, it is forgotten, so the file does not
	// grow for ever.
	w.items = append(w.items, witem{login: "alt-builds", owner: "alt-builds", repo: "foxtrot", kind: "PullRequest", number: 11, updated: "2026-11-03T15:00:00Z"})
	fx.advance(time.Minute)
	if p := fx.pollOK(prev); len(p.Activity) != 1 || !strings.HasSuffix(p.Activity[0].URL, "/pull/11") {
		t.Fatalf("new activity: %v", activityOf(p))
	}
	fx.advance(time.Minute)
	fx.pollOK(prev)
	raw, _ = os.ReadFile(filepath.Join(fx.cfg.StateDir, "events.json"))
	if strings.Contains(string(raw), "/issues/7") || !strings.Contains(string(raw), "/pull/11") {
		t.Errorf("the page the cursor has passed is still remembered, or the new one is not:\n%s", raw)
	}
}

func TestTheFallbackIsNotAskedWhenTheFeedWorks(t *testing.T) {
	w := standardWorld()
	usableFeeds(w)
	fx := watchFixture(t, w, nil)
	fx.pollOK(baseline(t, fx))
	if w.opCount("Activity") != 0 {
		t.Errorf("ops = %v: two working feeds need no fallback", w.ops)
	}
}

func TestTheFallbackSaysSoWhenThereIsMoreThanItReadsAndKeepsTheCursor(t *testing.T) {
	w := standardWorld()
	w.feeds["hangryclaude"] = feed(2, 1, "WatchEvent", "someone/else", "2026-09-01")
	w.moreActivity = true
	w.items = []witem{{login: "alt-builds", owner: "alt-builds", repo: "foxtrot", kind: "Issue", number: 7, updated: "2026-11-03T11:00:00Z"}}
	fx := watchFixture(t, w, nil)
	prev := baseline(t, fx)
	p, err := fx.inv.Poll(context.Background(), prev)
	if err == nil || !strings.Contains(err.Error(), "weekly deep scan") {
		t.Fatalf("err = %v: more results than a page must be said out loud", err)
	}
	if len(p.Activity) != 1 {
		t.Errorf("activity = %v: what was read still counts", activityOf(p))
	}
}

func TestTheFallbackKeepsItsCursorWhenGitHubRefuses(t *testing.T) {
	w := standardWorld()
	w.feeds["hangryclaude"] = feed(2, 1, "WatchEvent", "someone/else", "2026-09-01")
	w.fail["alt-builds Activity"] = failReply(502)
	fx := watchFixture(t, w, nil)
	prev := baseline(t, fx)
	p, err := fx.inv.Poll(context.Background(), prev)
	if err == nil || !strings.Contains(err.Error(), "activity of alt-builds") {
		t.Fatalf("err = %v", err)
	}
	if len(p.Activity) != 0 {
		t.Errorf("activity = %v", activityOf(p))
	}
	st := readAccounts(t, fx)["alt-builds"]
	if st.Seen != "2026-11-02T01:00:00Z" {
		t.Errorf("Seen = %q: it moves with what was read (the push), not past the listing that failed", st.Seen)
	}
}

// A feed that works names the pages its events are about, from numbers and a tag in the payload,
// and never keeps the text beside them.
func TestAFeedThatWorksNamesTheExactPagesItsEventsAreAbout(t *testing.T) {
	w := standardWorld()
	usableFeeds(w)
	w.feeds["hangryclaude"] = []wevent{
		{id: "70", typ: "ReleaseEvent", repo: "hangryclaude/alpha", at: "2026-11-03T11:50:00Z", tag: "v2.0 beta/1"},
		{id: "69", typ: "PullRequestReviewCommentEvent", repo: "someone-else/their-repo", at: "2026-11-03T11:40:00Z", number: 12},
		{id: "68", typ: "IssueCommentEvent", repo: "hangryclaude/bravo", at: "2026-11-03T11:30:00Z", number: 4},
		{id: "67", typ: "IssuesEvent", repo: "hangryclaude/bravo", at: "2026-11-03T11:20:00Z", number: 4},
		{id: "66", typ: "PullRequestEvent", repo: "hangryclaude/alpha", at: "2026-11-03T11:10:00Z", number: 8},
		{id: "65", typ: "IssuesEvent", repo: "../../etc/passwd", at: "2026-11-03T11:00:00Z", number: 1},   // not a repo
		{id: "64", typ: "IssuesEvent", repo: "hangryclaude/bravo", at: "2026-11-03T10:50:00Z", number: 0}, // no number
		{id: "63", typ: "WatchEvent", repo: "hangryclaude/bravo", at: "2026-11-03T10:40:00Z"},
	}
	fx := watchFixture(t, w, nil)
	p := fx.pollOK(baseline(t, fx))
	want := []string{
		"pr https://github.com/hangryclaude/alpha/pull/8",
		"issue https://github.com/hangryclaude/bravo/issues/4",
		"pr https://github.com/someone-else/their-repo/pull/12",
		"release https://github.com/hangryclaude/alpha/releases/tag/v2.0%20beta%2F1",
	}
	if got := activityOf(p); !slices.Equal(got, want) {
		t.Fatalf("activity:\n got %v\nwant %v", got, want)
	}
	b, _ := json.Marshal(p)
	if strings.Contains(string(b), "free text that may hold a key") {
		t.Error("payload text reached the poll result")
	}
	raw, _ := os.ReadFile(filepath.Join(fx.cfg.StateDir, "events.json"))
	if strings.Contains(string(raw), "free text that may hold a key") {
		t.Error("payload text reached the state file")
	}
}

func TestPageURLsAreBuiltFromValidatedPartsOnly(t *testing.T) {
	for _, tc := range []struct {
		owner, name, kind string
		n                 int
		tag               string
		want              string
		ok                bool
	}{
		{"o", "r", "issue", 7, "", "https://github.com/o/r/issues/7", true},
		{"o", "r", "pr", 7, "", "https://github.com/o/r/pull/7", true},
		{"o", "r", "release", 0, "v1", "https://github.com/o/r/releases/tag/v1", true},
		{"o", "r", "release", 0, "a/b c", "https://github.com/o/r/releases/tag/a%2Fb%20c", true},
		{"o", "r", "issue", 0, "", "", false},
		{"o", "r", "release", 0, "", "", false},
		{"o", "r", "release", 0, strings.Repeat("x", 201), "", false},
		{"o", "r", "release", 0, "a\nb", "", false},
		{"o/x", "r", "issue", 1, "", "", false},
		{"o", "..", "issue", 1, "", "", false},
		{"o", "r", "commit", 1, "", "", false},
		{"-o", "r", "issue", 1, "", "", false},
	} {
		got, ok := pageURL(tc.owner, tc.name, tc.kind, tc.n, tc.tag)
		if ok != tc.ok || (ok && got != tc.want) {
			t.Errorf("pageURL(%q,%q,%q,%d,%q) = %q, %v; want %q, %v", tc.owner, tc.name, tc.kind, tc.n, tc.tag, got, ok, tc.want, tc.ok)
		}
	}
}

// STEAL P0-21: flips are found by comparing visibility between snapshots, whatever the feed does.
func TestAFlipIsFoundByDiffingSnapshotsWhenTheFeedIsDead(t *testing.T) {
	w := standardWorld() // both feeds empty
	fx := watchFixture(t, w, nil)
	prev := baseline(t, fx)
	fx.pollOK(prev)
	fx.advance(time.Minute)
	w.find("alt-builds", "golf").vis = "PUBLIC"
	p := fx.pollOK(prev)
	if len(p.Flips) != 1 || p.Flips[0].Source.ID != "github.com/alt-builds/golf" || !p.Flips[0].Opened() {
		t.Fatalf("flips = %+v", p.Flips)
	}
	if p.Changed[0].ID != "github.com/alt-builds/golf" {
		t.Errorf("changed = %v: the flip comes first", ids(p.Changed))
	}
	if !slices.ContainsFunc(p.Events, func(e core.Event) bool { return e.Type == "PublicEvent" && e.Source == "github.com/alt-builds/golf" }) {
		t.Errorf("events = %+v: a dead feed never delivers the PublicEvent, so the poll supplies it", p.Events)
	}
}
