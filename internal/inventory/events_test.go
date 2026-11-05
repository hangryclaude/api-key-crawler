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

func stateFixture(t *testing.T, w *world, mod func(*Config)) *fixture {
	t.Helper()
	var state string
	return newFixture(t, w, func(c *Config) {
		state = filepath.Join(c.StateDir, "state")
		c.StateDir = state
		if mod != nil {
			mod(c)
		}
	})
}

func readState(t *testing.T, fx *fixture) map[string]eventState {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(fx.cfg.StateDir, "events.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]eventState
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func feed(first, last int, typ, repo, day string) []wevent {
	var out []wevent
	for i := first; i >= last; i-- { // newest first, as the API serves them
		out = append(out, wevent{id: fmt.Sprint(i), typ: typ, repo: repo, at: fmt.Sprintf("%sT11:%02d:00Z", day, i%60)})
	}
	return out
}

func TestEventsMapToSourcesAndDropTheRest(t *testing.T) {
	raw, err := os.ReadFile("testdata/events_page.json")
	if err != nil {
		t.Fatal(err)
	}
	w := standardWorld()
	h := w.handler(t)
	fx := newFixtureH(t, w, func(c ghclitest.Call) ghclitest.Reply {
		if strings.HasPrefix(c.Path, "users/hangryclaude/events") {
			return ghclitest.Reply{Status: 200, Body: raw, Header: map[string]string{"Etag": `"fixture"`}}
		}
		return h(c)
	}, nil)

	_, events := poll(t, fx, Index(nil))
	want := []core.Event{
		{Source: "github.com/someone-else/their-repo", Type: "PullRequestReviewCommentEvent", At: "2026-11-03T10:20:00Z"},
		{Source: "github.com/alt-builds/foxtrot", Type: "CreateEvent", At: "2026-11-03T10:30:00Z"},
		{Source: "github.com/hangryclaude/alpha", Type: "ReleaseEvent", At: "2026-11-03T10:50:00Z"},
		{Source: "github.com/someone-else/their-repo", Type: "IssueCommentEvent", At: "2026-11-03T11:20:00Z"},
		{Source: "github.com/acme-apps/india", Type: "PublicEvent", At: "2026-11-03T11:30:00Z"},
		{Source: "github.com/hangryclaude/alpha.wiki", Type: "GollumEvent", At: "2026-11-03T11:40:00Z"},
		{Source: "gist.github.com/hangryclaude/2c3d4e5f60718293a4b5c6d7e8f9a0b1", Type: "GistEvent", At: "2026-11-03T11:50:00Z"},
	}
	if !slices.Equal(events, want) {
		t.Fatalf("events:\n got %+v\nwant %+v", events, want)
	}
	if st := readState(t, fx)["hangryclaude"]; st.ETag != `"fixture"` || st.LastID != 9000000010 {
		t.Errorf("state = %+v: the high-water mark covers events that were filtered out too", st)
	}
}

func TestEventsETagIsPersistedAndAnUnchangedFeedCostsNothing(t *testing.T) {
	w := standardWorld()
	w.feeds["hangryclaude"] = feed(3, 1, "IssuesEvent", "hangryclaude/bravo", "2026-11-03")
	fx := stateFixture(t, w, nil)
	prev := baseline(t, fx)

	_, events := poll(t, fx, prev)
	if len(events) != 3 || events[0].At > events[2].At {
		t.Fatalf("events = %+v, want 3 oldest first", events)
	}
	st := readState(t, fx)["hangryclaude"]
	if st.ETag != etagOf(w.feeds["hangryclaude"]) || st.LastID != 3 {
		t.Fatalf("state = %+v", st)
	}
	file := filepath.Join(fx.cfg.StateDir, "events.json")
	if fi, _ := os.Stat(file); fi.Mode().Perm() != 0o600 {
		t.Errorf("events.json mode = %v", fi.Mode().Perm())
	}
	if fi, _ := os.Stat(fx.cfg.StateDir); fi.Mode().Perm() != 0o700 {
		t.Errorf("state dir mode = %v", fi.Mode().Perm())
	}
	first, _ := os.ReadFile(file)

	// A new process: the ETag must come from disk, and a 304 must change nothing.
	inv := fx.fresh()
	_, ev, err := inv.Changed(context.Background(), prev)
	if err != nil || len(ev) != 0 {
		t.Fatalf("304 poll: %v %+v", err, ev)
	}
	sent := w.polls["hangryclaude"]
	if sent[len(sent)-1] != st.ETag {
		t.Errorf("If-None-Match sent = %q, want persisted %q", sent[len(sent)-1], st.ETag)
	}
	if again, _ := os.ReadFile(file); string(again) != string(first) {
		t.Error("a 304 rewrote the state file")
	}

	// One new event shows through, once.
	w.feeds["hangryclaude"] = append([]wevent{{id: "4", typ: "PullRequestEvent", repo: "hangryclaude/alpha", at: "2026-11-03T11:59:00Z"}}, w.feeds["hangryclaude"]...)
	_, ev, err = fx.fresh().Changed(context.Background(), prev)
	if err != nil || len(ev) != 1 || ev[0].Type != "PullRequestEvent" {
		t.Fatalf("new event: %v %+v", err, ev)
	}
	if st := readState(t, fx)["hangryclaude"]; st.LastID != 4 || st.ETag != etagOf(w.feeds["hangryclaude"]) {
		t.Errorf("state after new event = %+v", st)
	}
	_, ev, _ = fx.fresh().Changed(context.Background(), prev)
	if len(ev) != 0 {
		t.Errorf("event delivered twice: %+v", ev)
	}
	fx.assertNoTokenAnywhere()
}

func TestEventsHighWaterMarkSuppressesSeenEventsWhenTheETagMoves(t *testing.T) {
	w := standardWorld()
	w.feeds["hangryclaude"] = feed(5, 1, "IssuesEvent", "hangryclaude/bravo", "2026-11-03")
	fx := stateFixture(t, w, nil)
	poll(t, fx, nil)
	// The feed changes in a way that moves the ETag but adds nothing new (an old event aged out).
	w.feeds["hangryclaude"] = w.feeds["hangryclaude"][:4]
	_, ev := poll(t, fx, nil)
	if len(ev) != 0 {
		t.Fatalf("seen events came back: %+v", ev)
	}
	if st := readState(t, fx)["hangryclaude"]; st.ETag != etagOf(w.feeds["hangryclaude"]) || st.LastID != 5 {
		t.Errorf("state = %+v", st)
	}
}

func TestEventsFirstPollOnlyLooksBackOneWindow(t *testing.T) {
	w := standardWorld()
	w.feeds["hangryclaude"] = []wevent{
		{id: "30", typ: "IssuesEvent", repo: "hangryclaude/bravo", at: "2026-11-03T11:00:00Z"},
		{id: "20", typ: "IssuesEvent", repo: "hangryclaude/bravo", at: "2026-11-02T10:00:00Z"}, // 26 h before "now"
		{id: "10", typ: "IssuesEvent", repo: "hangryclaude/bravo", at: "2026-10-01T10:00:00Z"},
	}
	fx := stateFixture(t, w, nil)
	_, ev := poll(t, fx, nil)
	if len(ev) != 1 || ev[0].At != "2026-11-03T11:00:00Z" {
		t.Fatalf("events = %+v, want only the one inside the 24 h window", ev)
	}
	if st := readState(t, fx)["hangryclaude"]; st.LastID != 30 {
		t.Errorf("baseline LastID = %d: older events must not resurface next poll", st.LastID)
	}

	w2 := standardWorld()
	w2.feeds["hangryclaude"] = w.feeds["hangryclaude"]
	fx2 := stateFixture(t, w2, func(c *Config) { c.EventWindow = 90 * 24 * time.Hour })
	if _, ev := poll(t, fx2, nil); len(ev) != 3 {
		t.Errorf("a 90-day window should return all 3: %+v", ev)
	}
}

func TestEventsPagingStopsAtTheFirstSeenEvent(t *testing.T) {
	w := standardWorld()
	w.feeds["hangryclaude"] = feed(300, 1, "IssueCommentEvent", "hangryclaude/bravo", "2026-11-03")
	fx := stateFixture(t, w, nil)
	if err := os.MkdirAll(fx.cfg.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fx.cfg.StateDir, "events.json"), []byte(`{"hangryclaude":{"etag":"\"stale\"","last_id":150}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	_, ev := poll(t, fx, nil)
	if len(ev) != 150 {
		t.Fatalf("got %d events, want the 150 newer than the mark", len(ev))
	}
	pages := 0
	for _, c := range fx.f.Calls() {
		if c.Acct == "hangryclaude" && strings.Contains(c.Path, "/events") {
			pages++
			if strings.Contains(c.Path, "page=3") {
				t.Error("fetched page 3 although page 2 already held a seen event")
			}
		}
	}
	if pages != 2 {
		t.Errorf("%d event pages fetched, want 2", pages)
	}
}

func TestEventsBeyondTheAPIWindowAreReportedNotHidden(t *testing.T) {
	w := standardWorld()
	w.feeds["hangryclaude"] = feed(300, 1, "IssuesEvent", "hangryclaude/bravo", "2026-11-03")
	fx := stateFixture(t, w, nil)
	_, ev, err := fx.inv.Changed(context.Background(), nil)
	if err == nil || !strings.Contains(err.Error(), "beyond the events API window") {
		t.Fatalf("err = %v", err)
	}
	if len(ev) != 300 {
		t.Errorf("returned %d of the 300 reachable events", len(ev))
	}
}

func TestEventsUnreadableStateStartsFreshAndSaysSo(t *testing.T) {
	w := standardWorld()
	w.feeds["hangryclaude"] = feed(2, 1, "IssuesEvent", "hangryclaude/bravo", "2026-11-03")
	fx := stateFixture(t, w, nil)
	if err := os.MkdirAll(fx.cfg.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(fx.cfg.StateDir, "events.json")
	if err := os.WriteFile(file, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	inv := fx.fresh()
	_, ev, err := inv.Changed(context.Background(), nil)
	if err == nil || !strings.Contains(err.Error(), "fresh baseline") {
		t.Fatalf("err = %v", err)
	}
	if len(ev) != 2 {
		t.Errorf("events = %+v", ev)
	}
	if st := readState(t, fx)["hangryclaude"]; st.LastID != 2 {
		t.Errorf("state was not repaired: %+v", st)
	}
}

func TestEventsPayloadTextIsNeverKept(t *testing.T) {
	w := standardWorld()
	w.feeds["hangryclaude"] = feed(2, 1, "IssueCommentEvent", "hangryclaude/bravo", "2026-11-03")
	fx := stateFixture(t, w, nil)
	_, ev := poll(t, fx, nil)
	if len(ev) != 2 {
		t.Fatalf("events = %+v", ev)
	}
	const marker = "free text that may hold a key"
	for i, b := range fx.f.Buffers() {
		if strings.Contains(string(b), marker) {
			t.Errorf("stdout buffer %d still holds comment text after the poll", i)
		}
	}
	b, _ := json.Marshal(ev)
	if strings.Contains(string(b), marker) {
		t.Error("an Event carries payload text")
	}
	state, _ := os.ReadFile(filepath.Join(fx.cfg.StateDir, "events.json"))
	if strings.Contains(string(state), marker) {
		t.Error("state holds payload text")
	}
}

func TestEventsFailureKeepsThePreviousState(t *testing.T) {
	w := standardWorld()
	w.feeds["hangryclaude"] = feed(2, 1, "IssuesEvent", "hangryclaude/bravo", "2026-11-03")
	fx := stateFixture(t, w, nil)
	poll(t, fx, nil)
	before := readState(t, fx)

	w.feeds["hangryclaude"] = append(feed(3, 3, "IssuesEvent", "hangryclaude/bravo", "2026-11-03"), w.feeds["hangryclaude"]...)
	r := ghclitest.JSON(403, map[string]string{"message": "API rate limit exceeded"})
	r.Header = map[string]string{"X-Ratelimit-Remaining": "0"}
	w.fail["hangryclaude events"] = r
	_, _, err := fx.inv.Changed(context.Background(), nil)
	var rl *ghcli.RateLimitError
	if !errors.As(err, &rl) {
		t.Fatalf("err = %v", err)
	}
	after := readState(t, fx)
	if after["hangryclaude"] != before["hangryclaude"] {
		t.Errorf("a failed poll advanced the state: %+v -> %+v", before["hangryclaude"], after["hangryclaude"])
	}

	// Once the limit clears, the event that arrived meanwhile is still delivered.
	delete(w.fail, "hangryclaude events")
	_, ev := poll(t, fx, nil)
	if len(ev) != 1 || ev[0].At != "2026-11-03T11:03:00Z" {
		t.Errorf("events after recovery = %+v", ev)
	}
}

func TestEventsEachAccountIsReadWithItsOwnToken(t *testing.T) {
	w := standardWorld()
	fx := stateFixture(t, w, nil)
	poll(t, fx, nil)
	seen := map[string]bool{}
	for _, c := range fx.f.Calls() {
		if rest, ok := strings.CutPrefix(c.Path, "users/"); ok {
			login, _, _ := strings.Cut(rest, "/")
			if login != c.Acct {
				t.Errorf("events of %s fetched as %s: private activity would be invisible", login, c.Acct)
			}
			seen[login] = true
		}
	}
	if !seen["hangryclaude"] || !seen["alt-builds"] {
		t.Errorf("polled %v", seen)
	}
}

func TestToEventMapping(t *testing.T) {
	owners := map[string]bool{"me": true, "myorg": true}
	cases := []struct {
		name string
		e    ghEvent
		want string
		ok   bool
	}{
		{"own issue", ev("IssuesEvent", "me/x"), "github.com/me/x", true},
		{"foreign comment counts", ev("IssueCommentEvent", "them/y"), "github.com/them/y", true},
		{"foreign create does not", ev("CreateEvent", "them/y"), "", false},
		{"org public", ev("PublicEvent", "MyOrg/z"), "github.com/MyOrg/z", true},
		{"wiki edit", ev("GollumEvent", "me/x"), "github.com/me/x.wiki", true},
		{"push is covered by pushedAt", ev("PushEvent", "me/x"), "", false},
		{"watch", ev("WatchEvent", "me/x"), "", false},
		{"no slash", ev("IssuesEvent", "nonsense"), "", false},
		{"gist without id", ev("GistEvent", "gist/abc"), "", false},
	}
	for _, tc := range cases {
		got, ok := toEvent(tc.e, "me", owners)
		if ok != tc.ok || got.Source != tc.want {
			t.Errorf("%s: got (%q, %v), want (%q, %v)", tc.name, got.Source, ok, tc.want, tc.ok)
		}
	}
}

func ev(typ, repo string) ghEvent {
	var e ghEvent
	e.Type, e.Repo.Name = typ, repo
	return e
}

func TestEventsInTheSameSecondKeepTheirIDOrder(t *testing.T) {
	w := standardWorld()
	w.feeds["hangryclaude"] = []wevent{
		{id: "12", typ: "ReleaseEvent", repo: "hangryclaude/alpha", at: "2026-11-03T11:00:00Z"},
		{id: "11", typ: "IssueCommentEvent", repo: "hangryclaude/alpha", at: "2026-11-03T11:00:00Z"},
		{id: "10", typ: "IssuesEvent", repo: "hangryclaude/alpha", at: "2026-11-03T11:00:00Z"},
	}
	fx := stateFixture(t, w, nil)
	_, ev := poll(t, fx, nil)
	var types []string
	for _, e := range ev {
		types = append(types, e.Type)
	}
	if !slices.Equal(types, []string{"IssuesEvent", "IssueCommentEvent", "ReleaseEvent"}) {
		t.Fatalf("order = %v", types)
	}
}

func TestEventsFirstPollWindowFollowsGitHubsClockNotTheLocalOne(t *testing.T) {
	w := standardWorld()
	// This Mac thinks it is 12:00 UTC; GitHub says 14:00. An event from 13:30 the previous day
	// is 22.5 h old by the local clock and 24.5 h old by GitHub's, which is the one that counts.
	w.date = "Tue, 03 Nov 2026 14:00:00 GMT"
	w.feeds["hangryclaude"] = []wevent{
		{id: "30", typ: "IssuesEvent", repo: "hangryclaude/bravo", at: "2026-11-03T13:00:00Z"},
		{id: "20", typ: "IssuesEvent", repo: "hangryclaude/bravo", at: "2026-11-02T13:30:00Z"},
	}
	fx := stateFixture(t, w, nil)
	_, ev := poll(t, fx, nil)
	if len(ev) != 1 || ev[0].At != "2026-11-03T13:00:00Z" {
		t.Fatalf("events = %+v, want only the one inside GitHub's 24 h window", ev)
	}
}
