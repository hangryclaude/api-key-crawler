package inventory

import (
	"context"
	"slices"
	"testing"
	"time"

	"keyguard/internal/core"
)

// PLAN.md "Sweep scope": the inventory lists everything and marks the sources a stranger can
// read as the ones to scan.
func TestScanSetIsPublicReposTheirWikisAndEveryGist(t *testing.T) {
	fx := newFixture(t, standardWorld(), nil)
	all, err := fx.inv.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"gist.github.com/hangryclaude/0a1b2c3d4e5f60718293a4b5c6d7e8f9",
		"gist.github.com/hangryclaude/1b2c3d4e5f60718293a4b5c6d7e8f9a0",
		"gist.github.com/hangryclaude/2c3d4e5f60718293a4b5c6d7e8f9a0b1",
		"github.com/Loony-Labs-Video/juliet",
		"github.com/acme-apps/hotel",
		"github.com/alt-builds/foxtrot",
		"github.com/hangryclaude/alpha",
		"github.com/hangryclaude/alpha.wiki",
	}
	if got := ids(ScanSet(all)); !slices.Equal(got, want) {
		t.Fatalf("scan set:\n got %v\nwant %v", got, want)
	}
	for _, s := range all {
		if Exposed(s) != slices.Contains(want, s.ID) {
			t.Errorf("Exposed(%s) = %v", s.ID, Exposed(s))
		}
	}
	// Everything else is listed, as metadata: it is in `all`, just not in the scan set.
	if len(all) != 16 {
		t.Errorf("%d sources listed, want all 16", len(all))
	}
}

func TestSummarizeCountsTheListingTheWayTheReportStatesIt(t *testing.T) {
	fx := newFixture(t, standardWorld(), nil)
	all, _ := fx.inv.List(context.Background())
	got := Summarize(all)
	want := Summary{
		Repos: 10, PublicRepos: 4, PrivateRepos: 6, Wikis: 1, SecretGists: 2, PublicGists: 1, Scan: 8,
		ReposByOwner:  map[string]int{"hangryclaude": 5, "alt-builds": 2, "acme-apps": 2, "loony-labs-video": 1},
		PublicByOwner: map[string]int{"hangryclaude": 1, "alt-builds": 1, "acme-apps": 1, "loony-labs-video": 1},
	}
	if got.Repos != want.Repos || got.PublicRepos != want.PublicRepos || got.PrivateRepos != want.PrivateRepos || got.Wikis != want.Wikis ||
		got.SecretGists != want.SecretGists || got.PublicGists != want.PublicGists || got.Scan != want.Scan || got.UnknownRepos != 0 {
		t.Errorf("summary = %+v, want %+v", got, want)
	}
	for k, v := range want.ReposByOwner {
		if got.ReposByOwner[k] != v {
			t.Errorf("repos of %s = %d, want %d", k, got.ReposByOwner[k], v)
		}
	}
	for k, v := range want.PublicByOwner {
		if got.PublicByOwner[k] != v {
			t.Errorf("public repos of %s = %d, want %d", k, got.PublicByOwner[k], v)
		}
	}
	// A repo whose visibility GitHub did not say is scanned, like a public one, and counted apart.
	odd := Summarize([]core.Source{{ID: "github.com/o/x", Kind: "repo", Owner: "o", Visibility: core.Unknown}})
	if odd.UnknownRepos != 1 || odd.Scan != 1 || odd.PublicRepos != 0 {
		t.Errorf("unknown = %+v", odd)
	}
}

func TestFlipOpenedMeansAStrangerCanReadItNowAndCouldNotBefore(t *testing.T) {
	for _, tc := range []struct {
		was, now core.Visibility
		want     bool
	}{
		{core.Private, core.Public, true},
		{core.Private, core.Unknown, true},
		{core.Local, core.Public, true},
		{core.Public, core.Private, false},
		{core.SecretGist, core.Public, false}, // readable before as well
		{core.Public, core.SecretGist, false},
		{core.Unknown, core.Public, false}, // unknown already counted as exposed
	} {
		if got := (Flip{Was: tc.was, Now: tc.now}).Opened(); got != tc.want {
			t.Errorf("%s -> %s Opened = %v", tc.was, tc.now, got)
		}
	}
}

func TestFlipsListOnlySourcesPrevHasSeenAndPutOpenedOnesFirst(t *testing.T) {
	prev := map[string]core.Source{
		"a": {ID: "a", Visibility: core.Public},
		"b": {ID: "b", Visibility: core.Private},
		"c": {ID: "c", Visibility: core.Private},
		"d": {ID: "d", Visibility: core.Public},
	}
	cur := []core.Source{
		{ID: "a", Visibility: core.Private}, // closed
		{ID: "b", Visibility: core.Public},  // opened
		{ID: "c", Visibility: core.Private}, // same
		{ID: "d", Visibility: core.Public},  // same
		{ID: "e", Visibility: core.Public},  // new, not a flip
		{ID: "b", Visibility: core.Public},  // listed twice
	}
	got := Flips(prev, cur)
	if len(got) != 2 || got[0].Source.ID != "b" || !got[0].Opened() || got[1].Source.ID != "a" || got[1].Opened() {
		t.Errorf("flips = %+v, want b (opened) before a (closed)", got)
	}
	if Flips(nil, cur) != nil {
		t.Error("with no baseline nothing can have flipped")
	}
}

// With nothing to measure a flip against, a poll reports every source and no flips: the first
// run scans everything exposed anyway.
func TestPollWithoutABaselineHasNoFlips(t *testing.T) {
	w := standardWorld()
	usableFeeds(w)
	fx := watchFixture(t, w, nil)
	p := fx.pollOK(nil)
	if len(p.Flips) != 0 || len(p.Changed) == 0 {
		t.Errorf("flips %v changed %d", p.Flips, len(p.Changed))
	}
	for _, e := range p.Events {
		if e.Type == "PublicEvent" {
			t.Errorf("a first poll invented %+v", e)
		}
	}
}

// STEAL P0-16, the first-poll window. This Mac's clock two hours off GitHub's moves the cutoff
// by two hours if it is the one consulted; GitHub's Date header is the one that counts.
func TestFirstEventWindowFollowsGitHubsClockWhateverTheMacSays(t *testing.T) {
	for name, skew := range map[string]time.Duration{"mac 2h fast": 2 * time.Hour, "mac 2h slow": -2 * time.Hour} {
		t.Run(name, func(t *testing.T) {
			w := standardWorld() // GitHub says it is 2026-11-03T12:00:00Z
			w.feeds["hangryclaude"] = []wevent{
				{id: "30", typ: "IssuesEvent", repo: "hangryclaude/bravo", at: "2026-11-02T12:30:00Z", number: 1}, // 23.5 h ago on GitHub's clock
				{id: "20", typ: "IssuesEvent", repo: "hangryclaude/bravo", at: "2026-11-02T11:30:00Z", number: 2}, // 24.5 h ago
			}
			fx := watchFixtureSkew(t, w, skew, nil)
			p := fx.pollOK(nil)
			var at []string
			for _, e := range p.Events {
				at = append(at, e.At)
			}
			if !slices.Equal(at, []string{"2026-11-02T12:30:00Z"}) {
				t.Errorf("events = %v with the Mac %v off: only the one inside GitHub's 24 h window", at, skew)
			}
		})
	}
}
