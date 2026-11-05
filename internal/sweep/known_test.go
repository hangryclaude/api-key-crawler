package sweep

import (
	"context"
	"slices"
	"strings"
	"sync"
	"testing"

	"keyguard/internal/core"
)

// spyBlobs wraps GitKnown and records the ranges the known pass was asked to cover.
type spyBlobs struct {
	inner BlobScanner
	mu    sync.Mutex
	calls []core.Range
}

func (s *spyBlobs) ScanBlobs(ctx context.Context, repo string, r core.Range, m core.KnownMatcher, loc core.Location, emit core.Emit) (BlobStats, error) {
	s.mu.Lock()
	s.calls = append(s.calls, r)
	s.mu.Unlock()
	return s.inner.ScanBlobs(ctx, repo, r, m, loc, emit)
}

func (s *spyBlobs) list() []core.Range {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.calls)
}
func (s *spyBlobs) reset() { s.mu.Lock(); s.calls = nil; s.mu.Unlock() }

func TestKnownSecretsFlowThroughPollsIncrementallyAndRescanWhenTheSetGrows(t *testing.T) {
	w := newWorld(t)
	known := &fakeKnown{kr: w.kr}
	spy := &spyBlobs{inner: GitKnown{}}
	w.cfg.Known, w.cfg.Blobs = known, spy
	a := w.addRepo("a", core.Private)
	raw1, raw2 := fakeKey(t, "sk-", 48), fakeKey(t, "ghp_", 36)
	known.add(raw1, "OPENAI_API_KEY")
	c1 := a.commit("env", map[string]string{".env": "OPENAI_API_KEY=" + raw1 + "\n", "notes/old.txt": "token " + raw2 + "\n"})
	r := w.runner()

	st := mustPoll(t, r)
	s := w.secret(raw1)
	if !slices.Equal(s.Engines, []string{"known"}) || !strings.HasSuffix(s.Known, " OPENAI_API_KEY") || s.Type != "openai" {
		t.Fatalf("known-only secret: engines=%v known=%q type=%s", s.Engines, s.Known, s.Type)
	}
	if s.Triage != "real" || s.Severity != core.High {
		t.Fatalf("a learned key in a private repo is high: %s / %v (%s)", s.Triage, s.Severity, s.TriageWhy)
	}
	if n := w.notif.list(); len(n) != 1 || n[0].sev != core.High || !strings.Contains(n[0].title, "your openai key is in a private place") {
		t.Fatalf("notices: %+v", n)
	}
	if es := st.Engines["known"]; es.Hits != 1 || es.Errors != 0 {
		t.Fatalf("known stats %+v", es)
	}
	state, _ := loadState(w.paths.Sources, w.src("a"))
	if state.ScannedWith["known"] != "entries=1" {
		t.Fatalf("scanned_with %v", state.ScannedWith)
	}
	if got := spy.list(); len(got) != 1 || !got[0].All {
		t.Fatalf("first known pass should be full: %+v", got)
	}

	spy.reset()
	a.commit("later", map[string]string{"x": "1\n"})
	w.pushed("a")
	mustPoll(t, r)
	got := spy.list()
	if len(got) != 1 || got[0].All || !slices.Equal(got[0].Revs, []string{"--all", "--not", c1}) {
		t.Fatalf("with the learned set unchanged the known pass is incremental: %+v", got)
	}

	// the user learns another key. raw2 has sat in history since c1, so the known pass must
	// go back over everything, even though no commit is new and nothing was pushed.
	spy.reset()
	w.resetCalls()
	known.add(raw2, "GITHUB_TOKEN")
	mustPoll(t, r)
	got = spy.list()
	if len(got) != 1 || !got[0].All {
		t.Fatalf("a bigger learned set needs a full known pass: %+v", got)
	}
	s2 := w.secret(raw2)
	if s2.Type != "github" || s2.Locations[0].Commit != c1 || s2.Locations[0].Path != "notes/old.txt" {
		t.Fatalf("a newly learned key found in old history: %+v", s2)
	}
	if n := w.notif.count(); n != 2 {
		t.Fatalf("each newly found secret alerts once: %d notices", n)
	}
	// ...and the engines, whose version did not change, did not rescan anything.
	if n := w.engineCalls(); n != 0 {
		t.Fatalf("the engines were caught up and must not rescan because the known set grew: %d scans", n)
	}
}

func TestKnownAndEngineHitsMergeIntoOneLocation(t *testing.T) {
	w := newWorld(t)
	known := &fakeKnown{kr: w.kr}
	w.cfg.Known = known
	a := w.addRepo("a", core.Public)
	raw := fakeKey(t, "sk-", 48)
	w.plantAll(raw, "openai", core.Unverified)
	known.add(raw, "OPENAI_API_KEY")
	a.commit("env", map[string]string{"cfg/.env": "A=1\nOPENAI_API_KEY=" + raw + "\n"})
	mustPoll(t, w.runner())
	s := w.secret(raw)
	if len(s.Locations) != 1 {
		t.Fatalf("engines and the known pass disagree on where the key is: %+v", s.Locations)
	}
	if !slices.Equal(s.Engines, []string{"betterleaks", "known", "titus", "trufflehog"}) {
		t.Fatalf("engines %v", s.Engines)
	}
	if s.Severity != core.Critical || s.Triage != "real" {
		t.Fatalf("a learned key in a public repo is critical: %v %s", s.Severity, s.Triage)
	}
	if n := w.notif.list(); len(n) != 1 || n[0].sev != core.Critical {
		t.Fatalf("%+v", n)
	}
}

func TestKnownPassSkipsAreInTheNotes(t *testing.T) {
	w := newWorld(t)
	known := &fakeKnown{kr: w.kr}
	w.cfg.Known, w.cfg.Blobs = known, GitKnown{MaxBlob: 100}
	a := w.addRepo("a", core.Private)
	raw := fakeKey(t, "sk-", 48)
	known.add(raw, "OPENAI_API_KEY")
	a.commit("big", map[string]string{"dump.sql": raw + strings.Repeat("\nINSERT INTO t VALUES (1,2,3);", 30)})
	st := mustPoll(t, w.runner())
	if !hasNote(st, "the known-secret pass skipped 1 blob(s) over 100 B") || !hasNote(st, "dump.sql") {
		t.Fatalf("a skipped blob must be said out loud: %v", st.Notes)
	}
}

func TestKnownMatcherWithAnExactVersionIsUsed(t *testing.T) {
	k := &versioned{fakeKnown{}, "v7"}
	if got := knownVersion(k); got != "v7" {
		t.Fatalf("%q", got)
	}
	if got := knownVersion(&fakeKnown{set: []knownEntry{{"a", "b"}}}); got != "entries=1" {
		t.Fatalf("%q", got)
	}
}

type versioned struct {
	fakeKnown
	v string
}

func (v *versioned) Version() string { return v.v }
