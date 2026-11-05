package sweep

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"keyguard/internal/core"
)

// clockedInventory is the fake inventory that has read a Date header: it knows GitHub's time.
type clockedInventory struct {
	*fakeInventory
	mu     sync.Mutex
	server time.Time
	known  bool
}

func (c *clockedInventory) ServerNow() (time.Time, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.server, c.known
}

// stamps is every timestamp-looking string under the keyguard home, for a test to ask which
// day and hour any of them claims.
func stamps(t testing.TB, root string) string {
	t.Helper()
	var sb strings.Builder
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || strings.HasSuffix(p, ".bin") {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		sb.Write(b)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return sb.String()
}

// This Mac's clock has run two hours fast. Everything the sweep stamps (the run's start and
// finish, a source's last scan, when a secret was first seen, when its verdict was taken, when
// an API resource was last read) has to be on GitHub's clock, or a verdict's age and the time
// it is next due would be measured against the wrong hour.
func TestEveryStampIsOnGitHubsClockWhateverThisMacsSays(t *testing.T) {
	for name, skew := range map[string]time.Duration{"two hours fast": 2 * time.Hour, "two hours slow": -2 * time.Hour} {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t)
			github := time.Date(2026, 11, 3, 8, 0, 0, 0, time.UTC)
			local := github.Add(skew)
			w.cfg.Now = func() time.Time { return local }
			ci := &clockedInventory{fakeInventory: w.inv, server: github, known: true}
			w.cfg.Inventory = ci
			api := &fakeAPI{}
			w.cfg.API = api
			a := w.addRepo("a", core.Public)
			raw := fakeKey(t, "sk-", 48)
			w.plantAll(raw, "openai", core.Live)
			a.commit("env", map[string]string{".env": "K=" + raw + "\n"})
			url := "https://github.com/o/a/issues/1"
			w.inv.events = []core.Event{w.event(w.src("a"), "IssuesEvent", "2026-11-03T07:59:00Z", url)}

			st, err := w.runner().Poll(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			want := github.Format(time.RFC3339)
			if st.Started != want || st.Finished != want {
				t.Fatalf("the run's own clock is GitHub's: started %s finished %s, want %s", st.Started, st.Finished, want)
			}
			s := w.secret(raw)
			if s.FirstSeen != want || s.LastSeen != want || s.VerifiedAt != want {
				t.Fatalf("first seen %s last seen %s verdict at %s, want %s", s.FirstSeen, s.LastSeen, s.VerifiedAt, want)
			}
			state, _ := loadState(w.paths.Sources, w.src("a"))
			if state.LastScan != want || state.LastAPI != want {
				t.Fatalf("scan record %s, API record %s, want %s", state.LastScan, state.LastAPI, want)
			}
			if hour := local.Format("2006-01-02T15:"); strings.Contains(stamps(t, w.paths.Root), hour) {
				t.Fatalf("a stamp on this Mac's clock (%s…) reached a file", hour)
			}
			if !hasNote(st, "this Mac's clock is 2h0m0s") {
				t.Fatalf("the skew has to be said, once, where the doctor and the report can see it: %v", st.Notes)
			}
			if skew > 0 && !hasNote(st, "ahead of GitHub's") || skew < 0 && !hasNote(st, "behind GitHub's") {
				t.Fatalf("%v", st.Notes)
			}
		})
	}
}

func TestWithoutAServerClockTheLocalOneIsUsedAndNoSkewIsClaimed(t *testing.T) {
	w := newWorld(t)
	local := time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)
	w.cfg.Now = func() time.Time { return local }
	// The inventory is Clocked but has not read a response yet (an offline poll).
	w.cfg.Inventory = &clockedInventory{fakeInventory: w.inv, known: false}
	a := w.addRepo("a", core.Private)
	a.commit("one", map[string]string{"f": "1\n"})
	st := mustPoll(t, w.runner())
	if st.Started != local.Format(time.RFC3339) || hasNote(st, "this Mac's clock") {
		t.Fatalf("%+v", st)
	}
	// And a plain inventory is never Clocked.
	w2 := newWorld(t)
	w2.cfg.Now = func() time.Time { return local }
	w2.addRepo("a", core.Private).commit("one", map[string]string{"f": "1\n"})
	if st := mustPoll(t, w2.runner()); st.Started != local.Format(time.RFC3339) {
		t.Fatalf("%+v", st)
	}
}

func TestASmallSkewIsNotWorthANote(t *testing.T) {
	w := newWorld(t)
	github := time.Date(2026, 11, 3, 8, 0, 0, 0, time.UTC)
	w.cfg.Now = func() time.Time { return github.Add(20 * time.Second) }
	w.cfg.Inventory = &clockedInventory{fakeInventory: w.inv, server: github, known: true}
	w.addRepo("a", core.Private).commit("one", map[string]string{"f": "1\n"})
	if st := mustPoll(t, w.runner()); hasNote(st, "this Mac's clock") {
		t.Fatalf("%v", st.Notes)
	}
}

// A verdict's age is GitHub's: two hours of skew must not make a fresh verdict look old, or a
// stale one look new.
func TestAVerdictsAgeIsMeasuredOnGitHubsClock(t *testing.T) {
	w := newWorld(t)
	github := time.Date(2026, 11, 3, 8, 0, 0, 0, time.UTC)
	ci := &clockedInventory{fakeInventory: w.inv, server: github, known: true}
	w.cfg.Inventory = ci
	w.cfg.Now = func() time.Time { return github.Add(2 * time.Hour) } // 2 h fast
	a := w.addRepo("a", core.Public)
	raw := fakeKey(t, "sk-", 48)
	w.plantAll(raw, "openai", core.Live)
	a.commit("env", map[string]string{".env": "K=" + raw + "\n"})
	r := w.runner()
	mustPoll(t, r)
	w.plantAll(raw, "openai", core.Dead)
	w.resetCalls()

	// Five and a half hours later by GitHub's clock; by the Mac's, seven and a half.
	ci.mu.Lock()
	ci.server = github.Add(5*time.Hour + 30*time.Minute)
	ci.mu.Unlock()
	if mustPoll(t, r); w.engineCalls() != 0 {
		t.Fatal("the live verdict is 5.5 hours old by GitHub's clock, inside its 6-hour life; this Mac's clock must not make it look due")
	}
	ci.mu.Lock()
	ci.server = github.Add(6*time.Hour + time.Minute)
	ci.mu.Unlock()
	mustPoll(t, r)
	if w.engineCalls() == 0 {
		t.Fatal("past six hours by GitHub's clock the verdict is due")
	}
	if s := w.secret(raw); s.Verified != core.Dead {
		t.Fatalf("%+v", s)
	}
}

// learningInventory has no server time until it has talked to GitHub, which is how the first
// poll of a process goes: the run begins on this Mac's clock and learns GitHub's mid-run.
type learningInventory struct{ *clockedInventory }

func (l learningInventory) learn() {
	l.mu.Lock()
	l.known = true
	l.mu.Unlock()
}

func (l learningInventory) List(ctx context.Context) ([]core.Source, error) {
	l.learn()
	return l.fakeInventory.List(ctx)
}

func (l learningInventory) Changed(ctx context.Context, prev map[string]core.Source) ([]core.Source, []core.Event, error) {
	l.learn()
	return l.fakeInventory.Changed(ctx, prev)
}

func TestARunThatLearnsGitHubsClockMidRunNeverFinishesBeforeItStarts(t *testing.T) {
	w := newWorld(t)
	github := time.Date(2026, 11, 3, 8, 0, 0, 0, time.UTC)
	w.cfg.Now = func() time.Time { return github.Add(2 * time.Hour) }
	w.cfg.Inventory = learningInventory{&clockedInventory{fakeInventory: w.inv, server: github}}
	w.addRepo("a", core.Private).commit("one", map[string]string{"f": "1\n"})
	st := mustPoll(t, w.runner())
	if st.Finished != github.Format(time.RFC3339) || st.Started > st.Finished || st.Started < github.Add(-time.Minute).Format(time.RFC3339) {
		t.Fatalf("started %s, finished %s: a run that began on a fast clock and ended on GitHub's must not look two hours long, or negative", st.Started, st.Finished)
	}
}
