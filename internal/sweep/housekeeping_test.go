package sweep

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"keyguard/internal/core"
	"keyguard/internal/inventory"
)

func TestRunRecordsOlderThanThirtyDaysAreFiledNotDeleted(t *testing.T) {
	w := newWorld(t) // the world's clock reads 2026-11-03
	if err := os.MkdirAll(w.paths.Runs, 0o700); err != nil {
		t.Fatal(err)
	}
	old := []string{"20260901T120000.000Z.json", "20260901T120000.000Z-2.json", "20261001T000000.000Z.json"}
	recent := []string{"20261005T120000.000Z.json", "20261103T090000.000Z.json"}
	odd := []string{"notes.json", "20260901T120000.000Z.txt", "short.json"}
	for _, n := range append(append(append([]string{}, old...), recent...), odd...) {
		if err := os.WriteFile(filepath.Join(w.paths.Runs, n), []byte("{\"kind\":\"poll\",\"file\":\""+n+"\"}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	w.addRepo("a", core.Private).commit("one", map[string]string{"f": "1\n"})
	st := mustPoll(t, w.runner())
	if !hasNote(st, "3 run record(s) older than 30 days were moved to runs/archive/") {
		t.Fatalf("%v", st.Notes)
	}
	for _, n := range old {
		if _, err := os.Stat(filepath.Join(w.paths.Runs, n)); err == nil {
			t.Errorf("%s was not filed", n)
		}
	}
	for n, month := range map[string]string{old[0]: "202609", old[1]: "202609", old[2]: "202610"} {
		b, err := os.ReadFile(filepath.Join(w.paths.Runs, "archive", month, n))
		if err != nil || len(b) == 0 {
			t.Errorf("%s is not under archive/%s: %v", n, month, err)
		}
	}
	for _, n := range append(append([]string{}, recent...), odd...) {
		if _, err := os.Stat(filepath.Join(w.paths.Runs, n)); err != nil {
			t.Errorf("%s was moved but is not old, or not a run record: %v", n, err)
		}
	}
	// The poll's own record is where it always was, beside archive/.
	if ents, _ := os.ReadDir(w.paths.Runs); len(ents) != len(recent)+len(odd)+2 {
		t.Errorf("%d entries", len(ents))
	}
}

// The inventory snapshot is written by both packages and read by the hooks; the layouts must
// stay the same.
func TestSnapshotLayoutIsTheInventorysAndReadsBack(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inventory.json")
	srcs := []core.Source{
		{ID: "github.com/o/b", Kind: "repo", Owner: "o", Name: "b", Visibility: core.Private, PushedAt: "2026-11-03T09:00:00Z"},
		{ID: "github.com/o/a", Kind: "repo", Owner: "o", Name: "a", Visibility: core.Public, PushedAt: "2026-11-03T08:00:00Z", SizeKB: 12, DefaultBranch: "main"},
	}
	now := time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)

	if err := saveSnapshot(path, map[string]core.Source{srcs[0].ID: srcs[0], srcs[1].ID: srcs[1]}, now); err != nil {
		t.Fatal(err)
	}
	got, err := inventory.LoadSnapshot(path)
	if err != nil || len(got) != 2 || got[0] != srcs[1] || got[1] != srcs[0] {
		t.Fatalf("the inventory cannot read what the sweep wrote: %v %+v", err, got)
	}

	path2 := filepath.Join(t.TempDir(), "inventory.json")
	if err := inventory.SaveSnapshot(path2, srcs, now); err != nil {
		t.Fatal(err)
	}
	back, err := loadSnapshot(path2)
	if err != nil || len(back) != 2 || back[srcs[0].ID] != srcs[0] || back[srcs[1].ID] != srcs[1] {
		t.Fatalf("the sweep cannot read what the inventory wrote: %v %+v", err, back)
	}
}
