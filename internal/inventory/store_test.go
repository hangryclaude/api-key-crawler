package inventory

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"keyguard/internal/core"
)

func TestSnapshotRoundTripIsAtomicAndPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "inventory.json")
	want := []core.Source{
		{ID: "github.com/a/b", Kind: "repo", Owner: "a", Name: "b", Account: "a", Visibility: core.Public, PushedAt: "2026-11-03T10:00:00Z", SizeKB: 7},
		{ID: "github.com/a/b.wiki", Kind: "wiki", Owner: "a", Name: "b.wiki", Account: "a", Visibility: core.Public},
	}
	if err := SaveSnapshot(path, want, time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	got, err := LoadSnapshot(path)
	if err != nil || !slices.Equal(got, want) {
		t.Fatalf("round trip: %v\n got %+v\nwant %+v", err, got, want)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v", fi.Mode().Perm())
	}
	if fi, _ := os.Stat(filepath.Dir(path)); fi.Mode().Perm() != 0o700 {
		t.Errorf("dir mode = %v", fi.Mode().Perm())
	}
	left, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".tmp-*"))
	if len(left) != 0 {
		t.Errorf("temp files left behind: %v", left)
	}
	if !strings.Contains(readFile(t, path), `"updated": "2026-11-03T12:00:00Z"`) {
		t.Error("snapshot does not record when it was taken")
	}
}

func TestSnapshotMissingIsFirstRunCorruptIsAnError(t *testing.T) {
	dir := t.TempDir()
	got, err := LoadSnapshot(filepath.Join(dir, "none.json"))
	if got != nil || err != nil {
		t.Fatalf("missing file: %v %v", got, err)
	}
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte("[1,2"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSnapshot(bad); err == nil {
		t.Fatal("corrupt snapshot accepted")
	}
}

func TestSnapshotRefusesToSaveNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inventory.json")
	good := []core.Source{{ID: "github.com/a/b"}}
	if err := SaveSnapshot(path, good, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := SaveSnapshot(path, nil, time.Now()); err == nil {
		t.Fatal("an empty inventory overwrote a good one")
	}
	if got, _ := LoadSnapshot(path); len(got) != 1 {
		t.Fatalf("the good snapshot did not survive: %+v", got)
	}
}

func TestIndexAndSort(t *testing.T) {
	in := []core.Source{{ID: "b"}, {ID: "a"}, {ID: "a.wiki"}}
	m := Index(in)
	if len(m) != 3 || m["a.wiki"].ID != "a.wiki" {
		t.Fatalf("Index = %v", m)
	}
	sortSources(in)
	if in[0].ID != "a" || in[1].ID != "a.wiki" || in[2].ID != "b" {
		t.Fatalf("sorted = %v", ids(in))
	}
	if d := dedupe([]core.Source{{ID: "a", Name: "first"}, {ID: "a", Name: "second"}, {ID: "b"}}); len(d) != 2 || d[0].Name != "first" {
		t.Fatalf("dedupe = %+v", d)
	}
}

func TestNewerHandlesEveryShape(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want bool
	}{
		{"2026-11-03T10:00:01Z", "2026-11-03T10:00:00Z", true},
		{"2026-11-03T10:00:00Z", "2026-11-03T10:00:00Z", false},
		{"2026-11-03T09:00:00Z", "2026-11-03T10:00:00Z", false},
		{"2026-11-03T10:00:00Z", "", true},
		{"", "2026-11-03T10:00:00Z", false},
		{"", "", false},
		{"2026-11-03T10:00:00-05:00", "2026-11-03T10:00:00Z", true}, // 15:00Z
		{"bbb", "aaa", true},                                        // unparseable: string order, never a panic
	} {
		if got := newer(tc.a, tc.b); got != tc.want {
			t.Errorf("newer(%q, %q) = %v", tc.a, tc.b, got)
		}
	}
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// When two routes report one source, the first listed is the one kept, which only holds if the
// sort leaves equal IDs in the order they came. A short slice sorts stably whatever the
// algorithm, so this one is long enough to reach the part that does not.
func TestSortSourcesKeepsEqualIDsInTheirOrder(t *testing.T) {
	var in []core.Source
	for i := range 200 {
		in = append(in, core.Source{ID: fmt.Sprintf("id-%d", i%7), Name: fmt.Sprintf("%03d", i)})
	}
	sortSources(in)
	last := map[string]string{}
	for _, s := range in {
		if s.Name < last[s.ID] {
			t.Fatalf("%s: %s came after %s: equal IDs were reordered", s.ID, s.Name, last[s.ID])
		}
		last[s.ID] = s.Name
	}
	got := dedupe(in)
	if len(got) != 7 || got[0].Name != "000" {
		t.Errorf("dedupe kept %+v: it must keep the first source listed for an ID", got[0])
	}
}
