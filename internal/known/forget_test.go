package known

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"keyguard/internal/core"
)

func TestForget(t *testing.T) {
	f := newFixture(t)
	a := f.secret("sk-proj-", 40, "A_API_KEY")
	b := f.secret("sk-proj-", 40, "B_API_KEY")
	f.write("dev/a/.env", "A_API_KEY="+a+"\nB_API_KEY="+b+"\n")
	f.learn(Options{})
	f.check()

	st, err := ReadStore(f.root)
	if err != nil || st == nil {
		t.Fatalf("ReadStore: %v %v", st, err)
	}
	var idA string
	for _, l := range st.Secrets() {
		if l.Name == "A_API_KEY" {
			idA = l.ID
		}
	}
	if idA == "" {
		t.Fatal("A_API_KEY was not learned")
	}
	before := len(st.Entries)

	gone, err := Forget(f.root, idA)
	if err != nil {
		t.Fatal(err)
	}
	if len(gone) != 1 || gone[0].Name != "A_API_KEY" || gone[0].Forms < 2 {
		t.Fatalf("Forget reported %+v", gone)
	}
	after, err := ReadStore(f.root)
	if err != nil {
		t.Fatal(err)
	}
	if len(after.Entries) != before-gone[0].Forms {
		t.Errorf("store went from %d to %d entries, want %d fewer", before, len(after.Entries), gone[0].Forms)
	}
	for _, e := range after.Entries {
		if e.Name == "A_API_KEY" {
			t.Errorf("a form of the forgotten secret is still in the store: %s", e.Variant)
		}
	}

	// The matcher stops finding it, and still finds the other one in every encoding.
	m, err := LoadMatcher([]string{f.root})
	if err != nil {
		t.Fatal(err)
	}
	if got := m.Match([]byte("x=" + a + "\n")); len(got) != 0 {
		t.Errorf("forgotten secret still matches: %d hits", len(got))
	}
	if got := m.Match([]byte("x=" + b + "\n")); len(got) != 1 || got[0].Name != "B_API_KEY" {
		t.Errorf("the other secret no longer matches: %+v", got)
	}
	// Permissions survive the rewrite: the store is read by every git hook on this Mac.
	if fi, err := os.Stat(filepath.Join(core.PathsAt(f.root).Known, storeFile)); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("known.json after Forget: %v %v", fi, err)
	}

	// Forgetting twice, or an id nobody has, says so and writes nothing.
	for _, id := range []string{idA, "kgffffff", "not an id"} {
		if _, err := Forget(f.root, id); !errors.Is(err, ErrNotLearned) {
			t.Errorf("Forget(%q) = %v, want ErrNotLearned", id, err)
		}
	}
	if _, err := Forget(filepath.Join(t.TempDir(), "empty"), idA); !errors.Is(err, ErrNotLearned) {
		t.Errorf("Forget on a root with no store = %v, want ErrNotLearned", err)
	}
}

func TestForgetAmbiguousIDNeedsFingerprint(t *testing.T) {
	f := newFixture(t)
	f.write("dev/a/.env", "A_API_KEY="+f.secret("sk-proj-", 40, "A_API_KEY")+"\nB_API_KEY="+f.secret("sk-proj-", 40, "B_API_KEY")+"\n")
	f.learn(Options{})

	// Two different secrets that share a six-digit id cannot be produced on demand, so the
	// store is edited the way a collision would look: B takes A's id.
	st, err := ReadStore(f.root)
	if err != nil {
		t.Fatal(err)
	}
	var idA, fpB string
	for _, e := range st.Entries {
		switch e.Name {
		case "A_API_KEY":
			idA = e.ID
		case "B_API_KEY":
			fpB = e.FP
		}
	}
	for i := range st.Entries {
		if st.Entries[i].Name == "B_API_KEY" {
			st.Entries[i].ID = idA
		}
	}
	if err := writeStore(core.PathsAt(f.root).Known, st); err != nil {
		t.Fatal(err)
	}

	_, err = Forget(f.root, idA)
	if err == nil || !strings.Contains(err.Error(), "full fingerprint") || !strings.Contains(err.Error(), "A_API_KEY") || !strings.Contains(err.Error(), "B_API_KEY") {
		t.Fatalf("an id two secrets share must be refused with both named, got: %v", err)
	}
	if after, _ := ReadStore(f.root); len(after.Entries) != len(st.Entries) {
		t.Error("a refused Forget changed the store")
	}
	if gone, err := Forget(f.root, fpB); err != nil || len(gone) != 1 || gone[0].Name != "B_API_KEY" {
		t.Fatalf("Forget by fingerprint: %+v %v", gone, err)
	}
}
