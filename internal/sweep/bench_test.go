package sweep

import (
	"bytes"
	"context"
	"fmt"
	"math/rand/v2"
	"path/filepath"
	"testing"
	"time"

	"keyguard/internal/core"
	"keyguard/internal/db"
	"keyguard/internal/fp"
	"keyguard/internal/triage"
)

// instantMirror answers Sync from memory, so a benchmark measures the sweep and not git.
type instantMirror struct{ tips map[string]string }

func (m instantMirror) Path(core.Source) string { return "/nonexistent/mirror.git" }
func (m instantMirror) Sync(context.Context, core.Source) (map[string]string, map[string]string, error) {
	return m.tips, m.tips, nil
}

// benchSweep is 469 sources (the real inventory's size) and a store of 1,000 secrets spread
// over them, with state files saying every engine is caught up.
func benchSweep(b *testing.B) (*Runner, *fakeInventory, core.Paths, []core.Source) {
	b.Helper()
	root := isolate(b)
	paths := core.PathsAt(filepath.Join(root, "kg"))
	kr := fp.NewEphemeral()
	store, err := db.Open(paths)
	if err != nil {
		b.Fatal(err)
	}
	tips := map[string]string{"refs/heads/main": fmt.Sprintf("%040x", 1)}
	var list []core.Source
	for i := 0; i < 469; i++ {
		list = append(list, core.Source{
			ID: fmt.Sprintf("github.com/o/repo%03d", i), Kind: "repo", Owner: "o", Name: fmt.Sprintf("repo%03d", i),
			Visibility: core.Private, PushedAt: "2026-11-03T10:00:00Z", SizeKB: i,
		})
	}
	var hits []core.Hit
	for i := 0; i < 1000; i++ {
		raw := fmt.Sprintf("sk-bench-%06d", i)
		hits = append(hits, core.Hit{
			Engine: "betterleaks", Rule: "openai", Type: "openai", FP: kr.FP(raw), Shape: fp.Shape(raw), Len: len(raw),
			Verified: core.Unverified, Loc: core.Location{Source: list[i%469].ID, Kind: "repo", Visibility: core.Private, Commit: "c", Path: "p", Line: 1},
		})
	}
	if _, err := store.Merge(hits, "2026-11-03T10:00:00Z"); err != nil {
		b.Fatal(err)
	}
	var engines []core.Engine
	for _, n := range []string{"betterleaks", "trufflehog", "titus"} {
		engines = append(engines, newGitEngine(n, kr))
	}
	inv := &fakeInventory{list: list}
	cfg := Config{
		Paths: paths, Inventory: inv, Mirror: instantMirror{tips}, Store: store, Engines: engines,
		Triage: triage.New(triage.WithStoreEvidence(store)), Reporter: &fakeReporter{}, Notifier: &fakeNotifier{}, Jobs: 8,
	}
	r, err := New(cfg)
	if err != nil {
		b.Fatal(err)
	}
	for _, s := range list {
		st := newState(s.ID)
		st.Tips, st.Visibility = tips, s.Visibility
		for _, e := range engines {
			st.ScannedWith[e.Name()] = e.Version()
		}
		if err := saveState(paths.Sources, st); err != nil {
			b.Fatal(err)
		}
	}
	return r, inv, paths, list
}

// BenchmarkIdlePoll is a poll where the inventory reports nothing changed: the snapshot is
// read, secrets are re-triaged, the report and the run record are written.
func BenchmarkIdlePoll(b *testing.B) {
	r, _, paths, list := benchSweep(b)
	prev := map[string]core.Source{}
	for _, s := range list {
		prev[s.ID] = s
	}
	if err := saveSnapshot(paths.Inventory, prev, time.Now()); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := r.Poll(context.Background()); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkPollAllSourcesChangedNothingNew is the sweep's own cost per source when GitHub says
// everything was pushed but no tip moved: state read, plan, state write, snapshot advance.
func BenchmarkPollAllSourcesChangedNothingNew(b *testing.B) {
	r, inv, paths, list := benchSweep(b)
	old := map[string]core.Source{}
	for _, s := range list {
		s.PushedAt = "2026-11-03T09:00:00Z" // the snapshot is older than the inventory, so every source is changed
		old[s.ID] = s
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		if err := saveSnapshot(paths.Inventory, old, time.Now()); err != nil {
			b.Fatal(err)
		}
		b.StartTimer()
		st, err := r.Poll(context.Background())
		if err != nil {
			b.Fatal(err)
		}
		if st.Sources != 469 || st.Skipped != 469 || st.Scanned != 0 {
			b.Fatalf("%+v", st)
		}
	}
	_ = inv
}

// BenchmarkIncrementalRange is the cost of turning old tips into an exclusion range: one
// `git cat-file --batch-check` that also drops tips the repo no longer has.
func BenchmarkIncrementalRange(b *testing.B) {
	isolate(b)
	r := newRepo(b, filepath.Join(b.TempDir(), "r"))
	var tips = map[string]string{}
	for i := 0; i < 5; i++ {
		tips[fmt.Sprintf("refs/heads/b%d", i)] = r.commit(fmt.Sprintf("c%d", i), map[string]string{"f": fmt.Sprint(i)})
		r.git("branch", "-q", fmt.Sprintf("b%d", i))
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok, err := incrementalRange(context.Background(), "git", r.dir, tips); err != nil || !ok {
			b.Fatal(err, ok)
		}
	}
}

// needleMatcher is the cheapest possible KnownMatcher, so the benchmark below measures the
// git plumbing around the matcher and not the matcher.
type needleMatcher struct{ needle []byte }

func (n needleMatcher) Len() int { return 1 }
func (n needleMatcher) Match(data []byte) []core.KnownMatch {
	if i := bytes.Index(data, n.needle); i >= 0 {
		return []core.KnownMatch{{EntryID: "kg000000", Name: "X", Variant: "raw", Offset: i, Len: len(n.needle), FP: "f", Shape: "…"}}
	}
	return nil
}

// BenchmarkGitKnown streams a repository of incompressible blobs through the known pass.
func BenchmarkGitKnown(b *testing.B) {
	isolate(b)
	r := newRepo(b, filepath.Join(b.TempDir(), "r"))
	rng := rand.New(rand.NewPCG(1, 2))
	const files, size = 64, 1 << 20
	content := make(map[string]string, files)
	for i := 0; i < files; i++ {
		buf := make([]byte, size)
		for j := 0; j < size; j += 8 {
			v := rng.Uint64()
			for k := 0; k < 8 && j+k < size; k++ {
				buf[j+k] = byte(v >> (8 * k))
			}
		}
		content[fmt.Sprintf("blob%02d.bin", i)] = string(buf)
	}
	r.commit("blobs", content)
	g := GitKnown{}
	m := needleMatcher{[]byte("not-in-the-data-0123456789")}
	b.SetBytes(files * size)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		st, err := g.ScanBlobs(context.Background(), r.dir, core.Range{All: true}, m, testLoc, func(core.Hit) {})
		if err != nil || st.Blobs < files {
			b.Fatal(err, st)
		}
	}
}

// BenchmarkLedgerSeen is the question the known pass asks of the ledger for every blob it
// lists: has this scanner read it already?
func BenchmarkLedgerSeen(b *testing.B) {
	l := newLedger(filepath.Join(b.TempDir(), "ledger"), func(string) {})
	set := l.set("known", "e1")
	const n = 500_000 // a few repos' worth of the real mirrors' 435,736 blobs
	ids := make([]oid, n)
	for i := range ids {
		for k := range ids[i] {
			ids[i][k] = byte(rand.Uint32())
		}
	}
	v := newSeenView(set, "github.com/o/a", false)
	for _, id := range ids {
		v.noteID(id)
	}
	if err := v.Commit(); err != nil {
		b.Fatal(err)
	}
	hex := make([]string, n)
	for i, id := range ids {
		hex[i] = fmt.Sprintf("%x", id[:])
	}
	b.ResetTimer()
	hits := 0
	for i := 0; i < b.N; i++ {
		if v.Seen(hex[i%n]) {
			hits++
		}
	}
	if hits != b.N {
		b.Fatalf("only %d of %d were seen", hits, b.N)
	}
}
