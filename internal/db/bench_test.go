package db

import (
	"fmt"
	"os"
	"testing"

	"keyguard/internal/core"
	"keyguard/internal/fp"
)

// benchHits builds n hits over distinct secrets, each reported by three engines at
// perSecret locations, the shape of a large first sweep.
func benchHits(b *testing.B, secrets, perSecret int) []core.Hit {
	b.Helper()
	kr := fp.NewEphemeral()
	engines := []string{"betterleaks", "trufflehog", "titus"}
	hits := make([]core.Hit, 0, secrets*perSecret*len(engines))
	for i := 0; i < secrets; i++ {
		raw := fmt.Sprintf("sk-bench-value-%08d", i)
		for l := 0; l < perSecret; l++ {
			for _, e := range engines {
				hits = append(hits, core.Hit{
					Engine: e, Rule: e + "-openai", Type: "openai", FP: kr.FP(raw), Shape: fp.Shape(raw), Len: len(raw),
					Entropy: 4.2, Verified: core.Unverified, Context: "API_KEY = «sk-…0001»",
					Loc: core.Location{Source: fmt.Sprintf("github.com/o/repo%d", i%400), Kind: "repo", Visibility: core.Private,
						Commit: fmt.Sprintf("%040x", l), Path: fmt.Sprintf("dir/file%d.env", l), Line: l + 1},
				})
			}
		}
	}
	return hits
}

// BenchmarkMerge folds 90,000 hits (10,000 secrets x 3 locations x 3 engines) into a store.
func BenchmarkMerge(b *testing.B) {
	hits := benchHits(b, 10000, 3)
	b.ReportMetric(float64(len(hits)), "hits/op")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		st, _ := Open(testPaths(b))
		b.StartTimer()
		for off := 0; off < len(hits); off += 5000 { // the batch size the sweep uses
			if _, err := st.Merge(hits[off:min(off+5000, len(hits))], t0); err != nil {
				b.Fatal(err)
			}
		}
	}
}

func benchStore(b *testing.B, secrets int) (*Store, core.Paths) {
	b.Helper()
	p := testPaths(b)
	st, _ := Open(p)
	hits := benchHits(b, secrets, 3)
	for off := 0; off < len(hits); off += 5000 {
		if _, err := st.Merge(hits[off:min(off+5000, len(hits))], t0); err != nil {
			b.Fatal(err)
		}
	}
	return st, p
}

// BenchmarkSave writes a 10,000-secret findings file (the size of a long-lived store).
func BenchmarkSave(b *testing.B) {
	st, p := benchStore(b, 10000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		st.mu.Lock()
		st.dirty = true
		st.mu.Unlock()
		if err := st.Save(); err != nil {
			b.Fatal(err)
		}
	}
	if fi, err := os.Stat(p.Findings); err == nil {
		b.ReportMetric(float64(fi.Size())/1e6, "MB/file")
	}
}

func BenchmarkOpen(b *testing.B) {
	st, p := benchStore(b, 10000)
	if err := st.Save(); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Open(p); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkGetAndRefresh is the per-poll cost of re-reading every secret, as the sweep's
// settleAll does after a visibility refresh.
func BenchmarkGetAndRefresh(b *testing.B) {
	st, _ := benchStore(b, 10000)
	vis := map[string]core.Visibility{}
	for i := 0; i < 469; i++ {
		vis[fmt.Sprintf("github.com/o/repo%d", i)] = core.Private
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		st.RefreshVisibility(vis)
		if n := len(st.Secrets()); n != 10000 {
			b.Fatal(n)
		}
	}
}
