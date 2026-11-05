package triage

import (
	"testing"

	"keyguard/internal/core"
)

// BenchmarkClassify is the cost of judging one secret with evidence, the common case in a
// sweep: a few locations, a handful of context lines.
func BenchmarkClassify(b *testing.B) {
	ev := Evidence{Entropy: 4.9, Contexts: []string{
		`OPENAI_API_KEY = "«sk-…k7Qz»"`, `export OPENAI_API_KEY=«sk-…k7Qz»`,
		`DATABASE_URL=postgres://app:«…ab»@prod-db.internal.example.com:5432/app`,
	}}
	tr := New(WithEvidence(func(string) (Evidence, bool) { return ev, true }))
	s := core.Secret{
		FP: "fp", Type: "openai", Shape: "sk-…k7Qz", Len: 51, Engines: []string{"betterleaks", "titus", "trufflehog"},
		Rules: []string{"openai-api-key"}, Verified: core.Unverified, Status: "open", Triage: Unreviewed,
		Locations: []core.Location{
			{Source: "github.com/o/a", Kind: "repo", Visibility: core.Private, Path: "src/config/app.ts", Line: 3},
			{Source: "github.com/o/b", Kind: "repo", Visibility: core.Public, Path: "deploy/prod.env", Line: 9},
			{Source: "github.com/o/c", Kind: "repo", Visibility: core.Private, Path: "tests/fixtures/env.json", Line: 1},
		},
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		t := s
		tr.Classify(&t)
	}
}
