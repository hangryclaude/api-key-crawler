package sweep

import (
	"context"
	"testing"

	"keyguard/internal/core"
	"keyguard/internal/engines"
	"keyguard/internal/testkit"
)

// The refresh reads again only the commits a key was found in, by naming them "<sha>^!" (the
// commit and none of its parents). The fake engines of the other tests take that as git does;
// this is the check that the real ones do: that each reads that commit's changes, no other
// commit's, and none of the history behind it.
func TestRealEnginesReadExactlyTheCommitsARefreshNames(t *testing.T) {
	w := newWorld(t)
	a := w.addRepo("a", core.Public)
	// Vowel-free so that trufflehog's dictionary-word filter cannot drop the token.
	tok1 := fakeKeyFrom(t, "ghp_", "bcdfghjklmnpqrstvwxyz0123456789", 36)
	tok2 := fakeKeyFrom(t, "ghp_", "bcdfghjklmnpqrstvwxyz0123456789", 36)
	c1 := a.commit("one", map[string]string{"a.env": "GITHUB_TOKEN=" + tok1 + "\n"})
	c2 := a.commit("two", map[string]string{"b.env": "GITHUB_TOKEN=" + tok2 + "\n"})
	c3 := a.commit("three", map[string]string{"c.txt": "nothing here\n"})
	clone := w.mir.Path(core.Source{ID: w.src("a")})
	runGit(t, w.root, "clone", "--mirror", "--quiet", a.dir, clone)

	for _, name := range []string{"betterleaks", "trufflehog"} {
		t.Run(name, func(t *testing.T) {
			e, err := engines.New(name, testkit.EnginePath(t, name), w.kr)
			if err != nil || !e.Available() {
				t.Fatalf("engine %s: %v", name, err)
			}
			for _, tc := range []struct {
				revs []string
				want map[string]string // commit -> the token expected there
			}{
				{[]string{c1 + "^!"}, map[string]string{c1: tok1}},
				{[]string{c2 + "^!"}, map[string]string{c2: tok2}},
				{[]string{c3 + "^!"}, nil},
				// Two adjacent commits in one range read only the newer: each excludes its parents,
				// and the older is the newer's parent. This is why a refresh reads a commit a call.
				{[]string{c1 + "^!", c2 + "^!"}, map[string]string{c2: tok2}},
			} {
				got := map[string]string{}
				err := e.ScanGit(context.Background(), clone, core.Range{Revs: tc.revs},
					core.ScanOpts{Threads: 2, Loc: core.Location{Source: w.src("a"), Kind: "repo", Visibility: core.Public}},
					func(h core.Hit) { got[h.Loc.Commit] = h.FP })
				if err != nil {
					t.Fatalf("%v: %v", tc.revs, err)
				}
				if len(got) != len(tc.want) {
					t.Fatalf("%s %v: found in %d commit(s), want %d", name, tc.revs, len(got), len(tc.want))
				}
				for c, tok := range tc.want {
					if got[c] != w.kr.FP(tok) {
						t.Fatalf("%s %v: the token of commit %s was not found there", name, tc.revs, c[:7])
					}
				}
			}
		})
	}
}

// fakeKeyFrom is fakeKey over a charset of the caller's choosing.
func fakeKeyFrom(t testing.TB, prefix, charset string, n int) string {
	return prefix + randStr(t, charset, n)
}
