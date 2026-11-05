package db

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"keyguard/internal/core"
)

func errorWith(why core.VerifyReason) func(*core.Hit) {
	return func(h *core.Hit) { h.Verified, h.VerifyReason = core.VerifyError, why }
}

func tags(ts ...string) func(*core.Hit) { return func(h *core.Hit) { h.Tags = ts } }

func ts(t *testing.T, s string) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// STEAL P0-09: Merge keeps the validity model, not a copy of it. An error is a reason class, a
// count and a retry time; a verdict is believed for a TTL; and an error never lowers a verdict.
func TestMergeFollowsTheValidityModel(t *testing.T) {
	st := mustOpen(t)
	f := newFixture()
	raw := f.raw(t)

	mustMerge(t, st, t0, f.hit(raw, "trufflehog", errorWith(core.ReasonRateLimited)))
	s := mustGet(t, st, f.kr.FP(raw))
	if s.Verified != core.VerifyError || s.VerifyReason != core.ReasonRateLimited || s.VerifyErrors != 1 ||
		s.VerifyAttempted != t0 || ts(t, s.NextVerifyAt).Sub(ts(t, t0)) != time.Minute {
		t.Fatalf("after one 429: %+v", s)
	}
	mustMerge(t, st, t1, f.hit(raw, "trufflehog", errorWith(core.ReasonTimeout)))
	s = mustGet(t, st, f.kr.FP(raw))
	if s.VerifyErrors != 2 || s.VerifyReason != core.ReasonTimeout || ts(t, s.NextVerifyAt).Sub(ts(t, t1)) != 5*time.Minute {
		t.Fatalf("after a second error the backoff moves on: %+v", s)
	}
	if !s.VerifyDue(ts(t, t1).Add(6 * time.Minute)) {
		t.Error("a retry should be due when its time has come")
	}

	mustMerge(t, st, t2, f.hit(raw, "betterleaks", verified(core.Live)))
	s = mustGet(t, st, f.kr.FP(raw))
	if s.Verified != core.Live || s.VerifiedAt != t2 || s.VerifyReason != "" || s.VerifyErrors != 0 ||
		ts(t, s.NextVerifyAt).Sub(ts(t, t2)) != core.LiveTTL {
		t.Fatalf("a verdict clears the errors and is believed for six hours: %+v", s)
	}

	// An error after a verdict records itself and lowers nothing.
	t3 := "2026-11-03T13:00:00Z"
	mustMerge(t, st, t3, f.hit(raw, "trufflehog", errorWith(core.ReasonDial)))
	s = mustGet(t, st, f.kr.FP(raw))
	if s.Verified != core.Live || s.VerifiedAt != t2 || s.VerifyReason != core.ReasonDial || s.VerifyErrors != 1 || s.Status != StatusOpen {
		t.Fatalf("an error after a live verdict: %+v", s)
	}

	// Dead is the one verdict that retires an alert, and it is believed for a week.
	t4 := "2026-11-03T14:00:00Z"
	mustMerge(t, st, t4, f.hit(raw, "betterleaks", verified(core.Dead)))
	s = mustGet(t, st, f.kr.FP(raw))
	if s.Verified != core.Dead || s.Status != StatusResolved || ts(t, s.NextVerifyAt).Sub(ts(t, t4)) != core.DeadTTL {
		t.Fatalf("dead: %+v", s)
	}
	// A late-arriving older verdict does not undo it.
	mustMerge(t, st, t1, f.hit(raw, "betterleaks", verified(core.Live)))
	if s = mustGet(t, st, f.kr.FP(raw)); s.Verified != core.Dead {
		t.Errorf("a verdict older than the one held replaced it: %+v", s)
	}
}

// The reason is a class, never the verifier's own words, which can quote the credential.
func TestAVerifyReasonThatIsTextIsDroppedBeforeItReachesDisk(t *testing.T) {
	paths := testPaths(t)
	st, err := Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	f := newFixture()
	raw := f.raw(t)
	words := core.VerifyReason("dial tcp: postgres://app:" + raw + "@db.example.com:5432 refused")
	mustMerge(t, st, t0, f.hit(raw, "trufflehog", errorWith(words)))
	if s := mustGet(t, st, f.kr.FP(raw)); s.VerifyReason != "" || s.Verified != core.VerifyError {
		t.Fatalf("text kept as a reason: %+v", s)
	}
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	if got := readAll(t, filepath.Dir(paths.Findings)); strings.Contains(got, raw) || strings.Contains(got, "postgres://") {
		t.Fatal("the verifier's words reached disk")
	}
	// A findings file edited by hand to hold text is read back as a class, too.
	b, _ := os.ReadFile(paths.Findings)
	edited := strings.Replace(string(b), `"verified": "error"`, `"verified": "error", "verify_reason": "`+string(words)+`"`, 1)
	if edited == string(b) {
		t.Fatal("setup: the findings file has no verify state to edit")
	}
	if err := os.WriteFile(paths.Findings, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}
	st2, err := Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	if s := mustGet(t, st2, f.kr.FP(raw)); s.VerifyReason != "" {
		t.Errorf("reading text back as a reason: %q", s.VerifyReason)
	}
}

// betterleaks checks every occurrence of a key, so six copies are six outcomes of one round, and
// two engines can disagree about it. One Merge call records the strongest, once.
func TestOneMergeCallIsOneRoundOfVerification(t *testing.T) {
	st := mustOpen(t)
	f := newFixture()
	cases := []struct {
		name string
		hits func(raw string) []core.Hit
		want core.Verified
		errs int
	}{
		{"live beats dead", func(r string) []core.Hit {
			return []core.Hit{f.hit(r, "trufflehog", verified(core.Dead)), f.hit(r, "betterleaks", verified(core.Live))}
		}, core.Live, 0},
		{"dead beats an error", func(r string) []core.Hit {
			return []core.Hit{f.hit(r, "trufflehog", errorWith(core.ReasonOverlap)), f.hit(r, "betterleaks", verified(core.Dead))}
		}, core.Dead, 0},
		{"six errors are one step of the backoff", func(r string) []core.Hit {
			var out []core.Hit
			for i := 0; i < 6; i++ {
				out = append(out, f.hit(r, "betterleaks", errorWith(core.ReasonTimeout), at2("c"+string(rune('a'+i)))))
			}
			return out
		}, core.VerifyError, 1},
		{"an error and an unverified is an error", func(r string) []core.Hit {
			return []core.Hit{f.hit(r, "titus"), f.hit(r, "trufflehog", errorWith(core.ReasonStatus))}
		}, core.VerifyError, 1},
	}
	for _, tc := range cases {
		raw := f.raw(t)
		mustMerge(t, st, t0, tc.hits(raw)...)
		s := mustGet(t, st, f.kr.FP(raw))
		if s.Verified != tc.want || s.VerifyErrors != tc.errs {
			t.Errorf("%s: %s with %d errors, want %s with %d", tc.name, s.Verified, s.VerifyErrors, tc.want, tc.errs)
		}
	}
}

func at2(commit string) func(*core.Hit) {
	return func(h *core.Hit) { h.Loc.Commit = commit }
}

// Tags are what the normalizer worked out from the raw value before it dropped it. A secret
// carries their union; triage reads them from the secret or from the evidence.
func TestTagsAreUnionedKeptWithTheEvidenceAndNeverPiecesOfAValue(t *testing.T) {
	paths := testPaths(t)
	st, err := Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	f := newFixture()
	raw := f.raw(t)
	mustMerge(t, st, t0,
		f.hit(raw, "betterleaks", tags("jwt.role=anon"), at2("c1")),
		f.hit(raw, "trufflehog", tags("placeholder", "jwt.role=anon"), at2("c2")))
	mustMerge(t, st, t1, f.hit(raw, "titus", tags("test-mode"), at2("c3")))
	s := mustGet(t, st, f.kr.FP(raw))
	if got := strings.Join(s.Tags, ","); got != "jwt.role=anon,placeholder,test-mode" {
		t.Fatalf("tags %q", got)
	}
	_, _, evTags, ok := st.Evidence(f.kr.FP(raw))
	if !ok || strings.Join(evTags, ",") != "jwt.role=anon,placeholder,test-mode" {
		t.Errorf("triage reads the tags from the evidence too: %v %v", evTags, ok)
	}

	// Something that could be a piece of a value is not a tag: it is dropped, and said once.
	piece := strings.ToLower(raw[len(raw)-20:])
	mustMerge(t, st, t2, f.hit(raw, "betterleaks", tags(piece, "Placeholder", "has space", ""), at2("c4")))
	if got := mustGet(t, st, f.kr.FP(raw)).Tags; len(got) != 3 {
		t.Errorf("a made-up tag was kept: %v", got)
	}
	var said int
	for _, n := range st.TakeNotes() {
		if strings.Contains(n, "was not a tag") {
			said++
		}
		if strings.Contains(n, piece) {
			t.Error("a note quoted the piece")
		}
	}
	if said != 1 {
		t.Errorf("the note should be said once, got %d", said)
	}
	// The vocabulary is a handful of words: a flood is capped.
	many := make([]string, 0, 20)
	for i := 0; i < 20; i++ {
		many = append(many, "kind"+string(rune('a'+i)))
	}
	mustMerge(t, st, t2, f.hit(raw, "betterleaks", tags(many...), at2("c5")))
	if got := mustGet(t, st, f.kr.FP(raw)).Tags; len(got) > maxTags {
		t.Errorf("%d tags kept, cap %d", len(got), maxTags)
	}

	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	st2, err := Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	if got := mustGet(t, st2, f.kr.FP(raw)).Tags; len(got) == 0 || got[0] != "jwt.role=anon" {
		t.Errorf("tags did not survive a save: %v", got)
	}
	if _, _, tg, _ := st2.Evidence(f.kr.FP(raw)); len(tg) == 0 {
		t.Error("evidence tags did not survive a save")
	}
}

// A branch or a tag can be called anything, a key included, and an engine names the ref a hit
// was found on. That name must not reach findings.json.
func TestARefNamedForAKeyIsMaskedAndOrdinaryRefsAreNot(t *testing.T) {
	paths := testPaths(t)
	st, err := Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	f := newFixture()
	secret := f.raw(t)
	other := "sk-" + randStr(t, alnum, 48) // the key a branch is named after
	for ref, wantKept := range map[string]bool{
		"refs/heads/main":                       true,
		"refs/pull/12/head":                     true,
		"refs/tags/v1.2.3":                      true,
		"refs/heads/feature/login-2026-11":      true,
		"refs/heads/dependabot/npm_and_yarn/x":  true,
		"refs/heads/" + other:                   false,
		"refs/tags/release/" + other + "/final": false,
	} {
		raw := f.raw(t)
		mustMerge(t, st, t0, f.hit(raw, "betterleaks", func(h *core.Hit) { h.Loc.Ref = ref }))
		got := mustGet(t, st, f.kr.FP(raw)).Locations[0].Ref
		if (got == ref) != wantKept || strings.Contains(got, other) {
			t.Errorf("ref %q was stored as %q", ref, got)
		}
	}
	_ = secret
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	if got := readAll(t, filepath.Dir(paths.Findings)); strings.Contains(got, other) {
		t.Fatal("a ref named for a key reached disk")
	}
}

// Two processes allowing two findings at once (a person at the terminal and a sweep) each read
// the list, add an entry and write the whole file back. The lock keeps one from erasing the other.
func TestTwoProcessesIgnoringAtOnceKeepEveryEntry(t *testing.T) {
	paths := testPaths(t)
	f := newFixture()
	seed, err := Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	var fps []string
	for i := 0; i < 24; i++ {
		raw := f.raw(t)
		mustMerge(t, seed, t0, f.hit(raw, "betterleaks", at2("c"+string(rune('a'+i)))))
		fps = append(fps, f.kr.FP(raw))
	}
	if err := seed.Save(); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for half := 0; half < 2; half++ {
		st, err := Open(paths) // each its own store, as each process has its own
		if err != nil {
			t.Fatal(err)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := half; i < len(fps); i += 2 {
				if err := st.Ignore(fps[i], "false positive"); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()

	list, err := LoadIgnore(paths.Ignore)
	if err != nil {
		t.Fatal(err)
	}
	if list.Len() != len(fps) {
		t.Fatalf("%d of %d entries survived two writers", list.Len(), len(fps))
	}
	if fi, err := os.Stat(paths.Ignore + ".lock"); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("lock file: %v %v", fi, err)
	}
}

func mustOpen(t *testing.T) *Store {
	t.Helper()
	st, err := Open(testPaths(t))
	if err != nil {
		t.Fatal(err)
	}
	return st
}
