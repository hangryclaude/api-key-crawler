package db

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"keyguard/internal/core"
	"keyguard/internal/fp"
)

const (
	t0 = "2026-11-03T10:00:00Z"
	t1 = "2026-11-03T11:00:00Z"
	t2 = "2026-11-03T12:00:00Z"
)

func TestMergeUnionsThreeEnginesTwoRepos(t *testing.T) {
	st, err := Open(testPaths(t))
	if err != nil {
		t.Fatal(err)
	}
	f := newFixture()
	raw := f.raw(t)
	var hits []core.Hit
	for _, repo := range []string{"github.com/o/a", "github.com/o/b"} {
		for _, eng := range []string{"betterleaks", "trufflehog", "titus"} {
			hits = append(hits, f.hit(raw, eng, at(repo, core.Private, "c1", ".env", 3)))
		}
	}
	fresh := mustMerge(t, st, t0, hits...)
	if len(fresh) != 1 || fresh[0] != f.kr.FP(raw) {
		t.Fatalf("newFPs = %v, want exactly the one fingerprint", fresh)
	}
	all := st.Secrets()
	if len(all) != 1 {
		t.Fatalf("%d secrets, want 1", len(all))
	}
	s := all[0]
	if len(s.Locations) != 2 {
		t.Fatalf("%d locations, want 2 (one per repo): %+v", len(s.Locations), s.Locations)
	}
	if !slices.Equal(s.Engines, []string{"betterleaks", "titus", "trufflehog"}) {
		t.Fatalf("engines %v", s.Engines)
	}
	if len(s.Rules) != 3 {
		t.Fatalf("rules %v, want one per engine", s.Rules)
	}
	if again := mustMerge(t, st, t1, hits...); len(again) != 0 {
		t.Fatalf("second merge reported %v as new", again)
	}
	if got := mustGet(t, st, f.kr.FP(raw)); len(got.Locations) != 2 {
		t.Fatalf("re-merge changed the location count to %d", len(got.Locations))
	}
}

func TestMergeNewSecretDefaults(t *testing.T) {
	st, _ := Open(testPaths(t))
	f := newFixture()
	raw := f.raw(t)
	mustMerge(t, st, t0, f.hit(raw, "betterleaks"))
	s := mustGet(t, st, f.kr.FP(raw))
	if s.ID != fp.ID(s.FP) || !strings.HasPrefix(s.ID, "kg") || len(s.ID) != 8 {
		t.Fatalf("id %q", s.ID)
	}
	if s.Status != StatusOpen || s.Triage != TriageUnreviewed || s.Severity != core.None || s.Notified != core.None {
		t.Fatalf("defaults: status=%s triage=%s sev=%v notified=%v", s.Status, s.Triage, s.Severity, s.Notified)
	}
	if s.Verified != core.Unverified || s.VerifiedAt != "" {
		t.Fatalf("verified=%s at=%q", s.Verified, s.VerifiedAt)
	}
	if s.FirstSeen != t0 || s.LastSeen != t0 {
		t.Fatalf("seen %s..%s", s.FirstSeen, s.LastSeen)
	}
	if s.Type != "openai" || s.Shape != fp.Shape(raw) || s.Len != len(raw) {
		t.Fatalf("identity fields: %+v", s)
	}
}

func TestVerdictSemantics(t *testing.T) {
	type step struct {
		v   core.Verified
		now string
	}
	cases := []struct {
		name     string
		steps    []step
		want     core.Verified
		wantAt   string
		wantStat string
	}{
		{"live then unverified keeps live", []step{{core.Live, t0}, {core.Unverified, t1}}, core.Live, t0, StatusOpen},
		{"live then error keeps live", []step{{core.Live, t0}, {core.VerifyError, t1}}, core.Live, t0, StatusOpen},
		{"dead then unverified keeps dead", []step{{core.Dead, t0}, {core.Unverified, t1}}, core.Dead, t0, StatusResolved},
		{"live then dead later: dead, resolved", []step{{core.Live, t0}, {core.Dead, t1}}, core.Dead, t1, StatusResolved},
		{"dead then live later: live, reopened", []step{{core.Dead, t0}, {core.Live, t1}}, core.Live, t1, StatusOpen},
		{"older dead does not replace newer live", []step{{core.Live, t1}, {core.Dead, t0}}, core.Live, t1, StatusOpen},
		{"older live does not replace newer dead", []step{{core.Dead, t1}, {core.Live, t0}}, core.Dead, t1, StatusResolved},
		{"same second, later call: dead replaces live", []step{{core.Live, t0}, {core.Dead, t0}}, core.Dead, t0, StatusResolved},
		{"same second, later call: live replaces dead", []step{{core.Dead, t0}, {core.Live, t0}}, core.Live, t0, StatusOpen},
		{"same second, same verdict: nothing changes", []step{{core.Live, t0}, {core.Live, t0}}, core.Live, t0, StatusOpen},
		{"same verdict later refreshes the stamp", []step{{core.Live, t0}, {core.Live, t2}}, core.Live, t2, StatusOpen},
		{"error then unverified stays error", []step{{core.VerifyError, t0}, {core.Unverified, t1}}, core.VerifyError, "", StatusOpen},
		{"unverified then error becomes error", []step{{core.Unverified, t0}, {core.VerifyError, t1}}, core.VerifyError, "", StatusOpen},
		{"error then live is live", []step{{core.VerifyError, t0}, {core.Live, t1}}, core.Live, t1, StatusOpen},
		{"empty verified is unverified", []step{{"", t0}}, core.Unverified, "", StatusOpen},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			st, _ := Open(testPaths(t))
			f := newFixture()
			raw := f.raw(t)
			for _, s := range c.steps {
				mustMerge(t, st, s.now, f.hit(raw, "trufflehog", verified(s.v)))
			}
			got := mustGet(t, st, f.kr.FP(raw))
			if got.Verified != c.want || got.VerifiedAt != c.wantAt || got.Status != c.wantStat {
				t.Fatalf("verified=%s at=%q status=%s; want %s %q %s", got.Verified, got.VerifiedAt, got.Status, c.want, c.wantAt, c.wantStat)
			}
		})
	}
}

func TestVerdictInOneBatchLiveBeatsDead(t *testing.T) {
	st, _ := Open(testPaths(t))
	f := newFixture()
	raw := f.raw(t)
	mustMerge(t, st, t0,
		f.hit(raw, "trufflehog", verified(core.Dead)),
		f.hit(raw, "betterleaks", verified(core.Live)),
		f.hit(raw, "titus", verified(core.Dead)))
	if got := mustGet(t, st, f.kr.FP(raw)); got.Verified != core.Live {
		t.Fatalf("a batch with a live and a dead verdict at one instant gave %s", got.Verified)
	}
}

func TestKnownIsSticky(t *testing.T) {
	st, _ := Open(testPaths(t))
	f := newFixture()
	raw := f.raw(t)
	mustMerge(t, st, t0, f.hit(raw, "betterleaks"))
	mustMerge(t, st, t1, f.hit(raw, "known", func(h *core.Hit) { h.Known = "kgabc123 OPENAI_API_KEY" }))
	mustMerge(t, st, t2, f.hit(raw, "titus"))
	if got := mustGet(t, st, f.kr.FP(raw)); got.Known != "kgabc123 OPENAI_API_KEY" {
		t.Fatalf("known = %q after a later hit without it", got.Known)
	}
	mustMerge(t, st, t2, f.hit(raw, "known", func(h *core.Hit) { h.Known = "kgabc123 OTHER_NAME" }))
	if got := mustGet(t, st, f.kr.FP(raw)); got.Known != "kgabc123 OPENAI_API_KEY" {
		t.Fatalf("a second name replaced the first: %q", got.Known)
	}
}

func TestFirstAndLastSeenOnlyMoveOutward(t *testing.T) {
	st, _ := Open(testPaths(t))
	f := newFixture()
	raw := f.raw(t)
	mustMerge(t, st, t1, f.hit(raw, "betterleaks"))
	mustMerge(t, st, t2, f.hit(raw, "betterleaks"))
	mustMerge(t, st, t0, f.hit(raw, "betterleaks")) // a late-arriving older batch
	got := mustGet(t, st, f.kr.FP(raw))
	if got.FirstSeen != t0 || got.LastSeen != t2 {
		t.Fatalf("seen %s..%s, want %s..%s", got.FirstSeen, got.LastSeen, t0, t2)
	}
}

func TestTimestampsCompareAsTimesAcrossOffsets(t *testing.T) {
	st, _ := Open(testPaths(t))
	f := newFixture()
	raw := f.raw(t)
	// 10:30 at -05:00 is 15:30Z, later than 11:00Z although the string sorts earlier.
	mustMerge(t, st, "2026-11-03T11:00:00Z", f.hit(raw, "trufflehog", verified(core.Dead)))
	mustMerge(t, st, "2026-11-03T10:30:00-05:00", f.hit(raw, "trufflehog", verified(core.Live)))
	if got := mustGet(t, st, f.kr.FP(raw)); got.Verified != core.Live {
		t.Fatalf("verified=%s: the later instant must win whatever offset it is written in", got.Verified)
	}
}

func TestTypeSpecificityAndAuthority(t *testing.T) {
	st, _ := Open(testPaths(t))
	f := newFixture()
	raw := f.raw(t)
	typed := func(ty string) func(*core.Hit) { return func(h *core.Hit) { h.Type = ty } }
	mustMerge(t, st, t0, f.hit(raw, "betterleaks", typed("generic")))
	mustMerge(t, st, t0, f.hit(raw, "titus", typed("openai")))
	if got := mustGet(t, st, f.kr.FP(raw)); got.Type != "openai" {
		t.Fatalf("specific did not replace generic: %s", got.Type)
	}
	mustMerge(t, st, t0, f.hit(raw, "betterleaks", typed("generic")))
	mustMerge(t, st, t0, f.hit(raw, "gitleaks", typed("anthropic")))
	if got := mustGet(t, st, f.kr.FP(raw)); got.Type != "openai" {
		t.Fatalf("generic or a later guess replaced the first specific type: %s", got.Type)
	}
	mustMerge(t, st, t1, f.hit(raw, "trufflehog", typed("anthropic"), verified(core.Live)))
	if got := mustGet(t, st, f.kr.FP(raw)); got.Type != "anthropic" {
		t.Fatalf("the provider that accepted the key should decide its type: %s", got.Type)
	}
}

func TestLocationRefreshAndFill(t *testing.T) {
	st, _ := Open(testPaths(t))
	f := newFixture()
	raw := f.raw(t)
	a := f.hit(raw, "betterleaks", at("github.com/o/a", core.Private, "c1", ".env", 3))
	mustMerge(t, st, t0, a)
	b := f.hit(raw, "trufflehog", at("github.com/o/a", core.Public, "c1", ".env", 3), func(h *core.Hit) {
		h.Loc.Author, h.Loc.Date, h.Loc.URL, h.Loc.Ref = "ann", "2026-01-01", "https://example.test/x", "refs/heads/main"
	})
	mustMerge(t, st, t1, b)
	got := mustGet(t, st, f.kr.FP(raw))
	if len(got.Locations) != 1 {
		t.Fatalf("same place twice made %d locations", len(got.Locations))
	}
	l := got.Locations[0]
	if l.Visibility != core.Public || l.Author != "ann" || l.URL == "" || l.Ref != "refs/heads/main" || l.Date != "2026-01-01" {
		t.Fatalf("location not refreshed/filled: %+v", l)
	}
	// A later sighting without the extras must not erase them.
	mustMerge(t, st, t2, f.hit(raw, "titus", at("github.com/o/a", core.Public, "c1", ".env", 3)))
	if l := mustGet(t, st, f.kr.FP(raw)).Locations[0]; l.Author != "ann" {
		t.Fatalf("a bare sighting erased the author: %+v", l)
	}
}

func TestEmptyVisibilityIsTreatedAsExposed(t *testing.T) {
	st, _ := Open(testPaths(t))
	f := newFixture()
	raw := f.raw(t)
	mustMerge(t, st, t0, f.hit(raw, "betterleaks", at("github.com/o/a", "", "c1", ".env", 1)))
	got := mustGet(t, st, f.kr.FP(raw))
	if got.Locations[0].Visibility != core.Unknown || !got.Exposed() {
		t.Fatalf("a location with no visibility must read as unknown/exposed, got %q", got.Locations[0].Visibility)
	}
}

func TestLocationCapPrefersExposedPlaces(t *testing.T) {
	st, _ := Open(testPaths(t), WithMaxLocations(5))
	f := newFixture()
	raw := f.raw(t)
	for i := 0; i < 8; i++ {
		mustMerge(t, st, t0, f.hit(raw, "betterleaks", at("github.com/o/priv", core.Private, "c", "f", i)))
	}
	if got := mustGet(t, st, f.kr.FP(raw)); len(got.Locations) != 5 || got.Exposed() {
		t.Fatalf("cap not applied: %d locations, exposed=%v", len(got.Locations), got.Exposed())
	}
	mustMerge(t, st, t0, f.hit(raw, "betterleaks", at("github.com/o/pub", core.Public, "c", "f", 1)))
	got := mustGet(t, st, f.kr.FP(raw))
	if len(got.Locations) != 5 || !got.Exposed() {
		t.Fatalf("an exposed sighting must displace a private one: %d locations, exposed=%v", len(got.Locations), got.Exposed())
	}
	// With no private slot left to give, further sightings are counted but not stored.
	for i := 0; i < 5; i++ {
		mustMerge(t, st, t0, f.hit(raw, "betterleaks", at("github.com/o/pub", core.Public, "c", "g", i)))
	}
	if got := mustGet(t, st, f.kr.FP(raw)); len(got.Locations) != 5 {
		t.Fatalf("%d locations stored", len(got.Locations))
	}
	if n := st.Dropped(f.kr.FP(raw)); n < 8 {
		t.Fatalf("dropped = %d, want the 3 + 5 + displaced sightings counted", n)
	}
	notes := st.TakeNotes()
	if len(notes) != 1 || !strings.Contains(notes[0], "more than 5 locations") {
		t.Fatalf("notes = %v, want one cap note", notes)
	}
	if again := st.TakeNotes(); len(again) != 0 {
		t.Fatalf("TakeNotes did not clear: %v", again)
	}
}

func TestSaveOpenRoundTrip(t *testing.T) {
	p := testPaths(t)
	st, _ := Open(p)
	f := newFixture()
	var raws []string
	for i := 0; i < 5; i++ {
		raw := f.raw(t)
		raws = append(raws, raw)
		mustMerge(t, st, t0,
			f.hit(raw, "betterleaks", at("github.com/o/b", core.Public, "c2", "z.txt", 9)),
			f.hit(raw, "titus", at("github.com/o/a", core.Private, "c1", "a.txt", 2)))
	}
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p.Findings)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("findings mode %v, want 0600", fi.Mode().Perm())
	}
	di, _ := os.Stat(filepath.Dir(p.Findings))
	if di.Mode().Perm() != 0o700 {
		t.Fatalf("state dir mode %v, want 0700", di.Mode().Perm())
	}
	entries, _ := os.ReadDir(filepath.Dir(p.Findings))
	if len(entries) != 1 {
		t.Fatalf("temp files left behind: %v", entries)
	}
	re, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	a, b := st.Secrets(), re.Secrets()
	if fmt.Sprint(a) != fmt.Sprint(b) {
		t.Fatalf("reload differs:\n%v\n%v", a, b)
	}
	for _, s := range b {
		if !sortedLocations(s.Locations) {
			t.Fatalf("locations not in canonical order: %+v", s.Locations)
		}
	}
	// Serving order is by fingerprint, so a reader sees the same list whatever the arrival order.
	if !slices.IsSortedFunc(b, func(x, y core.Secret) int { return strings.Compare(x.FP, y.FP) }) {
		t.Fatal("Secrets() not ordered by fingerprint")
	}
	_ = raws
}

func sortedLocations(l []core.Location) bool {
	return slices.IsSortedFunc(l, cmpLocation)
}

func TestSaveSkippedWhenClean(t *testing.T) {
	p := testPaths(t)
	st, _ := Open(p)
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p.Findings); err != nil {
		t.Fatalf("a first Save must leave a (possibly empty) findings file: %v", err)
	}
	before, _ := os.Stat(p.Findings)
	time.Sleep(10 * time.Millisecond)
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	after, _ := os.Stat(p.Findings)
	if !after.ModTime().Equal(before.ModTime()) {
		t.Fatal("a clean store rewrote its file")
	}
}

func TestOpenLeavesCorruptFileAlone(t *testing.T) {
	p := testPaths(t)
	if err := os.MkdirAll(filepath.Dir(p.Findings), 0o700); err != nil {
		t.Fatal(err)
	}
	junk := []byte(`{"version":1,"secrets":[{"fp":`)
	if err := os.WriteFile(p.Findings, junk, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(p); err == nil || !strings.Contains(err.Error(), "findings.json") {
		t.Fatalf("Open on corrupt file: %v", err)
	}
	if b, _ := os.ReadFile(p.Findings); string(b) != string(junk) {
		t.Fatal("Open modified the corrupt file")
	}
}

func TestOpenRejectsBadFiles(t *testing.T) {
	write := func(p core.Paths, s string) {
		if err := os.MkdirAll(filepath.Dir(p.Findings), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p.Findings, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	p := testPaths(t)
	write(p, `{"version":99,"secrets":[]}`)
	if _, err := Open(p); err == nil || !strings.Contains(err.Error(), "version 99") {
		t.Fatalf("newer version: %v", err)
	}
	write(p, `{"version":1,"secrets":[{"fp":""}]}`)
	if _, err := Open(p); err == nil || !strings.Contains(err.Error(), "no fingerprint") {
		t.Fatalf("missing fp: %v", err)
	}
	write(p, `{"version":1,"secrets":[{"fp":"aaaaaa0000"},{"fp":"aaaaaa0000"}]}`)
	if _, err := Open(p); err == nil || !strings.Contains(err.Error(), "twice") {
		t.Fatalf("duplicate fp: %v", err)
	}
	bad := testPaths(t)
	if err := os.MkdirAll(filepath.Dir(bad.Ignore), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bad.Ignore, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(bad); err == nil || !strings.Contains(err.Error(), "ignore") {
		t.Fatalf("corrupt ignore list: %v", err)
	}
}

func TestHitsWithoutFingerprintAreReportedNotFatal(t *testing.T) {
	st, _ := Open(testPaths(t))
	f := newFixture()
	raw := f.raw(t)
	good := f.hit(raw, "betterleaks")
	broken := f.hit(raw, "badengine")
	broken.FP = ""
	fresh, err := st.Merge([]core.Hit{broken, good, broken}, t0)
	if err == nil || !strings.Contains(err.Error(), "badengine") || !strings.Contains(err.Error(), "2 hit") {
		t.Fatalf("err = %v, want it to count the dropped hits and name the engine", err)
	}
	if len(fresh) != 1 || st.Len() != 1 {
		t.Fatalf("the valid hit must still be merged: fresh=%v len=%d", fresh, st.Len())
	}
}

func TestIgnoreByFingerprintAndIDSurvivesLosingFindings(t *testing.T) {
	p := testPaths(t)
	st, _ := Open(p)
	f := newFixture()
	raw := f.raw(t)
	mustMerge(t, st, t0, f.hit(raw, "betterleaks", verified(core.Live)))
	id := fp.ID(f.kr.FP(raw))
	if err := st.Ignore(strings.ToUpper(id), "docs example"); err != nil {
		t.Fatal(err)
	}
	got := mustGet(t, st, f.kr.FP(raw))
	if got.Status != StatusIgnored || got.Triage != TriageFalsePositive || got.TriageBy != TriageByHuman || got.Severity != core.Info {
		t.Fatalf("ignored secret: %+v", got)
	}
	if !strings.Contains(got.TriageWhy, "docs example") {
		t.Fatalf("reason lost: %q", got.TriageWhy)
	}
	// Later sightings, even a live verdict, leave it ignored.
	mustMerge(t, st, t1, f.hit(raw, "trufflehog", verified(core.Live), at("github.com/o/new", core.Public, "c9", "x", 1)))
	got = mustGet(t, st, f.kr.FP(raw))
	if got.Status != StatusIgnored || len(got.Locations) != 2 {
		t.Fatalf("after a new sighting: status=%s locations=%d", got.Status, len(got.Locations))
	}
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p.Ignore)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("ignore.json: %v %v", fi, err)
	}
	// Lose the findings file entirely: the ignore list alone must keep the decision.
	if err := os.Rename(p.Findings, p.Findings+".moved"); err != nil {
		t.Fatal(err)
	}
	fresh, _ := Open(p)
	n := mustMerge(t, fresh, t2, f.hit(raw, "betterleaks"))
	if len(n) != 1 {
		t.Fatalf("the rebuilt store should see the fingerprint as new, got %v", n)
	}
	got = mustGet(t, fresh, f.kr.FP(raw))
	if got.Status != StatusIgnored || got.Severity != core.Info {
		t.Fatalf("a rebuilt store forgot the ignore: %+v", got)
	}
	list, err := LoadIgnore(p.Ignore)
	if err != nil || !list.Has(f.kr.FP(raw)) || list.Len() != 1 {
		t.Fatalf("ignore list view: %v %v", list, err)
	}
	if e, _ := list.Entry(f.kr.FP(raw)); e.ID != id || e.At == "" {
		t.Fatalf("entry %+v", e)
	}
	if !IgnoredFunc(p.Ignore)(f.kr.FP(raw)) || IgnoredFunc(p.Ignore)("0000") {
		t.Fatal("IgnoredFunc answers wrong")
	}
}

func TestIgnoreArgumentResolution(t *testing.T) {
	st, _ := Open(testPaths(t))
	f := newFixture()
	if err := st.Ignore("kgdeadbe", "x"); err == nil || !strings.Contains(err.Error(), "no stored secret") {
		t.Fatalf("unknown id: %v", err)
	}
	if err := st.Ignore("what", "x"); err == nil {
		t.Fatal("garbage argument accepted")
	}
	// A full fingerprint of a value never found yet is fine: ignore it before it appears.
	raw := f.raw(t)
	if err := st.Ignore(f.kr.FP(raw), "known fake"); err != nil {
		t.Fatal(err)
	}
	fresh := mustMerge(t, st, t0, f.hit(raw, "betterleaks"))
	if len(fresh) != 1 {
		t.Fatalf("fresh=%v", fresh)
	}
	if got := mustGet(t, st, f.kr.FP(raw)); got.Status != StatusIgnored {
		t.Fatalf("pre-ignored fingerprint arrived as %s", got.Status)
	}
	if s, ok := st.Find(fp.ID(f.kr.FP(raw))); !ok || s.FP != f.kr.FP(raw) {
		t.Fatalf("Find by id: %v %v", s, ok)
	}
	if !st.Ignored(f.kr.FP(raw)) {
		t.Fatal("Ignored() false for an ignored fingerprint")
	}
}

func TestIgnoreIDCollisionAsksForTheFingerprint(t *testing.T) {
	st, _ := Open(testPaths(t))
	// Two stored secrets whose fingerprints share their first six hex digits.
	a := "abcdef" + strings.Repeat("0", 26)
	b := "abcdef" + strings.Repeat("1", 26)
	for _, fpv := range []string{a, b} {
		mustMerge(t, st, t0, core.Hit{Engine: "e", FP: fpv, Shape: "…", Loc: core.Location{Source: "s", Visibility: core.Private}})
	}
	if err := st.Ignore("kgabcdef", "x"); err == nil || !strings.Contains(err.Error(), "matches 2") {
		t.Fatalf("ambiguous id: %v", err)
	}
	if err := st.Ignore(b, "x"); err != nil {
		t.Fatal(err)
	}
}

func TestIgnoreFileChangedMidRunTakesEffect(t *testing.T) {
	p := testPaths(t)
	run, _ := Open(p) // the sweep
	f := newFixture()
	raw := f.raw(t)
	mustMerge(t, run, t0, f.hit(raw, "betterleaks"))
	cli, _ := Open(p) // `keyguard allow` in another process
	if err := cli.Ignore(f.kr.FP(raw), "mid-run"); err != nil {
		t.Fatal(err)
	}
	mustMerge(t, run, t1, f.hit(raw, "titus"))
	if got := mustGet(t, run, f.kr.FP(raw)); got.Status != StatusIgnored {
		t.Fatalf("a running sweep did not pick up the new ignore: %s", got.Status)
	}
	if err := cli.Unignore(f.kr.FP(raw)); err != nil {
		t.Fatal(err)
	}
	mustMerge(t, run, t2, f.hit(raw, "gitleaks"))
	got := mustGet(t, run, f.kr.FP(raw))
	if got.Status != StatusOpen || got.Triage != TriageUnreviewed || got.Severity != core.None {
		t.Fatalf("unignore not picked up: %+v", got)
	}
}

func TestUnignoreOfDeadSecretIsResolved(t *testing.T) {
	st, _ := Open(testPaths(t))
	f := newFixture()
	raw := f.raw(t)
	mustMerge(t, st, t0, f.hit(raw, "trufflehog", verified(core.Dead)))
	if err := st.Ignore(f.kr.FP(raw), ""); err != nil {
		t.Fatal(err)
	}
	if err := st.Unignore(fp.ID(f.kr.FP(raw))); err != nil {
		t.Fatal(err)
	}
	if got := mustGet(t, st, f.kr.FP(raw)); got.Status != StatusResolved {
		t.Fatalf("status %s, want resolved", got.Status)
	}
	if err := st.Unignore(f.kr.FP(raw)); err == nil {
		t.Fatal("unignoring something not ignored should say so")
	}
}

func TestRefreshVisibilityRewritesLocations(t *testing.T) {
	st, _ := Open(testPaths(t))
	f := newFixture()
	raw := f.raw(t)
	mustMerge(t, st, t0,
		f.hit(raw, "betterleaks", at("github.com/o/a", core.Private, "c1", "x", 1)),
		f.hit(raw, "betterleaks", at("github.com/o/b", core.Private, "c2", "y", 2)),
		f.hit(raw, "betterleaks", at("local:/Users/x/proj", core.Local, "c3", "z", 3)))
	if mustGet(t, st, f.kr.FP(raw)).Exposed() {
		t.Fatal("private locations read as exposed")
	}
	st.RefreshVisibility(map[string]core.Visibility{"github.com/o/a": core.Public, "github.com/o/unrelated": core.Public})
	got := mustGet(t, st, f.kr.FP(raw))
	vis := map[string]core.Visibility{}
	for _, l := range got.Locations {
		vis[l.Source] = l.Visibility
	}
	if vis["github.com/o/a"] != core.Public || vis["github.com/o/b"] != core.Private || vis["local:/Users/x/proj"] != core.Local {
		t.Fatalf("visibilities %v", vis)
	}
	if !got.Exposed() {
		t.Fatal("secret not exposed after one of its repos went public")
	}
	// The cap bookkeeping must follow the flip: with the public one now counted, a full
	// list can still make room for new exposed places.
	st2, _ := Open(testPaths(t), WithMaxLocations(2))
	mustMerge(t, st2, t0,
		f.hit(raw, "e", at("a", core.Private, "c", "x", 1)),
		f.hit(raw, "e", at("b", core.Private, "c", "x", 1)))
	st2.RefreshVisibility(map[string]core.Visibility{"a": core.Public, "b": core.Public})
	mustMerge(t, st2, t0, f.hit(raw, "e", at("c", core.Public, "c", "x", 1)))
	if n := len(mustGet(t, st2, f.kr.FP(raw)).Locations); n != 2 {
		t.Fatalf("%d locations", n)
	}
}

func TestPutReplacesNormalizesAndRespectsIgnore(t *testing.T) {
	st, _ := Open(testPaths(t))
	if err := st.Put(core.Secret{}); err == nil {
		t.Fatal("Put of a secret with no fingerprint must fail")
	}
	f := newFixture()
	raw := f.raw(t)
	fpv := f.kr.FP(raw)
	err := st.Put(core.Secret{FP: fpv, Engines: []string{"titus", "betterleaks", "titus"}, Shape: raw, // a raw value in the shape field
		Locations: []core.Location{{Source: "s", Commit: "c", Path: "p", Line: 1}, {Source: "s", Commit: "c", Path: "p", Line: 1}}})
	if err != nil {
		t.Fatal(err)
	}
	got := mustGet(t, st, fpv)
	if got.ID != fp.ID(fpv) || got.Verified != core.Unverified || got.Status != StatusOpen || got.Triage != TriageUnreviewed {
		t.Fatalf("defaults not applied: %+v", got)
	}
	if !slices.Equal(got.Engines, []string{"betterleaks", "titus"}) || len(got.Locations) != 1 || got.Locations[0].Visibility != core.Unknown {
		t.Fatalf("not normalized: %+v", got)
	}
	if got.Shape != "…" {
		t.Fatalf("a raw-looking shape was kept (%d characters)", len([]rune(got.Shape)))
	}
	// Put returns what it stored, by copy: later edits to the argument must not leak in.
	if err := st.Ignore(fpv, "r"); err != nil {
		t.Fatal(err)
	}
	if err := st.Put(core.Secret{FP: fpv, Status: StatusOpen, Severity: core.Critical}); err != nil {
		t.Fatal(err)
	}
	if got := mustGet(t, st, fpv); got.Status != StatusIgnored || got.Severity != core.Info {
		t.Fatalf("Put un-ignored a human-ignored fingerprint: %+v", got)
	}
}

func TestGetAndSecretsReturnCopies(t *testing.T) {
	st, _ := Open(testPaths(t))
	f := newFixture()
	raw := f.raw(t)
	mustMerge(t, st, t0, f.hit(raw, "betterleaks"))
	s := mustGet(t, st, f.kr.FP(raw))
	s.Locations[0].Path = "tampered"
	s.Engines[0] = "tampered"
	all := st.Secrets()
	all[0].Rules[0] = "tampered"
	again := mustGet(t, st, f.kr.FP(raw))
	if again.Locations[0].Path == "tampered" || again.Engines[0] == "tampered" || again.Rules[0] == "tampered" {
		t.Fatal("callers can mutate the store through returned slices")
	}
	if _, ok := st.Get("nope"); ok {
		t.Fatal("Get of an unknown fingerprint")
	}
}

func TestEvidenceKeptAndPersisted(t *testing.T) {
	p := testPaths(t)
	st, _ := Open(p)
	f := newFixture()
	raw := f.raw(t)
	for i := 0; i < 6; i++ {
		raw := raw
		mustMerge(t, st, t0, f.hit(raw, "betterleaks", func(h *core.Hit) {
			h.Context = fmt.Sprintf("line %d: KEY = «%s»", i, fp.Shape(raw))
			h.Entropy = float64(i)
		}))
	}
	mustMerge(t, st, t0, f.hit(raw, "titus", func(h *core.Hit) { // a duplicate line with a lower entropy
		h.Context = "line 0: KEY = «" + fp.Shape(raw) + "»"
		h.Entropy = 2
	}))
	ctxs, ent, _, ok := st.Evidence(f.kr.FP(raw))
	if !ok || len(ctxs) != maxContexts || ent != 5 {
		t.Fatalf("evidence: %d contexts, entropy %v, ok=%v", len(ctxs), ent, ok)
	}
	if _, _, _, ok := st.Evidence("none"); ok {
		t.Fatal("evidence for an unknown fingerprint")
	}
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	re, _ := Open(p)
	ctxs2, ent2, _, ok := re.Evidence(f.kr.FP(raw))
	if !ok || !slices.Equal(ctxs, ctxs2) || ent != ent2 {
		t.Fatalf("evidence did not survive a reload: %v %v", ctxs2, ent2)
	}
}

// The store is the last stop before disk. Whatever a buggy normalizer puts in a field, no
// raw value may reach the files.
func TestNoRawValueReachesDisk(t *testing.T) {
	p := testPaths(t)
	st, _ := Open(p)
	f := newFixture()
	raw := f.raw(t)
	hit := f.hit(raw, "leaky", func(h *core.Hit) {
		h.Shape = raw                                 // raw in the shape field
		h.Context = "token=" + raw + " and more text" // an unredacted context
	})
	mustMerge(t, st, t0, hit)
	if err := st.Ignore(f.kr.FP(raw), "pasted by mistake: "+raw); err != nil {
		t.Fatal(err)
	}
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	disk := readAll(t, filepath.Dir(p.Findings))
	for _, needle := range []string{raw, raw[3:], raw[:20], raw[len(raw)-20:]} {
		if strings.Contains(disk, needle) {
			t.Fatalf("a %d-character piece of the raw value reached the state directory", len(needle))
		}
	}
	notes := st.TakeNotes()
	if len(notes) != 1 || !strings.Contains(notes[0], "leaky") {
		t.Fatalf("a blanked shape must be reported by engine name, got %v", notes)
	}
}

func TestConcurrentMergeGetSave(t *testing.T) {
	p := testPaths(t)
	st, _ := Open(p)
	f := newFixture()
	raws := make([]string, 40)
	for i := range raws {
		raws[i] = f.raw(t)
	}
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i, raw := range raws {
				if _, err := st.Merge([]core.Hit{f.hit(raw, fmt.Sprintf("e%d", w), at("github.com/o/a", core.Private, "c", "p", i))}, t0); err != nil {
					t.Error(err)
					return
				}
				st.Get(f.kr.FP(raw))
				if i%10 == 0 {
					st.Save()
					st.Secrets()
				}
			}
		}()
	}
	wg.Wait()
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	re, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if re.Len() != len(raws) {
		t.Fatalf("%d secrets after reload, want %d", re.Len(), len(raws))
	}
	for _, s := range re.Secrets() {
		if len(s.Engines) != 8 || len(s.Locations) != 1 {
			t.Fatalf("racing merges lost data: engines=%v locations=%d", s.Engines, len(s.Locations))
		}
	}
}

func TestScratchStoreWritesNothing(t *testing.T) {
	p := testPaths(t)
	real, _ := Open(p)
	f := newFixture()
	raw := f.raw(t)
	if err := real.Ignore(f.kr.FP(raw), "known fake"); err != nil {
		t.Fatal(err)
	}
	before := readAll(t, filepath.Dir(p.Ignore))
	sc, err := NewScratch(p)
	if err != nil {
		t.Fatal(err)
	}
	mustMerge(t, sc, t0, f.hit(raw, "betterleaks"))
	if got := mustGet(t, sc, f.kr.FP(raw)); got.Status != StatusIgnored {
		t.Fatalf("a scratch store must honor the real ignore list, got %s", got.Status)
	}
	other := f.raw(t)
	mustMerge(t, sc, t0, f.hit(other, "betterleaks"))
	if err := sc.Ignore(f.kr.FP(other), "scratch only"); err != nil {
		t.Fatal(err)
	}
	if err := sc.Save(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p.Findings); !os.IsNotExist(err) {
		t.Fatalf("scratch Save wrote findings: %v", err)
	}
	if after := readAll(t, filepath.Dir(p.Ignore)); after != before {
		t.Fatal("scratch store changed the ignore list on disk")
	}
}

func TestAtomicWriteReplacesWholeFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "f.json")
	if err := WriteFileAtomic(path, []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(path, []byte("two"), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); string(b) != "two" {
		t.Fatalf("content %q", b)
	}
	ents, _ := os.ReadDir(filepath.Dir(path))
	if len(ents) != 1 {
		t.Fatalf("leftovers: %v", ents)
	}
	if fi, _ := os.Stat(filepath.Dir(path)); fi.Mode().Perm() != 0o700 {
		t.Fatalf("parent dir mode %v", fi.Mode().Perm())
	}
	// A failure must not leave a temp file or touch the target.
	if err := WriteFileAtomic(filepath.Join(path, "x"), []byte("y"), 0o600); err == nil {
		t.Fatal("writing under a regular file should fail")
	}
	if b, _ := os.ReadFile(path); string(b) != "two" {
		t.Fatal("failed write damaged the target")
	}
}

func TestClockOptionDrivesTheTimestampsTheStoreMakes(t *testing.T) {
	p := testPaths(t)
	fixed := time.Date(2026, 5, 6, 7, 8, 9, 0, time.UTC)
	st, _ := Open(p, WithClock(func() time.Time { return fixed }))
	f := newFixture()
	raw := f.raw(t)
	mustMerge(t, st, "", f.hit(raw, "betterleaks")) // no timestamp given: the store's clock is used
	got := mustGet(t, st, f.kr.FP(raw))
	if got.FirstSeen != "2026-05-06T07:08:09Z" || got.LastSeen != got.FirstSeen {
		t.Fatalf("seen %s..%s", got.FirstSeen, got.LastSeen)
	}
	if err := st.Ignore(f.kr.FP(raw), "r"); err != nil {
		t.Fatal(err)
	}
	list, _ := LoadIgnore(p.Ignore)
	if e, _ := list.Entry(f.kr.FP(raw)); e.At != "2026-05-06T07:08:09Z" {
		t.Fatalf("ignore entry stamped %q", e.At)
	}
}

func TestLazyWriteIsAtomicToo(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "s.json")
	if err := WriteFileAtomicLazy(path, []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomicLazy(path, []byte("two"), 0o600); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	ents, _ := os.ReadDir(filepath.Dir(path))
	fi, _ := os.Stat(path)
	if string(b) != "two" || len(ents) != 1 || fi.Mode().Perm() != 0o600 {
		t.Fatalf("content %q, %d entries, mode %v", b, len(ents), fi.Mode().Perm())
	}
}
