package core

import (
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)

func at(min int) time.Time { return t0.Add(time.Duration(min) * time.Minute) }

func stamp(tm time.Time) string { return tm.UTC().Format(time.RFC3339) }

func TestSeverityStringNeverPanics(t *testing.T) {
	for _, s := range []Severity{-1, -100, 6, 9, 1 << 20} {
		if got := s.String(); got != "none" {
			t.Errorf("Severity(%d).String() = %q, want none", int(s), got)
		}
	}
	for s := None; s <= Critical; s++ {
		if ParseSeverity(s.String()) != s {
			t.Errorf("%v does not survive a round trip through its name", s)
		}
	}
	if ParseSeverity("CRITICAL") != Critical || ParseSeverity("nonsense") != None {
		t.Error("ParseSeverity: case folding or the unknown fallback is wrong")
	}
}

func TestVerifyBackoffIsTheRowsSchedule(t *testing.T) {
	for n, want := range map[int]time.Duration{
		-3: time.Minute, 0: time.Minute, 1: time.Minute, 2: 5 * time.Minute, 3: 30 * time.Minute,
		4: 6 * time.Hour, 5: 6 * time.Hour, 50: 6 * time.Hour,
	} {
		if got := VerifyBackoff(n); got != want {
			t.Errorf("VerifyBackoff(%d) = %v, want %v", n, got, want)
		}
	}
}

func TestVerdictTTL(t *testing.T) {
	for v, want := range map[Verified]time.Duration{
		Live: 6 * time.Hour, Dead: 7 * 24 * time.Hour, Unverified: 0, VerifyError: 0, "": 0, "weird": 0,
	} {
		if got := VerdictTTL(v); got != want {
			t.Errorf("VerdictTTL(%q) = %v, want %v", v, got, want)
		}
	}
}

// step is one verification outcome arriving at minute `min`.
type step struct {
	v    Verified
	why  VerifyReason
	min  int
	want bool // RecordVerification's report of whether anything changed
}

// state is what the merge rules must leave behind after the last step.
type state struct {
	verified  Verified
	at        int // minute of the standing verdict, -1 for none
	reason    VerifyReason
	errs      int
	attempted int // minute of the last attempt, -1 for never
	next      int // minute the next check is due, -1 for nothing scheduled
}

func TestRecordVerificationMergeRules(t *testing.T) {
	h := func(hours int) int { return hours * 60 }
	cases := []struct {
		name  string
		steps []step
		want  state
	}{
		{"error on a fresh secret becomes the state, with a reason and a retry in a minute",
			[]step{{VerifyError, ReasonTimeout, 0, true}},
			state{VerifyError, -1, ReasonTimeout, 1, 0, 1}},
		{"errors back off 1 m, 5 m, 30 m, then 6 h",
			[]step{{VerifyError, ReasonDNS, 0, true}, {VerifyError, ReasonDNS, 1, true}, {VerifyError, ReasonDial, 6, true}, {VerifyError, ReasonDial, 36, true}, {VerifyError, ReasonStatus, h(7), true}},
			state{VerifyError, -1, ReasonStatus, 5, h(7), h(7) + h(6)}},
		{"an unreachable endpoint never makes a live key dead or unknown",
			[]step{{Live, ReasonNone, 0, true}, {VerifyError, ReasonDial, 30, true}},
			state{Live, 0, ReasonDial, 1, 30, 31}},
		{"an error never lowers a dead verdict either",
			[]step{{Dead, ReasonNone, 0, true}, {VerifyError, ReasonRateLimited, 10, true}},
			state{Dead, 0, ReasonRateLimited, 1, 10, 11}},
		{"dead that carries a failure reason is not a verdict",
			[]step{{Dead, ReasonDial, 0, true}},
			state{VerifyError, -1, ReasonDial, 1, 0, 1}},
		{"dead with a reason does not retire a live key",
			[]step{{Live, ReasonNone, 0, true}, {Dead, ReasonTimeout, 5, true}},
			state{Live, 0, ReasonTimeout, 1, 5, 6}},
		{"a verdict clears the reason and the error count and waits out its TTL",
			[]step{{VerifyError, ReasonTimeout, 0, true}, {VerifyError, ReasonTimeout, 1, true}, {Live, ReasonNone, 10, true}},
			state{Live, 10, ReasonNone, 0, 10, 10 + h(6)}},
		{"a dead verdict is asked again in a week",
			[]step{{Dead, ReasonNone, 0, true}},
			state{Dead, 0, ReasonNone, 0, 0, 7 * 24 * 60}},
		{"a live reason on a verdict is dropped: the provider answered",
			[]step{{Live, ReasonTimeout, 0, true}},
			state{Live, 0, ReasonNone, 0, 0, h(6)}},
		{"a newer verdict replaces the standing one",
			[]step{{Live, ReasonNone, 0, true}, {Dead, ReasonNone, 20, true}},
			state{Dead, 20, ReasonNone, 0, 20, 20 + 7*24*60}},
		{"an older verdict does not replace a newer one",
			[]step{{Live, ReasonNone, 30, true}, {Dead, ReasonNone, 10, false}},
			state{Live, 30, ReasonNone, 0, 30, 30 + h(6)}},
		{"at the same instant the later call wins",
			[]step{{Live, ReasonNone, 7, true}, {Dead, ReasonNone, 7, true}},
			state{Dead, 7, ReasonNone, 0, 7, 7 + 7*24*60}},
		{"unverified on an empty secret just names the state",
			[]step{{Unverified, ReasonNone, 0, true}},
			state{Unverified, -1, ReasonNone, 0, -1, -1}},
		{"an empty verdict counts as unverified",
			[]step{{"", ReasonNone, 0, true}},
			state{Unverified, -1, ReasonNone, 0, -1, -1}},
		{"unverified is not an attempt: it keeps a recorded error as it was",
			[]step{{VerifyError, ReasonTimeout, 0, true}, {Unverified, ReasonNone, 5, false}},
			state{VerifyError, -1, ReasonTimeout, 1, 0, 1}},
		{"unverified never forgets a live key",
			[]step{{Live, ReasonNone, 0, true}, {Unverified, ReasonNone, 5, false}},
			state{Live, 0, ReasonNone, 0, 0, h(6)}},
		{"a detector overlap keeps a live key live and is retried like any error",
			[]step{{Live, ReasonNone, 0, true}, {VerifyError, ReasonOverlap, 3, true}},
			state{Live, 0, ReasonOverlap, 1, 3, 4}},
		{"error after unverified becomes error",
			[]step{{Unverified, ReasonNone, 0, true}, {VerifyError, ReasonStatus, 1, true}},
			state{VerifyError, -1, ReasonStatus, 1, 1, 2}},
	}
	minute := func(t *testing.T, s string) int {
		if s == "" {
			return -1
		}
		tm, err := time.Parse(time.RFC3339, s)
		if err != nil {
			t.Errorf("not an RFC 3339 stamp: %q", s)
			return -2
		}
		return int(tm.Sub(t0) / time.Minute)
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var s Secret
			for i, st := range c.steps {
				if got := s.RecordVerification(st.v, st.why, at(st.min)); got != st.want {
					t.Fatalf("step %d (%s at %d): changed = %v, want %v", i, st.v, st.min, got, st.want)
				}
			}
			got := state{s.Verified, minute(t, s.VerifiedAt), s.VerifyReason, s.VerifyErrors, minute(t, s.VerifyAttempted), minute(t, s.NextVerifyAt)}
			if got != c.want {
				t.Fatalf("state\n got  %+v\n want %+v", got, c.want)
			}
		})
	}
}

func TestVerifyDue(t *testing.T) {
	s := Secret{NextVerifyAt: stamp(at(10))}
	for min, want := range map[int]bool{9: false, 10: true, 11: true, 600: true} {
		if got := s.VerifyDue(at(min)); got != want {
			t.Errorf("due at minute %d = %v, want %v", min, got, want)
		}
	}
	for _, empty := range []string{"", "not a time", "2026-11-03"} {
		if (Secret{NextVerifyAt: empty}).VerifyDue(at(1 << 20)) {
			t.Errorf("%q is not a schedule, so nothing is ever due", empty)
		}
	}
	// A time zone offset is a different spelling of the same instant.
	if !(Secret{NextVerifyAt: "2026-11-03T08:10:00-04:00"}).VerifyDue(at(10)) {
		t.Error("08:10 at -04:00 is 12:10Z and must be due then")
	}
}

func TestRecordVerificationSurvivesAJSONRoundTrip(t *testing.T) {
	var s Secret
	s.RecordVerification(Live, ReasonNone, at(10))
	s.RecordVerification(VerifyError, ReasonRateLimited, at(15))
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	var back Secret
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	// The next fold has to see the same standing verdict it left.
	if got := back.RecordVerification(Dead, ReasonNone, at(5)); got {
		t.Fatalf("a verdict older than the one stored was taken after a round trip: %+v", back)
	}
	if back.Verified != Live || back.VerifyReason != ReasonRateLimited || back.VerifyErrors != 1 {
		t.Fatalf("round trip lost state: %+v", back)
	}
}

// The field names are the contract STEAL P0-09 names and the stages after this one read.
func TestValidityFieldsKeepTheirJSONNames(t *testing.T) {
	var s Secret
	s.Tags = []string{"placeholder"}
	s.ExposedEver = true
	s.RecordVerification(VerifyError, ReasonTimeout, at(0))
	b, _ := json.Marshal(s)
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"verified", "verify_reason", "verify_attempted", "verify_errors", "next_verify_at", "exposed_ever", "tags"} {
		if _, ok := m[k]; !ok {
			t.Errorf("Secret JSON lacks %q: %s", k, b)
		}
	}
	if m["verify_reason"] != "timeout" {
		t.Errorf("reason is %v, want the class name", m["verify_reason"])
	}

	hb, _ := json.Marshal(Hit{Verified: VerifyError, VerifyReason: ReasonRateLimited, Tags: []string{"test-mode"}})
	var hm map[string]any
	if err := json.Unmarshal(hb, &hm); err != nil {
		t.Fatal(err)
	}
	if hm["verify_reason"] != "429" || hm["tags"] == nil {
		t.Errorf("Hit JSON: %s", hb)
	}

	// Old records have none of the new fields and must still read; zero values are not written.
	var old Secret
	if err := json.Unmarshal([]byte(`{"fp":"x","verified":"live","verified_at":"2026-11-03T10:00:00Z"}`), &old); err != nil {
		t.Fatal(err)
	}
	if old.Verified != Live || old.VerifyErrors != 0 || old.NextVerifyAt != "" {
		t.Errorf("old record: %+v", old)
	}
	cb, _ := json.Marshal(Secret{FP: "x"})
	for _, k := range []string{"verify_reason", "verify_attempted", "verify_errors", "next_verify_at", "exposed_ever", "tags"} {
		if strings.Contains(string(cb), `"`+k+`"`) {
			t.Errorf("a zero %s is written: %s", k, cb)
		}
	}
}

func TestRunStatsNewCountersAreOptionalInJSON(t *testing.T) {
	b, _ := json.Marshal(RunStats{Kind: "poll"})
	for _, k := range []string{"failed", "alerts", "refs", "commits", "blobs", "gists", "wikis", "api_resources"} {
		if strings.Contains(string(b), `"`+k+`"`) {
			t.Errorf("a zero %s is written: %s", k, b)
		}
	}
	b, _ = json.Marshal(RunStats{Failed: 2, Alerts: 3, Refs: 4, Commits: 5, Blobs: 6, Gists: 7, Wikis: 8, APIResources: 9})
	for _, k := range []string{`"failed":2`, `"alerts":3`, `"refs":4`, `"commits":5`, `"blobs":6`, `"gists":7`, `"wikis":8`, `"api_resources":9`} {
		if !strings.Contains(string(b), k) {
			t.Errorf("missing %s in %s", k, b)
		}
	}
	b, _ = json.Marshal(LayerStatus{Name: "reftx", Fix: "keyguard install"})
	if !strings.Contains(string(b), `"fix":"keyguard install"`) {
		t.Errorf("LayerStatus.Fix: %s", b)
	}
}

func TestLocationKey(t *testing.T) {
	plain := Location{Source: "github.com/o/r", Commit: "abc", Path: "a.env", Line: 3}
	if got, want := plain.Key(), "github.com/o/r|abc|a.env|3"; got != want {
		t.Errorf("a located hit's key changed: %q, want %q (stored findings depend on it)", got, want)
	}
	withBlob := plain
	withBlob.Blob = "deadbeef"
	if withBlob.Key() != plain.Key() {
		t.Error("with a commit to place it, the blob id is not part of the key")
	}
	// Titus finds a blob kept alive only by a tag: no commit, no path.
	a := Location{Source: "github.com/o/r", Ref: "refs/tags/v1", Line: 1, Blob: "aaaa"}
	b := a
	b.Blob = "bbbb"
	if a.Key() == b.Key() {
		t.Errorf("two different blobs on line 1 share the key %q", a.Key())
	}
	noBlob := Location{Source: "github.com/o/r", Line: 1}
	if noBlob.Key() != "github.com/o/r|||1" {
		t.Errorf("a hit with neither commit nor blob keeps the old key: %q", noBlob.Key())
	}
}

func TestExposureLatches(t *testing.T) {
	loc := func(v Visibility) Location { return Location{Source: "s", Visibility: v} }
	cases := []struct {
		name         string
		locs         []Location
		now, latched bool // exposed to a stranger now; ExposedEver after NoteExposure
	}{
		{"public", []Location{loc(Public)}, true, true},
		{"secret gist", []Location{loc(SecretGist)}, true, true},
		{"private", []Location{loc(Private)}, false, false},
		{"local", []Location{loc(Local)}, false, false},
		{"unknown counts now but never latches", []Location{loc(Unknown)}, true, false},
		{"one public among private", []Location{loc(Private), loc(Public)}, true, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := Secret{Locations: c.locs}
			if s.Exposed() != c.now {
				t.Fatalf("Exposed = %v", s.Exposed())
			}
			s.NoteExposure()
			if s.ExposedEver != c.latched {
				t.Fatalf("ExposedEver = %v after NoteExposure", s.ExposedEver)
			}
			if s.WasExposed() != (c.now || c.latched) {
				t.Fatalf("WasExposed = %v", s.WasExposed())
			}
		})
	}

	// The reason for the field: the repo goes private again, the key does not stop being public.
	s := Secret{Locations: []Location{loc(Public)}}
	s.NoteExposure()
	s.Locations[0].Visibility = Private
	s.NoteExposure()
	if s.Exposed() || !s.WasExposed() {
		t.Fatalf("after going private: Exposed=%v WasExposed=%v", s.Exposed(), s.WasExposed())
	}
}

func TestStatusAndJudgeVocabulary(t *testing.T) {
	if slices.Compare([]string{StatusOpen, StatusResolved, StatusIgnored}, []string{"open", "resolved", "ignored"}) != 0 {
		t.Error("status words changed")
	}
	if slices.Compare([]string{TriageReal, TriageTest, TriagePlaceholder, TriagePublicByDesign, TriageFalsePositive, TriageUnreviewed},
		[]string{"real", "test", "placeholder", "public-by-design", "false-positive", "unreviewed"}) != 0 {
		t.Error("triage labels changed")
	}
	// The judge list stays claude|codex|human (plus the rules): findings.json already holds these words.
	if slices.Compare([]string{TriageByRule, TriageByClaude, TriageByCodex, TriageByHuman}, []string{"rule", "claude", "codex", "human"}) != 0 {
		t.Error("the judge list changed")
	}
}

func TestVerifyReasonNames(t *testing.T) {
	want := map[VerifyReason]string{
		ReasonTimeout: "timeout", ReasonRateLimited: "429", ReasonDNS: "dns", ReasonDial: "dial", ReasonStatus: "status", ReasonOverlap: "overlap",
	}
	for r, w := range want {
		if string(r) != w {
			t.Errorf("reason %q should be spelled %q", r, w)
		}
	}
	if ReasonNone != "" {
		t.Error("no reason is the empty string, so omitempty drops it")
	}
	if !Live.Decisive() || !Dead.Decisive() || Unverified.Decisive() || VerifyError.Decisive() || Verified("").Decisive() {
		t.Error("only live and dead are verdicts")
	}
}

func TestRootsAddNeverRemove(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("KEYGUARD_HOME", "")
	if got := KnownRoots(); len(got) != 1 || got[0] != RealRoot() {
		t.Fatalf("no KEYGUARD_HOME: %v", got)
	}
	other := t.TempDir()
	t.Setenv("KEYGUARD_HOME", other)
	got := KnownRoots()
	if len(got) != 2 || got[0] != RealRoot() || got[1] != other {
		t.Fatalf("KEYGUARD_HOME must add a store and keep the real one first: %v", got)
	}
	if Root() != other {
		t.Errorf("Root() = %q, want %q", Root(), other)
	}
	t.Setenv("KEYGUARD_HOME", RealRoot())
	if got := KnownRoots(); len(got) != 1 {
		t.Errorf("the real root is not listed twice: %v", got)
	}
}

// Every file keyguard keeps has one name, here. These are the strings other packages wrote
// by hand in v1 and the ones the P0 rows fix, so a rename in core would orphan stored data.
func TestPathsAtNamesEveryFileOnceUnderTheRoot(t *testing.T) {
	root := t.TempDir()
	p := PathsAt(root)
	want := map[string]string{
		"Bin": "bin/keyguard", "State": "state", "Known": "state/known", "Findings": "state/findings.json",
		"Ignore": "state/ignore.json", "Sources": "state/sources", "Inventory": "state/inventory.json",
		"Runs": "state/runs", "Config": "state/config.json", "Mirrors": "cache/mirrors",
		"Report": "report/index.html", "Logs": "logs", "Lock": "state/lock",

		"Events": "state/events.json", "KnownStore": "state/known/known.json", "KnownLock": "state/known/.learn.lock",
		"Install": "state/install.json", "Selftest": "state/selftest.json", "Blocked": "state/blocked.jsonl",
		"Rules": "rules/keyguard.toml",

		"BinDir": "bin", "Tmp": "tmp", "TitusCache": "cache/titus", "Ledger": "state/ledger",
		"GHSettings": "state/ghsettings.json",
	}
	v := reflect.ValueOf(p)
	if p.Root != root {
		t.Errorf("Root = %q, want %q", p.Root, root)
	}
	seen := map[string]string{root: "Root"}
	for i := 0; i < v.NumField(); i++ {
		name, got := v.Type().Field(i).Name, v.Field(i).String()
		if name == "Root" {
			continue
		}
		rel, ok := want[name]
		if !ok {
			t.Errorf("Paths.%s has no entry in this test: add it, so its layout is pinned", name)
			continue
		}
		if got != filepath.Join(root, filepath.FromSlash(rel)) {
			t.Errorf("Paths.%s = %q, want <root>/%s", name, got, rel)
		}
		if other, dup := seen[got]; dup {
			t.Errorf("Paths.%s and Paths.%s are the same path %q", name, other, got)
		}
		seen[got] = name
		delete(want, name)
	}
	for name := range want {
		t.Errorf("the test names Paths.%s, which does not exist", name)
	}
}

// The known store and its lock live in the Known directory the salt lives in, so one chmod
// and one flock cover them; the engine pins sit beside the keyguard binary hooks run.
func TestPathsGroupFilesWhereTheirOwnersExpectThem(t *testing.T) {
	p := PathsAt(filepath.Join(string(filepath.Separator), "k"))
	if filepath.Dir(p.KnownStore) != p.Known || filepath.Dir(p.KnownLock) != p.Known {
		t.Errorf("known store %q and lock %q must sit in %q", p.KnownStore, p.KnownLock, p.Known)
	}
	if filepath.Dir(p.Bin) != p.BinDir {
		t.Errorf("the binary %q must sit in the pin directory %q", p.Bin, p.BinDir)
	}
	for _, f := range []string{p.Events, p.Install, p.Selftest, p.Blocked, p.GHSettings, p.Ledger} {
		if filepath.Dir(f) != p.State {
			t.Errorf("%q should sit directly in %q", f, p.State)
		}
	}
}

type plainMatcher struct{}

func (plainMatcher) Match([]byte) []KnownMatch { return nil }
func (plainMatcher) Len() int                  { return 0 }

type fullMatcher struct{ plainMatcher }

func (fullMatcher) MatchLimit(data []byte, limit int) ([]KnownMatch, bool) {
	return nil, limit > 0 && len(data) > limit
}
func (fullMatcher) Version() string { return "set-1" }

// A caller asks a matcher for more than the bare interface the way sweep does, by type
// assertion, so a matcher that cannot say still works.
func TestKnownMatcherExtrasAreOptional(t *testing.T) {
	var plain KnownMatcher = plainMatcher{}
	if _, ok := plain.(LimitedMatcher); ok {
		t.Error("a bare matcher is not a LimitedMatcher")
	}
	if _, ok := plain.(VersionedMatcher); ok {
		t.Error("a bare matcher is not a VersionedMatcher")
	}
	var full KnownMatcher = fullMatcher{}
	lm, ok := full.(LimitedMatcher)
	if !ok {
		t.Fatal("fullMatcher should satisfy LimitedMatcher")
	}
	if _, truncated := lm.MatchLimit(make([]byte, 10), 4); !truncated {
		t.Error("MatchLimit lost the truncation signal")
	}
	vm, ok := full.(VersionedMatcher)
	if !ok || vm.Version() != "set-1" {
		t.Errorf("fullMatcher should satisfy VersionedMatcher with its version, got %v %v", ok, vm)
	}
}

func TestVerifyReasonIsAClassNeverText(t *testing.T) {
	for _, r := range []VerifyReason{ReasonTimeout, ReasonRateLimited, ReasonDNS, ReasonDial, ReasonStatus, ReasonOverlap} {
		if r.Class() != r {
			t.Errorf("%q is a class and must survive", r)
		}
	}
	// A verifier's own error text can quote the credential it was checking, here a connection
	// URL built from parts so no such literal sits in this source.
	quoted := "Post " + "https://" + "user" + ":" + "hunter2" + "@db.example/ping: dial tcp: i/o timeout"
	for _, r := range []VerifyReason{ReasonNone, VerifyReason(quoted), "Timeout", " timeout", "timeout\n", "weird"} {
		if r.Class() != ReasonNone {
			t.Errorf("%q is not a class and must be dropped", r)
		}
	}

	var s Secret
	s.RecordVerification(VerifyError, VerifyReason(quoted), at(0))
	if s.Verified != VerifyError || s.VerifyReason != ReasonNone || s.VerifyErrors != 1 {
		t.Fatalf("an error with free text is still an error, with no reason kept: %+v", s)
	}
	// Dead that arrives with a reason, even a bogus one, is a failed check, not a rejection.
	var d Secret
	d.RecordVerification(Live, ReasonNone, at(0))
	d.RecordVerification(Dead, VerifyReason(quoted), at(5))
	if d.Verified != Live || d.VerifyReason != ReasonNone || d.VerifyErrors != 1 {
		t.Fatalf("a dead that carries text must not retire a live key: %+v", d)
	}
	for _, x := range []Secret{s, d} {
		b, _ := json.Marshal(x)
		if strings.Contains(string(b), "hunter2") || strings.Contains(string(b), "example") {
			t.Fatalf("free text reached the stored record: %s", b)
		}
	}
}

// betterleaks checks every occurrence of a key: six copies are six outcomes in one round.
// One instant is one round, so they must not walk the backoff six steps.
func TestOneInstantIsOneRound(t *testing.T) {
	run := func(steps ...step) Secret {
		var s Secret
		for _, st := range steps {
			s.RecordVerification(st.v, st.why, at(st.min))
		}
		return s
	}
	same := func(t *testing.T, name string, a, b Secret) {
		t.Helper()
		if !reflect.DeepEqual(a, b) {
			t.Errorf("%s depends on the order:\n %+v\n %+v", name, a, b)
		}
	}

	six := make([]step, 6)
	for i := range six {
		six[i] = step{VerifyError, ReasonTimeout, 0, false}
	}
	s := run(six...)
	if s.VerifyErrors != 1 || stamp(at(1)) != s.NextVerifyAt {
		t.Fatalf("six errors in one round: %d attempts, next %s (want 1 attempt, due in a minute)", s.VerifyErrors, s.NextVerifyAt)
	}
	// The next round is a new attempt and takes the next step.
	if s = run(append(six, step{VerifyError, ReasonTimeout, 1, true})...); s.VerifyErrors != 2 || s.NextVerifyAt != stamp(at(6)) {
		t.Fatalf("the following round: %d attempts, next %s", s.VerifyErrors, s.NextVerifyAt)
	}
	// The first reason of the round stands.
	if s = run(step{VerifyError, ReasonTimeout, 0, true}, step{VerifyError, ReasonStatus, 0, false}); s.VerifyReason != ReasonTimeout {
		t.Errorf("reason %q", s.VerifyReason)
	}

	// A verdict and an error from one round: the verdict wins, whichever came first.
	for _, v := range []Verified{Live, Dead} {
		a := run(step{v, ReasonNone, 7, true}, step{VerifyError, ReasonDial, 7, false})
		b := run(step{VerifyError, ReasonDial, 7, true}, step{v, ReasonNone, 7, true})
		same(t, "a "+string(v)+" verdict and an error in one round", a, b)
		if a.Verified != v || a.VerifyErrors != 0 || a.VerifyReason != ReasonNone || a.NextVerifyAt != stamp(at(7).Add(VerdictTTL(v))) {
			t.Errorf("%s in the same round as an error: %+v", v, a)
		}
	}

	// An error in the round after a verdict is a real failed re-check and counts.
	if s = run(step{Live, ReasonNone, 0, true}, step{VerifyError, ReasonDial, 1, true}); s.Verified != Live || s.VerifyErrors != 1 {
		t.Errorf("a failed re-check one minute later: %+v", s)
	}
}

// apiStub is written against the contract as documented: a URL, the options, an emit.
type apiStub struct {
	url string
	o   ScanOpts
}

func (a *apiStub) ScanAPI(_ context.Context, url string, o ScanOpts, emit Emit) error {
	a.url, a.o = url, o
	emit(Hit{Engine: "stub", Loc: o.Loc})
	return nil
}

// The scanner for GitHub's API resources is an optional capability, found by type assertion,
// and the safe default is the cheap scan: release assets are off unless a caller asks.
func TestAPIScannerIsAnOptionalEngineCapability(t *testing.T) {
	var e any = &apiStub{}
	a, ok := e.(APIScanner)
	if !ok {
		t.Fatal("a type with ScanAPI(ctx, url, ScanOpts, Emit) is an APIScanner")
	}
	var plain any = plainMatcher{}
	if _, ok := plain.(APIScanner); ok {
		t.Error("a type without ScanAPI is not an APIScanner")
	}
	var o ScanOpts
	if o.ReleaseAssets {
		t.Fatal("release assets are off by default")
	}
	o.Env = []string{"GITHUB_TOKEN=placeholder"}
	o.Loc = Location{Source: "github.com/o/r", Visibility: Public}
	const page = "https://github.com/o/r/issues/7"
	var got []Hit
	if err := a.ScanAPI(context.Background(), page, o, func(h Hit) { got = append(got, h) }); err != nil {
		t.Fatal(err)
	}
	stub := e.(*apiStub)
	if stub.url != page || len(stub.o.Env) != 1 || len(got) != 1 || got[0].Loc.Source != "github.com/o/r" {
		t.Errorf("the contract did not carry the url, the env and the location template: %+v %+v", stub, got)
	}
}
