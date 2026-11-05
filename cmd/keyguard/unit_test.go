package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"keyguard/internal/core"
	"keyguard/internal/db"
	"keyguard/internal/install"
)

func TestTableAlignsNumbersOnTheRight(t *testing.T) {
	var b bytes.Buffer
	table(&b, "  ", [][]string{
		{"ENGINE", "TIME", "HITS"},
		{"betterleaks", "0.3 s", "4"},
		{"trufflehog", "12.5 s", "120"},
	}, 1, 2)
	want := "  ENGINE         TIME  HITS\n  betterleaks   0.3 s     4\n  trufflehog   12.5 s   120\n"
	if b.String() != want {
		t.Errorf("table:\n%q\nwant\n%q", b.String(), want)
	}
	// A last text column is not padded, so lines carry no trailing spaces.
	b.Reset()
	table(&b, "", [][]string{{"a", "bb", "last"}, {"aaaa", "b", "x"}})
	for _, ln := range strings.Split(strings.TrimRight(b.String(), "\n"), "\n") {
		if ln != strings.TrimRight(ln, " ") {
			t.Errorf("trailing spaces in %q", ln)
		}
	}
	table(&b, "", nil) // nothing, quietly
}

func TestEditDistanceAndSuggestions(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		d    int
	}{{"", "", 0}, {"poll", "poll", 0}, {"pol", "poll", 1}, {"instal", "install", 1}, {"kitten", "sitting", 3}, {"ünï", "uni", 2}} {
		if got := editDistance(tc.a, tc.b); got != tc.d {
			t.Errorf("editDistance(%q,%q) = %d, want %d", tc.a, tc.b, got, tc.d)
		}
	}
}

func TestSafeErrMasksKeyShapedTextAndStaysShort(t *testing.T) {
	key := "sk-" + fakeKey(t, "", 48)
	got := safeErr(fmt.Errorf("open /x/%s: no such file\nsecond line\x00", key))
	if strings.Contains(got, key) || strings.ContainsAny(got, "\n\x00") {
		t.Errorf("safeErr: %q", got)
	}
	long := safeErr(errors.New(strings.Repeat("word ", 200)))
	if n := len([]rune(long)); n > 300 {
		t.Errorf("safeErr is %d runes", n)
	}
}

func TestSplitListAndExposedOnly(t *testing.T) {
	if got := splitList(" a, b ,,c "); !slices.Equal(got, []string{"a", "b", "c"}) {
		t.Errorf("splitList: %q", got)
	}
	if got := splitList(""); len(got) != 0 {
		t.Errorf("splitList of nothing: %q", got)
	}
	keep, private := exposedOnly([]core.Source{
		{ID: "a", Visibility: core.Public}, {ID: "b", Visibility: core.Private}, {ID: "c", Visibility: core.SecretGist},
		{ID: "d", Visibility: core.Unknown}, {ID: "e", Visibility: core.Local},
	})
	ids := []string{}
	for _, s := range keep {
		ids = append(ids, s.ID)
	}
	if !slices.Equal(ids, []string{"a", "c", "d"}) || private != 2 {
		t.Errorf("exposedOnly kept %v and left %d: unknown counts as exposed, local does not", ids, private)
	}
}

func TestParseVerdictsAcceptsWhatModelsProduce(t *testing.T) {
	for name, in := range map[string]string{
		"array":    `[{"id":"kg111111","triage":"real","why":"w"}]`,
		"verdicts": `{"verdicts":[{"id":"kg111111","triage":"real","why":"w"}]}`,
		"items":    `{"items":[{"id":"kg111111","triage":"real","why":"w"}]}`,
	} {
		vs, err := parseVerdicts([]byte(in))
		if err != nil || len(vs) != 1 || vs[0].ID != "kg111111" || vs[0].Triage != "real" {
			t.Errorf("%s: %+v %v", name, vs, err)
		}
	}
	if _, err := parseVerdicts([]byte("sure, here you go: real")); err == nil {
		t.Error("prose is not verdicts")
	}
}

func TestNeedsReviewIsTheResidue(t *testing.T) {
	for name, tc := range map[string]struct {
		s    core.Secret
		want bool
	}{
		"unreviewed":                     {core.Secret{Triage: "unreviewed"}, true},
		"no label at all":                {core.Secret{}, true},
		"rule said real":                 {core.Secret{Triage: "real", TriageBy: "rule", Severity: core.Medium}, true},
		"rule said placeholder":          {core.Secret{Triage: "placeholder", TriageBy: "rule", Severity: core.Info}, false},
		"a learned key":                  {core.Secret{Triage: "real", Known: "kg1 X", Severity: core.High}, false},
		"the provider says live":         {core.Secret{Triage: "real", Verified: core.Live, Severity: core.Critical}, false},
		"the provider says dead":         {core.Secret{Triage: "real", Verified: core.Dead, Severity: core.Info}, false},
		"claude already judged":          {core.Secret{Triage: "real", TriageBy: "claude", Severity: core.Medium}, false},
		"a person already judged":        {core.Secret{Triage: "false-positive", TriageBy: "human"}, false},
		"unreviewed even at high (opus)": {core.Secret{Triage: "unreviewed", Severity: core.High}, true},
	} {
		if got := needsReview(tc.s); got != tc.want {
			t.Errorf("%s: needsReview = %v, want %v", name, got, tc.want)
		}
	}
}

func TestArchiveRunsMovesOldRecordsAndNothingElse(t *testing.T) {
	p := core.PathsAt(t.TempDir())
	if err := os.MkdirAll(p.Runs, 0o700); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	files := []string{
		"20260801T010000.000Z.json",   // 3 months old
		"20261001T010000.000Z.json",   // 33 days old
		"20261004T010000.000Z.json",   // 30 days old: the cutoff day is kept
		"20261030T010000.000Z.json",   // recent
		"20261103T115959.000Z.json",   // today
		"20261103T115959.000Z-2.json", // a same-millisecond twin
		"notes.txt",                   // not a run record
	}
	for _, f := range files {
		if err := os.WriteFile(filepath.Join(p.Runs, f), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	archiveRuns(p, now)

	for _, f := range []string{"20260801T010000.000Z.json", "20261001T010000.000Z.json"} {
		moved := filepath.Join(p.Runs, "archive", f[:6], f)
		if _, err := os.Stat(moved); err != nil {
			t.Errorf("%s was not archived: %v", f, err)
		}
		if _, err := os.Stat(filepath.Join(p.Runs, f)); err == nil {
			t.Errorf("%s is still in runs/", f)
		}
	}
	for _, f := range files[2:] {
		if _, err := os.Stat(filepath.Join(p.Runs, f)); err != nil {
			t.Errorf("%s should have stayed: %v", f, err)
		}
	}
	// Running again changes nothing, and a missing directory is not an error.
	archiveRuns(p, now)
	archiveRuns(core.PathsAt(filepath.Join(t.TempDir(), "nowhere")), now)
}

func TestPrintRunAndOpenSummaries(t *testing.T) {
	var b bytes.Buffer
	printRun(&b, core.RunStats{
		Kind: "poll", Started: "2026-11-03T10:00:00Z", Finished: "2026-11-03T10:00:04Z", Sources: 5, Scanned: 2, Skipped: 3, NewFPs: 1,
		Engines: map[string]core.EngineStats{"trufflehog": {Seconds: 2.5, Hits: 3}, "betterleaks": {Seconds: 0.5, Hits: 1, Errors: 1}},
		Notes:   []string{"one", "two"},
	})
	out := b.String()
	for _, want := range []string{"poll finished in 4.0 s", "sources 5   scanned 2   skipped 3   new secrets 1", "betterleaks", "note: two"} {
		if !strings.Contains(out, want) {
			t.Errorf("printRun lacks %q:\n%s", want, out)
		}
	}
	if strings.Index(out, "betterleaks") > strings.Index(out, "trufflehog") {
		t.Errorf("engines are listed by name:\n%s", out)
	}
	notes := make([]string, 30)
	for i := range notes {
		notes[i] = fmt.Sprintf("n%d", i)
	}
	b.Reset()
	printRun(&b, core.RunStats{Kind: "deep", Notes: notes})
	if !strings.Contains(b.String(), "and 18 more notes") {
		t.Errorf("long note lists are cut with a count:\n%s", b.String())
	}

	b.Reset()
	printOpen(&b, nil)
	if !strings.Contains(b.String(), "open findings: none") {
		t.Errorf("printOpen of nothing: %s", b.String())
	}
	b.Reset()
	printOpen(&b, []core.Secret{
		{Status: db.StatusOpen, Severity: core.Critical}, {Status: db.StatusOpen, Severity: core.Low}, {Status: db.StatusOpen, Severity: core.Low},
		{Status: db.StatusResolved, Severity: core.Critical}, {Status: db.StatusIgnored, Severity: core.High},
	})
	if !strings.Contains(b.String(), "open findings: 3 (1 critical, 2 low)") {
		t.Errorf("printOpen: %s", b.String())
	}
}

func TestLockedMessage(t *testing.T) {
	msg, ok := lockedMessage(&db.LockedError{PID: 4242, Started: "2026-11-03T03:30:00Z"})
	if !ok || !strings.Contains(msg, "pid 4242") || !strings.Contains(msg, "since 2026-11-03T03:30:00Z") || !strings.Contains(msg, "wait") {
		t.Errorf("lockedMessage: %q", msg)
	}
	if msg, ok := lockedMessage(fmt.Errorf("wrapped: %w", db.ErrLocked)); !ok || !strings.Contains(msg, "in progress") {
		t.Errorf("wrapped ErrLocked: %q %v", msg, ok)
	}
	if _, ok := lockedMessage(errors.New("disk full")); ok {
		t.Error("an unrelated error is not a lock")
	}
}

func TestOpenKeyringWillNotMintASaltBesideALearnedStore(t *testing.T) {
	p := core.PathsAt(t.TempDir())
	// First use: no store, no salt: one is made.
	if _, err := openKeyring(p); err != nil {
		t.Fatal(err)
	}
	salt := filepath.Join(p.Known, "salt")
	if _, err := os.Stat(salt); err != nil {
		t.Fatal("the first use should have made a salt")
	}
	// A store whose salt has gone is an error, and no new salt appears.
	if err := os.WriteFile(filepath.Join(p.Known, "known.json"), []byte(`{"version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(salt, salt+".moved"); err != nil {
		t.Fatal(err)
	}
	_, err := openKeyring(p)
	if err == nil || !strings.Contains(err.Error(), "known.json exists") {
		t.Fatalf("expected a refusal that says what to do, got %v", err)
	}
	if _, err := os.Stat(salt); err == nil {
		t.Fatal("a new salt was minted")
	}
}

func TestTilde(t *testing.T) {
	c := &cli{}
	t.Setenv("HOME", "/Users/someone")
	if got := c.tilde("from /Users/someone/.keyguard/bin/keyguard to /Users/someone/x"); got != "from ~/.keyguard/bin/keyguard to ~/x" {
		t.Errorf("tilde: %q", got)
	}
	if got := c.tilde("/Users/someoneelse/x"); got != "/Users/someoneelse/x" {
		t.Errorf("tilde must not touch another user's path: %q", got)
	}
}

// ----- the daily check -----

func TestDailyCheckRunsOncePerDayAndAlertsWhenALayerIsDown(t *testing.T) {
	w := newWorld(t)
	w.config("betterleaks")
	w.addRepo("open", core.Public)

	// A binary that fails at everything: every layer is down, and the user is told.
	broken := filepath.Join(w.m.dir, "broken")
	if err := os.WriteFile(broken, []byte("#!/bin/sh\nexit 3\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	w.seams.exe = broken
	out := w.mustCLI("poll", "--daily", "--no-verify")
	if !strings.Contains(out, "daily check: selftest FAILED") {
		t.Fatalf("the poll's daily check:\n%s", out)
	}
	notes := w.notices.list()
	var alert *notice
	for i := range notes {
		if strings.Contains(notes[i].title, "protection layer is broken") {
			alert = &notes[i]
		}
	}
	if alert == nil || alert.sev != core.High {
		t.Fatalf("no high-severity alert about the broken layers: %+v", notes)
	}
	if !strings.Contains(alert.body, "install:") || !strings.Contains(alert.body, "keyguard doctor") {
		t.Errorf("the alert should name the layers and the next step:\n%s", alert.body)
	}

	// It recorded the result, so the next poll within a day leaves the selftest alone.
	rec, ok := install.LoadSelftest(w.paths)
	if !ok || rec.OK {
		t.Fatalf("recorded selftest: %+v ok=%v", rec, ok)
	}
	before := len(w.notices.list())
	fi1, _ := os.Stat(install.SelftestPath(w.paths))
	out = w.mustCLI("poll", "--no-verify") // within the day, no --daily
	fi2, _ := os.Stat(install.SelftestPath(w.paths))
	if strings.Contains(out, "daily check") || len(w.notices.list()) != before || !fi1.ModTime().Equal(fi2.ModTime()) {
		t.Errorf("the selftest ran again within a day:\n%s", out)
	}
	// And --no-daily never runs it.
	w.mustCLI("poll", "--daily", "--no-daily", "--no-verify")
}

func TestPollCommandsRunInThisProcessWithoutRealGitHub(t *testing.T) {
	// The seams must keep the whole suite off the network: a seam left nil would reach for
	// the real gh and the real GitHub.
	w := newWorld(t)
	if w.seams.inventory == nil || w.seams.mirror == nil || w.seams.notifier == nil || w.seams.open == nil || w.seams.gh == nil || w.seams.run == nil {
		t.Fatal("a seam is unset")
	}
	var out, errb bytes.Buffer
	c := &cli{ctx: context.Background(), in: strings.NewReader(""), out: &out, err: &errb, seams: w.seams}
	if code := c.dispatch([]string{"version"}); code != 0 {
		t.Errorf("version: %d", code)
	}
}

// The independent leak check must be able to fail: a value planted in a file, raw or as
// base64, is found; a directory without it is clean; the mirrors are skipped on purpose.
func TestGrepHoldsFindsPlantedValuesAndOnlyThose(t *testing.T) {
	root := t.TempDir()
	val := fakeKey(t, "sk-proj-", 48)
	if grepHolds(t, root, val) != "" {
		t.Fatal("an empty directory holds the value?")
	}
	plant := func(rel, body string) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	plant("state/raw.json", "x = "+val)
	plant("state/b64.json", base64.StdEncoding.EncodeToString([]byte(val)))
	plant("state/clean.json", "{}")
	plant("cache/mirrors/leaky.git/objects/x", val)
	got := grepHolds(t, root, val)
	if !strings.Contains(got, "raw.json") || !strings.Contains(got, "b64.json") || strings.Contains(got, "clean.json") || strings.Contains(got, "cache") {
		t.Errorf("grepHolds found:\n%s", got)
	}
}
