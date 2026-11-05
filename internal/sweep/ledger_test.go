package sweep

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"keyguard/internal/core"
	"keyguard/internal/db"
	"keyguard/internal/triage"
)

func sha(t testing.TB, n byte) string {
	t.Helper()
	var id oid
	for i := range id {
		id[i] = n + byte(i)
	}
	return hex.EncodeToString(id[:])
}

// ledgerFiles is the ledger directory's *.bin files and their sizes.
func ledgerFiles(t testing.TB, dir string) map[string]int64 {
	t.Helper()
	out := map[string]int64{}
	ents, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return out
		}
		t.Fatal(err)
	}
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".bin") {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			t.Fatal(err)
		}
		out[e.Name()] = fi.Size()
	}
	return out
}

func namesWithPrefix(files map[string]int64, prefix string) []string {
	var out []string
	for n := range files {
		if strings.HasPrefix(n, prefix+".") {
			out = append(out, n)
		}
	}
	slices.Sort(out)
	return out
}

func quietLedger(t testing.TB, dir string) (*ledger, *[]string) {
	t.Helper()
	var mu sync.Mutex
	var notes []string
	l := newLedger(dir, func(s string) { mu.Lock(); notes = append(notes, s); mu.Unlock() })
	return l, &notes
}

func TestParseOID(t *testing.T) {
	good := strings.Repeat("ab", 20)
	if id, ok := parseOID(good); !ok || hex.EncodeToString(id[:]) != good {
		t.Fatalf("%v %v", id, ok)
	}
	for _, bad := range []string{"", strings.Repeat("a", 39), strings.Repeat("a", 41), strings.Repeat("g", 40), strings.Repeat("A", 40), strings.Repeat("a", 64)} {
		if _, ok := parseOID(bad); ok {
			t.Errorf("%q is not a SHA-1 object id the ledger keeps", bad)
		}
	}
}

func TestLedgerRoundTripsAndIgnoresATornTail(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ledger")
	l, notes := quietLedger(t, dir)
	set := l.set("betterleaks", "1.9.0")
	v := newSeenView(set, "github.com/o/a", false)
	v.Note(sha(t, 1))
	v.Note(sha(t, 2))
	v.Note("not an object id") // junk is dropped, not recorded
	if v.Seen(sha(t, 1)) {
		t.Fatal("a blob is not seen until the scan that read it has committed")
	}
	if err := v.Commit(); err != nil {
		t.Fatal(err)
	}
	if !v.Seen(sha(t, 1)) || v.Seen(sha(t, 3)) {
		t.Fatal("seen after commit, and only what was read")
	}
	if other := newSeenView(set, "github.com/o/b", false); other.Seen(sha(t, 1)) {
		t.Fatal("a blob read in one source says nothing about the same blob in another: that place would never be reported")
	}
	l.close()

	files := ledgerFiles(t, dir)
	names := namesWithPrefix(files, "betterleaks")
	if len(names) != 1 {
		t.Fatalf("%v", files)
	}
	header := "kgledger 1 betterleaks " + strings.Split(names[0], ".")[1] + "\n"
	if files[names[0]] != int64(len(header)+2*ledgerRecLen) {
		t.Fatalf("file is %d bytes: a header line and 28 bytes per blob, nothing else", files[names[0]])
	}

	// A crash tore the last record in half; the next run appends.
	path := filepath.Join(dir, names[0])
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.Write([]byte{9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9})
	f.Close()

	l2, _ := quietLedger(t, dir)
	set2 := l2.set("betterleaks", "1.9.0")
	v2 := newSeenView(set2, "github.com/o/a", false)
	if !v2.Seen(sha(t, 1)) || !v2.Seen(sha(t, 2)) || set2.size() != 2 {
		t.Fatalf("a torn tail must cost nothing but itself: %d entries", set2.size())
	}
	v2.Note(sha(t, 3))
	if err := v2.Commit(); err != nil {
		t.Fatal(err)
	}
	l2.close()
	if fi, _ := os.Stat(path); fi.Size() != int64(len(header)+3*ledgerRecLen) {
		t.Fatalf("the torn bytes must be cut off before appending, or every later record reads shifted: %d bytes", fi.Size())
	}
	l3, _ := quietLedger(t, dir)
	v3 := newSeenView(l3.set("betterleaks", "1.9.0"), "github.com/o/a", false)
	if !v3.Seen(sha(t, 1)) || !v3.Seen(sha(t, 2)) || !v3.Seen(sha(t, 3)) {
		t.Fatal("the record appended after the repair must read back")
	}
	if len(*notes) != 0 {
		t.Fatalf("notes: %v", *notes)
	}
}

func TestLedgerMovesOtherVersionsOfAScannerAside(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ledger")
	l, _ := quietLedger(t, dir)
	for _, unit := range []string{"betterleaks", "trufflehog"} {
		v := newSeenView(l.set(unit, "1"), "s", false)
		v.Note(sha(t, 1))
		if err := v.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	l.close()
	before := ledgerFiles(t, dir)
	if len(before) != 2 {
		t.Fatalf("%v", before)
	}

	l2, notes := quietLedger(t, dir)
	l2.set("betterleaks", "2") // betterleaks upgraded; trufflehog did not
	after := ledgerFiles(t, dir)
	if len(namesWithPrefix(after, "betterleaks")) != 0 {
		t.Fatalf("the old betterleaks ledger must leave the directory, and the new one is not written until something is read: %v", after)
	}
	if !slices.Equal(namesWithPrefix(after, "trufflehog"), namesWithPrefix(before, "trufflehog")) {
		t.Fatalf("an upgrade of one scanner must not touch another's ledger: %v", after)
	}
	moved := ledgerFiles(t, filepath.Join(dir, "superseded"))
	if len(moved) != 1 || len(namesWithPrefix(moved, "betterleaks")) != 1 {
		t.Fatalf("nothing is deleted: the old file is moved: %v", moved)
	}
	if len(*notes) != 1 || !strings.Contains((*notes)[0], "betterleaks changed version") {
		t.Fatalf("a rescan that the ledger causes must be said: %v", *notes)
	}
	if v := newSeenView(l2.set("betterleaks", "2"), "s", false); v.Seen(sha(t, 1)) {
		t.Fatal("the new version has read nothing")
	}
}

func TestADamagedLedgerIsMovedAsideAndStartsOver(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ledger")
	l, _ := quietLedger(t, dir)
	name, _ := unitFile("titus", "1")
	l.close()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte("garbage that is not a header\n"+strings.Repeat("x", 100)), 0o600); err != nil {
		t.Fatal(err)
	}
	l2, notes := quietLedger(t, dir)
	set := l2.set("titus", "1")
	if set.size() != 0 || !strings.Contains(strings.Join(*notes, "\n"), "damaged header") {
		t.Fatalf("%d entries, notes %v", set.size(), *notes)
	}
	if ents, err := os.ReadDir(filepath.Join(dir, "superseded")); err != nil || len(ents) != 1 {
		t.Fatalf("a file that cannot be read is kept, not deleted: %v %v", ents, err)
	}
}

func TestSeenViewThatBypassesReadsEverythingButStillRecords(t *testing.T) {
	l, _ := quietLedger(t, filepath.Join(t.TempDir(), "ledger"))
	set := l.set("known", "e1")
	first := newSeenView(set, "s", false)
	first.Note(sha(t, 5))
	first.Commit()
	fresh := newSeenView(set, "s", true)
	if fresh.Seen(sha(t, 5)) || fresh.warm() || fresh.allSeen([]oid{{}}) {
		t.Fatal("a fresh scan trusts nothing the ledger says")
	}
	fresh.Note(sha(t, 6))
	fresh.Commit()
	if !newSeenView(set, "s", false).Seen(sha(t, 6)) {
		t.Fatal("but what it read is recorded for the next scan")
	}
}

// ----- the sweep with a ledger -----

// countingBlobs wraps GitKnown and keeps the stats of every call.
type countingBlobs struct {
	GitKnown
	mu    sync.Mutex
	calls []core.Range
	stats []BlobStats
}

func (c *countingBlobs) ScanBlobsSeen(ctx context.Context, repo string, r core.Range, m core.KnownMatcher, loc core.Location, seen BlobSeen, emit core.Emit) (BlobStats, error) {
	bs, err := c.GitKnown.ScanBlobsSeen(ctx, repo, r, m, loc, seen, emit)
	c.mu.Lock()
	c.calls, c.stats = append(c.calls, r), append(c.stats, bs)
	c.mu.Unlock()
	return bs, err
}

func (c *countingBlobs) count() int { c.mu.Lock(); defer c.mu.Unlock(); return len(c.calls) }
func (c *countingBlobs) seen() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, s := range c.stats {
		n += s.Seen
	}
	return n
}
func (c *countingBlobs) last() BlobStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stats[len(c.stats)-1]
}

// worldWithKnown is a world whose known pass is on, with a counting blob scanner.
func worldWithKnown(t testing.TB) (*world, *fakeKnown, *countingBlobs) {
	w := newWorld(t)
	known := &fakeKnown{kr: w.kr}
	cb := &countingBlobs{}
	w.cfg.Known, w.cfg.Blobs = known, cb
	return w, known, cb
}

func TestASecondPollWithNoChangesReadsZeroBlobs(t *testing.T) {
	w, known, cb := worldWithKnown(t)
	a := w.addRepo("a", core.Public)
	raw := fakeKey(t, "sk-", 48)
	known.add(raw, "OPENAI_API_KEY")
	a.commit("files", map[string]string{".env": "K=" + raw + "\n", "a.txt": "1\n", "b.txt": "2\n"})
	r := w.runner()

	first := mustPoll(t, r)
	if first.Blobs != 3 || cb.count() != 1 {
		t.Fatalf("the first poll reads the three blobs: %+v, %d known passes", first, cb.count())
	}
	w.resetCalls()
	w.pushed("a") // GitHub says it was pushed; the branches did not move
	second := mustPoll(t, r)
	if second.Blobs != 0 || cb.count() != 1 || w.engineCalls() != 0 {
		t.Fatalf("a poll with nothing new reads no blob and starts nothing: %+v, %d known passes, %d engine runs", second, cb.count(), w.engineCalls())
	}
	third := mustPoll(t, r)
	if third.Blobs != 0 || third.Sources != 0 {
		t.Fatalf("%+v", third)
	}
}

func TestOneNewCommitReadsOnlyItsNewBlobs(t *testing.T) {
	w, known, cb := worldWithKnown(t)
	a := w.addRepo("a", core.Public)
	raw := fakeKey(t, "sk-", 48)
	known.add(raw, "OPENAI_API_KEY")
	a.commit("first", map[string]string{".env": "K=" + raw + "\n", "a.txt": "1\n", "b.txt": "2\n"})
	r := w.runner()
	mustPoll(t, r)

	// Two new blobs; nobody polls before the full scan, so it is the first to see them.
	a.commit("second", map[string]string{"c.txt": "3\n", "d.txt": "4\n"})
	w.pushed("a")
	st := mustFull(t, r)
	if st.Blobs != 2 || cb.last().Seen != 3 {
		t.Fatalf("a full scan reads the two blobs no scanner has seen and none of the three it has: read %d, already seen %d", st.Blobs, cb.last().Seen)
	}
	if !hasNote(st, "3 blob(s) were not read again") {
		t.Fatalf("what the ledger spared must be said: %v", st.Notes)
	}
}

func TestFullWithAWarmLedgerReadsNothingAndStartsNothing(t *testing.T) {
	w, known, cb := worldWithKnown(t)
	a := w.addRepo("a", core.Public)
	b := w.addRepo("b", core.Public)
	raw := fakeKey(t, "sk-", 48)
	known.add(raw, "OPENAI_API_KEY")
	w.plantAll(raw, "openai", core.Unverified)
	a.commit("files", map[string]string{".env": "K=" + raw + "\n", "a.txt": "1\n"})
	b.commit("files", map[string]string{"b.txt": "2\n"})
	r := w.runner()
	mustPoll(t, r)
	w.resetCalls()

	st := mustFull(t, r)
	if st.Blobs != 0 || w.engineCalls() != 0 {
		t.Fatalf("a rescan with nothing new reads no blob and starts no engine: %+v, %d engine runs", st, w.engineCalls())
	}
	if st.Scanned != 0 || st.Skipped != 2 || st.Failed != 0 {
		t.Fatalf("nothing was scanned, and nothing went wrong: %+v", st)
	}
	if cb.seen() != 3 || !hasNote(st, "3 blob(s) were not read again and 6 engine run(s) were not started") {
		t.Fatalf("%d blobs seen: %v", cb.seen(), st.Notes)
	}
	// And the state still says everything is caught up: the next poll has nothing to do.
	if idle := mustPoll(t, r); idle.Sources != 0 || w.engineCalls() != 0 {
		t.Fatalf("%+v", idle)
	}
}

func TestLostStateDoesNotCostARescanOfWhatTheLedgerKnows(t *testing.T) {
	w, known, cb := worldWithKnown(t)
	a := w.addRepo("a", core.Public)
	raw := fakeKey(t, "sk-", 48)
	known.add(raw, "OPENAI_API_KEY")
	w.plantAll(raw, "openai", core.Unverified)
	c1 := a.commit("first", map[string]string{".env": "K=" + raw + "\n", "a.txt": "1\n", "b.txt": "2\n"})
	r := w.runner()
	mustPoll(t, r)

	if err := os.RemoveAll(w.paths.Sources); err != nil { // the tips are gone; the ledger is not
		t.Fatal(err)
	}
	c2 := a.commit("second", map[string]string{"c.txt": "3\n", "d.txt": "4\n"})
	w.pushed("a")
	w.resetCalls()
	st := mustPoll(t, r)
	if st.Blobs != 2 || cb.last().Seen != 3 {
		t.Fatalf("without tips the whole history is the range, and the known pass still reads only the two new blobs: read %d, seen %d", st.Blobs, cb.last().Seen)
	}
	for _, e := range w.engines {
		c := e.callList()
		if len(c) != 1 || !c[0].rng.All || !slices.Equal(c[0].commits, []string{c1, c2}) {
			t.Fatalf("%s has unseen blobs in the range, so it runs over it: %+v", e.name, c)
		}
	}
}

func TestIncrementalScansReadTheWholeRangeSoACopiedKeyFileIsStillAPlace(t *testing.T) {
	w, known, cb := worldWithKnown(t)
	a := w.addRepo("a", core.Public)
	raw := fakeKey(t, "sk-", 48)
	known.add(raw, "OPENAI_API_KEY")
	w.plantAll(raw, "openai", core.Unverified)
	a.commit("env", map[string]string{".env": "K=" + raw + "\n"})
	r := w.runner()
	mustPoll(t, r)
	if n := len(w.secret(raw).Locations); n != 1 {
		t.Fatalf("setup: %d locations", n)
	}

	// The same bytes under a new name: the blob is one the ledger has.
	a.commit("backup", map[string]string{".env.backup": "K=" + raw + "\n"})
	w.pushed("a")
	w.resetCalls()
	mustPoll(t, r)
	for _, e := range w.engines {
		if len(e.callList()) != 1 {
			t.Fatalf("%s must read the new commit even though its blob was read before: the copy is a place the user has to clean", e.name)
		}
	}
	var paths []string
	for _, l := range w.secret(raw).Locations {
		paths = append(paths, l.Path)
	}
	slices.Sort(paths)
	if !slices.Equal(paths, []string{".env", ".env.backup"}) {
		t.Fatalf("locations %v", paths)
	}
	if cb.last().Seen != 0 {
		t.Fatalf("an incremental scan does not consult the ledger: %+v", cb.last())
	}
}

func TestARulesChangeRescansOnlyTheEnginesThatReadRules(t *testing.T) {
	w, known, cb := worldWithKnown(t)
	rules := filepath.Join(t.TempDir(), "keyguard.toml")
	if err := os.WriteFile(rules, []byte("# rules v1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	w.cfg.Rules = rules
	a := w.addRepo("a", core.Public)
	known.add(fakeKey(t, "sk-", 48), "OPENAI_API_KEY")
	c1 := a.commit("one", map[string]string{"a.txt": "1\n"})
	r := w.runner()
	mustPoll(t, r)
	led := w.paths.Ledger
	before := ledgerFiles(t, led)
	w.resetCalls()
	knownPasses := cb.count()

	if err := os.WriteFile(rules, []byte("# rules v2: one more rule\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	st := mustPoll(t, r) // nothing was pushed
	for i, e := range w.engines {
		calls := e.callList()
		if e.name == "betterleaks" {
			if len(calls) != 1 || !calls[0].rng.All || !slices.Equal(calls[0].commits, []string{c1}) {
				t.Fatalf("betterleaks reads the rules, so edited rules mean a rescan: %+v", calls)
			}
		} else if len(calls) != 0 {
			t.Fatalf("engine %d (%s) does not read the rules and must not be rescanned: %+v", i, e.name, calls)
		}
	}
	if cb.count() != knownPasses {
		t.Fatal("the known pass does not depend on the rules file")
	}
	if st.Scanned != 1 {
		t.Fatalf("%+v", st)
	}
	after := ledgerFiles(t, led)
	if len(namesWithPrefix(after, "betterleaks")) != 1 || namesWithPrefix(after, "betterleaks")[0] == namesWithPrefix(before, "betterleaks")[0] {
		t.Fatalf("betterleaks' old ledger must be replaced by one for the new rules: %v -> %v", before, after)
	}
	for _, n := range []string{"trufflehog", "titus", "known"} {
		if !slices.Equal(namesWithPrefix(after, n), namesWithPrefix(before, n)) {
			t.Fatalf("%s's ledger is not affected by the rules: %v -> %v", n, before, after)
		}
	}
	state, _ := loadState(w.paths.Sources, w.src("a"))
	if !strings.Contains(state.ScannedWith["betterleaks"], "+rules.") || strings.Contains(state.ScannedWith["trufflehog"], "rules") {
		t.Fatalf("the state names the rules only for the engine that read them: %v", state.ScannedWith)
	}
	// Putting the old rules back is a third version, not the first again; nothing breaks.
	mustPoll(t, r)
}

func TestAnEngineUpgradeInvalidatesOnlyThatEnginesEntries(t *testing.T) {
	w, known, _ := worldWithKnown(t)
	a := w.addRepo("a", core.Public)
	known.add(fakeKey(t, "sk-", 48), "OPENAI_API_KEY")
	a.commit("one", map[string]string{"a.txt": "1\n"})
	r := w.runner()
	mustPoll(t, r)
	before := ledgerFiles(t, w.paths.Ledger)
	if len(before) != 4 { // three engines and the known pass
		t.Fatalf("%v", before)
	}
	w.engines[1].set(func(e *gitEngine) { e.ver = "2.0.0" }) // trufflehog
	w.resetCalls()
	mustPoll(t, r)

	after := ledgerFiles(t, w.paths.Ledger)
	if len(after) != 4 {
		t.Fatalf("%v", after)
	}
	for _, n := range []string{"betterleaks", "titus", "known"} {
		if !slices.Equal(namesWithPrefix(after, n), namesWithPrefix(before, n)) {
			t.Fatalf("%s was not upgraded and its ledger must not change", n)
		}
	}
	if slices.Equal(namesWithPrefix(after, "trufflehog"), namesWithPrefix(before, "trufflehog")) {
		t.Fatal("trufflehog was upgraded and needs a ledger of its own")
	}
	old := ledgerFiles(t, filepath.Join(w.paths.Ledger, "superseded"))
	if !slices.Equal(namesWithPrefix(old, "trufflehog"), namesWithPrefix(before, "trufflehog")) {
		t.Fatalf("the old trufflehog ledger is kept, in superseded/: %v", old)
	}
	if got := len(w.engines[1].callList()); got != 1 || len(w.engines[0].callList()) != 0 {
		t.Fatalf("only trufflehog rescans: trufflehog %d, betterleaks %d", got, len(w.engines[0].callList()))
	}
}

func TestTheLedgerNeverHoldsContent(t *testing.T) {
	w, known, _ := worldWithKnown(t)
	a := w.addRepo("a", core.Public)
	raw := fakeKey(t, "sk-", 48)
	known.add(raw, "OPENAI_API_KEY")
	w.plantAll(raw, "openai", core.Live)
	a.commit("env", map[string]string{".env": "OPENAI_API_KEY=" + raw + "\n", "src/deep/path/config.go": "package config\n"})
	r := w.runner()
	mustPoll(t, r)
	mustFull(t, r)

	files := ledgerFiles(t, w.paths.Ledger)
	if len(files) != 4 {
		t.Fatalf("%v", files)
	}
	var all strings.Builder
	err := filepath.WalkDir(w.paths.Ledger, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		all.Write(b)
		if strings.HasSuffix(p, ".bin") {
			// A header line, then 28 bytes a blob: there is no room in it for anything else.
			head, _, _ := strings.Cut(string(b), "\n")
			if len(b) != len(head)+1+2*ledgerRecLen || !strings.HasPrefix(head, "kgledger 1 ") {
				t.Errorf("%s: %d bytes for two blobs under %q", filepath.Base(p), len(b), head)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	text := all.String()
	// Named, so that a failure says what it found without printing it.
	for name, probe := range map[string]string{
		"the key": raw, "the key's first 20 bytes": raw[:20], "the key's last 20 bytes": raw[len(raw)-20:],
		"a variable name": "OPENAI_API_KEY", "a file name": "config.go", "a directory": "deep/path", "file content": "package config",
	} {
		if strings.Contains(text, probe) {
			t.Fatalf("the ledger holds %s", name)
		}
	}
	if strings.Contains(w.allFiles(), raw) {
		t.Fatal("the raw value reached a file under the keyguard home")
	}
}

func TestLosingTheFindingsMakesTheLedgerUntrusted(t *testing.T) {
	w, known, _ := worldWithKnown(t)
	a := w.addRepo("a", core.Public)
	raw := fakeKey(t, "sk-", 48)
	known.add(raw, "OPENAI_API_KEY")
	w.plantAll(raw, "openai", core.Unverified)
	a.commit("env", map[string]string{".env": "K=" + raw + "\n"})
	r := w.runner()
	mustPoll(t, r)
	if _, ok := w.store.Get(w.kr.FP(raw)); !ok {
		t.Fatal("setup")
	}

	if err := os.Rename(w.paths.Findings, w.paths.Findings+".gone"); err != nil {
		t.Fatal(err)
	}
	fresh, err := db.Open(w.paths)
	if err != nil {
		t.Fatal(err)
	}
	cfg := w.cfg
	cfg.Store = fresh
	cfg.Triage = triage.New(triage.WithStoreEvidence(fresh), triage.WithFingerprinter(w.kr))
	r2, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	w.resetCalls()
	st := mustFull(t, r2)
	if !hasNote(st, "the findings hold 0 secret(s) where they once held 1") {
		t.Fatalf("%v", st.Notes)
	}
	if _, ok := fresh.Get(w.kr.FP(raw)); !ok {
		t.Fatal("a ledger that outlives the findings it was built beside would have left the secret lost for good")
	}
	if st.Blobs == 0 || w.engineCalls() != 3 {
		t.Fatalf("everything is read again: %d blobs, %d engine runs", st.Blobs, w.engineCalls())
	}
	if ents, err := os.ReadDir(filepath.Join(w.paths.Ledger, "superseded")); err != nil || len(ents) != 4 {
		t.Fatalf("the distrusted files are kept, moved: %v %v", ents, err)
	}
}

func TestAPublishCheckNeitherReadsNorFeedsTheLedger(t *testing.T) {
	w, known, _ := worldWithKnown(t)
	a := w.addRepo("a", core.Public)
	raw := fakeKey(t, "sk-", 48)
	known.add(raw, "OPENAI_API_KEY")
	w.plantAll(raw, "openai", core.Unverified)
	a.commit("env", map[string]string{".env": "K=" + raw + "\n"})
	r := w.runner()
	mustPoll(t, r)
	before := ledgerFiles(t, w.paths.Ledger)
	beforeTimes := dirTimes(t, w.paths.Ledger)
	w.resetCalls()

	res, err := r.PublishCheck(context.Background(), "o/a")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Blocking) != 1 || w.engineCalls() != 3 {
		t.Fatalf("the check scans into a scratch store, so it must read everything: %d findings, %d engine runs", len(res.Blocking), w.engineCalls())
	}
	if after := ledgerFiles(t, w.paths.Ledger); !maps2Equal(before, after) {
		t.Fatalf("the check must leave the ledger alone: %v -> %v", before, after)
	}
	if _, err := os.Stat(filepath.Join(w.paths.Ledger, "superseded")); err == nil {
		t.Fatal("the check moved ledger files aside: it distrusted a ledger it must not even open")
	}
	if got := dirTimes(t, w.paths.Ledger); got != beforeTimes {
		t.Fatalf("the check touched the ledger directory:\n%s\n%s", beforeTimes, got)
	}
}

// dirTimes is every entry under dir with its size and modification time.
func dirTimes(t testing.TB, dir string) string {
	t.Helper()
	var sb strings.Builder
	filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil {
			fi, _ := d.Info()
			sb.WriteString(strings.TrimPrefix(p, dir) + " " + fi.ModTime().String() + " " + strconv.FormatInt(fi.Size(), 10) + "\n")
		}
		return nil
	})
	return sb.String()
}

func maps2Equal(a, b map[string]int64) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func TestNoLedgerKeepsNoFilesAndReadsEverything(t *testing.T) {
	w, known, cb := worldWithKnown(t)
	w.cfg.NoLedger = true
	a := w.addRepo("a", core.Public)
	known.add(fakeKey(t, "sk-", 48), "OPENAI_API_KEY")
	a.commit("one", map[string]string{"a.txt": "1\n", "b.txt": "2\n"})
	r := w.runner()
	mustPoll(t, r)
	w.resetCalls()
	st := mustFull(t, r)
	if st.Blobs != 2 || w.engineCalls() != 3 || cb.count() != 0 {
		t.Fatalf("without a ledger a full run reads it all: %+v, %d engine runs", st, w.engineCalls())
	}
	if _, err := os.Stat(w.paths.Ledger); !os.IsNotExist(err) {
		t.Fatalf("NoLedger wrote a ledger: %v", err)
	}
}

func TestFreshReadsEverythingButFeedsTheLedger(t *testing.T) {
	w, known, cb := worldWithKnown(t)
	a := w.addRepo("a", core.Public)
	known.add(fakeKey(t, "sk-", 48), "OPENAI_API_KEY")
	a.commit("one", map[string]string{"a.txt": "1\n", "b.txt": "2\n"})
	r := w.runner()
	mustPoll(t, r)
	w.resetCalls()
	w.cfg.Fresh = true
	st := mustFull(t, w.runner())
	if st.Blobs != 2 || w.engineCalls() != 3 || cb.last().Seen != 0 {
		t.Fatalf("fresh trusts no ledger: %+v, %d engine runs", st, w.engineCalls())
	}
	w.cfg.Fresh = false
	w.resetCalls()
	if st := mustFull(t, w.runner()); st.Blobs != 0 || w.engineCalls() != 0 {
		t.Fatalf("and the ledger it fed is good for the next plain full: %+v", st)
	}
}

func TestAnUnreadableStateFileMeansTheLedgerIsNotTrustedForThatSource(t *testing.T) {
	w, known, cb := worldWithKnown(t)
	a := w.addRepo("a", core.Public)
	known.add(fakeKey(t, "sk-", 48), "OPENAI_API_KEY")
	a.commit("one", map[string]string{"a.txt": "1\n", "b.txt": "2\n"})
	r := w.runner()
	mustPoll(t, r)
	if err := os.WriteFile(filepath.Join(w.paths.Sources, "github.com__o__a.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	w.pushed("a")
	w.resetCalls()
	st := mustPoll(t, r)
	if st.Blobs != 2 || w.engineCalls() != 3 || cb.last().Seen != 0 {
		t.Fatalf("a record that cannot be read errs towards scanning more: %+v, %d engine runs", st, w.engineCalls())
	}
}

// A learned key must alert on the strength of the known pass alone: it is in-process, takes no
// engine slot, and does not wait behind the engines.
func TestAKnownKeyAlertsWhileEveryEngineIsStillBusy(t *testing.T) {
	w, known, _ := worldWithKnown(t)
	w.cfg.Jobs = 1 // one slot; an engine holds it for as long as the test says
	a := w.addRepo("a", core.Public)
	raw := fakeKey(t, "sk-", 48)
	known.add(raw, "OPENAI_API_KEY")
	a.commit("env", map[string]string{".env": "K=" + raw + "\n"})
	gate := make(chan struct{})
	entered := make(chan struct{}, 8)
	for _, e := range w.engines {
		e.set(func(e *gitEngine) { e.gate, e.entered = gate, entered })
	}
	// The known pass is held until an engine has the slot, so it is certain to be the one
	// that has to get past it.
	known.hold = make(chan struct{})
	r := w.runner()
	done := make(chan error, 1)
	go func() {
		_, err := r.Poll(context.Background())
		done <- err
	}()
	select {
	case <-entered:
		close(known.hold)
	case <-time.After(20 * time.Second):
		close(known.hold)
		close(gate)
		<-done
		t.Fatal("no engine started: the known pass is holding the only engine slot")
	}
	deadline := time.Now().Add(20 * time.Second)
	for w.notif.count() == 0 {
		if time.Now().After(deadline) {
			close(gate)
			<-done
			t.Fatal("the learned key did not alert while an engine held the only slot: the known pass waited for the engines")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if n := w.notif.list(); n[0].sev != core.Critical {
		t.Fatalf("%+v", n)
	}
	close(gate)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// The ledger says a scanner has read a blob. A scanner that failed has not.
func TestAnEngineThatFailedHasNotReadAnythingAsFarAsTheLedgerKnows(t *testing.T) {
	w := newWorld(t)
	a := w.addRepo("a", core.Public)
	raw := fakeKey(t, "sk-", 48)
	w.plantAll(raw, "openai", core.Unverified)
	c1 := a.commit("env", map[string]string{".env": "K=" + raw + "\n"})
	titus := w.engines[2]
	titus.set(func(e *gitEngine) { e.err = errors.New("titus crashed on a blob") })
	r := w.runner()
	if _, err := r.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	titus.set(func(e *gitEngine) { e.err = nil })
	w.resetCalls()
	mustFull(t, r)
	if c := titus.callList(); len(c) != 1 || !c[0].rng.All || !slices.Equal(c[0].commits, []string{c1}) {
		t.Fatalf("titus never finished, so a full run must give it the whole history: %+v", c)
	}
	if n := len(w.engines[0].callList()) + len(w.engines[1].callList()); n != 0 {
		t.Fatalf("the engines that finished have nothing new to read: %d runs", n)
	}
}

// failingBlobs reads (and notes) every blob, throws what it found away, and fails: a matcher
// that crashed after the part of the work the ledger would remember.
type failingBlobs struct {
	GitKnown
	fail bool
}

func (f *failingBlobs) ScanBlobsSeen(ctx context.Context, repo string, r core.Range, m core.KnownMatcher, loc core.Location, seen BlobSeen, emit core.Emit) (BlobStats, error) {
	if !f.fail {
		return f.GitKnown.ScanBlobsSeen(ctx, repo, r, m, loc, seen, emit)
	}
	bs, _ := f.GitKnown.ScanBlobsSeen(ctx, repo, r, m, loc, seen, func(core.Hit) {})
	return bs, errors.New("the matcher crashed after reading the blobs")
}

func TestAKnownPassThatFailedHasNotReadItsBlobsAsFarAsTheLedgerKnows(t *testing.T) {
	w := newWorld(t)
	known := &fakeKnown{kr: w.kr}
	fb := &failingBlobs{fail: true}
	w.cfg.Known, w.cfg.Blobs = known, fb
	a := w.addRepo("a", core.Public)
	raw := fakeKey(t, "sk-", 48)
	known.add(raw, "OPENAI_API_KEY")
	a.commit("files", map[string]string{".env": "K=" + raw + "\n", "a.txt": "1\n"})
	r := w.runner()
	st, err := r.Poll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st.Engines["known"].Errors != 1 {
		t.Fatalf("setup: the known pass should have failed: %+v", st.Engines)
	}
	if _, ok := w.store.Get(w.kr.FP(raw)); ok {
		t.Fatal("setup: nothing was reported")
	}

	fb.fail = false
	st = mustPoll(t, r) // the known pass lags, so the poll gives it the whole history again
	if st.Blobs != 2 {
		t.Fatalf("a pass that did not finish has read nothing: it read %d blobs", st.Blobs)
	}
	if _, ok := w.store.Get(w.kr.FP(raw)); !ok {
		t.Fatal("the learned key was never found: blobs of a failed pass were remembered as scanned")
	}
}
