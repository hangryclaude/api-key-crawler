package known

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"keyguard/internal/core"
	"keyguard/internal/fp"
)

// learnInto runs Learn into root over a home holding the given .env contents.
func learnInto(t *testing.T, root string, files map[string]string) *Report {
	t.Helper()
	home := t.TempDir()
	for rel, content := range files {
		p := filepath.Join(home, rel)
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	rep, err := Learn(Options{Home: home, Root: root, GHUsers: []string{}})
	if err != nil {
		t.Fatalf("Learn: %v", err)
	}
	return rep
}

func TestStoreFormat(t *testing.T) {
	f := newFixture(t)
	v := f.secret("sk-proj-", 48, "OPENAI_API_KEY")
	short := f.reject("", 11, "11 bytes: one under the window")
	f.write("dev/a/.env", "OPENAI_API_KEY="+v+"\nSHORT_TOKEN="+short+"\n")
	f.learn(Options{})
	f.check()

	b := mustRead(t, filepath.Join(core.PathsAt(f.root).Known, storeFile))
	var raw struct {
		Version   int              `json:"version"`
		SaltCheck string           `json:"salt_check"`
		Updated   string           `json:"updated"`
		Entries   []map[string]any `json:"entries"`
	}
	if err := json.Unmarshal([]byte(b), &raw); err != nil {
		t.Fatalf("known.json is not valid JSON: %v", err)
	}
	if raw.Version != 1 || len(raw.SaltCheck) != 32 || raw.Updated == "" || len(raw.Entries) < 4 {
		t.Fatalf("header: %+v (%d entries)", raw, len(raw.Entries))
	}
	_, kr := f.store()
	hex := func(s any, n int) bool {
		str, ok := s.(string)
		if !ok || len(str) != n {
			return false
		}
		for _, c := range str {
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				return false
			}
		}
		return true
	}
	for i, e := range raw.Entries {
		for _, k := range []string{"id", "name", "source", "len", "tail", "fp", "vfp", "variant", "suffix_hash"} {
			if _, ok := e[k]; !ok {
				t.Fatalf("entry %d has no %q", i, k)
			}
		}
		if !hex(e["fp"], 32) || !hex(e["vfp"], 32) || !hex(e["suffix_hash"], 16) {
			t.Errorf("entry %d: fp/vfp/suffix_hash are not fixed-width hex", i)
		}
		if e["id"] != "kg"+e["fp"].(string)[:6] || e["fp"] != kr.FP(v) {
			t.Errorf("entry %d: id %v fp %v", i, e["id"], e["fp"])
		}
		if n := int(e["len"].(float64)); n < MinLen {
			t.Errorf("entry %d is %d bytes: under the %d-byte minimum", i, n, MinLen)
		}
		if tail := e["tail"].(string); len([]rune(tail)) > 4 || !strings.HasSuffix(v, tail) {
			t.Errorf("entry %d: tail of %d characters is not the end of the value", i, len(tail))
		}
		if _, ok := e["value"]; ok {
			t.Errorf("entry %d has a value field", i)
		}
	}
	// The 11-byte value never made it in, in any form, under any field.
	if strings.Contains(b, short) || strings.Contains(b, b64(short)) {
		t.Error("the 11-byte value is in the store")
	}
	if len(EntriesFor(kr, "N", "s", []byte(short))) != 0 {
		t.Error("EntriesFor accepted 11 bytes")
	}
	// The display listing: one row per secret, no value in it.
	if rs, err := ReadStore(f.root); err != nil || rs == nil {
		t.Fatalf("ReadStore: %v", err)
	} else if sec := rs.Secrets(); len(sec) != 1 || sec[0].Name != "OPENAI_API_KEY" || sec[0].Len != len(v) || sec[0].Forms != len(rs.Entries) || sec[0].ID != "kg"+kr.FP(v)[:6] {
		t.Errorf("Secrets() = %+v", sec)
	}
	if rs, err := ReadStore(filepath.Join(t.TempDir(), "never-learned")); rs != nil || err != nil {
		t.Errorf("ReadStore of an empty root = %v, %v", rs, err)
	}
	// Tails of short values follow fp.Shape's grading: two characters for a 12-byte value,
	// four only from 20 up.
	for n, max := range map[int]int{12: 2, 19: 2, 20: 4, 60: 4} {
		for _, e := range EntriesFor(kr, "N", "s", []byte(randFrom(f.r, alnum, n))) {
			if len(e.Tail) > max {
				t.Errorf("a %d-byte value stored a %d-character tail", n, len(e.Tail))
			}
		}
	}
}

func TestLoadMatcherMergesRootsWithTheirOwnSalts(t *testing.T) {
	testEnv(t)
	r := newRNG(t)
	a, b, shared := "sk-proj-"+randFrom(r, alnum, 40), "ghp_"+randFrom(r, alnum, 36), randFrom(r, alnum, 40)
	rootA, rootB := filepath.Join(t.TempDir(), "a"), filepath.Join(t.TempDir(), "b")
	learnInto(t, rootA, map[string]string{"dev/x/.env": fmt.Sprintf("A_API_KEY=%s\nSHARED_TOKEN=%s\n", a, shared)})
	learnInto(t, rootB, map[string]string{"dev/y/.env": fmt.Sprintf("B_TOKEN=%s\nSHARED_TOKEN=%s\n", b, shared)})
	saltA, _ := os.ReadFile(filepath.Join(core.PathsAt(rootA).Known, "salt"))
	saltB, _ := os.ReadFile(filepath.Join(core.PathsAt(rootB).Known, "salt"))
	if string(saltA) == string(saltB) {
		t.Fatal("two roots share a salt")
	}

	m, err := LoadMatcher([]string{rootA, rootB, rootA}) // a repeated root counts once
	if err != nil {
		t.Fatal(err)
	}
	ea, eb := mustStore(t, rootA), mustStore(t, rootB)
	if m.Len() != len(ea.Entries)+len(eb.Entries) {
		t.Fatalf("Len %d, want %d", m.Len(), len(ea.Entries)+len(eb.Entries))
	}
	content := []byte("a=" + a + "\nb=" + b + "\nc=" + b64(shared) + "\nd=" + shared + "\n")
	got := m.Match(content)
	names := map[string]int{}
	for _, g := range got {
		names[g.Name]++
	}
	// The value known to both roots is reported once per place it appears, not once per root.
	if names["A_API_KEY"] != 1 || names["B_TOKEN"] != 1 || names["SHARED_TOKEN"] != 2 || len(got) != 4 {
		t.Fatalf("matches by name: %v (%d)", names, len(got))
	}
	// A root alone knows only its own.
	mA, _ := LoadMatcher([]string{rootA})
	if len(mA.Match(content)) != 3 { // A_API_KEY and the shared value twice
		t.Errorf("root A alone found %d", len(mA.Match(content)))
	}
	// Each match carries the fingerprint of its own root's salt.
	krA, _ := fp.Load(core.PathsAt(rootA).Known)
	for _, g := range got {
		if g.Name == "A_API_KEY" && g.FP != krA.FP(a) {
			t.Error("FP is not the root's HMAC of the raw value")
		}
	}
}

func mustStore(t *testing.T, root string) *Store {
	t.Helper()
	st, err := readStore(core.PathsAt(root).Known)
	if err != nil || st == nil {
		t.Fatalf("store of %s: %v", root, err)
	}
	return st
}

// PLAN.md invariant 4: the environment can add a store, never switch the real one off.
func TestEnvironmentCannotDisableTheRealStore(t *testing.T) {
	root := testEnv(t) // KEYGUARD_HOME=root, HOME=<tmp>
	realRoot := core.RealRoot()
	if !strings.HasPrefix(realRoot, os.Getenv("HOME")) || os.Getenv("HOME") == "" {
		t.Fatalf("the real root %s is not under the test's HOME: refusing to continue", realRoot)
	}
	r := newRNG(t)
	secret := "sk-proj-" + randFrom(r, alnum, 40)
	extra := "ghp_" + randFrom(r, alnum, 36)
	learnInto(t, realRoot, map[string]string{"dev/x/.env": "REAL_API_KEY=" + secret + "\n"})
	content := []byte("x " + secret + " y " + extra)

	// KEYGUARD_HOME unset or empty of stores: only the real store.
	m, err := LoadMatcher(core.KnownRoots())
	if err != nil || len(m.Match(content)) != 1 {
		t.Fatalf("real store alone: %v, %d matches", err, len(m.Match(content)))
	}
	// KEYGUARD_HOME with its own store adds to it.
	learnInto(t, root, map[string]string{"dev/y/.env": "EXTRA_API_KEY=" + extra + "\n"})
	m, err = LoadMatcher(core.KnownRoots())
	if err != nil || len(m.Match(content)) != 2 {
		t.Fatalf("both stores: %v, %d matches", err, len(m.Match(content)))
	}
	// A KEYGUARD_HOME whose store is garbage cannot take the real one down with it.
	if err := os.WriteFile(filepath.Join(core.PathsAt(root).Known, storeFile), []byte("{ not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err = LoadMatcher(core.KnownRoots())
	if err == nil {
		t.Error("a corrupt store was not reported")
	}
	if got := m.Match(content); len(got) != 1 || got[0].Name != "REAL_API_KEY" {
		t.Fatalf("with a corrupt extra store the real one matched %d times", len(got))
	}
	// Learn heals it: the unreadable file is moved aside, not deleted.
	rep := learnInto(t, root, map[string]string{"dev/y/.env": "EXTRA_API_KEY=" + extra + "\n"})
	if !containsSub(rep.Notes, "moved to") {
		t.Errorf("notes: %v", rep.Notes)
	}
	if bad, _ := filepath.Glob(filepath.Join(core.PathsAt(root).Known, storeFile+".bad-*")); len(bad) != 1 {
		t.Errorf("the corrupt store was not preserved: %v", bad)
	}
	// Nor can a deleted salt.
	os.Remove(filepath.Join(core.PathsAt(root).Known, "salt"))
	m, err = LoadMatcher(core.KnownRoots())
	if err == nil || len(m.Match(content)) != 1 {
		t.Fatalf("missing salt: err %v, %d matches", err, len(m.Match(content)))
	}
	if _, statErr := os.Stat(filepath.Join(core.PathsAt(root).Known, "salt")); statErr == nil {
		t.Error("LoadMatcher created a salt: a hook must never write the data dir")
	}
	// KEYGUARD_HOME pointing at nothing at all is fine.
	t.Setenv("KEYGUARD_HOME", filepath.Join(t.TempDir(), "does-not-exist"))
	m, err = LoadMatcher(core.KnownRoots())
	if err != nil || len(m.Match(content)) != 1 {
		t.Fatalf("nonexistent KEYGUARD_HOME: %v, %d", err, len(m.Match(content)))
	}
	if _, statErr := os.Stat(os.Getenv("KEYGUARD_HOME")); statErr == nil {
		t.Error("LoadMatcher created the KEYGUARD_HOME directory")
	}
	// KEYGUARD_HOME equal to the real root is one root.
	t.Setenv("KEYGUARD_HOME", realRoot)
	if got := core.KnownRoots(); len(got) != 1 {
		t.Errorf("roots %v", got)
	}
}

func TestLoadMatcherSkipsMalformedEntries(t *testing.T) {
	f := newFixture(t)
	v := f.secret("sk-proj-", 40, "A_API_KEY")
	f.write("dev/a/.env", "A_API_KEY="+v+"\n")
	f.learn(Options{})
	p := filepath.Join(core.PathsAt(f.root).Known, storeFile)
	st := mustStore(t, f.root)
	good := len(st.Entries)
	st.Entries = append(st.Entries,
		Entry{ID: "kg000000", FP: strings.Repeat("0", 32), VFP: strings.Repeat("0", 32), Len: 40, SuffixHash: "zz"},
		Entry{ID: "kg000001", FP: strings.Repeat("1", 32), VFP: "short", Len: 40, SuffixHash: strings.Repeat("1", 16)},
		Entry{ID: "kg000002", FP: strings.Repeat("2", 32), VFP: strings.Repeat("2", 32), Len: 5, SuffixHash: strings.Repeat("2", 16)},
	)
	if err := writeStore(filepath.Dir(p), st); err != nil {
		t.Fatal(err)
	}
	m, err := LoadMatcher([]string{f.root})
	if err == nil || !strings.Contains(err.Error(), "3 malformed") {
		t.Fatalf("err %v", err)
	}
	if m.Len() != good || len(m.Match([]byte("x "+v))) != 1 {
		t.Fatalf("good entries lost: Len %d want %d", m.Len(), good)
	}
}

// Learn replaces known.json by rename while hooks read it; a reader sees one whole version
// or the other.
func TestStoreIsReplacedAtomically(t *testing.T) {
	f := newFixture(t)
	a := f.secret("sk-proj-", 40, "A_API_KEY")
	b := f.secret("ghp_", 36, "B_TOKEN")
	pa := f.write("dev/a/.env", "A_API_KEY="+a+"\n")
	f.write("dev/b/.env", "B_TOKEN="+b+"\n")
	f.learn(Options{})
	sizes := map[int]bool{}
	var mu sync.Mutex
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				m, err := LoadMatcher([]string{f.root})
				if err != nil {
					t.Errorf("a reader saw an error during a relearn: %v", err)
					return
				}
				mu.Lock()
				sizes[m.Len()] = true
				mu.Unlock()
			}
		}()
	}
	for i := 0; i < 25; i++ {
		off := filepath.Join(filepath.Dir(pa), "off.txt")
		os.Rename(pa, off) // the secret leaves and returns; Prune makes the store shrink and grow
		if _, err := Learn(Options{Home: f.home, Root: f.root, GHUsers: []string{}, Prune: true}); err != nil {
			t.Fatal(err)
		}
		os.Rename(off, pa)
		if _, err := Learn(Options{Home: f.home, Root: f.root, GHUsers: []string{}, Prune: true}); err != nil {
			t.Fatal(err)
		}
	}
	close(stop)
	wg.Wait()
	if len(sizes) != 2 {
		t.Errorf("readers saw store sizes %v, want exactly the two whole versions", sizes)
	}
}

func BenchmarkLoadMatcher(b *testing.B) {
	for _, secrets := range []int{100, 300, 1000} {
		b.Run(fmt.Sprintf("%dsecrets", secrets), func(b *testing.B) {
			b.Setenv("KEYGUARD_HOME", filepath.Join(b.TempDir(), "kg"))
			root := os.Getenv("KEYGUARD_HOME")
			dir := core.PathsAt(root).Known
			kr, err := fp.Load(dir)
			if err != nil {
				b.Fatal(err)
			}
			r := newRNG(b)
			var entries []Entry
			for i := 0; i < secrets; i++ {
				entries = append(entries, EntriesFor(kr, fmt.Sprintf("SOME_SERVICE_%d_API_KEY", i), "/Users/me/dev/project/subdir/.env.local", []byte(fakeSecret(r)))...)
			}
			if err := writeStore(dir, &Store{Version: storeVersion, SaltCheck: saltCheck(kr), Updated: now(), Entries: entries}); err != nil {
				b.Fatal(err)
			}
			st, _ := os.Stat(filepath.Join(dir, storeFile))
			b.ResetTimer()
			start := time.Now()
			for i := 0; i < b.N; i++ {
				m, err := LoadMatcher([]string{root})
				if err != nil || m.Len() != len(entries) {
					b.Fatal(err)
				}
			}
			b.ReportMetric(float64(time.Since(start).Microseconds())/float64(b.N)/1000, "ms/load")
			b.ReportMetric(float64(len(entries)), "entries")
			b.ReportMetric(float64(st.Size())/1024, "KiB")
		})
	}
}
