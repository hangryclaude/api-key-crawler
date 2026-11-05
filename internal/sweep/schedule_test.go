package sweep

import (
	"crypto/rand"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"keyguard/internal/core"
)

// noise is incompressible text of about n bytes, so a repo made of it has a pack of about n.
func noise(t testing.TB, n int) string {
	t.Helper()
	b := make([]byte, n*3/4)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func runCmd(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput()
}

// repack gives a mirror a pack file, as a clone of a real repository has. A clone of a local
// directory hardlinks loose objects instead.
func repack(t testing.TB, w *world, id string) {
	t.Helper()
	runGit(t, w.mir.Path(core.Source{ID: id}), "repack", "-adq")
}

func TestSourcesRunLargestPackFirstWhateverGitHubSaysTheirSizeIs(t *testing.T) {
	w := newWorld(t)
	w.cfg.Jobs = 1 // one worker, so the order sources start in is the order they are queued in
	repos := map[string]*repo{}
	for name, n := range map[string]int{"small": 2_000, "mid": 40_000, "big": 400_000} {
		repos[name] = w.addRepo(name, core.Public)
		repos[name].commit("seed", map[string]string{"data.txt": noise(t, n)})
	}
	// GitHub's own figure is the wrong way round on purpose: the pack on disk is what a scan reads.
	w.inv.edit(w.src("small"), func(s *core.Source) { s.SizeKB = 1_000_000 })
	w.inv.edit(w.src("mid"), func(s *core.Source) { s.SizeKB = 500 })
	w.inv.edit(w.src("big"), func(s *core.Source) { s.SizeKB = 1 })
	r := w.runner()
	mustPoll(t, r)
	for name := range repos {
		repack(t, w, w.src(name))
		repos[name].commit("more", map[string]string{"more.txt": name + "\n"})
		w.pushed(name)
	}
	before := len(w.mir.syncOrder())
	mustPoll(t, r)
	got := w.mir.syncOrder()[before:]
	want := []string{w.src("big"), w.src("mid"), w.src("small")}
	if !slices.Equal(got, want) {
		t.Fatalf("the longest scan has to start first so it does not finish last and alone:\n got %v\nwant %v", got, want)
	}
}

func TestAnUnmirroredSourceIsOrderedByWhatGitHubSaysItWeighs(t *testing.T) {
	w := newWorld(t)
	w.cfg.Jobs = 1
	for name, kb := range map[string]int{"light": 10, "heavy": 9_000, "medium": 800} {
		w.addRepo(name, core.Public).commit("seed", map[string]string{"f": name + "\n"})
		w.inv.edit(w.src(name), func(s *core.Source) { s.SizeKB = kb })
	}
	mustPoll(t, w.runner())
	want := []string{w.src("heavy"), w.src("medium"), w.src("light")}
	if got := w.mir.syncOrder(); !slices.Equal(got, want) {
		t.Fatalf("with no pack to measure yet GitHub's figure stands in: %v", got)
	}
}

func TestAPrivateToPublicFlipJumpsTheQueue(t *testing.T) {
	w := newWorld(t)
	w.cfg.Jobs = 1
	w.cfg.ExposedOnly = true
	big := w.addRepo("big", core.Public)
	other := w.addRepo("other", core.Public)
	flip := w.addRepo("flipper", core.Private)
	big.commit("seed", map[string]string{"data.txt": noise(t, 300_000)})
	other.commit("seed", map[string]string{"data.txt": noise(t, 50_000)})
	flip.commit("seed", map[string]string{"f": "tiny\n"})
	r := w.runner()
	mustPoll(t, r)
	if n := w.mir.syncCount(w.src("flipper")); n != 0 {
		t.Fatalf("a private repo is not fetched: %d", n)
	}
	repack(t, w, w.src("big"))
	repack(t, w, w.src("other"))
	big.commit("more", map[string]string{"x": "1\n"})
	other.commit("more", map[string]string{"x": "1\n"})
	w.pushed("big")
	w.pushed("other")
	w.inv.edit(w.src("flipper"), func(s *core.Source) { s.Visibility = core.Public })

	before := len(w.mir.syncOrder())
	st := mustPoll(t, r)
	got := w.mir.syncOrder()[before:]
	want := []string{w.src("flipper"), w.src("big"), w.src("other")}
	if !slices.Equal(got, want) {
		t.Fatalf("a repo that just went public is read before the biggest one waiting:\n got %v\nwant %v", got, want)
	}
	if st.Scanned != 3 {
		t.Fatalf("%+v", st)
	}
}

func TestAFlipThatNeverScannedItsStateIsStillFirst(t *testing.T) {
	// The inventory snapshot says private and the state file does not exist: the queue has to
	// know from the snapshot, since there is no record of an earlier scan to compare with.
	w := newWorld(t)
	w.cfg.Jobs = 1
	w.cfg.ExposedOnly = true
	a := w.addRepo("a", core.Public)
	flip := w.addRepo("flip", core.Private)
	a.commit("seed", map[string]string{"data.txt": noise(t, 100_000)})
	flip.commit("seed", map[string]string{"f": "1\n"})
	r := w.runner()
	mustPoll(t, r)
	if _, err := os.Stat(filepath.Join(w.paths.Sources, "github.com__o__flip.json")); err == nil {
		t.Fatal("setup: a private repo has no scan record")
	}
	repack(t, w, w.src("a"))
	a.commit("more", map[string]string{"x": "1\n"})
	w.pushed("a")
	w.inv.edit(w.src("flip"), func(s *core.Source) { s.Visibility = core.SecretGist })
	before := len(w.mir.syncOrder())
	mustPoll(t, r)
	if got := w.mir.syncOrder()[before:]; len(got) != 2 || got[0] != w.src("flip") {
		t.Fatalf("%v", got)
	}
}

// A repo with a huge pack scanned from the start runs by itself with more threads per engine.
func TestAHugeSourceRunsAloneWithMoreThreadsAndOthersShareTheMachine(t *testing.T) {
	w := newWorld(t)
	w.cfg.Jobs = 4
	w.cfg.Fresh = true // the ledger would skip a rescan; this is about one that happens
	w.cfg.HugeBytes = 100_000
	w.cfg.HugeThreads = 1000 // absurd on purpose: no ordinary share can be mistaken for it
	for name, n := range map[string]int{"huge": 400_000, "s1": 1_000, "s2": 1_000, "s3": 1_000} {
		w.addRepo(name, core.Public).commit("seed", map[string]string{"data.txt": noise(t, n)})
	}
	r := w.runner()
	mustPoll(t, r)
	for _, name := range []string{"huge", "s1", "s2", "s3"} {
		repack(t, w, w.src(name))
	}
	for _, e := range w.engines {
		e.set(func(e *gitEngine) { e.delay = 80 * time.Millisecond })
		e.reset()
	}
	st := mustFull(t, r)
	if !hasNote(st, "its full scan ran alone with 1000 thread(s) per engine") {
		t.Fatalf("%v", st.Notes)
	}

	var spansOfHuge, spansOfOthers []span
	for _, e := range w.engines {
		for _, sp := range e.spanList() {
			if strings.Contains(sp.repo, "o__huge") {
				spansOfHuge = append(spansOfHuge, sp)
			} else {
				spansOfOthers = append(spansOfOthers, sp)
			}
		}
		for _, c := range e.callList() {
			huge := strings.Contains(c.repo, "o__huge")
			if huge && c.opts.Threads != 1000 || !huge && (c.opts.Threads >= 1000 || c.opts.Threads < 1) {
				t.Fatalf("%s threads for %s: %d", e.name, filepath.Base(c.repo), c.opts.Threads)
			}
		}
	}
	if len(spansOfHuge) != 3 || len(spansOfOthers) != 9 {
		t.Fatalf("%d scans of the huge repo, %d of the others", len(spansOfHuge), len(spansOfOthers))
	}
	for _, h := range spansOfHuge {
		for _, o := range spansOfOthers {
			if h.start.Before(o.end) && o.start.Before(h.end) {
				t.Fatalf("a scan of %s ran during a scan of the huge repo", filepath.Base(o.repo))
			}
		}
	}
	// ...and the others did share the machine: with Jobs=4 three small sources at once is what it
	// takes to see more than one engine at a time.
	if peak := w.track.peak.Load(); peak < 4 {
		t.Fatalf("the small sources should still run side by side: peak %d", peak)
	}
}

func TestAnIncrementalScanOfAHugeRepoShareTheMachine(t *testing.T) {
	w := newWorld(t)
	w.cfg.HugeBytes = 100_000
	w.cfg.HugeThreads = 1000
	a := w.addRepo("huge", core.Public)
	a.commit("seed", map[string]string{"data.txt": noise(t, 400_000)})
	r := w.runner()
	mustPoll(t, r)
	repack(t, w, w.src("huge"))
	a.commit("tiny", map[string]string{"x": "1\n"})
	w.pushed("huge")
	w.resetCalls()
	st := mustPoll(t, r)
	if hasNote(st, "ran alone") {
		t.Fatalf("a handful of new commits is not worth the machine: %v", st.Notes)
	}
	for _, e := range w.engines {
		if c := e.callList(); len(c) != 1 || c[0].opts.Threads >= 1000 {
			t.Fatalf("%s: %+v", e.name, c)
		}
	}
}

func TestHugeBytesBelowZeroNeverRunsAnythingAlone(t *testing.T) {
	w := newWorld(t)
	w.cfg.Fresh = true
	w.cfg.HugeBytes = -1
	w.addRepo("a", core.Public).commit("seed", map[string]string{"data.txt": noise(t, 300_000)})
	r := w.runner()
	mustPoll(t, r)
	repack(t, w, w.src("a"))
	if st := mustFull(t, r); hasNote(st, "ran alone") {
		t.Fatalf("%v", st.Notes)
	}
}

// The scope: a private repo is not fetched, scanned, ordered, weighed, ledgered or
// re-verified, and a mirror of it that is on disk is left exactly as it was.
func TestAPrivateMirrorOnDiskIsLeftAloneByEveryKindOfRun(t *testing.T) {
	w := newWorld(t)
	w.cfg.ExposedOnly = true
	w.cfg.Fresh = true
	known := &fakeKnown{kr: w.kr}
	w.cfg.Known = known
	w.cfg.API = &fakeAPI{}
	priv := w.addRepo("secret-project", core.Private)
	pub := w.addRepo("open-source", core.Public)
	raw := fakeKey(t, "sk-", 48)
	known.add(raw, "OPENAI_API_KEY")
	w.plantAll(raw, "openai", core.Live)
	priv.commit("env", map[string]string{".env": "K=" + raw + "\n"})
	pub.commit("seed", map[string]string{"a": "1\n"})

	// A mirror from before the sweep was told to leave private repos alone.
	dir := w.mir.Path(core.Source{ID: w.src("secret-project")})
	if out, err := runCmd("git", "clone", "--mirror", "--no-hardlinks", "--quiet", priv.dir, dir); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	sentinel := filepath.Join(dir, "sentinel")
	if err := os.WriteFile(sentinel, []byte("untouched"), 0o600); err != nil {
		t.Fatal(err)
	}
	snapshot := func() map[string]string {
		m := map[string]string{}
		filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
			if err == nil {
				fi, _ := d.Info()
				m[strings.TrimPrefix(p, dir)] = fi.ModTime().String() + " " + strconv.FormatInt(fi.Size(), 10)
			}
			return nil
		})
		return m
	}
	before := snapshot()

	r := w.runner()
	mustPoll(t, r)
	priv.commit("more", map[string]string{"x": "1\n"})
	w.pushed("secret-project")
	pub.commit("more", map[string]string{"x": "1\n"})
	w.pushed("open-source")
	mustPoll(t, r)
	mustFull(t, r)
	if _, err := r.Deep(t.Context()); err != nil {
		t.Fatal(err)
	}
	after := snapshot()
	for p, v := range before {
		if after[p] != v {
			t.Errorf("a private mirror on disk changed at %s: %q -> %q", p, v, after[p])
		}
	}
	for p := range after {
		if _, ok := before[p]; !ok {
			t.Errorf("a private mirror on disk grew %s", p)
		}
	}
	if n := w.mir.syncCount(w.src("secret-project")); n != 0 {
		t.Fatalf("fetched %d times", n)
	}
	if _, ok := w.store.Get(w.kr.FP(raw)); ok {
		t.Fatal("a key in a private repo reached the findings")
	}
	if _, err := os.Stat(filepath.Join(w.paths.Sources, "github.com__o__secret-project.json")); err == nil {
		t.Fatal("a private repo got a scan record")
	}
	// Not one ledger record names it either: the tag of its id appears in no ledger file.
	tag := tagOf(w.src("secret-project"))
	filepath.WalkDir(w.paths.Ledger, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			b, _ := os.ReadFile(p)
			if strings.Contains(string(b), string(tag[:])) {
				t.Errorf("%s holds a record of the private repo", p)
			}
		}
		return nil
	})
}
