package sweep

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"keyguard/internal/core"
	"keyguard/internal/fp"
)

func (w *world) localRepo(name string) *repo {
	return newRepo(w.t, filepath.Join(w.root, "local", name))
}

func TestPublishCheckOfACleanLocalRepoPassesAndLeavesNoFindings(t *testing.T) {
	w := newWorld(t)
	l := w.localRepo("clean")
	l.commit("hello", map[string]string{"README.md": "just docs\n", "main.go": "package main\n"})
	res, err := w.runner().PublishCheck(context.Background(), l.dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Blocking) != 0 || res.Source != "local:"+l.dir || res.Stats.Kind != "publish-check" || res.Stats.Scanned != 1 {
		t.Fatalf("%+v", res)
	}
	for _, e := range w.engines {
		c := e.callList()
		if len(c) != 1 || !c[0].rng.All || !c[0].opts.Verify || c[0].opts.Loc.Visibility != core.Public {
			t.Fatalf("%s must scan all history, with verification, as if public: %+v", e.name, c)
		}
	}
	assertUntouched(t, w)
	if ents, _ := os.ReadDir(w.paths.Runs); len(ents) != 1 {
		t.Fatalf("a publish check still records its run: %d files", len(ents))
	}
}

// assertUntouched checks that a publish check left the real findings, source state and
// inventory alone.
func assertUntouched(t *testing.T, w *world) {
	t.Helper()
	if w.store.Len() != 0 {
		t.Fatalf("a publish check put %d what-if secrets in the real store", w.store.Len())
	}
	for _, p := range []string{w.paths.Findings, w.paths.Inventory, w.paths.Sources} {
		if _, err := os.Stat(p); err == nil {
			t.Fatalf("a publish check wrote %s", p)
		}
	}
}

func TestPublishCheckJudgesAsIfPublicAndBlocksOnLowOrMore(t *testing.T) {
	cases := []struct {
		name  string
		setup func(w *world, l *repo)
		want  []core.Severity // severities of blocking secrets
	}{
		{"live key", func(w *world, l *repo) {
			raw := fakeKey(t, "sk-", 48)
			w.plantAll(raw, "openai", core.Live)
			l.commit("env", map[string]string{".env": "K=" + raw + "\n"})
		}, []core.Severity{core.Critical}},
		{"dead key does not block", func(w *world, l *repo) {
			raw := fakeKey(t, "sk-", 48)
			w.plantAll(raw, "openai", core.Dead)
			l.commit("env", map[string]string{".env": "K=" + raw + "\n"})
		}, nil},
		{"unverified key three engines agree on", func(w *world, l *repo) {
			raw := fakeKey(t, "sk-", 48)
			w.plantAll(raw, "openai", core.Unverified)
			l.commit("env", map[string]string{".env": "K=" + raw + "\n"})
		}, []core.Severity{core.Medium}},
		{"unreviewed single detector is low and still blocks", func(w *world, l *repo) {
			raw := fakeKey(t, "", 40)
			w.engines[0].plantValue(raw, "generic", core.Unverified)
			l.commit("cfg", map[string]string{"app.cfg": "secret=" + raw + "\n"})
		}, []core.Severity{core.Low}},
		{"test fixture is low and blocks until ignored", func(w *world, l *repo) {
			raw := fakeKey(t, "sk-", 48)
			w.plantAll(raw, "openai", core.Unverified)
			l.commit("fixture", map[string]string{"tests/fixtures/key.json": raw + "\n"})
		}, []core.Severity{core.Low}},
		{"placeholder does not block", func(w *world, l *repo) {
			raw := "sk-" + randStr(t, alnum, 44) + "xxxx"
			w.plantAll(raw, "openai", core.Unverified)
			l.commit("docs", map[string]string{"README.md": "export K=" + raw + "\n"})
		}, nil},
		{"removed in a later commit still blocks", func(w *world, l *repo) {
			raw := fakeKey(t, "sk-", 48)
			w.plantAll(raw, "openai", core.Live)
			l.commit("oops", map[string]string{".env": "K=" + raw + "\n"})
			l.commit("remove it", map[string]string{".env": ""})
		}, []core.Severity{core.Critical}},
		{"only on another branch still blocks", func(w *world, l *repo) {
			l.commit("base", map[string]string{"a": "1\n"})
			l.git("checkout", "-q", "-b", "wip")
			raw := fakeKey(t, "sk-", 48)
			w.plantAll(raw, "openai", core.Live)
			l.commit("wip", map[string]string{".env": "K=" + raw + "\n"})
			l.git("checkout", "-q", "main")
		}, []core.Severity{core.Critical}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := newWorld(t)
			l := w.localRepo("x")
			c.setup(w, l)
			res, err := w.runner().PublishCheck(context.Background(), l.dir)
			if err != nil {
				t.Fatal(err)
			}
			var got []core.Severity
			for _, s := range res.Blocking {
				got = append(got, s.Severity)
				if s.ID == "" || s.Shape == "" || len(s.Locations) == 0 {
					t.Fatalf("a blocking secret needs display fields: %+v", s)
				}
			}
			if len(got) != len(c.want) || (len(got) > 0 && got[0] != c.want[0]) {
				t.Fatalf("blocking severities %v, want %v", got, c.want)
			}
			assertUntouched(t, w)
		})
	}
}

func TestPublishCheckHonorsTheIgnoreListAndKnownKeys(t *testing.T) {
	w := newWorld(t)
	known := &fakeKnown{kr: w.kr}
	w.cfg.Known = known
	l := w.localRepo("x")
	ignored, learned := fakeKey(t, "sk-", 48), fakeKey(t, "sk-", 48)
	w.plantAll(ignored, "openai", core.Live)
	known.add(learned, "OPENAI_API_KEY")
	l.commit("env", map[string]string{"a.env": "K=" + ignored + "\n", "b.env": "K=" + learned + "\n"})
	if err := w.store.Ignore(w.kr.FP(ignored), "documented example"); err != nil {
		t.Fatal(err)
	}
	res, err := w.runner().PublishCheck(context.Background(), l.dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Blocking) != 1 || res.Blocking[0].Known == "" || res.Blocking[0].Severity != core.Critical {
		t.Fatalf("only the learned key should block, as critical (learned and public): %+v", res.Blocking)
	}
	if res.Blocking[0].FP != w.kr.FP(learned) {
		t.Fatal("the wrong secret blocked")
	}
	b, _ := json.Marshal(res)
	if strings.Contains(string(b), learned[3:]) || strings.Contains(string(b), ignored[3:]) {
		t.Fatal("the verdict carries a raw value")
	}
}

func TestPublishCheckOfAWatchedRepoByAnyName(t *testing.T) {
	for _, target := range []string{"o/a", "O/A", "github.com/o/a", "https://github.com/o/a", "https://github.com/o/a.git", "git@github.com:o/a.git", "https://www.github.com/o/a/"} {
		t.Run(target, func(t *testing.T) {
			w := newWorld(t)
			a := w.addRepo("a", core.Private) // private today; the check asks about public
			raw := fakeKey(t, "sk-", 48)
			w.plantAll(raw, "openai", core.Live)
			a.commit("env", map[string]string{".env": "K=" + raw + "\n"})
			res, err := w.runner().PublishCheck(context.Background(), target)
			if err != nil {
				t.Fatal(err)
			}
			if res.Source != w.src("a") || len(res.Blocking) != 1 || res.Blocking[0].Severity != core.Critical {
				t.Fatalf("a live key in a private repo about to go public is critical: %+v", res)
			}
			if res.Blocking[0].Locations[0].Visibility != core.Public {
				t.Fatalf("the what-if location must be public: %+v", res.Blocking[0].Locations)
			}
			if w.mir.syncCount(w.src("a")) != 1 {
				t.Fatal("the mirror should be fresh before the check")
			}
			assertUntouched(t, w)
		})
	}
}

func TestPublishCheckNeedsATargetItCanFind(t *testing.T) {
	w := newWorld(t)
	w.addRepo("a", core.Private)
	r := w.runner()
	notRepo := filepath.Join(w.root, "plain")
	if err := os.MkdirAll(notRepo, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, target := range map[string]string{
		"unknown repo":     "o/ghost",
		"not a repo dir":   notRepo,
		"garbage":          "not a thing at all",
		"empty":            "",
		"missing path":     filepath.Join(w.root, "nope"),
		"option-looking":   "--output=/tmp/x",
		"nested too deep":  "a/b/c/d",
		"just an owner":    "o",
		"trailing garbage": "o/a;rm",
	} {
		if _, err := r.PublishCheck(context.Background(), target); err == nil {
			t.Errorf("%s (%q): no error", name, target)
		}
	}
}

func TestPublishCheckThatCannotFinishIsAnError(t *testing.T) {
	w := newWorld(t)
	l := w.localRepo("x")
	l.commit("one", map[string]string{"a": "1\n"})
	w.engines[1].set(func(e *gitEngine) { e.err = errors.New("trufflehog: network down") })
	res, err := w.runner().PublishCheck(context.Background(), l.dir)
	if !errors.Is(err, ErrIncomplete) {
		t.Fatalf("a check that could not run every engine cannot say 'clean': %v", err)
	}
	if !hasNote(res.Stats, "trufflehog failed") {
		t.Fatalf("notes: %v", res.Stats.Notes)
	}
}

func TestPublishCheckWaitsForARunningSweepThenGivesUp(t *testing.T) {
	w := newWorld(t)
	a := w.addRepo("a", core.Private)
	a.commit("x", map[string]string{"f": "1\n"})
	l := w.localRepo("y")
	l.commit("x", map[string]string{"f": "1\n"})
	gate := make(chan struct{})
	entered := make(chan struct{}, 16)
	for _, e := range w.engines {
		e.set(func(e *gitEngine) { e.gate, e.entered = gate, entered })
	}
	done := make(chan error, 1)
	go func() { _, err := w.runner().Poll(context.Background()); done <- err }()
	<-entered

	w.cfg.LockWait = 300 * time.Millisecond
	start := time.Now()
	if _, err := w.runner().PublishCheck(context.Background(), l.dir); !errors.Is(err, ErrLocked) {
		t.Fatalf("while a sweep runs the check must wait and then say it is locked: %v", err)
	} else if took := time.Since(start); took < 250*time.Millisecond {
		t.Fatalf("gave up after %v without waiting", took)
	}

	// With enough patience it gets in once the sweep ends.
	w.cfg.LockWait = 20 * time.Second
	type result struct {
		res PublishResult
		err error
	}
	got := make(chan result, 1)
	go func() {
		res, err := w.runner().PublishCheck(context.Background(), l.dir)
		got <- result{res, err}
	}()
	time.Sleep(700 * time.Millisecond) // the check is queued behind the sweep
	close(gate)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	r := <-got
	if r.err != nil || r.res.Stats.Scanned != 1 {
		t.Fatalf("queued check: %+v %v", r.res.Stats, r.err)
	}
}

func TestParseRepoRef(t *testing.T) {
	for in, want := range map[string]string{
		"o/a": "github.com/o/a", " o/a ": "github.com/o/a", "github.com/o/a": "github.com/o/a",
		"https://github.com/o/a.git": "github.com/o/a", "git@github.com:o/a.git": "github.com/o/a",
		"ssh://git@github.com/o/a": "github.com/o/a", "o/a.wiki": "github.com/o/a.wiki", "o/my.repo-1_x": "github.com/o/my.repo-1_x",
		"https://github.com/o/a/": "github.com/o/a",
	} {
		if got, ok := parseRepoRef(in); !ok || got != want {
			t.Errorf("parseRepoRef(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
	for _, bad := range []string{"", "o", "o/", "/a", "o/a/b", "-x/a", "o/a b", "o/a;x", "http://evil.test/o/a"} {
		if got, ok := parseRepoRef(bad); ok {
			t.Errorf("parseRepoRef(%q) = %q, want a refusal", bad, got)
		}
	}
	_ = fp.ID
}
