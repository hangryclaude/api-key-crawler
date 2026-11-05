package sweep

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"testing"

	"keyguard/internal/core"
	"keyguard/internal/fp"
	"keyguard/internal/testkit"
)

// realLeaks drives a real gitleaks-family binary as a core.Engine, for these tests only.
// The production adapters live in internal/engines, which the sweep must not import; this
// one does the same job in thirty lines so the sweep's ranges can be checked against a real
// tool's reading of them. It fingerprints each finding the moment it is decoded and keeps
// nothing else.
type realLeaks struct {
	name, bin string
	kr        *fp.Keyring
}

var verRE = regexp.MustCompile(`\d+\.\d+\.\d+`)

func (r *realLeaks) Name() string { return r.name }
func (r *realLeaks) Version() string {
	out, _ := exec.Command(r.bin, "version").CombinedOutput()
	return verRE.FindString(string(out))
}
func (r *realLeaks) Available() bool {
	fi, err := os.Stat(r.bin)
	return err == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&0o111 != 0
}
func (r *realLeaks) ScanStaged(context.Context, string, core.ScanOpts, core.Emit) error {
	return core.ErrUnsupported
}
func (r *realLeaks) ScanDir(context.Context, string, core.ScanOpts, core.Emit) error {
	return core.ErrUnsupported
}

func (r *realLeaks) ScanGit(ctx context.Context, repoDir string, rng core.Range, o core.ScanOpts, emit core.Emit) error {
	var revs []string
	if rng.All {
		revs = append(revs, "--all")
	}
	revs = append(revs, rng.Revs...)
	cmd := exec.CommandContext(ctx, r.bin, "git", repoDir, "--no-banner", "--log-level", "error",
		"-r", "-", "-f", "json", "--exit-code", "0", "--log-opts", strings.Join(revs, " "))
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	var stderr tailBuffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	dec := json.NewDecoder(out)
	var decodeErr error
	if _, err := dec.Token(); err != nil { // the opening [
		decodeErr = err
	}
	for decodeErr == nil && dec.More() {
		var f struct {
			RuleID    string
			Secret    string
			Match     string
			File      string
			Commit    string
			StartLine int
			Entropy   float64
			Author    string
			Date      string
		}
		if decodeErr = dec.Decode(&f); decodeErr != nil {
			break
		}
		typ, _, _ := strings.Cut(f.RuleID, "-")
		emit(core.Hit{
			Engine: r.name, Rule: f.RuleID, Type: typ, FP: r.kr.FP(f.Secret), Shape: fp.Shape(f.Secret), Len: len(f.Secret),
			Entropy: f.Entropy, Verified: core.Unverified, Context: fp.Context(f.Match, f.Secret),
			Loc: core.Location{Source: o.Loc.Source, Kind: o.Loc.Kind, Visibility: o.Loc.Visibility,
				Commit: f.Commit, Path: f.File, Line: f.StartLine, Author: f.Author, Date: f.Date},
		})
	}
	if decodeErr != nil {
		cmd.Process.Kill()
	}
	if err := cmd.Wait(); err != nil && ctx.Err() == nil {
		return fmt.Errorf("%s: %w%s", r.name, err, stderr.suffix())
	}
	return decodeErr
}

// Real scanner binaries, found by testkit. Where one is missing the test is skipped, and in CI
// (KEYGUARD_TEST_REQUIRE_ENGINES=1) failed: a test that quietly skips itself proves nothing
// about the integration it exists for.
func TestRealScannersThroughTheSweep(t *testing.T) {
	w := newWorld(t)
	bl := &realLeaks{name: "betterleaks", bin: testkit.EnginePath(t, "betterleaks"), kr: w.kr}
	gl := &realLeaks{name: "gitleaks", bin: testkit.EnginePath(t, "gitleaks"), kr: w.kr}
	for _, e := range []*realLeaks{bl, gl} {
		if !e.Available() || e.Version() == "" {
			t.Fatalf("%s found at %s does not run: this test needs the real binary", e.name, e.bin)
		}
	}
	w.cfg.Engines = []core.Engine{bl, gl}
	a := w.addRepo("a", core.Private)
	tok1, tok2 := fakeKey(t, "ghp_", 36), fakeKey(t, "ghp_", 36)
	c1 := a.commit("env", map[string]string{".env": "GITHUB_TOKEN=" + tok1 + "\n", "README.md": "docs\n"})
	r := w.runner()

	st := mustPoll(t, r)
	if st.Engines["betterleaks"].Hits != 1 || st.Engines["gitleaks"].Hits != 1 || st.Engines["betterleaks"].Errors+st.Engines["gitleaks"].Errors != 0 {
		t.Fatalf("first scan: %+v\nnotes: %v", st.Engines, st.Notes)
	}
	s := w.secret(tok1)
	if !slices.Equal(s.Engines, []string{"betterleaks", "gitleaks"}) || s.Type != "github" || len(s.Locations) != 1 {
		t.Fatalf("secret: engines=%v type=%s locations=%v", s.Engines, s.Type, s.Locations)
	}
	if l := s.Locations[0]; l.Commit != c1 || l.Path != ".env" || l.Line != 1 || l.Source != w.src("a") || l.Visibility != core.Private {
		t.Fatalf("location %+v", l)
	}

	// An incremental scan hands the real tools "--all --not <old tip>"; each must find only
	// what came after.
	c2 := a.commit("more", map[string]string{"cfg/app.env": "T=" + tok2 + "\n"})
	w.pushed("a")
	st = mustPoll(t, r)
	if st.Engines["betterleaks"].Hits != 1 || st.Engines["gitleaks"].Hits != 1 {
		t.Fatalf("incremental scan should see only the new token: %+v\nnotes: %v", st.Engines, st.Notes)
	}
	if s2 := w.secret(tok2); s2.Locations[0].Commit != c2 || s2.Locations[0].Path != "cfg/app.env" {
		t.Fatalf("%+v", s2.Locations)
	}
	if len(w.secret(tok1).Locations) != 1 {
		t.Fatal("the first token was reported again by an incremental scan")
	}

	// Going public rescans the whole history with the real tools.
	w.inv.edit(w.src("a"), func(s *core.Source) { s.Visibility = core.Public })
	st = mustPoll(t, r)
	if st.Engines["betterleaks"].Hits != 2 || st.Engines["gitleaks"].Hits != 2 {
		t.Fatalf("a flip must rescan everything: %+v\nnotes: %v", st.Engines, st.Notes)
	}
	if s := w.secret(tok1); !s.Exposed() || s.Severity < core.Medium {
		t.Fatalf("after going public: %v exposed=%v", s.Severity, s.Exposed())
	}

	// A publish check of the same repo, by name.
	res, err := r.PublishCheck(context.Background(), "o/a")
	if err != nil || len(res.Blocking) != 2 {
		t.Fatalf("publish check: %v, %d blocking\nnotes: %v", err, len(res.Blocking), res.Stats.Notes)
	}

	// Every blob has now been read by both tools, so a full run starts neither of them.
	st = mustFull(t, r)
	if len(st.Engines) != 0 || st.Skipped != 1 || !hasNote(st, "2 engine run(s) were not started") {
		t.Fatalf("a full run over a history the real tools have read must start no tool: %+v\nnotes: %v", st.Engines, st.Notes)
	}

	everything := w.allFiles()
	for _, n := range w.notif.list() {
		everything += n.title + n.body
	}
	for _, tok := range []string{tok1, tok2} {
		if strings.Contains(everything, tok[4:]) {
			t.Fatalf("a token the real scanners found reached keyguard's state")
		}
	}
}
