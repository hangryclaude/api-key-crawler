package bench

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"

	"keyguard/internal/core"
	"keyguard/internal/fp"
	"keyguard/internal/testkit"
)

// Minimal adapters, test-only: the real engines package arrives at integration. Each runs the
// installed binary over a git repo and streams its JSON straight into a Hit, fingerprinting
// the secret and dropping it, the way PLAN's normalizer does.

// engineBin is where this machine keeps an engine. A missing one skips the test, or fails it
// in CI (KEYGUARD_TEST_REQUIRE_ENGINES=1); testkit owns the search.
func engineBin(t *testing.T, name string) string {
	t.Helper()
	return testkit.EnginePath(t, name)
}

// ruleType maps a rule id to the provider vocabulary the way the real normalizer's table
// will; here it only needs to be stable.
func ruleType(rule string) string {
	switch {
	case strings.HasPrefix(rule, "private-key"):
		return "private-key"
	case strings.HasPrefix(rule, "generic"):
		return "generic"
	}
	t, _, _ := strings.Cut(strings.ToLower(rule), "-")
	return t
}

type scanner struct {
	name string
	bin  string
	kr   core.Fingerprinter

	verOnce sync.Once
	ver     string
}

func (s *scanner) Name() string { return s.name }
func (s *scanner) Available() bool {
	st, err := os.Stat(s.bin)
	return err == nil && st.Mode()&0o111 != 0
}
func (s *scanner) Version() string {
	s.verOnce.Do(func() {
		if !s.Available() {
			return
		}
		arg := "version"
		if s.name == "trufflehog" {
			arg = "--version"
		}
		out, _ := exec.Command(s.bin, arg).CombinedOutput()
		s.ver = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(out)), "trufflehog"))
		if i := strings.IndexByte(s.ver, '\n'); i >= 0 {
			s.ver = s.ver[:i]
		}
	})
	return s.ver
}
func (s *scanner) ScanStaged(context.Context, string, core.ScanOpts, core.Emit) error {
	return core.ErrUnsupported
}

// leaksEngine drives betterleaks and gitleaks, whose CLIs and JSON reports match.
type leaksEngine struct{ scanner }

func newLeaks(name, bin string, kr core.Fingerprinter) *leaksEngine {
	return &leaksEngine{scanner{name: name, bin: bin, kr: kr}}
}

type leakFinding struct {
	RuleID    string
	StartLine int
	Match     string
	Secret    string
	File      string
	Commit    string
	Entropy   float64
	Author    string
	Date      string
}

func (e *leaksEngine) ScanGit(ctx context.Context, repo string, r core.Range, o core.ScanOpts, emit core.Emit) error {
	return e.run(ctx, []string{"git"}, repo, o, emit)
}

func (e *leaksEngine) ScanDir(ctx context.Context, dir string, o core.ScanOpts, emit core.Emit) error {
	return e.run(ctx, []string{"dir"}, dir, o, emit)
}

// run scans a git repo or a directory. Inline allow comments are ignored, as the production
// engines ignore them on every call (STEAL P0-12), and verification is never asked for: these
// adapters measure raw precision, and the bench makes no network calls.
func (e *leaksEngine) run(ctx context.Context, mode []string, target string, o core.ScanOpts, emit core.Emit) error {
	args := append(append([]string{}, mode...), "--no-banner", "-r", "-", "-f", "json", "--exit-code", "0", "-l", "error", "--ignore-gitleaks-allow")
	if o.Rules != "" {
		args = append(args, "-c", o.Rules)
	}
	cmd := exec.CommandContext(ctx, e.bin, append(args, target)...)
	cmd.Env = gitEnvForEngines()
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	dec := json.NewDecoder(bufio.NewReaderSize(out, 1<<20))
	var decErr error
	if tok, err := dec.Token(); err == nil && tok == json.Delim('[') {
		for dec.More() {
			var f leakFinding
			if err := dec.Decode(&f); err != nil {
				decErr = err
				break
			}
			loc := o.Loc
			loc.Path, loc.Line, loc.Commit, loc.Author, loc.Date = f.File, f.StartLine, f.Commit, f.Author, f.Date
			emit(core.Hit{
				Engine: e.name, Rule: f.RuleID, Type: ruleType(f.RuleID), FP: e.kr.FP(f.Secret), Shape: fp.Shape(f.Secret),
				Len: len(f.Secret), Entropy: f.Entropy, Verified: core.Unverified, Context: fp.Context(f.Match, f.Secret), Loc: loc,
			})
		}
	}
	io.Copy(io.Discard, out)
	if err := cmd.Wait(); err != nil {
		first, _, _ := strings.Cut(stderr.String(), "\n")
		return fmt.Errorf("%s: %w: %.200s", e.name, err, fp.Scrub(first))
	}
	return decErr
}

// gitEnvForEngines keeps the engines' own git calls away from the developer's global config.
func gitEnvForEngines() []string { return gitEnv() }

// truffleEngine drives trufflehog's git source with verification off.
type truffleEngine struct{ scanner }

func newTrufflehog(bin string, kr core.Fingerprinter) *truffleEngine {
	return &truffleEngine{scanner{name: "trufflehog", bin: bin, kr: kr}}
}

type truffleFinding struct {
	DetectorName   string
	Raw            string
	SourceMetadata struct {
		Data struct {
			Git struct {
				Commit string
				File   string
				Line   int
				Email  string
			}
			Filesystem struct {
				File string
				Line int
			}
		}
	}
}

func (e *truffleEngine) ScanGit(ctx context.Context, repo string, r core.Range, o core.ScanOpts, emit core.Emit) error {
	return e.run(ctx, []string{"git", "file://" + repo}, o, emit)
}

func (e *truffleEngine) ScanDir(ctx context.Context, dir string, o core.ScanOpts, emit core.Emit) error {
	return e.run(ctx, []string{"filesystem", dir}, o, emit)
}

// run scans with verification off, inline ignore tags not honored (STEAL P0-12) and every
// result class kept, since the default hides a key that holds a dictionary word (P0-03).
func (e *truffleEngine) run(ctx context.Context, mode []string, o core.ScanOpts, emit core.Emit) error {
	args := append(append([]string{}, mode...), "--json", "--no-update", "--no-verification", "--no-color", "--log-level=-1",
		"--no-ignore-tag", "--results=verified,unknown,unverified,filtered_unverified")
	cmd := exec.CommandContext(ctx, e.bin, args...)
	cmd.Env = gitEnvForEngines()
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	rd := bufio.NewReaderSize(out, 1<<20)
	for {
		line, err := rd.ReadBytes('\n')
		if len(strings.TrimSpace(string(line))) > 0 {
			var f truffleFinding
			if json.Unmarshal(line, &f) == nil && f.Raw != "" {
				g := f.SourceMetadata.Data.Git
				loc := o.Loc
				loc.Path, loc.Line, loc.Commit, loc.Author = g.File, g.Line, g.Commit, g.Email
				if fsd := f.SourceMetadata.Data.Filesystem; fsd.File != "" {
					loc.Path, loc.Line = fsd.File, fsd.Line
				}
				emit(core.Hit{
					Engine: "trufflehog", Rule: strings.ToLower(f.DetectorName), Type: strings.ToLower(f.DetectorName),
					FP: e.kr.FP(f.Raw), Shape: fp.Shape(f.Raw), Len: len(f.Raw), Entropy: fp.Entropy(f.Raw),
					Verified: core.Unverified, Context: "", Loc: loc,
				})
			}
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				return err
			}
			break
		}
	}
	if err := cmd.Wait(); err != nil {
		first, _, _ := strings.Cut(stderr.String(), "\n")
		return fmt.Errorf("trufflehog: %w: %.200s", err, fp.Scrub(first))
	}
	return nil
}
