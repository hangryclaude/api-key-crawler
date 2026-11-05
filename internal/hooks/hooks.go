// Package hooks is keyguard's commit gate: the commit-msg, pre-commit, pre-push and
// reference-transaction hooks, plus the filename rules they share. Everything outside git
// is injected through Deps, so tests drive the real hooks against real git with a plain
// substring matcher, while cmd/keyguard wires in the learned-secret store and the engines.
//
// Hooks fail open on internal errors and closed on findings (PLAN.md invariant 5): a
// keyguard bug must never break git everywhere, and a confirmed finding blocks.
//
// cmd/keyguard calls `keyguard hook <name> [args...]` (pre-commit, pre-push,
// reference-transaction, commit-msg) as Run(ctx, name, args, os.Stdin,
// deps) and exits with the result. Deps.Dir stays empty there: git runs a hook from the
// top of the working tree (or the git dir of a bare repo), with GIT_INDEX_FILE and friends
// in the environment, and every git call made here inherits exactly that.
package hooks

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"keyguard/internal/core"
	"keyguard/internal/fp"
)

// Hook names, as git passes them to `keyguard hook <name>`.
const (
	NamePreCommit = "pre-commit"
	NamePrePush   = "pre-push"
	NameRefTx     = "reference-transaction"
)

const (
	preCommitTimeout = 30 * time.Second
	prePushTimeout   = 2 * time.Minute
	refTxTimeout     = 20 * time.Second

	// maxRefTxCommits caps how many new commits one reference-transaction scans: the hook
	// runs on every ref update and must stay quick. pre-push has no cap.
	maxRefTxCommits = 2000
)

// Deps is everything a hook needs from outside git. Nil funcs switch that check off.
type Deps struct {
	// Dir is the repository to inspect; "" is the process's working directory, which is
	// where git runs hooks.
	Dir string

	// Known matches learned local secrets in added lines. LoadKnown is the lazy form,
	// used when Known is nil and called at most once, only on a path that needs the
	// matcher, so a hook that exits early never pays to load the store.
	Known     core.KnownMatcher
	LoadKnown func() (core.KnownMatcher, error)

	// FP fingerprints filename findings (path + blob) so they have an id that
	// `keyguard allow` can take. Nil leaves them without one.
	FP core.Fingerprinter

	// ScanStaged runs the regex engine over the staged changes of worktree. The engine behind
	// it must honour no inline allow marker (betterleaks:allow, gitleaks:allow,
	// trufflehog:ignore, pragma: allowlist secret) and no ignore file or config in the repo:
	// the only allowlist is Ignored, which reads ~/.keyguard (STEAL P0-12, P0-05). A committer,
	// or an agent trying to get a blocked commit through, writes the comment itself.
	ScanStaged func(ctx context.Context, worktree string, emit core.Emit) error
	// ScanRange runs the regex engine over a rev range of repo, under the same rule.
	ScanRange func(ctx context.Context, repo string, r core.Range, emit core.Emit) error
	// ScanVerified is the verifying engine pass (trufflehog) for pushes to public or
	// unknown remotes. Only hits it reports as Live block.
	ScanVerified func(ctx context.Context, repo string, r core.Range, emit core.Emit) error

	// Visibility says who can read the remote a push goes to; nil counts as Unknown.
	Visibility func(remote, url string) core.Visibility
	// Ignored reports a fingerprint a human marked false-positive (state/ignore.json).
	Ignored func(fp string) bool
	// Record, when set, receives the hits that block, so `keyguard allow <id>` can
	// resolve the id the block message printed. layer is "pre-commit", "pre-push" or
	// "reference-transaction".
	Record func(layer string, hits []core.Hit)

	Stderr io.Writer
}

// Run dispatches one hook by name. A panic anywhere below is turned into a warning and
// exit 0: reference-transaction runs on every ref update, so a keyguard bug must not
// take git down with it.
func Run(ctx context.Context, name string, args []string, stdin io.Reader, d Deps) (code int) {
	if d.Stderr == nil {
		d.Stderr = os.Stderr
	}
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(d.Stderr, "keyguard: warning: %s hook hit an internal error (%s); allowing\n", name, errText(fmt.Errorf("%v", r)))
			code = 0
		}
	}()
	switch name {
	case NamePreCommit:
		return PreCommit(ctx, d)
	case NamePrePush:
		return PrePush(ctx, d, args, stdin)
	case NameRefTx:
		return RefTx(ctx, d, args, stdin)
	case NameCommitMsg:
		return CommitMsg(ctx, d, args)
	}
	fmt.Fprintf(d.Stderr, "keyguard: warning: unknown hook %q; allowing\n", name)
	return 0
}

// hook is the state one hook invocation shares between its steps.
type hook struct {
	d      Deps
	g      *git
	ctx    context.Context
	cancel context.CancelFunc
	layer  string

	once sync.Once
	m    core.KnownMatcher

	mu    sync.Mutex // guards warns and writes to d.Stderr
	warns int
}

func newHook(ctx context.Context, d Deps, layer string, timeout time.Duration) *hook {
	if d.Stderr == nil {
		d.Stderr = os.Stderr
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	return &hook{d: d, g: newGit(d.Dir), ctx: ctx, cancel: cancel, layer: layer}
}

// warn prints one non-fatal problem. Nothing here may ever carry a raw secret, so error
// text goes through errText.
func (h *hook) warn(format string, a ...any) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.warns++
	fmt.Fprintf(h.d.Stderr, "keyguard: warning: "+format+"\n", a...)
}

// matcher returns the learned-secret matcher, or nil when there is none (no store
// learned yet, or it failed to load, which is warned about once).
func (h *hook) matcher() core.KnownMatcher {
	h.once.Do(func() {
		h.m = h.d.Known
		if h.m == nil && h.d.LoadKnown != nil {
			m, err := h.d.LoadKnown()
			if err != nil {
				h.warn("learned-secret store not loaded (%s); that check is off", errText(err))
				return
			}
			h.m = m
		}
	})
	if h.m == nil || h.m.Len() == 0 {
		return nil
	}
	return h.m
}

// source is the Location.Source for hits found in this repository.
func (h *hook) source() string {
	dir := h.d.Dir
	if dir == "" {
		dir, _ = os.Getwd()
	}
	if abs, err := filepath.Abs(dir); err == nil {
		dir = abs
	}
	return "local:" + dir
}

// safely runs fn and turns a panic into an error: a panic in a goroutine would bypass
// Run's recover and kill the process, which git reads as "block".
func safely(fn func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	return fn()
}

// collector gathers hits from engine callbacks, which may arrive from any goroutine.
type collector struct {
	mu   sync.Mutex
	hits []core.Hit
}

func (c *collector) emit(h core.Hit) {
	c.mu.Lock()
	c.hits = append(c.hits, h)
	c.mu.Unlock()
}

// onlyLive keeps verified-live hits, the contract of the verifying pass.
func (c *collector) onlyLive(h core.Hit) {
	if h.Verified == core.Live {
		c.emit(h)
	}
}

// knownHit turns a diff match into a Hit; Loc.Kind says where it was found.
func (h *hook) knownHit(dm diffMatch, kind string) core.Hit {
	km := dm.KM
	return core.Hit{
		Engine: "known", Rule: "known-secret", Type: "known",
		FP: km.FP, Shape: km.Shape, Len: km.Len, Entropy: dm.Entr,
		Verified: core.Unverified,
		Context:  dm.Ctx,
		Known:    km.EntryID + " " + km.Name,
		Loc: core.Location{
			Source: h.source(), Kind: kind, Visibility: core.Local,
			Commit: dm.Commit, Path: dm.Path, Line: dm.Line,
		},
	}
}

// finalize drops what must not block (ignored fingerprints, keys already verified dead),
// fills in location defaults engines may leave empty, removes duplicates and orders the
// rest for display.
func (h *hook) finalize(hits []core.Hit, kind string) []core.Hit {
	seen := map[string]int{}
	var out []core.Hit
	for _, x := range hits {
		if x.Verified == core.Dead || (x.FP != "" && h.d.Ignored != nil && h.d.Ignored(x.FP)) {
			continue
		}
		if x.Loc.Source == "" {
			x.Loc.Source = h.source()
		}
		if x.Loc.Kind == "" {
			x.Loc.Kind = kind
		}
		if x.Loc.Visibility == "" {
			x.Loc.Visibility = core.Local
		}
		key := x.FP + "|" + x.Loc.Commit + "|" + x.Loc.Path + "|" + strconv.Itoa(x.Loc.Line)
		if x.FP == "" {
			key += "|" + x.Rule
		}
		if x.Engine == "filename" {
			// A filename hit's id is the file's (path plus blob), so two credentials on one
			// line of a minified config share it. Their contexts tell them apart.
			key += "|" + x.Context
		}
		if i, dup := seen[key]; dup {
			// Two engines on one line: keep the first, but it learns what the other knows,
			// which learned key it is and that the provider said it is live.
			if x.Known != "" && out[i].Known == "" {
				out[i].Known = x.Known
			}
			if x.Verified == core.Live {
				out[i].Verified = core.Live
			}
			continue
		}
		seen[key] = len(out)
		out = append(out, x)
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i].Loc, out[j].Loc
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.Commit < b.Commit
	})
	return out
}

// block records and prints a block message, and returns the exit code that stops git.
func (h *hook) block(title string, hits []core.Hit) int {
	if h.d.Record != nil {
		_ = safely(func() error { h.d.Record(h.layer, hits); return nil })
	}
	writeBlock(h.d.Stderr, title, hits)
	return 1
}

// errText makes an error safe to print: control bytes dropped, random-looking tokens
// masked in case an upstream message ever carried one, and short.
func errText(err error) string {
	s := fp.Scrub(err.Error())
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	if r := []rune(s); len(r) > 240 {
		s = string(r[:239]) + "…"
	}
	return s
}

// failText says why a step failed. A deadline gets its own words: a git killed by the
// timeout otherwise reads as "signal: killed".
func (h *hook) failText(err error) string {
	if h.ctx.Err() == context.DeadlineExceeded {
		return "timed out"
	}
	return errText(err)
}

func isZeroOID(s string) bool { return strings.Trim(s, "0") == "" }

func validOID(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// realOID is a valid, non-zero object id.
func realOID(s string) bool { return validOID(s) && !isZeroOID(s) }

func dedupe(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	var out []string
	for _, s := range in {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}
