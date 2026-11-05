package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"keyguard/internal/core"
	"keyguard/internal/db"
	"keyguard/internal/engines"
	"keyguard/internal/fp"
	"keyguard/internal/guard"
	"keyguard/internal/hooks"
	"keyguard/internal/install"
)

// hookEnv is what one hook invocation reads from disk, each piece only when a code path
// needs it: git runs the reference-transaction hook about eight times per commit and seven
// of them must exit before touching anything.
//
// Hooks read everything from the real data root, never from $KEYGUARD_HOME: the environment
// may add a second learned store (core.KnownRoots) but it must not be able to swap the
// config, the ignore list or the salt for ones that protect less (PLAN.md invariant 4).
type hookEnv struct {
	c     *cli
	paths core.Paths

	once sync.Once
	cfg  install.Config
	kr   *fp.Keyring

	warnedPin []string // engines already named as not the pinned binary, so a hook says it once
}

func (c *cli) cmdHook(args []string) (code int) {
	if len(args) == 0 {
		fmt.Fprintln(c.err, "usage: keyguard hook <pre-commit|pre-push|reference-transaction|commit-msg> [args...]")
		return exitUsage
	}
	// Everything below fails open on a keyguard bug (invariant 5); hooks.Run has its own
	// recover for the hooks themselves, this one covers the wiring around them.
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(c.err, "keyguard: warning: %s hook hit an internal error (%v); allowing\n", args[0], r)
			code = exitOK
		}
	}()
	h := &hookEnv{c: c, paths: core.PathsAt(core.RealRoot())}
	return hooks.Run(c.ctx, args[0], args[1:], c.in, h.deps())
}

func (h *hookEnv) deps() hooks.Deps {
	return hooks.Deps{
		LoadKnown:    h.loadKnown,
		FP:           hookFP{h},
		ScanStaged:   h.scanStaged,
		ScanRange:    h.scanRange,
		ScanVerified: h.scanVerified,
		Visibility:   visibilityFrom(h.paths.Inventory),
		Ignored:      db.IgnoredFunc(h.paths.Ignore),
		Record:       h.record,
		Stderr:       h.c.err,
	}
}

// setup reads the config and the salt, once, the first time a code path needs either.
func (h *hookEnv) setup() {
	h.once.Do(func() {
		cfg, err := install.LoadConfig(h.paths, h.c.home())
		if err != nil {
			h.c.warnf("%s; using the defaults", safeErr(err))
		}
		h.cfg = cfg
		kr, err := openKeyringHook(h.paths)
		if err != nil {
			// An unusable salt costs the ignore list (its fingerprints cannot match) but not the
			// scan; a block that cannot be ignored is the safe way to be wrong.
			h.c.warnf("%s; findings will have fingerprints no ignore entry can match", safeErr(err))
			kr = fp.NewEphemeral()
		}
		h.kr = kr
	})
}

type hookFP struct{ h *hookEnv }

func (f hookFP) FP(raw string) string {
	f.h.setup()
	return f.h.kr.FP(raw)
}

// loadKnown loads the learned store of every root. hooks.Run drops the matcher if this
// returns an error, so a store that half loaded (the real one fine, $KEYGUARD_HOME's
// broken) is reported here and returned as success: the part that loaded must keep matching.
func (h *hookEnv) loadKnown() (core.KnownMatcher, error) {
	m, err := knownLoad()
	if err != nil && m != nil && m.Len() > 0 {
		h.c.warnf("part of the learned-secret store did not load (%s); matching with the rest", safeErr(err))
		return m, nil
	}
	if m == nil {
		return nil, err
	}
	return m, err
}

// engine returns the first engine of a tier that is installed and is the binary that was
// pinned (STEAL P0-01). One that is not does not run at all, so a hook that picked it would warn
// and fail open with no scan while the next engine of the tier sat there pinned and fine: it is
// named once and skipped. If none is left the hook fails open, loudly, as it does for any
// engine it cannot use; a sweep or a publish check in the same position fails instead.
func (h *hookEnv) engine(tier string) (core.Engine, error) {
	h.setup()
	names := h.cfg.Tier(tier)
	var refused []string
	for _, n := range names {
		e, err := engines.New(n, h.cfg.EnginePaths()[n], h.kr, h.cfg.EngineOptions(h.paths)...)
		if err != nil || !e.Available() {
			continue
		}
		if perr := engines.CheckPin(e); perr != nil {
			if !slices.Contains(h.warnedPin, n) {
				h.warnedPin = append(h.warnedPin, n)
				h.c.warnf("%s is not the binary that was pinned, so it was not run; use `keyguard doctor` to see what changed", n)
			}
			refused = append(refused, n)
			continue
		}
		return e, nil
	}
	if len(refused) > 0 {
		return nil, fmt.Errorf("no engine of the %q tier is usable: %s changed since it was pinned", tier, strings.Join(refused, ", "))
	}
	return nil, fmt.Errorf("no engine of the %q tier is installed (%s)", tier, strings.Join(names, ", "))
}

func (h *hookEnv) scanOpts(kind string, verify bool) core.ScanOpts {
	o := core.ScanOpts{Verify: verify, Loc: core.Location{Kind: kind, Visibility: core.Local}}
	if r := h.cfg.Rules; r != "" {
		if _, err := os.Stat(r); err == nil {
			o.Rules = r
		}
	}
	return o
}

func (h *hookEnv) scanStaged(ctx context.Context, worktree string, emit core.Emit) error {
	e, err := h.engine(install.TierPreCommit)
	if err != nil {
		return err
	}
	return e.ScanStaged(ctx, worktree, h.scanOpts("staged", false), emit)
}

func (h *hookEnv) scanRange(ctx context.Context, repo string, r core.Range, emit core.Emit) error {
	e, err := h.engine(install.TierPrePush)
	if err != nil {
		return err
	}
	return e.ScanGit(ctx, repo, r, h.scanOpts("unpushed", false), emit)
}

func (h *hookEnv) scanVerified(ctx context.Context, repo string, r core.Range, emit core.Emit) error {
	e, err := h.engine(install.TierVerify)
	if err != nil {
		return err
	}
	return e.ScanGit(ctx, repo, r, h.scanOpts("unpushed", true), emit)
}

// record keeps the findings that blocked a commit or push, so `keyguard allow <id>` can
// resolve the id the block message printed. They go to a side journal and not into the
// findings: a blocked attempt is not a leak, and the journal needs no lock, so a sweep
// that holds the run lock for an hour cannot make a block unrecordable.
func (h *hookEnv) record(layer string, hits []core.Hit) {
	if err := appendBlocked(h.paths, layer, hits, h.c.now()); err != nil {
		h.c.warnf("could not record the block (%s); `keyguard allow` will need the full fingerprint", safeErr(err))
	}
}

// ----- the agent guard -----

// cmdGuard is the Claude Code PreToolUse hook: `keyguard guard claude`, registered for Bash,
// Write, Edit, MultiEdit, NotebookEdit and mcp__* (STEAL P0-14). It answers in the shape Claude
// Code reads: a JSON decision on standard output, and exit 2 with the same reason on standard
// error to block, exit 0 to allow, a visible "NOT scanned" notice when it could not look. It
// calls this same binary back for the publish gate, so the check runs with the same data root
// the guard did.
func (c *cli) cmdGuard(args []string) int {
	if len(args) != 1 || args[0] != "claude" {
		fmt.Fprintln(c.err, "usage: keyguard guard claude   (reads a PreToolUse event on stdin)")
		return exitUsage
	}
	self, err := c.exe()
	if err != nil {
		// Without our own path the publish gate cannot run, and a gate that cannot run must
		// not wave a publish through.
		self = filepath.Join(core.RealRoot(), "bin", "keyguard")
	}
	return guard.Hook(c.ctx, c.in, c.out, c.err, guard.Options{Check: guard.ExecPublishCheck(self)})
}
