// Package sweep runs keyguard's scans: the 10-minute poll, the full and deep rescans, and
// the publish check. It is built only on the core interfaces plus a few small ones defined
// here (BlobScanner for the known-secret matcher, Clocked for GitHub's clock), so every
// collaborator can be replaced by a fake and every path is testable against real git.
//
// What a run does, per source: sync the mirror, work out for each engine what it has not
// seen yet, run the engines side by side, fold their hits into the store, re-triage, alert,
// save, and only then advance the source's state. That last ordering is the point: a crash
// anywhere earlier leaves the old tips in place, so the next run re-scans the same commits
// and the (idempotent) merge absorbs the repeat. Nothing is ever marked scanned that was not.
//
// Incremental scans. A source's state (state/sources/<id>.json) records, per engine, the
// version it last scanned with and the ref tips it had finished. The next scan of that
// engine is Range{Revs: --all --not <old tips>, Since: old tips}: exactly the commits the
// engine has not seen. It is a full scan instead when there is no state, when the engine's
// version (or, for the engines that read it, the rules file) changed, when a run is a Full,
// or when a repo has just gone from private to public. An engine that fails keeps its old
// tips, so the next run retries only that engine and only its backlog. The known-secret pass
// is one more such engine whose "version" is the learned set, so a newly learned key is
// looked for in all of every repo's history at the next poll.
//
// The blob ledger (ledger.go) is the finer record under the tips: which blobs each scanner
// version has already read, per source. A rescan, whatever asked for it (a Full, lost state,
// a push that moved refs without adding content), reads only what no current version has
// seen; and a scanner is not started at all when its range holds nothing new for it.
//
// Speed. The known matcher runs in-process over `git cat-file --batch` of each new blob, with
// no engine process in its way, so a learned key alerts without waiting for the engines.
// Sources are scheduled flips first, then largest pack first (schedule.go); a full scan of a
// huge repo that outweighs the rest of the queue runs alone with more threads per engine. Only
// exposed sources are fetched or scanned when Config.ExposedOnly is set (PLAN.md "Sweep scope").
//
// Keys that were verified are asked about again when their verdict ages (reverify.go), by
// reading again only the commits they were found in, which is what lets a full run skip the
// history the ledger already holds without losing the weekly refresh of live keys.
//
// GitHub's API resources (issues, pull requests, releases, Actions runs) are scanned one
// exact URL per changed resource (events.go, STEAL P0-22), never from a cursor, and every
// stamp and cursor the sweep writes is on GitHub's clock when the inventory has it (P0-16).
//
// No silent caps: everything dropped, capped, skipped or deferred is a line in
// RunStats.Notes, and the run's stats are written to state/runs/ whether or not it found
// anything.
package sweep

import (
	"context"
	"errors"
	"runtime"
	"time"

	"keyguard/internal/core"
	"keyguard/internal/db"
)

// Errors a run can end with.
var (
	ErrLocked    = db.ErrLocked
	ErrNoEngines = errors.New("sweep: no engine is available and there are no learned secrets to match, so a scan would protect nothing")
	ErrLockLost  = errors.New("sweep: the run lock was taken over by another run; stopped to avoid two writers")
)

// BlobScanner finds learned secrets in the git objects a range covers. It is separate from
// core.Engine because the known matcher works on bytes, not on an external tool's report,
// and because it must see every blob, including binary ones and ones no diff mentions.
type BlobScanner interface {
	ScanBlobs(ctx context.Context, repo string, r core.Range, m core.KnownMatcher, loc core.Location, emit core.Emit) (BlobStats, error)
}

// BlobSeen is a window onto the blob ledger for one scan of one source. Seen is asked before a
// blob is read; Note is told about each blob that was. The blobs noted enter the ledger only
// when the run has saved their findings.
type BlobSeen interface {
	Seen(oid string) bool
	Note(oid string)
}

// LedgerBlobScanner is a BlobScanner that can skip the blobs a ledger already has. GitKnown is
// one; a scanner that is not (a test double) is simply run on everything, as before.
type LedgerBlobScanner interface {
	BlobScanner
	ScanBlobsSeen(ctx context.Context, repo string, r core.Range, m core.KnownMatcher, loc core.Location, seen BlobSeen, emit core.Emit) (BlobStats, error)
}

// BlobStats counts what a blob scan covered and what it had to leave out.
type BlobStats struct {
	Blobs        int      // blobs read and matched
	Bytes        int64    // bytes of those blobs
	Seen         int      // blobs not read because the ledger already had them
	Limit        int64    // the size above which a blob is not read
	Skipped      int      // blobs over the limit, not read
	SkippedBytes int64    // their total size
	SkippedPaths []string // a few of them, for the note
	Truncated    int      // blobs with more matches than were kept
}

// Clocked is an Inventory that keeps GitHub's clock: the Date header of the last response it
// read, carried forward by the time since. This Mac's clock has run two hours fast (STEAL
// P0-16), so every stamp the sweep writes, and every cursor it keeps, comes from here when the
// inventory has it and from Config.Now otherwise. ok is false until a response has been seen.
type Clocked interface {
	ServerNow() (now time.Time, ok bool)
}

// Config wires a Runner to its collaborators. Everything but the first six fields may be
// left zero.
type Config struct {
	Paths     core.Paths
	Inventory core.Inventory
	Mirror    core.Mirror
	Engines   []core.Engine
	Store     core.Store
	Triage    core.Triager

	Known    core.KnownMatcher // learned local secrets; nil switches the known pass off
	Blobs    BlobScanner       // the known pass's plumbing; default GitKnown
	Reporter core.Reporter
	Notifier core.Notifier
	Layers   func() []core.LayerStatus // protection layers' health, passed to the reporter

	// API scans one GitHub resource by its exact URL (an issue, a pull request, a release, an
	// Actions run). Left nil it is the first engine that has the capability. With none, or
	// without Token or EventURL, events about those resources are said out loud in the notes
	// and not scanned.
	API core.APIScanner
	// Token returns the GitHub token of a gh login. It goes to the scanner in its environment
	// and nowhere else; the sweep never logs or stores it. An empty account is an event about
	// a repo that is not the user's, which any of their tokens can read.
	Token func(ctx context.Context, account string) (string, error)
	// EventURL is the page of the resource an event is about (core.Event carries no URL of its
	// own yet; see the handoff). It returns "" for an event that names none.
	EventURL func(core.Event) string

	// Scratch makes the throwaway store a publish check scans into. The default is an
	// in-memory db.Store that still honors the real ignore list.
	Scratch func() (core.Store, error)

	// ExposedOnly limits scanning to sources a stranger can read (PLAN.md "Sweep scope"):
	// public repos, their wikis, gists. The rest are still listed, and their visibility is kept
	// in the snapshot so a private repo going public is seen, but they are never fetched.
	ExposedOnly bool

	// NoLedger reads every blob again and keeps no ledger files. Left off, the ledger lets a
	// full-range scan skip what its scanners have already read. Fresh reads everything again
	// but still records it: the way to rebuild findings from the history, or to doubt the ledger.
	NoLedger bool
	Fresh    bool
	// HugeBytes is the pack size at which a full scan of one source runs alone, with
	// HugeThreads per engine, instead of beside the others; 0 means 256 MiB, negative never.
	HugeBytes   int64
	HugeThreads int // 0 means the machine's cores divided among the engines, between 4 and 8
	APIJobs     int // API resources scanned at once; 0 means Jobs, at most 4, since GitHub throttles

	Jobs          int           // sources scanned at once, and engine processes at once; default 8
	NoVerify      bool          // verification is on unless this is set: a scan that forgets to verify loses precision silently
	Rules         string        // extra rules file passed to every engine
	SourceTimeout time.Duration // per source, mirror sync included; default 30 min
	MaxNotify     int           // alerts sent one by one per run before the rest become one digest; default 10
	LockWait      time.Duration // how long a publish check waits for a running sweep; default 30 s
	Now           func() time.Time
}

// Runner runs scans. Create one with New; its methods may be called one run at a time
// (the run lock enforces that across processes too).
type Runner struct {
	cfg     Config
	threads int // engine-internal threads, so Jobs engines together use about every core
}

// New checks the config and fills in defaults.
func New(cfg Config) (*Runner, error) {
	switch {
	case cfg.Paths.State == "" || cfg.Paths.Lock == "" || cfg.Paths.Sources == "" || cfg.Paths.Runs == "":
		return nil, errors.New("sweep: Paths is incomplete; build it with core.PathsAt")
	case cfg.Inventory == nil:
		return nil, errors.New("sweep: no Inventory")
	case cfg.Mirror == nil:
		return nil, errors.New("sweep: no Mirror")
	case cfg.Store == nil:
		return nil, errors.New("sweep: no Store")
	case cfg.Triage == nil:
		return nil, errors.New("sweep: no Triager")
	case len(cfg.Engines) == 0 && cfg.Known == nil:
		return nil, ErrNoEngines
	}
	cfg.Inventory = wrapInventory(cfg.Inventory)
	if cfg.Jobs <= 0 {
		cfg.Jobs = 8
	}
	if cfg.SourceTimeout <= 0 {
		cfg.SourceTimeout = 30 * time.Minute
	}
	if cfg.APIJobs <= 0 {
		cfg.APIJobs = min(cfg.Jobs, 4)
	}
	if cfg.HugeBytes == 0 {
		cfg.HugeBytes = 256 << 20
	}
	if cfg.MaxNotify <= 0 {
		cfg.MaxNotify = 10
	}
	if cfg.LockWait <= 0 {
		cfg.LockWait = 30 * time.Second
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Blobs == nil {
		cfg.Blobs = GitKnown{}
	}
	if cfg.Scratch == nil {
		paths := cfg.Paths
		cfg.Scratch = func() (core.Store, error) { return db.NewScratch(paths) }
	}
	return &Runner{cfg: cfg, threads: max(1, runtime.NumCPU()/cfg.Jobs)}, nil
}

func stamp(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// apiScanner is the capability that reads GitHub's API resources: the configured one, else the
// first available engine that has it.
func (r *Runner) apiScanner() core.APIScanner {
	if r.cfg.API != nil {
		return r.cfg.API
	}
	for _, e := range r.cfg.Engines {
		if a, ok := e.(core.APIScanner); ok && e.Available() {
			return a
		}
	}
	return nil
}
