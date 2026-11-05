package sweep

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"keyguard/internal/core"
	"keyguard/internal/db"
)

// ErrIncomplete is wrapped by a publish check that could not scan its whole target. A check
// that did not look cannot say the target is clean.
var ErrIncomplete = errors.New("publish check did not finish")

// PublishResult is the verdict on a target about to become public.
type PublishResult struct {
	Target string
	Source string // the source id that was scanned
	Stats  core.RunStats
	// Blocking holds every open secret of severity low or more, judged as if the target were
	// already public. It carries display fields only. Empty means clean.
	Blocking []core.Secret
}

// PublishCheck scans a repo's whole history, every ref, with every engine and verification,
// and reports what would leak if it were public. target is a directory (a repo not on
// GitHub yet, or a clone), or "owner/name" (also github.com/owner/name and clone URLs) for a
// repo keyguard watches.
//
// The scan runs into a scratch store and writes no findings, no source state and no
// inventory: a what-if scan of something that is not public yet must not leave "public"
// locations in the real store. It does honor the real ignore list, so a secret the user has
// marked a false positive does not block. It waits up to Config.LockWait for a running
// sweep, then gives up with ErrLocked, since the answer would otherwise be a guess.
func (r *Runner) PublishCheck(ctx context.Context, target string) (PublishResult, error) {
	res := PublishResult{Target: target}
	scratch, err := r.cfg.Scratch()
	if err != nil {
		return res, err
	}
	rn, err := r.begin(ctx, "publish-check", false, scratch, r.cfg.LockWait)
	if err != nil {
		res.Stats = rn.aborted()
		return res, err
	}
	src, local, err := r.resolveTarget(ctx, target)
	if err != nil {
		res.Stats, _ = rn.finish(ctx, nil)
		return res, err
	}
	res.Source = src.ID
	rn.mu.Lock()
	rn.stats.Sources = 1
	rn.mu.Unlock()

	var out srcOutcome
	if local != "" {
		out = rn.guard(ctx, src, func(ctx context.Context) srcOutcome {
			return rn.scanRepo(ctx, src, local, nil, nil, true, true)
		})
	} else {
		out = rn.source(ctx, src, true)
	}
	rn.tally(src, out)

	for _, s := range scratch.Secrets() {
		if s.Status == db.StatusOpen && s.Severity >= core.Low {
			res.Blocking = append(res.Blocking, s)
		}
	}
	slices.SortStableFunc(res.Blocking, func(a, b core.Secret) int {
		if a.Severity != b.Severity {
			return int(b.Severity) - int(a.Severity)
		}
		return strings.Compare(a.ID, b.ID)
	})
	var runErr error
	if !out.complete || !out.scanned {
		runErr = fmt.Errorf("sweep: %w for %s; see the notes", ErrIncomplete, target)
	}
	res.Stats, err = rn.finish(ctx, runErr)
	return res, err
}

var (
	repoRefRE = regexp.MustCompile(`^(?:(?:https?://|ssh://git@|git@)?(?:www\.)?github\.com[/:])?([A-Za-z0-9][A-Za-z0-9_.-]*)/([A-Za-z0-9_.-]+?)(?:\.git)?/?$`)
)

// parseRepoRef reads owner/name in the forms people type and paste.
func parseRepoRef(s string) (id string, ok bool) {
	m := repoRefRE.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return "", false
	}
	return "github.com/" + m[1] + "/" + m[2], true
}

// resolveTarget finds what to scan. A directory that is a git repo is scanned in place; a
// repo reference is looked up in the inventory, which supplies the clone URL and account the
// mirror needs. Either way the source is scanned as public, because that is what the check
// asks: would this leak if it were.
func (r *Runner) resolveTarget(ctx context.Context, target string) (src core.Source, local string, err error) {
	if fi, serr := os.Stat(target); serr == nil && fi.IsDir() {
		abs, err := filepath.Abs(target)
		if err != nil {
			return src, "", err
		}
		if gitCmd(ctx, "git", abs, "rev-parse", "--git-dir").Run() == nil {
			return core.Source{ID: "local:" + abs, Kind: "repo", Name: filepath.Base(abs), Visibility: core.Public}, abs, nil
		}
		// A directory that is no repository may just share its name with owner/name.
		if _, ok := parseRepoRef(target); !ok {
			return src, "", fmt.Errorf("sweep: %s is not a git repository", abs)
		}
	}
	id, ok := parseRepoRef(target)
	if !ok {
		return src, "", fmt.Errorf("sweep: %q is neither a directory nor an owner/name", target)
	}
	if snap, err := loadSnapshot(r.cfg.Paths.Inventory); err == nil {
		if s, ok := findSource(values(snap), id); ok {
			s.Visibility = core.Public
			return s, "", nil
		}
	}
	list, err := r.cfg.Inventory.List(ctx)
	if err != nil {
		return src, "", fmt.Errorf("sweep: looking up %s: %s", id, safeErr(err))
	}
	s, ok := findSource(list, id)
	if !ok {
		return src, "", fmt.Errorf("sweep: %s is not in the inventory; scan a local clone by path instead", id)
	}
	s.Visibility = core.Public
	return s, "", nil
}

// findSource matches ids the way GitHub does, ignoring case.
func findSource(list []core.Source, id string) (core.Source, bool) {
	for _, s := range list {
		if strings.EqualFold(s.ID, id) {
			return s, true
		}
	}
	return core.Source{}, false
}
