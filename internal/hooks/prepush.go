package hooks

import (
	"bufio"
	"context"
	"io"
	"strings"
	"sync"

	"keyguard/internal/core"
)

// PrePush scans the commits a push would send. It is the net under --no-verify, rebases,
// cherry-picks and commits made on another machine: whatever got past pre-commit is here
// before it leaves the Mac. args are git's: the remote's name and its URL.
func PrePush(ctx context.Context, d Deps, args []string, stdin io.Reader) int {
	h := newHook(ctx, d, NamePrePush, prePushTimeout)
	defer h.cancel()
	return h.prePush(args, stdin)
}

// pushUpdate is one stdin line: <local ref> <local sha> <remote ref> <remote sha>.
type pushUpdate struct{ lref, lsha, rref, rsha string }

func readPushUpdates(r io.Reader) ([]pushUpdate, error) {
	var ups []pushUpdate
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		if f := strings.Fields(sc.Text()); len(f) == 4 {
			ups = append(ups, pushUpdate{f[0], f[1], f[2], f[3]})
		}
	}
	return ups, sc.Err()
}

func (h *hook) prePush(args []string, stdin io.Reader) int {
	remote, url := argAt(args, 0), argAt(args, 1)
	ups, err := readPushUpdates(stdin)
	if err != nil {
		h.warn("could not read the push list (%s); nothing scanned", h.failText(err))
		return 0
	}

	// A deletion arrives with an all-zero local sha and sends no commits.
	var tips, olds []string
	for _, u := range ups {
		if !realOID(u.lsha) {
			continue
		}
		tips = append(tips, u.lsha)
		if realOID(u.rsha) {
			olds = append(olds, u.rsha)
		}
	}
	if len(tips) == 0 {
		return 0
	}

	revs := h.pushRevs(remote, dedupe(tips), dedupe(olds))
	has, err := h.g.anyCommit(h.ctx, revs)
	if err != nil {
		h.warn("could not list the commits being pushed (%s); nothing scanned", h.failText(err))
		return 0
	}
	if !has {
		return 0
	}

	vis := core.Unknown
	if h.d.Visibility != nil {
		vis = h.d.Visibility(remote, url)
	}
	rng := core.Range{Revs: revs}
	repo := h.worktree()

	var (
		wg         sync.WaitGroup
		regex, ver collector
		known      []core.Hit
		texts      []core.Hit // commit messages and authors
		refs       []core.Hit // ref names and tag annotations
		failMu     sync.Mutex
		failed     []string
		runPass    = func(name string, fn func() error) {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := safely(fn); err != nil {
					failMu.Lock()
					failed = append(failed, name+": "+h.failText(err))
					failMu.Unlock()
				}
			}()
		}
	)
	if m := h.matcher(); m != nil {
		runPass("learned-secret scan", func() error {
			st, err := h.g.logPatch(h.ctx, 0, revs)
			if err != nil {
				return err
			}
			_, _, serr := scanAdded(st.r, m, 0, func(dm diffMatch) { known = append(known, h.knownHit(dm, "unpushed")) })
			if ferr := st.finish(false); serr == nil {
				serr = ferr
			}
			return serr
		})
	}
	if m := h.matcher(); m != nil {
		// What git sends besides the diff (STEAL P0-13): the messages and authors of the
		// commits, the names of the refs, the annotations of the tags.
		runPass("commit messages", func() error {
			wait, _ := h.scanMessages(m, 0, revs, "unpushed")
			hs, err := wait()
			texts = append(texts, hs...)
			return err
		})
		var names, tags []string
		for _, u := range ups {
			if !realOID(u.lsha) {
				continue
			}
			names = append(names, u.lref, u.rref)
			if strings.HasPrefix(u.lref, "refs/tags/") {
				tags = append(tags, u.lsha)
			}
		}
		runPass("ref names and tag annotations", func() error {
			hs := h.refNameHits(m, names, "unpushed")
			th, err := h.tagHits(m, tags, "unpushed")
			refs = append(append(refs, hs...), th...)
			return err
		})
	}
	if h.d.ScanRange != nil {
		runPass("regex engine", func() error { return h.d.ScanRange(h.ctx, repo, rng, regex.emit) })
	}
	// A key that is live and about to go somewhere strangers can read is worth the extra
	// pass: it is the only one that calls the provider.
	if vis.Exposed() && h.d.ScanVerified != nil {
		runPass("verifying engine", func() error { return h.d.ScanVerified(h.ctx, repo, rng, ver.onlyLive) })
	}
	wg.Wait()

	for _, f := range failed {
		h.warn("%s failed; the push got the other checks only", f)
	}
	hits := append(append(append(append(known, texts...), refs...), regex.hits...), ver.hits...)
	hits = h.finalize(hits, "unpushed")
	if len(hits) == 0 {
		return 0
	}
	return h.block("push blocked", hits)
}

// pushRevs builds the rev arguments for what a push sends: the tips being pushed, minus
// what the remote already holds. "What the remote holds" is what this clone knows of it
// (--remotes=<name>) plus the shas the remote advertised, when those objects are local.
// A URL given instead of a remote name excludes nothing by name: the cautious direction.
func (h *hook) pushRevs(remote string, tips, olds []string) []string {
	var neg []string
	if validRemoteName(remote) {
		neg = append(neg, "--remotes="+remote)
	}
	if len(olds) > 0 {
		// An advertised sha we never fetched cannot be named to rev-list.
		if have, err := h.g.have(h.ctx, olds); err != nil {
			h.warn("could not check the remote's tips (%s); scanning more than needed", h.failText(err))
		} else {
			neg = append(neg, have...)
		}
	}
	revs := append([]string(nil), tips...)
	if len(neg) > 0 {
		revs = append(append(revs, "--not"), neg...)
	}
	return revs
}

// validRemoteName guards the --remotes= glob: a remote name has no glob characters, a
// URL or path passed to `git push` instead of a name might.
func validRemoteName(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return s[0] != '-'
}

func argAt(args []string, i int) string {
	if i < len(args) {
		return args[i]
	}
	return ""
}
