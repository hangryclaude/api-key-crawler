package hooks

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"keyguard/internal/core"
)

// RefTx is the reference-transaction hook: the one gate `git commit --no-verify` cannot
// skip. It only ever looks for learned secrets (zero false positives, so it is safe to be
// unskippable) and it fails open: it runs on every ref update, fetches included.
func RefTx(ctx context.Context, d Deps, args []string, stdin io.Reader) int {
	h := newHook(ctx, d, NameRefTx, refTxTimeout)
	defer h.cancel()
	return h.refTx(args, stdin)
}

// refUpdate is one stdin line: <old> <new> <ref>. Either oid can be all zeros, or
// "ref:<target>" for a symbolic ref.
type refUpdate struct{ old, new, ref string }

func readRefUpdates(r io.Reader) ([]refUpdate, error) {
	var ups []refUpdate
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		if f := strings.SplitN(sc.Text(), " ", 3); len(f) == 3 {
			ups = append(ups, refUpdate{f[0], f[1], f[2]})
		}
	}
	return ups, sc.Err()
}

func (h *hook) refTx(args []string, stdin io.Reader) int {
	// git calls the hook for preparing, prepared, committed and aborted. Only "prepared"
	// can still abort the update, and it is the only one worth the work. Reading stdin
	// first (always) keeps git from writing into a closed pipe.
	ups, rerr := readRefUpdates(stdin)
	if argAt(args, 0) != "prepared" {
		return 0
	}
	if rerr != nil {
		h.warn("could not read the ref list (%s); nothing scanned", h.failText(rerr))
		return 0
	}

	// Only branches and tags can carry a commit onward. `old` is dropped from the range
	// when zero: git also sends zero for "force, whatever it was". A clone creates tags
	// in the same transaction as refs/remotes/*, which do not exist yet at this point, so
	// the incoming remote tips are subtracted too or every clone would rescan all history.
	var news, olds, incoming []string
	var refs []string
	for _, u := range ups {
		switch {
		case strings.HasPrefix(u.ref, "refs/remotes/"):
			if realOID(u.new) {
				incoming = append(incoming, u.new)
			}
		case strings.HasPrefix(u.ref, "refs/heads/"), strings.HasPrefix(u.ref, "refs/tags/"):
			if !realOID(u.new) { // a delete, or a symbolic ref
				continue
			}
			news = append(news, u.new)
			refs = append(refs, u.ref)
			if realOID(u.old) {
				olds = append(olds, u.old)
			}
		}
	}
	if len(news) == 0 {
		return 0
	}
	if h.inMirrorCache() {
		return 0
	}
	m := h.matcher()
	if m == nil {
		return 0
	}

	// The range is what is new: not reachable from the old values, from any branch or tag
	// that exists, or from a remote. A commit made just now (--no-verify included) is on
	// none of them while the transaction is only prepared. Commits already on a ref were
	// judged when they got there, and rejudging them would make `git tag`, `git branch`
	// or a merge of a local branch fail wherever old unpushed history holds a key; pre-push
	// still scans every unpushed commit when it leaves. HEAD is deliberately not a
	// subtraction: a commit made on a detached HEAD has to be judged when a ref takes it.
	// One --not covers all of them: a second would flip the sign back.
	revs := append(dedupe(news), "--not")
	revs = append(revs, dedupe(olds)...)
	revs = append(revs, "--branches", "--tags", "--remotes")
	revs = append(revs, dedupe(incoming)...)

	// Both reads of the new commits (the diff, and the messages with their authors) start now
	// and run while git is asked whether this is a bare repository: a bare repository has no
	// working tree to author a commit in. Refs arrive there by clone, fetch or push, carrying
	// history that already exists elsewhere, and no remote-tracking refs exist to subtract
	// it, so scanning it would only block `git clone --bare`. The wasted pair of processes in
	// a bare repository is the price of a shorter wait in every other.
	st, err := h.g.logPatch(h.ctx, maxRefTxCommits+1, revs)
	if err != nil {
		h.warn("could not list new commits (%s); not scanned", h.failText(err))
		return 0
	}
	waitMsgs, stopMsgs := h.scanMessages(m, maxRefTxCommits, revs, "unpushed")
	bare, berr := h.g.isBare(h.ctx)
	if berr != nil || bare {
		_ = st.finish(true)
		stopMsgs()
		if berr != nil {
			h.warn("could not tell whether this repository is bare (%s); not scanned", h.failText(berr))
		}
		return 0
	}

	// The names of the refs. A name that holds a key is not repeated anywhere: a hit does not
	// carry the ref it was found under then.
	nameHits := h.refNameHits(m, refs, "unpushed")
	ref := ""
	if len(dedupe(refs)) == 1 && len(nameHits) == 0 {
		ref = refs[0]
	}
	var hits []core.Hit
	_, capped, serr := scanAdded(st.r, m, maxRefTxCommits, func(dm diffMatch) {
		hit := h.knownHit(dm, "unpushed")
		hit.Loc.Ref = ref
		hits = append(hits, hit)
	})
	if ferr := st.finish(capped); serr == nil {
		serr = ferr
	}
	if serr != nil {
		stopMsgs()
		h.warn("could not scan new commits (%s); not blocked", h.failText(serr))
		return 0
	}

	// What git records besides the diff (STEAL P0-13): the messages and authors of the new
	// commits, the annotation of a tag, the names of the refs. Each one that cannot be read
	// is said so and the rest still count.
	msgHits, merr := waitMsgs()
	if merr != nil {
		h.warn("could not scan the commit messages (%s); the diff was checked", h.failText(merr))
	}
	hits = append(hits, msgHits...)
	hits = append(hits, nameHits...)
	var tags []string
	for _, u := range ups {
		if strings.HasPrefix(u.ref, "refs/tags/") && realOID(u.new) {
			tags = append(tags, u.new)
		}
	}
	if th, terr := h.tagHits(m, tags, "unpushed"); terr != nil {
		h.warn("could not read the tag annotation (%s); it was not checked", h.failText(terr))
	} else {
		hits = append(hits, th...)
	}
	if capped {
		h.mu.Lock()
		fmt.Fprintf(h.d.Stderr, "keyguard: note: more than %d new commits; scanned the newest %d. pre-push and the GitHub poll cover the rest.\n", maxRefTxCommits, maxRefTxCommits)
		h.mu.Unlock()
	}

	hits = h.finalize(hits, "unpushed")
	if len(hits) == 0 {
		return 0
	}
	if fetchLike(h.ctx) {
		// History that arrives by fetch or clone already exists outside this repository;
		// refusing to record it would break git without protecting anything.
		h.mu.Lock()
		fmt.Fprintf(h.d.Stderr, "keyguard: note: fetched history holds %d learned key%s; allowed, not authored here\n", len(hits), plural(len(hits)))
		h.mu.Unlock()
		return 0
	}
	return h.block("ref update blocked", hits)
}

// inMirrorCache reports whether this repository lives under a keyguard cache: the sweep's
// mirrors are fed with leaked keys on purpose, and blocking that would blind the sweep.
// Both the real data root and $KEYGUARD_HOME are checked, symlinks resolved (macOS temp
// dirs sit behind /var -> /private/var).
func (h *hook) inMirrorCache() bool {
	cwd := h.d.Dir
	if cwd == "" {
		cwd, _ = os.Getwd()
	}
	dirs := []string{cwd}
	if gd := os.Getenv("GIT_DIR"); gd != "" {
		if !filepath.IsAbs(gd) {
			gd = filepath.Join(cwd, gd)
		}
		dirs = append(dirs, gd)
	}
	for _, root := range core.KnownRoots() {
		cache := filepath.Join(resolvePath(root), "cache")
		for _, d := range dirs {
			if within(resolvePath(d), cache) {
				return true
			}
		}
	}
	return false
}

func resolvePath(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return filepath.Clean(p)
}

func within(p, root string) bool {
	return p == root || strings.HasPrefix(p, root+string(filepath.Separator))
}

// fetchLike reports whether the git process running this hook is bringing history in from
// elsewhere. It is only asked when about to block, so the process lookup costs nothing on
// the normal path. It reads the parent's command line, not GIT_REFLOG_ACTION or any other
// variable: the environment is the caller's to set, and this hook has to stay unskippable.
func fetchLike(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second) // a stuck ps must not hold git up
	defer cancel()
	out, err := exec.CommandContext(ctx, "ps", "-o", "args=", "-p", strconv.Itoa(os.Getppid())).Output()
	if err != nil {
		return false
	}
	return isFetchCommand(strings.Fields(string(out)))
}

// isFetchCommand reads a process's argv: git-receive-pack, or git with a fetch-ish
// subcommand after any global options (-C dir, -c k=v, ...).
func isFetchCommand(argv []string) bool {
	if len(argv) == 0 {
		return false
	}
	switch bin := path.Base(argv[0]); bin {
	case "git-receive-pack", "git-fetch-pack", "git-fetch":
		return true
	case "git":
	default:
		return false
	}
	for i := 1; i < len(argv); i++ {
		switch w := argv[i]; {
		case w == "-C" || w == "-c" || w == "--git-dir" || w == "--work-tree" || w == "--namespace" || w == "--config-env" || w == "--super-prefix":
			i++
		case strings.HasPrefix(w, "-"):
		default:
			switch w {
			case "fetch", "clone", "receive-pack", "fetch-pack":
				return true
			case "merge":
				// `git pull <url> <branch>` merges what it just fetched, by name, into a
				// repository that keeps no remote-tracking ref for it.
				return slices.Contains(argv[i+1:], "FETCH_HEAD")
			}
			return false
		}
	}
	return false
}
