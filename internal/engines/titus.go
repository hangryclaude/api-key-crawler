package engines

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"crypto/sha1"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"

	"keyguard/internal/core"
	"keyguard/internal/fp"
)

// titus is Praetorian's Hyperscan scanner. It works on blobs: a finding names the blob it
// is in, not a commit or path, so locations are recovered from git afterwards, and only for
// the blobs that hit.
type titus struct{ *base }

type titusRec struct {
	BlobID      string
	RuleID      string
	Groups      [][]byte
	NamedGroups map[string][]byte
	Location    struct {
		Source struct {
			Start struct{ Line int }
			End   struct{ Line int }
		}
	}
	Snippet struct {
		Before, Matching, After []byte
	}
}

// titusHit is a finding waiting for its location. It holds the finished Hit, whose raw value
// is already gone, so no secret waits in memory for the git lookups.
type titusHit struct {
	blob string
	hit  core.Hit
}

// flags.
//   - --output :memory: because titus's datastore is a SQLite file holding every match in the
//     clear (measured: 20 of 20 planted keys were in datastore.db);
//   - --ignore replaces the built-in ignore list, which skips lockfiles and *.min.js, where real
//     keys end up;
//   - --accessibility private: the default, auto, looks the repository up on GitHub to decide how to
//     score what it found, which is a connection made because of what is being scanned;
//   - --workers and --readers always: they are native threads that GOMAXPROCS does not bound.
func (e *titus) flags(o core.ScanOpts, ignoreFile string) []string {
	n := strconv.Itoa(threads(o))
	return []string{"-q", "--format", "json", "--output", ":memory:", "--context-lines", "1", "--ignore", ignoreFile,
		"--accessibility", "private", "--workers", n, "--readers", n}
}

func (e *titus) gitArgs(o core.ScanOpts, gitDir, ignoreFile string) []string {
	return append([]string{"scan", gitDir, "--git"}, e.flags(o, ignoreFile)...)
}

func (e *titus) dirArgs(o core.ScanOpts, dir, ignoreFile string) []string {
	return append([]string{"scan", dir}, e.flags(o, ignoreFile)...)
}

// cacheEnv puts titus's compiled-rules cache under the keyguard data root: 2 MB of Hyperscan
// databases with no secret in them, 2.7 s to build and 30 ms to read back. Where install and
// doctor can warm it and see it, instead of wherever titus decides (STEAL P0-06).
func cacheEnv() string {
	dir := core.PathsAt(core.Root()).TitusCache
	os.MkdirAll(dir, 0o700) // titus makes it too; this keeps a read-only parent from being its problem
	return "TITUS_CACHE_DIR=" + dir
}

// writeIgnore puts an ignore file in scratch. ".git/" is skipped in directory scans so all
// four engines agree on what a directory scan covers (betterleaks and gitleaks skip it).
func writeIgnore(scratch string) (string, error) {
	p := filepath.Join(scratch, "titus.ignore")
	return p, os.WriteFile(p, []byte(".git/\n"), 0o600)
}

// secretPreference orders the names titus gives a rule's capture groups. The secret of a rule
// with several groups is the one named for it: np.postgres.1 captures the user name, the
// password, the host and the port, in that order, and the first is not the secret.
var secretPreference = []string{
	"secret", "client_secret", "secret_key", "token_secret", "password", "token", "access_token", "bearer_token",
	"api_key", "private_key", "key", "access_key", "account_key", "server_key", "webhook",
}

// titusSecret picks the value of the group that is the secret. sure is false when the rule has
// several groups and none is named for a secret, so the first is a guess: the caller then hides
// the whole match from the context line, because the guess may be the user name.
func titusSecret(rec *titusRec) (raw string, sure bool) {
	for _, want := range secretPreference {
		for name, v := range rec.NamedGroups {
			if strings.EqualFold(name, want) && len(bytes.TrimSpace(v)) > 0 {
				return strings.TrimSpace(string(v)), true
			}
		}
	}
	if len(rec.NamedGroups) == 1 {
		for _, v := range rec.NamedGroups {
			if s := strings.TrimSpace(string(v)); s != "" {
				return s, true
			}
		}
	}
	if len(rec.Groups) > 0 {
		if s := strings.TrimSpace(string(rec.Groups[0])); s != "" {
			return s, len(rec.Groups) == 1
		}
	}
	return strings.TrimSpace(string(rec.Snippet.Matching)), false
}

// pending turns a record into a candidate without a location. The blob id is the candidate's
// group: two findings in one blob are in one text, wherever the blob is found.
func (e *titus) pending(o core.ScanOpts, rec *titusRec) (titusCand, bool) {
	raw, sure := titusSecret(rec)
	if raw == "" || rec.BlobID == "" {
		return titusCand{}, false
	}
	// The snippet is the match plus whole lines around it, so the flagged line is the tail of
	// Before, the match, and the head of After.
	matching := string(rec.Snippet.Matching)
	line := lastLine(rec.Snippet.Before) + matching + firstLine(rec.Snippet.After)
	if !sure {
		line = fp.Redact(line, matching)
	}
	c := e.newCand(o, found{
		raw: raw, line: line, rule: rec.RuleID, verified: core.Unverified,
		lineNo: rec.Location.Source.Start.Line, endLine: rec.Location.Source.End.Line, group: "blob:" + rec.BlobID,
	})
	return titusCand{blob: rec.BlobID, c: c}, true
}

type titusCand struct {
	blob string
	c    cand
}

func lastLine(b []byte) string {
	if i := bytes.LastIndexByte(b, '\n'); i >= 0 {
		b = b[i+1:]
	}
	return string(b)
}

func firstLine(b []byte) string {
	if i := bytes.IndexByte(b, '\n'); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

// collect runs titus and returns its findings without locations, fragments of other findings
// of the same blob already dropped (see dropContained).
func (e *titus) collect(ctx context.Context, o core.ScanOpts, args func(scratch, ignore string) []string) ([]titusHit, error) {
	var cands []cand
	err := e.run(ctx, func(scratch string) (job, error) {
		ig, err := writeIgnore(scratch)
		if err != nil {
			ig = "/dev/null" // the file is an optimisation of what is scanned, not a safety property
		}
		return job{args: args(scratch, ig), env: jobEnv(o, cacheEnv())}, nil
	}, func(rd io.Reader) error {
		return streamArray(rd, func(rec *titusRec) error {
			if tc, ok := e.pending(o, rec); ok {
				cands = append(cands, tc.c)
			}
			return nil
		})
	})
	kept := dropContained(cands)
	hits := make([]titusHit, len(kept))
	for i, c := range kept {
		hits[i] = titusHit{blob: strings.TrimPrefix(c.group, "blob:"), hit: c.hit}
	}
	return hits, err
}

func wantedBlobs(hits []titusHit) map[string]struct{} {
	w := make(map[string]struct{}, len(hits))
	for _, h := range hits {
		w[h.blob] = struct{}{}
	}
	return w
}

func (e *titus) ScanGit(ctx context.Context, repo string, r core.Range, o core.ScanOpts, emit core.Emit) error {
	g, err := e.openGit(ctx, repo, r)
	if err != nil || len(g.args) == 0 {
		return err
	}
	hits, err := e.collect(ctx, o, func(_, ig string) []string { return e.gitArgs(o, g.dir, ig) })
	if err != nil || len(hits) == 0 {
		return err
	}
	locs, capped, err := blobLocations(ctx, g.dir, g.args, wantedBlobs(hits))
	if err != nil {
		return err
	}
	if capped > 0 {
		e.note("titus: %d blob(s) are at more than %d paths; each reports its first %d", capped, maxBlobLocs, maxBlobLocs)
	}
	// Titus scans every blob in the repo, so a range-limited scan keeps only the blobs the
	// range introduced. A whole-repo scan keeps a blob git cannot place (reachable only through
	// a tag on a tree, say) rather than lose the finding.
	ranged := len(r.Revs) > 0 || len(r.Since) > 0
	sk := &sink{emit: emit, namer: newRefNamer(ctx, g.dir)}
	var pointed map[string]string // loaded only if a blob turns out to be unplaceable
	tagOnly := 0
	for _, th := range hits {
		ls := locs[th.blob]
		if len(ls) == 0 {
			if pointed == nil {
				pointed = refsByObject(ctx, g.dir)
			}
			if ranged {
				// Most of these are old blobs, which a ranged scan is meant to leave out. One that a
				// tag points at and no commit contains is not old news, it is a leak the range cannot
				// place, and it is said so.
				if pointed[th.blob] != "" {
					tagOnly++
				}
				continue
			}
			h := th.hit
			h.Loc.Ref = cmp.Or(pointed[th.blob], h.Loc.Ref)
			h.Loc.Blob = th.blob // no commit places it, so the object is its identity
			sk.add(cand{hit: h, group: "blob:" + th.blob})
			continue
		}
		for _, l := range ls {
			h := th.hit
			h.Loc.Commit, h.Loc.Path, h.Loc.Author, h.Loc.Date = l.commit, l.path, l.author, isoDate(l.date)
			h.Loc.URL = blobURL(h.Loc)
			sk.add(cand{hit: h, group: "blob:" + th.blob})
		}
	}
	if tagOnly > 0 {
		e.note("titus: %d hit(s) were on blobs that only a tag reaches, which a ranged scan cannot place and did not report", tagOnly)
	}
	sk.flush()
	return nil
}

// refsByObject maps an object id to a ref that points straight at it, or at a tag that does.
// It finds the tag that keeps an otherwise unreachable blob alive.
func refsByObject(ctx context.Context, gitDir string) map[string]string {
	out, err := gitRepo(ctx, gitDir, "for-each-ref", "--format=%(refname) %(objectname) %(*objectname)")
	m := map[string]string{}
	if err != nil {
		return m
	}
	for _, l := range strings.Split(string(out), "\n") {
		f := strings.Fields(l)
		for _, oid := range f[min(1, len(f)):] {
			if _, seen := m[oid]; !seen {
				m[oid] = f[0]
			}
		}
	}
	return m
}

func (e *titus) ScanStaged(context.Context, string, core.ScanOpts, core.Emit) error {
	return core.ErrUnsupported
}

func (e *titus) ScanDir(ctx context.Context, dir string, o core.ScanOpts, emit core.Emit) error {
	d, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	fi, err := os.Stat(d)
	if err != nil {
		return fmt.Errorf("engines: %w", err)
	}
	root := d
	if !fi.IsDir() {
		root = filepath.Dir(d)
	}
	hits, err := e.collect(ctx, o, func(_, ig string) []string { return e.dirArgs(o, d, ig) })
	if err != nil || len(hits) == 0 {
		return err
	}
	paths, capped, err := hashFiles(ctx, d, root, wantedBlobs(hits))
	if err != nil {
		return err
	}
	if capped > 0 {
		e.note("titus: %d blob(s) are in more than %d files; each reports its first %d", capped, maxBlobLocs, maxBlobLocs)
	}
	for _, th := range hits {
		ps := paths[th.blob]
		if len(ps) == 0 {
			emit(th.hit) // the file changed or vanished between the scan and the hash
			continue
		}
		for _, p := range ps {
			h := th.hit
			h.Loc.Path = p
			emit(h)
		}
	}
	return nil
}

// maxBlobLocs bounds how many paths one blob reports: a file vendored into thousands of
// directories is one secret, and thousands of locations of it help no one.
const maxBlobLocs = 32

type blobLoc struct{ commit, author, date, path string }

// blobLocations finds, for each wanted blob, the commits that introduced it and the paths it
// was added under, oldest first, in one pass of `git log --raw` over the range. A pass per
// blob (`log --find-object`) would walk the whole history once for each hit. Topological
// order, not commit dates: a skewed clock must not make a later copy look like the origin.
func blobLocations(ctx context.Context, gitDir string, args []string, wanted map[string]struct{}) (locs map[string][]blobLoc, capped int, err error) {
	cmd := gitCmd(ctx, gitDir, nil, append(append([]string{
		"--git-dir=" + gitDir, "log", "--topo-order", "--reverse", "--raw", "-c", "--no-abbrev", "--no-renames",
		"--no-ext-diff", "-z", "--format=%x01%H%x00%an%x00%aI",
	}, args...), "--")...)
	var stderr tailBuf
	cmd.Stderr = &stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, 0, err
	}
	if err := cmd.Start(); err != nil {
		return nil, 0, err
	}
	locs = map[string][]blobLoc{}
	cappedBlobs := map[string]bool{}
	sc := bufio.NewScanner(out)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	sc.Split(splitNUL)
	var cur blobLoc
	var blob string // blob of the raw entry whose path token comes next; "" = skip that path
	expectPath := false
	for sc.Scan() {
		tok := sc.Text()
		switch {
		case expectPath:
			expectPath = false
			if blob != "" {
				if !addLoc(locs, blob, blobLoc{cur.commit, cur.author, cur.date, tok}) {
					cappedBlobs[blob] = true
				}
			}
		case strings.HasPrefix(tok, "\x01"):
			cur = blobLoc{commit: tok[1:]}
			if sc.Scan() {
				cur.author = sc.Text()
			}
			if sc.Scan() {
				cur.date = sc.Text()
			}
		default:
			if id, ok := rawEntryBlob(strings.TrimLeft(tok, "\n")); ok {
				if _, want := wanted[id]; want {
					blob = id
				} else {
					blob = ""
				}
				expectPath = true
			}
		}
	}
	scanErr := sc.Err()
	if scanErr != nil {
		cmd.Process.Kill()
	}
	io.Copy(io.Discard, out)
	if werr := cmd.Wait(); werr != nil && scanErr == nil {
		if ctx.Err() != nil {
			return nil, 0, ctx.Err()
		}
		return nil, 0, fmt.Errorf("engines: git log: %v; stderr: %s", werr, stderr.text())
	}
	return locs, len(cappedBlobs), scanErr
}

// addLoc records one path of a blob and reports false when the blob already has the most it
// reports and this path would have been a new one.
func addLoc(locs map[string][]blobLoc, blob string, l blobLoc) bool {
	cur := locs[blob]
	for _, c := range cur {
		if c.path == l.path {
			return true // already have the earliest commit for this path
		}
	}
	if len(cur) >= maxBlobLocs {
		return false
	}
	locs[blob] = append(cur, l)
	return true
}

// rawEntryBlob parses a `git log --raw` entry header such as ":000000 100644 <old> <new> A".
// Combined-diff entries from merges have one extra colon, mode and id per parent
// ("::100644 100644 100644 <a> <b> <result> MM"). The result id is the last id; deletions
// (all-zero id) and submodules (mode 160000) are not blobs.
func rawEntryBlob(meta string) (string, bool) {
	n := 0
	for n < len(meta) && meta[n] == ':' {
		n++
	}
	if n == 0 {
		return "", false
	}
	f := strings.Fields(meta[n:])
	if len(f) != 2*(n+1)+1 {
		return "", false
	}
	mode, id := f[n], f[2*n+1]
	if mode == "160000" || strings.Trim(id, "0") == "" {
		return "", true // a real entry whose path token must still be consumed
	}
	return id, true
}

func splitNUL(data []byte, atEOF bool) (int, []byte, error) {
	if i := bytes.IndexByte(data, 0); i >= 0 {
		return i + 1, data[:i], nil
	}
	if atEOF && len(data) > 0 {
		return len(data), data, nil
	}
	return 0, nil, nil
}

// maxTitusFile is titus's own --max-file-size default; larger files were never scanned.
const maxTitusFile = 10 << 20

// hashFiles maps wanted blob ids to the files under d that hold them. Titus's directory
// report has no path, but its blob id is git's (sha1 of "blob <len>\0<content>"), which can
// be recomputed for the files.
func hashFiles(ctx context.Context, d, root string, wanted map[string]struct{}) (map[string][]string, int, error) {
	var files []string
	walkErr := filepath.WalkDir(d, func(p string, de fs.DirEntry, err error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			return nil // unreadable entries were not scanned either
		}
		if de.IsDir() {
			if de.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if de.Type().IsRegular() {
			files = append(files, p)
		}
		return nil
	})
	if walkErr != nil {
		return nil, 0, walkErr
	}
	var (
		mu     sync.Mutex
		over   = map[string]bool{}
		byBlob = map[string][]string{}
		wg     sync.WaitGroup
		work   = make(chan string)
	)
	for range min(runtime.NumCPU(), 8) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range work {
				id, ok := gitBlobID(p)
				if !ok {
					continue
				}
				if _, want := wanted[id]; !want {
					continue
				}
				rel, err := filepath.Rel(root, p)
				if err != nil {
					rel = p
				}
				mu.Lock()
				if len(byBlob[id]) < maxBlobLocs {
					byBlob[id] = append(byBlob[id], rel)
				} else {
					over[id] = true
				}
				mu.Unlock()
			}
		}()
	}
	for _, p := range files {
		work <- p
	}
	close(work)
	wg.Wait()
	for _, ps := range byBlob {
		slices.Sort(ps)
	}
	return byBlob, len(over), nil
}

func gitBlobID(path string) (string, bool) {
	f, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || fi.Size() > maxTitusFile {
		return "", false
	}
	h := sha1.New()
	fmt.Fprintf(h, "blob %d\x00", fi.Size())
	if _, err := io.Copy(h, f); err != nil {
		return "", false
	}
	return fmt.Sprintf("%x", h.Sum(nil)), true
}
