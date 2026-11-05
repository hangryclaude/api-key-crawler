// Package mirror keeps one bare mirror clone per source under the cache root, laid out as
// <root>/<host>/<owner>/<name>.git, and
// Sync only ever fetches into those paths. The mirrors hold full history of private repos,
// so every directory made here is 0700 and no credential ever touches argv or disk: git asks
// a per-account helper, which asks gh, at the moment it needs one.
package mirror

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"keyguard/internal/core"
)

// Config says where the mirrors live and how to reach GitHub.
type Config struct {
	Root         string        // core.Paths.Mirrors
	Git          string        // git binary; "git" when empty
	GH           string        // gh binary the credential helper runs; found on PATH when empty
	CloneTimeout time.Duration // 0 means 30 min, what the bootstrap allowed
	FetchTimeout time.Duration // 0 means 10 min
	StaleLockAge time.Duration // a git lock file older than this is a crash's leftover; 0 means 10 min
	AllowLocal   bool          // accept file:// remotes; tests only, production talks to GitHub
	// NoFetch serves the mirrors that are already on disk and changes nothing: no clone, no
	// fetch, no lock, no new directory, not even the root. A source with no mirror is an
	// error. It is how a scan reads mirrors it does not own, or that must stay as they are.
	NoFetch bool
	// ExposedOnly makes Sync refuse a source a stranger cannot read (PLAN.md "Sweep scope"): no
	// clone, no fetch, no lock, no directory, and a mirror of it that is already on disk is left
	// exactly as it was. The sweep keeps this rule itself; this is the same rule at the one place
	// every caller, the `sync` command included, has to pass through. An unset visibility counts
	// as not exposed. The publish check is how a private repo is scanned: it asks for its
	// what-if self, a source marked public.
	ExposedOnly bool
}

// Mirror implements core.Mirror.
type Mirror struct {
	cfg   Config
	roots []string // the cache root as configured and as the file system resolves it

	mu    sync.Mutex
	locks map[string]chan struct{}
}

var _ core.Mirror = (*Mirror)(nil)

// Errors Sync wraps, so a caller can tell a vanished repo or a dead login from a flaky network.
var (
	ErrNotFound = errors.New("remote repository not found")
	ErrAuth     = errors.New("GitHub refused the credentials")
	ErrTimeout  = errors.New("git timed out")
	// ErrNotExposed is what Sync answers for a private source when Config.ExposedOnly is set.
	ErrNotExposed = errors.New("source is not readable by strangers, and this mirror serves only what is")
)

// New checks cfg and fills defaults.
func New(cfg Config) (*Mirror, error) {
	if !filepath.IsAbs(cfg.Root) {
		return nil, fmt.Errorf("mirror: root %q is not an absolute path", cfg.Root)
	}
	cfg.Root = filepath.Clean(cfg.Root)
	cfg.Git = cmp.Or(cfg.Git, "git")
	if cfg.GH == "" {
		if p, err := exec.LookPath("gh"); err == nil {
			cfg.GH = p
		} else {
			cfg.GH = "/opt/homebrew/bin/gh" // where Homebrew puts it, and what the bootstrap used
		}
	}
	cfg.CloneTimeout = cmp.Or(cfg.CloneTimeout, 30*time.Minute)
	cfg.FetchTimeout = cmp.Or(cfg.FetchTimeout, 10*time.Minute)
	cfg.StaleLockAge = cmp.Or(cfg.StaleLockAge, 10*time.Minute)
	if cfg.NoFetch {
		if fi, err := os.Stat(cfg.Root); err != nil || !fi.IsDir() {
			return nil, fmt.Errorf("mirror: %s is not a directory, and fetching is off, so nothing will make it", cfg.Root)
		}
	} else if err := os.MkdirAll(cfg.Root, 0o700); err != nil {
		return nil, err
	}
	m := &Mirror{cfg: cfg, locks: map[string]chan struct{}{}, roots: []string{cfg.Root}}
	if real, err := filepath.EvalSymlinks(cfg.Root); err == nil && real != cfg.Root {
		m.roots = append(m.roots, real) // git prints resolved paths; /var is /private/var on macOS
	}
	return m, nil
}

var (
	segRE  = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)
	hostRE = regexp.MustCompile(`^[a-z0-9]+(\.[a-z0-9-]+)+$`)
)

// relPath maps a Source ID onto its mirror directory under the root. IDs are
// "<host>/<owner>/<name>" and arrive from GitHub or a state file, so every segment is held
// to the characters GitHub allows: nothing can climb out of the root.
func relPath(id string) (string, error) {
	parts := strings.Split(id, "/")
	if len(parts) != 3 || !hostRE.MatchString(parts[0]) {
		return "", fmt.Errorf("mirror: %q is not a <host>/<owner>/<name> source id", id)
	}
	for _, p := range parts[1:] {
		if !segRE.MatchString(p) || p == "." || p == ".." {
			return "", fmt.Errorf("mirror: %q has an unsafe path segment", id)
		}
	}
	return id + ".git", nil
}

// Path is where s is mirrored, or "" for an ID that cannot be a mirror path.
func (m *Mirror) Path(s core.Source) string {
	rel, err := relPath(s.ID)
	if err != nil {
		return ""
	}
	return filepath.Join(m.cfg.Root, filepath.FromSlash(rel))
}

// Result is what one Sync did.
type Result struct {
	Before, After map[string]string // ref -> tip, every ref under refs/
	Cloned        bool              // a fresh clone, so Before is empty
	Absent        bool              // a wiki that does not exist upstream: nothing to scan, not a failure
	Elapsed       time.Duration
}

// Moved lists the refs that are new or point somewhere else after the sync, sorted. Refs
// that disappeared are not listed: there is nothing left to scan behind them.
func (r Result) Moved() []string { return Moved(r.Before, r.After) }

// Moved compares two tip maps.
func Moved(before, after map[string]string) []string {
	var out []string
	for ref, tip := range after {
		if before[ref] != tip {
			out = append(out, ref)
		}
	}
	slices.Sort(out)
	return out
}

// Sync brings s's mirror up to date and returns the tips before and after. It implements
// core.Mirror; SyncResult says more. An absent wiki returns two empty maps and no error.
func (m *Mirror) Sync(ctx context.Context, s core.Source) (before, after map[string]string, err error) {
	r, err := m.SyncResult(ctx, s)
	return r.Before, r.After, err
}

// SyncResult clones s into place when it has no mirror yet and fetches into the existing
// one otherwise. Syncs of the same source are serialized; different sources run in parallel.
func (m *Mirror) SyncResult(ctx context.Context, s core.Source) (Result, error) {
	start := time.Now()
	rel, err := relPath(s.ID)
	if err != nil {
		return Result{}, err
	}
	if m.cfg.ExposedOnly && !s.Visibility.Exposed() {
		return Result{}, fmt.Errorf("mirror: %s: %w", s.ID, ErrNotExposed)
	}
	if m.cfg.NoFetch {
		return m.onDisk(ctx, s, rel, start)
	}
	remote, err := m.remote(s)
	if err != nil {
		return Result{}, err
	}
	if s.Account != "" && !loginRE.MatchString(s.Account) {
		return Result{}, fmt.Errorf("mirror: %q is not a GitHub login", s.Account)
	}
	release, err := m.lock(ctx, rel)
	if err != nil {
		return Result{}, err
	}
	defer release()

	dest := filepath.Join(m.cfg.Root, filepath.FromSlash(rel))
	var res Result
	st, statErr := os.Stat(dest)
	switch {
	case statErr == nil && st.IsDir():
		res, err = m.fetch(ctx, s, dest, rel, remote)
	case statErr == nil:
		err = fmt.Errorf("mirror: %s exists and is not a directory", dest)
	case errors.Is(statErr, fs.ErrNotExist):
		res, err = m.clone(ctx, s, dest, remote)
	default:
		err = statErr
	}
	res.Elapsed = time.Since(start)
	return res, err
}

// onDisk is SyncResult under NoFetch: the refs the mirror has, as both Before and After
// because nothing moved. It reads and writes nothing else.
func (m *Mirror) onDisk(ctx context.Context, s core.Source, rel string, start time.Time) (Result, error) {
	dest := filepath.Join(m.cfg.Root, filepath.FromSlash(rel))
	if fi, err := os.Stat(dest); err != nil || !fi.IsDir() {
		return Result{}, fmt.Errorf("mirror: %s has no mirror under %s, and fetching is off", s.ID, m.cfg.Root)
	}
	tips, err := m.refs(ctx, dest)
	if err != nil {
		return Result{}, err
	}
	return Result{Before: tips, After: tips, Elapsed: time.Since(start)}, nil
}

// Tips lists the refs of an existing mirror without touching the network.
func (m *Mirror) Tips(ctx context.Context, s core.Source) (map[string]string, error) {
	p := m.Path(s)
	if p == "" {
		return nil, fmt.Errorf("mirror: %q is not a mirror id", s.ID)
	}
	return m.refs(ctx, p)
}

func (m *Mirror) fetch(ctx context.Context, s core.Source, dest, rel, remote string) (Result, error) {
	before, err := m.refs(ctx, dest)
	if err != nil {
		if !errors.Is(err, errNotARepo) {
			return Result{}, err
		}
		// A directory git does not recognise as a repository (an interrupted copy, a stray
		// mkdir) is moved aside rather than trusted or erased, then cloned afresh.
		if qerr := m.quarantine(dest, rel); qerr != nil {
			return Result{}, qerr
		}
		return m.clone(ctx, s, dest, remote)
	}
	fetchOnce := func() ([]byte, error) {
		_, stderr, err := m.git(ctx, m.cfg.FetchTimeout, s.Account, true, "--git-dir="+dest, "fetch", "--quiet", "--prune", "--prune-tags", "origin")
		return stderr, err
	}
	stderr, err := fetchOnce()
	if err != nil && m.clearStaleLocks(dest, stderr) {
		stderr, err = fetchOnce() // once: a lock that comes back is not a leftover
	}
	if err != nil {
		if s.Kind == "wiki" && notFound(stderr) {
			// The wiki was switched off or deleted upstream; the mirror keeps what it had.
			return Result{Before: before, After: before, Absent: true}, nil
		}
		return Result{}, m.syncErr("fetch", s, err, stderr)
	}
	after, err := m.refs(ctx, dest)
	if err != nil {
		return Result{}, err
	}
	return Result{Before: before, After: after}, nil
}

// lockRE finds the lock file git names when it cannot take one.
var lockRE = regexp.MustCompile(`Unable to create '([^']+\.lock)': File exists`)

// clearStaleLocks removes lock files git reported inside this mirror when they are old
// enough that no running fetch can own them. A fetch we killed on timeout (SIGKILL cannot
// run git's cleanup) leaves such files behind, and without this the mirror would refuse
// every later fetch. It reports whether it removed anything, i.e. whether a retry is worth it.
func (m *Mirror) clearStaleLocks(dest string, stderr []byte) bool {
	inside := []string{dest}
	if real, err := filepath.EvalSymlinks(dest); err == nil && real != dest {
		inside = append(inside, real) // git prints resolved paths; /var is /private/var on macOS
	}
	cleared := false
	for _, match := range lockRE.FindAllSubmatch(stderr, -1) {
		p := string(match[1])
		if !slices.ContainsFunc(inside, func(d string) bool { return strings.HasPrefix(p, d+string(filepath.Separator)) }) {
			continue
		}
		if fi, err := os.Lstat(p); err == nil && fi.Mode().IsRegular() && time.Since(fi.ModTime()) > m.cfg.StaleLockAge {
			cleared = os.Remove(p) == nil || cleared
		}
	}
	return cleared
}

// clone builds the mirror beside its final name and renames it into place only when
// complete, so a killed clone can never be mistaken for a mirror.
func (m *Mirror) clone(ctx context.Context, s core.Source, dest, remote string) (Result, error) {
	part := dest + ".partial"
	if _, err := os.Lstat(part); err == nil {
		if err := m.discard(part); err != nil {
			return Result{}, err
		}
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
		return Result{}, err
	}
	_, stderr, err := m.git(ctx, m.cfg.CloneTimeout, s.Account, true, "clone", "--mirror", "--quiet", "--", remote, part)
	if err != nil {
		derr := m.discard(part)
		if s.Kind == "wiki" && notFound(stderr) {
			// A wiki that is enabled but has no pages yet answers 404; that is not a fault.
			return Result{Before: map[string]string{}, After: map[string]string{}, Absent: true}, derr
		}
		return Result{}, errors.Join(m.syncErr("clone", s, err, stderr), derr)
	}
	// git creates the repository 0755; the directories above it are 0700 already, and this
	// closes the last gap should the cache root ever be reached some other way.
	if err := os.Chmod(part, 0o700); err != nil {
		return Result{}, err
	}
	if err := os.Rename(part, dest); err != nil {
		return Result{}, err
	}
	after, err := m.refs(ctx, dest)
	if err != nil {
		return Result{}, err
	}
	return Result{Before: map[string]string{}, After: after, Cloned: true}, nil
}

// discard removes an incomplete clone. It is a cache directory this package created, so
// there is nothing to preserve; the guard keeps the call from ever reaching further.
func (m *Mirror) discard(part string) error {
	if !strings.HasSuffix(part, ".git.partial") || !strings.HasPrefix(part, m.cfg.Root+string(filepath.Separator)) {
		return fmt.Errorf("mirror: refusing to remove %s", part)
	}
	return os.RemoveAll(part)
}

// quarantine moves an unusable mirror under <root>/.stale instead of deleting it.
func (m *Mirror) quarantine(dest, rel string) error {
	stale := filepath.Join(m.cfg.Root, ".stale")
	if err := os.MkdirAll(stale, 0o700); err != nil {
		return err
	}
	name := strings.ReplaceAll(rel, "/", "__") + "." + strconv.FormatInt(time.Now().UnixNano(), 10)
	return os.Rename(dest, filepath.Join(stale, name))
}

// refs lists every ref under refs/ with its tip. Refnames cannot contain spaces, so one
// space is an unambiguous separator. git is pointed at the directory with --git-dir rather
// than -C: -C would search upward for a repository, and a damaged mirror inside some other
// checkout would silently be read as that checkout.
func (m *Mirror) refs(ctx context.Context, dir string) (map[string]string, error) {
	out, stderr, err := m.git(ctx, time.Minute, "", false, "--git-dir="+dir, "for-each-ref", "--format=%(objectname) %(refname)")
	if err != nil {
		if strings.Contains(string(stderr), "not a git repository") {
			return nil, fmt.Errorf("mirror: %s: %w", dir, errNotARepo)
		}
		return nil, fmt.Errorf("mirror: list refs of %s: %s", dir, lastLine(stderr, err, m.roots...))
	}
	refs := map[string]string{}
	for _, ln := range strings.Split(string(out), "\n") {
		if tip, name, ok := strings.Cut(ln, " "); ok {
			refs[name] = tip
		}
	}
	return refs, nil
}

var errNotARepo = errors.New("not a git repository")

// lock serializes work on one mirror directory. It is a channel, not a mutex, so a caller
// whose context ends stops waiting behind a long clone.
func (m *Mirror) lock(ctx context.Context, rel string) (release func(), err error) {
	m.mu.Lock()
	ch := m.locks[rel]
	if ch == nil {
		ch = make(chan struct{}, 1)
		m.locks[rel] = ch
	}
	m.mu.Unlock()
	select {
	case ch <- struct{}{}:
		return func() { <-ch }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// remote is the URL to clone s from. GitHub URLs are only ever https on github.com or
// gist.github.com: the credential helper answers for whichever host git is talking to, so
// the allow-list is what keeps a token from being offered to a stranger's server.
func (m *Mirror) remote(s core.Source) (string, error) {
	raw := s.CloneURL
	if raw == "" {
		rel, _ := relPath(s.ID)
		host, rest, _ := strings.Cut(strings.TrimSuffix(rel, ".git"), "/")
		if strings.HasPrefix(host, "gist.") {
			rest = rest[strings.LastIndexByte(rest, '/')+1:] // gist URLs carry no owner
		}
		raw = "https://" + host + "/" + rest + ".git"
	}
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("mirror: %s has an unusable clone URL", s.ID)
	}
	switch {
	case u.Scheme == "https" && (u.Host == "github.com" || u.Host == "gist.github.com"):
	case u.Scheme == "file" && m.cfg.AllowLocal:
	default:
		return "", fmt.Errorf("mirror: %s: clone URL scheme or host is not allowed", s.ID)
	}
	return raw, nil
}

var loginRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,38}$`)

func (m *Mirror) syncErr(op string, s core.Source, err error, stderr []byte) error {
	kind := error(nil)
	switch {
	case errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded):
		// The caller gave up; keep that inspectable so the sweep can tell it from a fault.
		return fmt.Errorf("mirror: %s %s: %w", op, s.ID, err)
	case errors.Is(err, ErrTimeout):
		kind = ErrTimeout
	case notFound(stderr):
		kind = ErrNotFound
	case authFailed(stderr):
		kind = ErrAuth
	}
	line := lastLine(stderr, err, m.roots...)
	if kind != nil {
		return fmt.Errorf("mirror: %s %s: %w: %s", op, s.ID, kind, line)
	}
	return fmt.Errorf("mirror: %s %s: %s", op, s.ID, line)
}
