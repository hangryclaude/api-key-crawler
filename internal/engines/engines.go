// Package engines runs the external scanners keyguard relies on (betterleaks, gitleaks,
// trufflehog, titus) and turns each finding into a core.Hit.
//
// Every engine is a child process whose report goes through a pipe straight into a stream
// decoder. The raw secret lives in this process only as long as it takes to fingerprint it
// and compare it with the other hits of its scan: it is never written to disk, never put in
// an error string, and the child gets a private TMPDIR, under the keyguard data root, that is
// removed afterwards so nothing a scanner caches next to its work outlives it.
//
// Behaviour the callers can rely on, and why:
//   - A Range must select something: an empty one is an error, and one that selects no commits
//     starts no process. Since entries are tips already scanned; everything they reach is
//     excluded, whichever ref they were recorded for.
//   - Git scans point the engine at the git dir, never the worktree, run it from an empty
//     directory with git's attribute files switched off, and hand it a config of ours with -c:
//     nothing in a scanned repository (an ignore file, a .betterleaks.toml, a .gitattributes
//     that makes git print "Binary files differ") can silence a scan of it. ScanStaged does
//     the same, with the repository named by absolute GIT_DIR, GIT_WORK_TREE and GIT_INDEX_FILE.
//   - Inline allow comments (gitleaks:allow, betterleaks:allow, trufflehog:ignore) are honored
//     nowhere, the pre-commit scan included: a blocked agent can add the comment itself. The only
//     allowlist is ignore.json, applied by the layers above.
//   - One credential is one fingerprint: the fingerprint is of fp.Canonical of what the engine
//     reported (a PEM block however it is wrapped, the password of a connection URI), and a hit
//     that is part of another hit on the same lines is dropped.
//   - Verified is Live or Dead only from betterleaks validation. Trufflehog cannot tell a key
//     its provider rejected from one it has no verifier for, so it never reports Dead. A check
//     that could not decide is VerifyError with a VerifyReason class and never the verifier's words.
//   - Trufflehog verifies only through the allowlist of detectors that talk to their own provider;
//     every other run is offline. No engine is asked to look anything up on the network.
//   - An engine binary with a pin (WithPins) that does not match it is not run.
//   - Hits already emitted when a scan fails are valid; the error says the scan is incomplete.
package engines

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"keyguard/internal/core"
)

// Names lists the supported engines in the order PLAN.md ranks them.
var Names = []string{"betterleaks", "gitleaks", "trufflehog", "titus"}

// NewAll builds every supported engine, in Names order, from the binary paths in config.json
// ("" or absent = look in $PATH). An engine whose binary is missing is still returned: the
// sweep decides what to do about it from Available.
func NewAll(paths map[string]string, f core.Fingerprinter, opts ...Option) ([]core.Engine, error) {
	var all []core.Engine
	for _, n := range Names {
		e, err := New(n, paths[n], f, opts...)
		if err != nil {
			return nil, err
		}
		all = append(all, e)
	}
	return all, nil
}

// Option adjusts an engine at construction. Options are additive: New and NewAll without any
// behave as they always did.
type Option func(*base)

// New builds the named engine around the binary at binPath. An empty binPath falls back to
// $PATH; a missing binary is not an error here, Available reports it.
func New(name, binPath string, f core.Fingerprinter, opts ...Option) (core.Engine, error) {
	if f == nil {
		return nil, errors.New("engines: nil Fingerprinter")
	}
	b := &base{name: name, bin: binPath, fp: f}
	if b.bin == "" {
		if p, err := exec.LookPath(name); err == nil {
			b.bin = p
		}
	}
	for _, o := range opts {
		o(b)
	}
	switch name {
	case "betterleaks":
		return &leaks{base: b, better: true}, nil
	case "gitleaks":
		return &leaks{base: b}, nil
	case "trufflehog":
		return &truffle{base: b}, nil
	case "titus":
		return &titus{base: b}, nil
	}
	return nil, fmt.Errorf("engines: unknown engine %q", name)
}

// auditScratch lets a test look inside an engine's private TMPDIR before it is removed.
var auditScratch func(dir string)

type base struct {
	name string
	bin  string
	fp   core.Fingerprinter

	pin       *Pin   // nil: the binary is not checked
	hashCache string // WithHashCache

	verOnce sync.Once
	ver     string

	noteMu sync.Mutex
	notes  []string
}

var _ core.NoteTaker = (*base)(nil)

func (b *base) Name() string { return b.name }

func (b *base) Available() bool {
	if b.bin == "" {
		return false
	}
	fi, err := os.Stat(b.bin)
	return err == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&0o111 != 0
}

var versionRE = regexp.MustCompile(`\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?`)

// Version is cached: trufflehog is a 170 MB binary and takes 200 ms just to say its version.
// An engine whose binary fails its pin has no version: it is not started to ask.
func (b *base) Version() string {
	b.verOnce.Do(func() {
		if !b.Available() || b.checkPin() != nil {
			return
		}
		args := []string{"version"}
		if b.name == "trufflehog" {
			// trufflehog replaces its own binary on startup unless told not to (it did, mid-session).
			args = []string{"--no-update", "--version"}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, b.bin, args...)
		cmd.Env = childEnv("", job{})
		out, _ := cmd.CombinedOutput() // versions go to stdout or stderr depending on the engine
		if m := versionRE.Find(out); m != nil {
			b.ver = string(m)
		} else {
			b.ver = "unknown"
		}
	})
	return b.ver
}

// maxNotes bounds what a long-lived engine value keeps between TakeNotes calls.
const maxNotes = 200

func (b *base) note(format string, args ...any) {
	b.noteMu.Lock()
	defer b.noteMu.Unlock()
	if len(b.notes) < maxNotes {
		b.notes = append(b.notes, fmt.Sprintf(format, args...))
	}
}

// TakeNotes returns what the engine dropped, capped or widened since the last call and
// forgets it (core.NoteTaker). The sweep puts the lines in RunStats.Notes: no silent caps.
// Notes name counts and kinds, never values.
func (b *base) TakeNotes() []string {
	b.noteMu.Lock()
	defer b.noteMu.Unlock()
	n := b.notes
	b.notes = nil
	return n
}

// job is one engine invocation.
type job struct {
	args   []string
	dir    string     // working directory; "" = the private scratch dir
	env    []string   // KEY=VALUE additions, which win over everything childEnv sets
	stderr stderrSink // nil = a scrubbed tail of whatever the engine says
}

// run starts the engine, hands its stdout pipe to parse and reports a failure with a
// scrubbed stderr tail. plan gets the private scratch dir because some flags (-i, cwd) point
// into it.
func (b *base) run(ctx context.Context, plan func(scratch string) (job, error), parse func(io.Reader) error) error {
	if !b.Available() {
		return fmt.Errorf("engines: %s: binary not found", b.name)
	}
	if err := b.checkPin(); err != nil {
		return err
	}
	scratch, err := b.newScratch()
	if err != nil {
		return err
	}
	defer func() {
		if auditScratch != nil {
			auditScratch(scratch)
		}
		os.RemoveAll(scratch)
	}()
	j, err := plan(scratch)
	if err != nil {
		return err
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := exec.CommandContext(runCtx, b.bin, j.args...)
	cmd.Dir = j.dir
	if cmd.Dir == "" {
		cmd.Dir = scratch
	}
	cmd.Env = childEnv(scratch, j)
	// Own process group so cancellation also reaches the git children the engines spawn.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 5 * time.Second
	stderr := j.stderr
	if stderr == nil {
		stderr = &tailBuf{}
	}
	cmd.Stderr = stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("engines: %s: %w", b.name, err)
	}
	perr := parse(out)
	if perr != nil {
		cancel()
	}
	io.Copy(io.Discard, out) // let a healthy engine finish instead of dying on SIGPIPE
	werr := cmd.Wait()
	switch {
	case ctx.Err() != nil:
		return ctx.Err()
	case perr != nil:
		return fmt.Errorf("engines: %s: reading report: %s; stderr: %s", b.name, safeText([]byte(perr.Error())), stderr.text())
	case werr != nil:
		return fmt.Errorf("engines: %s: %v; stderr: %s", b.name, werr, stderr.text())
	}
	return nil
}

// Prewarm runs e once over a directory holding one short file, so that whatever the engine
// builds the first time it runs is built now and not by the first hook. Titus compiles its
// Hyperscan database in 2.7 s and reads it back in 30 ms (STEAL P0-07); install and doctor call
// this. A cache the engine keeps goes where the engine's own environment puts it (titus: under
// the keyguard data root).
func Prewarm(ctx context.Context, e core.Engine) error {
	dir, err := os.MkdirTemp("", "keyguard-prewarm-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	if err := os.WriteFile(filepath.Join(dir, "prewarm.txt"), []byte("prewarm\n"), 0o600); err != nil {
		return err
	}
	return e.ScanDir(ctx, dir, core.ScanOpts{Threads: 1}, func(core.Hit) {})
}

// clip keeps the window of a line that fp.Context can show: minified bundles run to
// megabytes, and redacting a 5 MB line once per hit would cost more than the scan.
func clip(line, raw string) string {
	const pad = 80
	if len(line) <= 2*pad+len(raw) {
		return line
	}
	i := strings.Index(line, raw)
	if i < 0 {
		return strings.ToValidUTF8(line[:2*pad], "")
	}
	lo, hi := max(0, i-pad), min(len(line), i+len(raw)+pad)
	return strings.ToValidUTF8(line[lo:hi], "")
}

var dateLayouts = []string{time.RFC3339, "2006-01-02 15:04:05 -0700", "2006-01-02T15:04:05-0700", time.RFC1123Z}

// isoDate normalizes the engines' commit dates to RFC 3339 UTC so locations from different
// engines compare equal.
func isoDate(s string) string {
	for _, l := range dateLayouts {
		if t, err := time.Parse(l, s); err == nil {
			return t.UTC().Format(time.RFC3339)
		}
	}
	return s
}

// authorName turns trufflehog's "Name <mail>" into the name alone, as the other engines give it.
func authorName(s string) string {
	if i := strings.LastIndex(s, " <"); i > 0 && strings.HasSuffix(s, ">") {
		return s[:i]
	}
	return s
}

// blobURL is the permalink to the line on GitHub, for locations that are in a github.com repo.
func blobURL(l core.Location) string {
	if l.Commit == "" || l.Path == "" || l.Kind != "repo" || !strings.HasPrefix(l.Source, "github.com/") {
		return ""
	}
	segs := strings.Split(l.Path, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	u := "https://" + l.Source + "/blob/" + l.Commit + "/" + strings.Join(segs, "/")
	if l.Line > 0 {
		u += "#L" + strconv.Itoa(l.Line)
	}
	return u
}

// streamArray decodes a top-level JSON array one element at a time, so a report with tens of
// thousands of findings never sits in memory whole.
func streamArray[T any](r io.Reader, each func(*T) error) error {
	dec := json.NewDecoder(bufio.NewReaderSize(r, 1<<20))
	tok, err := dec.Token()
	if err == io.EOF {
		return nil // the engine printed nothing at all
	}
	if err != nil {
		return err
	}
	if tok == nil {
		return nil // a bare null
	}
	if d, ok := tok.(json.Delim); !ok || d != '[' {
		return errors.New("report is not a JSON array")
	}
	for dec.More() {
		var v T
		if err := dec.Decode(&v); err != nil {
			return err
		}
		if err := each(&v); err != nil {
			return err
		}
	}
	_, err = dec.Token()
	return err
}

// streamValues decodes concatenated JSON values (trufflehog prints one object per finding).
func streamValues[T any](r io.Reader, each func(*T) error) error {
	dec := json.NewDecoder(bufio.NewReaderSize(r, 1<<20))
	for {
		var v T
		if err := dec.Decode(&v); err == io.EOF {
			return nil
		} else if err != nil {
			return err
		}
		if err := each(&v); err != nil {
			return err
		}
	}
}
