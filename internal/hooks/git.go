package hooks

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"keyguard/internal/known"
)

// git runs the real git binary. Hooks never mock it: what git hands a hook (cwd, env,
// GIT_INDEX_FILE for `commit -a`) is exactly what these calls must inherit.
type git struct {
	bin string
	dir string // "" = the hook's own working directory, which is where git runs hooks
	env []string
}

func newGit(dir string) *git {
	bin, err := exec.LookPath("git")
	if err != nil {
		bin = "git" // the exec error below names the real problem
	}
	return &git{bin: bin, dir: dir, env: append(os.Environ(),
		// A hook must not take index.lock away from the commit that is running it.
		"GIT_OPTIONAL_LOCKS=0",
		// A blobless clone would otherwise fetch from the network inside a hook, which
		// can hang and can re-enter this very hook.
		"GIT_NO_LAZY_FETCH=1",
		"GIT_TERMINAL_PROMPT=0",
	)}
}

func (g *git) command(ctx context.Context, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, g.bin, args...)
	cmd.Dir = g.dir
	cmd.Env = g.env
	return cmd
}

// errBuf keeps the head of git's stderr for error messages without letting a noisy git
// grow it unbounded.
type errBuf struct{ b []byte }

func (e *errBuf) Write(p []byte) (int, error) {
	if room := 512 - len(e.b); room > 0 {
		e.b = append(e.b, p[:min(room, len(p))]...)
	}
	return len(p), nil
}

func (e *errBuf) String() string { return strings.TrimSpace(string(e.b)) }

func gitErr(args []string, err error, stderr *errBuf) error {
	if s := stderr.String(); s != "" {
		return fmt.Errorf("git %s: %w: %s", args[0], err, s)
	}
	return fmt.Errorf("git %s: %w", args[0], err)
}

// out runs git to completion and returns stdout.
func (g *git) out(ctx context.Context, args ...string) ([]byte, error) {
	cmd := g.command(ctx, args...)
	var stderr errBuf
	cmd.Stderr = &stderr
	b, err := cmd.Output()
	if err != nil {
		return nil, gitErr(args, err, &stderr)
	}
	return b, nil
}

// stream is a running git whose stdout is consumed incrementally: `git log -p` over a
// big range is far larger than anything worth holding in memory.
type stream struct {
	cmd    *exec.Cmd
	r      io.ReadCloser
	stderr *errBuf
	args   []string
	cancel context.CancelFunc
}

func (g *git) stream(ctx context.Context, args ...string) (*stream, error) {
	ctx, cancel := context.WithCancel(ctx)
	cmd := g.command(ctx, args...)
	st := &stream{cmd: cmd, stderr: &errBuf{}, args: args, cancel: cancel}
	cmd.Stderr = st.stderr
	r, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return nil, err
	}
	st.r = r
	if err := cmd.Start(); err != nil {
		cancel()
		return nil, gitErr(args, err, st.stderr)
	}
	return st, nil
}

// finish waits for git. killed says the caller stopped reading on purpose, so the signal
// that ends git is not an error.
func (s *stream) finish(killed bool) error {
	if killed {
		s.cancel()
	}
	_, _ = io.Copy(io.Discard, s.r) // let git exit instead of blocking on a full pipe
	err := s.cmd.Wait()
	s.cancel()
	if err != nil && !killed {
		return gitErr(s.args, err, s.stderr)
	}
	return nil
}

// Common diff flags: every one pins a behaviour a user's git config could change under us.
//
// --text matters as much as --no-textconv: a .gitattributes line such as `*.env -diff` makes
// git print "Binary files differ" for the file, and a scanner that reads the diff sees
// nothing, so a repo file the committer controls would blind the check (STEAL P0-05). It also
// shows the bytes of a binary file, which the learned-secret matcher can search.
var diffFlags = []string{
	"-U0", "-M", "--no-color", "--no-ext-diff", "--no-textconv", "--text", "--ignore-submodules=all",
	"--src-prefix=a/", "--dst-prefix=b/", "--diff-filter=ACMR",
}

// commitMarker starts the one line `git log` prints per commit; diff content lines always
// begin with '+', '-' or ' ', so a control byte can never be mistaken for file content.
const commitMarker = "%x01KG %H"

func (g *git) isBare(ctx context.Context) (bool, error) {
	b, err := g.out(ctx, "rev-parse", "--is-bare-repository")
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(string(b)) == "true", nil
}

type stagedFile struct {
	path string
	mode string
	blob string
}

// staged lists what the commit will add or change. --no-renames so a rename shows up as a
// new path (its name is judged afresh); content is diffed separately with renames on.
func (g *git) staged(ctx context.Context) ([]stagedFile, error) {
	b, err := g.out(ctx, "diff", "--cached", "--raw", "-z", "--no-abbrev", "--no-renames",
		"--no-ext-diff", "--ignore-submodules=all", "--diff-filter=ACMR")
	if err != nil {
		return nil, err
	}
	var files []stagedFile
	toks := strings.Split(string(b), "\x00")
	for i := 0; i+1 < len(toks); i += 2 {
		meta := strings.Fields(strings.TrimPrefix(toks[i], ":"))
		if len(meta) < 5 {
			return nil, fmt.Errorf("unexpected diff --raw entry")
		}
		files = append(files, stagedFile{path: toks[i+1], mode: meta[1], blob: meta[3]})
	}
	return files, nil
}

// blobs returns the first limit bytes of each blob. A missing blob is simply absent.
func (g *git) blobs(ctx context.Context, shas []string, limit int64) (map[string][]byte, error) {
	if len(shas) == 0 {
		return nil, nil
	}
	cmd := g.command(ctx, "cat-file", "--batch")
	cmd.Stdin = strings.NewReader(strings.Join(shas, "\n") + "\n")
	var stderr errBuf
	cmd.Stderr = &stderr
	r, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, gitErr([]string{"cat-file"}, err, &stderr)
	}
	br := bufio.NewReader(r)
	res := make(map[string][]byte, len(shas))
	var perr error
	for range shas {
		hdr, err := br.ReadString('\n')
		if err != nil {
			perr = err
			break
		}
		f := strings.Fields(hdr)
		if len(f) == 3 {
			size, err := strconv.ParseInt(f[2], 10, 64)
			if err != nil {
				perr = err
				break
			}
			keep := min(size, limit)
			buf := make([]byte, keep)
			if _, err := io.ReadFull(br, buf); err != nil {
				perr = err
				break
			}
			if _, err := io.CopyN(io.Discard, br, size-keep+1); err != nil { // +1: trailing newline
				perr = err
				break
			}
			res[f[0]] = buf
		}
	}
	_, _ = io.Copy(io.Discard, br)
	werr := cmd.Wait()
	if perr != nil {
		return nil, gitErr([]string{"cat-file"}, perr, &stderr)
	}
	if werr != nil {
		return nil, gitErr([]string{"cat-file"}, werr, &stderr)
	}
	return res, nil
}

// have filters shas down to those that exist here as a commit (or a tag of one).
func (g *git) have(ctx context.Context, shas []string) ([]string, error) {
	if len(shas) == 0 {
		return nil, nil
	}
	var in strings.Builder
	for _, s := range shas {
		in.WriteString(s + "^{commit}\n")
	}
	cmd := g.command(ctx, "cat-file", "--batch-check")
	cmd.Stdin = strings.NewReader(in.String())
	var stderr errBuf
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, gitErr([]string{"cat-file"}, err, &stderr)
	}
	lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	if len(lines) != len(shas) {
		return nil, errors.New("git cat-file --batch-check: short answer")
	}
	var have []string
	for i, l := range lines {
		if !strings.HasSuffix(l, " missing") && !strings.HasSuffix(l, " ambiguous") {
			have = append(have, shas[i])
		}
	}
	return have, nil
}

// anyCommit reports whether the rev arguments select at least one commit.
func (g *git) anyCommit(ctx context.Context, revs []string) (bool, error) {
	args := append([]string{"rev-list", "--max-count=1"}, revs...)
	b, err := g.out(ctx, append(args, "--")...)
	if err != nil {
		return false, err
	}
	return len(bytes.TrimSpace(b)) > 0, nil
}

// logPatch streams the added lines of every commit the revs select, newest first.
func (g *git) logPatch(ctx context.Context, maxCount int, revs []string) (*stream, error) {
	args := []string{"log", "-p", "--cc", "--no-show-signature", "--format=" + commitMarker}
	args = append(args, diffFlags...)
	if maxCount > 0 {
		args = append(args, "--max-count="+strconv.Itoa(maxCount))
	}
	args = append(args, revs...)
	return g.stream(ctx, append(args, "--")...)
}

// logMessages streams one NUL-terminated record per commit the revs select: the author's name
// and email and the message, in the form known.MatchMessages reads.
func (g *git) logMessages(ctx context.Context, maxCount int, revs []string) (*stream, error) {
	args := []string{"log", "-z", "--no-show-signature", "--format=" + known.MessageFormat}
	if maxCount > 0 {
		args = append(args, "--max-count="+strconv.Itoa(maxCount))
	}
	args = append(args, revs...)
	return g.stream(ctx, append(args, "--")...)
}

// cachedPatch streams the staged diff against HEAD, or against another commit when given.
func (g *git) cachedPatch(ctx context.Context, against ...string) (*stream, error) {
	args := append(append([]string{"diff", "--cached"}, diffFlags...), against...)
	return g.stream(ctx, args...)
}

// merging reports whether a merge is waiting to be committed. A failed check counts as
// "no": the caller then keeps every finding, the cautious direction.
func (g *git) merging(ctx context.Context) bool {
	_, err := g.out(ctx, "rev-parse", "-q", "--verify", "MERGE_HEAD")
	return err == nil
}
