package engines

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// lineReader fetches the text of the line an engine flagged, for engines whose report
// carries no source text (trufflehog, gitleaks). The text only ever feeds fp.Context, which
// replaces the secret before anything is stored.
type lineReader interface {
	// line returns line n (1-based) of the file as it was scanned; "" when it cannot be had.
	line(commit, path string, n int) string
	close()
}

// maxLineFile bounds what is read to find one line: engines scan large files, but a hit's
// context is not worth megabytes.
const maxLineFile = 4 << 20

// fileLines caches the last few files so the many hits of one file cost one read.
type fileLines struct {
	order []string
	byKey map[string]*lineIndex
}

type lineIndex struct {
	data []byte
	offs []int // offs[i] = start of line i+1; built on first use
}

func newFileLines() fileLines { return fileLines{byKey: map[string]*lineIndex{}} }

func (f *fileLines) get(key string, load func() []byte) *lineIndex {
	if li, ok := f.byKey[key]; ok {
		return li
	}
	li := &lineIndex{data: load()}
	if len(f.order) >= 4 {
		delete(f.byKey, f.order[0])
		f.order = f.order[1:]
	}
	f.order = append(f.order, key)
	f.byKey[key] = li
	return li
}

func (li *lineIndex) line(n int) string {
	if li.data == nil || n < 1 {
		return ""
	}
	if li.offs == nil {
		li.offs = []int{0}
		for i, c := range li.data {
			if c == '\n' && i+1 < len(li.data) {
				li.offs = append(li.offs, i+1)
			}
		}
	}
	if n > len(li.offs) {
		return ""
	}
	end := len(li.data)
	if n < len(li.offs) {
		end = li.offs[n] - 1
	}
	return strings.TrimRight(string(li.data[li.offs[n-1]:end]), "\r\n")
}

// gitLines reads blobs through one long-lived `git cat-file --batch`. With no commit it
// reads the index entry, which is what a staged scan looked at.
type gitLines struct {
	ctx    context.Context
	gitDir string
	staged *stagedRepo // staged mode: the repository whose index to read, by absolute paths
	files  fileLines
	cmd    *exec.Cmd
	in     io.WriteCloser
	out    *bufio.Reader
	broken bool
}

func newGitLines(ctx context.Context, gitDir string) *gitLines {
	return &gitLines{ctx: ctx, gitDir: gitDir, files: newFileLines()}
}

func newStagedLines(ctx context.Context, st stagedRepo) *gitLines {
	return &gitLines{ctx: ctx, staged: &st, files: newFileLines()}
}

func (g *gitLines) start() bool {
	if g.cmd != nil {
		return !g.broken
	}
	var cmd *exec.Cmd
	if g.staged != nil {
		cmd = g.staged.git(g.ctx, "cat-file", "--batch")
	} else {
		cmd = gitCmd(g.ctx, g.gitDir, nil, "--git-dir="+g.gitDir, "cat-file", "--batch")
	}
	in, err := cmd.StdinPipe()
	if err != nil {
		g.broken = true
		return false
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		g.broken = true
		return false
	}
	if err := cmd.Start(); err != nil {
		g.broken = true
		return false
	}
	g.cmd, g.in, g.out = cmd, in, bufio.NewReaderSize(out, 64<<10)
	return true
}

func (g *gitLines) line(commit, path string, n int) string {
	if path == "" || strings.ContainsAny(path, "\n\x00") {
		return ""
	}
	spec := commit + ":" + path // "" commit = ":<path>" = the index
	li := g.files.get(spec, func() []byte { return g.blob(spec) })
	return li.line(n)
}

func (g *gitLines) blob(spec string) []byte {
	if !g.start() {
		return nil
	}
	if _, err := io.WriteString(g.in, spec+"\n"); err != nil {
		g.broken = true
		return nil
	}
	hdr, err := g.out.ReadString('\n')
	if err != nil {
		g.broken = true
		return nil
	}
	f := strings.Fields(hdr)
	if len(f) != 3 { // "<spec> missing" or "<spec> ambiguous"
		return nil
	}
	size, err := strconv.Atoi(f[2])
	if err != nil {
		g.broken = true
		return nil
	}
	keep := f[1] == "blob" && size <= maxLineFile
	var data []byte
	if keep {
		data = make([]byte, size)
		_, err = io.ReadFull(g.out, data)
	} else {
		_, err = io.CopyN(io.Discard, g.out, int64(size))
	}
	if err == nil {
		_, err = g.out.ReadByte() // trailing newline
	}
	if err != nil {
		g.broken = true
		return nil
	}
	if !keep {
		return nil
	}
	return data
}

func (g *gitLines) close() {
	if g.cmd == nil {
		return
	}
	g.in.Close()
	g.cmd.Process.Kill()
	g.cmd.Wait()
}

// fsLines reads lines straight from the files an engine scanned in dir mode.
type fsLines struct{ files fileLines }

func newFSLines() *fsLines { return &fsLines{files: newFileLines()} }

func (f *fsLines) line(_, path string, n int) string {
	li := f.files.get(path, func() []byte {
		fh, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer fh.Close()
		data, err := io.ReadAll(io.LimitReader(fh, maxLineFile+1))
		if err != nil || len(data) > maxLineFile || bytes.IndexByte(data, 0) >= 0 {
			return nil // too big or binary: no line to show
		}
		return data
	})
	return li.line(n)
}

func (f *fsLines) close() {}
