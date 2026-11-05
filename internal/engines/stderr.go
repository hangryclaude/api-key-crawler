package engines

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"sync"

	"keyguard/internal/fp"
)

// stderrSink receives an engine's stderr and answers with what may go into an error string.
type stderrSink interface {
	io.Writer
	text() string
}

// tailBuf keeps the last few KiB of a stream; engine failures are explained at the end.
type tailBuf struct{ b []byte }

const tailMax = 8 << 10

func (t *tailBuf) Write(p []byte) (int, error) {
	t.b = append(t.b, p...)
	if len(t.b) > 2*tailMax {
		t.b = append(t.b[:0], t.b[len(t.b)-tailMax:]...)
	}
	return len(p), nil
}

func (t *tailBuf) text() string { return safeText(t.b) }

// safeText makes engine chatter fit for an error string: one line, any token that looks like
// key material masked, short. Engines log paths and rule names, not findings, but an error
// path is exactly where a surprise would leak, so it is scrubbed regardless.
func safeText(b []byte) string {
	s := strings.Join(strings.Fields(strings.ToValidUTF8(string(b), "?")), " ")
	s = fp.Scrub(s)
	if r := []rune(s); len(r) > 300 {
		s = "…" + string(r[len(r)-299:])
	}
	return s
}

// thLog is trufflehog's stderr. At the log level that prints the line we need (a scan summary:
// the only way to learn that it read nothing) trufflehog also logs other things, and with some
// flags the whole result, secret included (STEAL P0-04). So the log is not kept: each line is
// read as it arrives, the three we act on are used, and everything else is dropped on the spot
// and never reaches an error string, a buffer or a log of ours.
type thLog struct {
	mu      sync.Mutex
	partial []byte
	skip    bool // inside a line longer than maxLogLine: dropped to its end
	kept    tailBuf

	finished      bool
	chunks, bytes int64
}

const maxLogLine = 1 << 20

// thLine is every field of a log line we read. Notably not the detector's output.
type thLine struct {
	Msg    string `json:"msg"`
	Error  string `json:"error"`
	Chunks int64  `json:"chunks"`
	Bytes  int64  `json:"bytes"`
}

func (l *thLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := len(p)
	for len(p) > 0 {
		i := bytes.IndexByte(p, '\n')
		if i < 0 {
			if !l.skip {
				l.partial = append(l.partial, p...)
				if len(l.partial) > maxLogLine {
					l.partial, l.skip = nil, true
				}
			}
			break
		}
		if !l.skip {
			l.partial = append(l.partial, p[:i]...)
			if len(l.partial) <= maxLogLine {
				l.line(l.partial)
			}
		}
		l.partial, l.skip = l.partial[:0], false
		p = p[i+1:]
	}
	return n, nil
}

func (l *thLog) line(b []byte) {
	b = bytes.TrimSpace(b)
	switch {
	case len(b) == 0:
	case b[0] == '{':
		var r thLine
		if json.Unmarshal(b, &r) != nil {
			return
		}
		switch r.Msg {
		case "finished scanning":
			l.finished, l.chunks, l.bytes = true, r.Chunks, r.Bytes
		case "error running scan", "encountered errors during scan":
			l.kept.Write([]byte(r.Msg + ": " + r.Error + "\n"))
		}
	case bytes.HasPrefix(b, []byte("trufflehog: error")), bytes.HasPrefix(b, []byte("panic:")), bytes.HasPrefix(b, []byte("fatal error:")):
		// kingpin's usage errors ("unknown long flag") and a crash: plain text, and the only
		// explanation there will be.
		l.kept.Write(append(b, '\n'))
	}
}

func (l *thLog) text() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.kept.text()
}

// summary is the "finished scanning" line: whether it came, and how much was read.
func (l *thLog) summary() (seen bool, chunks, bytes int64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.finished, l.chunks, l.bytes
}
