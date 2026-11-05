package hooks

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"time"

	"keyguard/internal/core"
	"keyguard/internal/known"
)

// Text git keeps about a change (STEAL P0-13): a token in a commit message, a tag annotation
// or a branch name was found by betterleaks in none of them and by gitleaks in none. The
// commit-msg hook reads the message as it is typed; reference-transaction and pre-push read
// what git is about to record or send, which is how a commit made with --no-verify, a
// rebase or a cherry-pick is caught.

const (
	NameCommitMsg = "commit-msg"

	commitMsgTimeout = 10 * time.Second

	// maxMessage bounds how much of the message file is read. A message is a few lines; this
	// only stops a pathological file from holding a commit.
	maxMessage = 8 << 20
)

// CommitMsg judges the commit message git is about to record. args[0] is the file it is in.
// The learned-secret matcher is the only check: it has no false positives, so a block here is
// always a real key. A message with no learned key in it costs a file read and one scan.
func CommitMsg(ctx context.Context, d Deps, args []string) int {
	h := newHook(ctx, d, NameCommitMsg, commitMsgTimeout)
	defer h.cancel()
	return h.commitMsg(args)
}

// scissorsLine is what `git commit -v` writes above the diff it shows in the editor, after
// the comment character (# unless core.commentChar says otherwise). Everything below it is
// dropped by git's own cleanup, so it is not part of the message, and a diff that removes a
// leaked key must not be refused for showing it. Git follows it with a line that says so;
// without that line it is only words in a message, and the message is read in full.
var (
	scissorsLine = []byte(" ------------------------ >8 ------------------------\n")
	scissorsNote = []byte("Do not modify or remove the line above.")
)

// cutScissors drops the diff the editor showed, if the message has one.
func cutScissors(b []byte) []byte {
	for from := 0; ; {
		i := bytes.Index(b[from:], scissorsLine)
		if i < 0 {
			return b
		}
		i += from
		if start := i - 1; start >= 0 && (start == 0 || b[start-1] == '\n') && !isAlnum(b[start]) {
			next, _, _ := bytes.Cut(b[i+len(scissorsLine):], []byte{'\n'})
			if bytes.Contains(next, scissorsNote) {
				return b[:start]
			}
		}
		from = i + len(scissorsLine)
	}
}

func isAlnum(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func (h *hook) commitMsg(args []string) int {
	path := argAt(args, 0)
	if path == "" {
		return 0
	}
	m := h.matcher()
	if m == nil {
		return 0
	}
	if h.d.Dir != "" && !filepath.IsAbs(path) {
		path = filepath.Join(h.d.Dir, path)
	}
	f, err := os.Open(path)
	if err != nil {
		h.warn("could not read the commit message (%s); it was not checked", errText(err))
		return 0
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxMessage+1))
	if err != nil {
		h.warn("could not read the commit message (%s); it was not checked", errText(err))
		return 0
	}
	if len(b) > maxMessage {
		h.warn("the commit message is larger than %d bytes; only its start was checked", maxMessage)
		b = b[:maxMessage]
	}
	b = cutScissors(b)
	var hits []core.Hit
	known.MatchText(m, "commit message", "", "", b, func(t known.TextHit) { hits = append(hits, h.textHit(t, "staged")) })
	hits = h.finalize(hits, "staged")
	if len(hits) == 0 {
		return 0
	}
	return h.block("commit message blocked", hits)
}

// textHit turns a learned secret found in text git keeps about a change into a Hit. The place
// is described in words, not as a path: a ref name that holds a key must not be printed, or
// written to the journal of blocks, as if it were one.
func (h *hook) textHit(t known.TextHit, kind string) core.Hit {
	km := t.KnownMatch
	return core.Hit{
		Engine: "known", Rule: "known-secret", Type: "known",
		FP: km.FP, Shape: km.Shape, Len: km.Len,
		Verified: core.Unverified,
		Context:  t.Context,
		Known:    km.EntryID + " " + km.Name,
		Loc: core.Location{
			Source: h.source(), Kind: kind, Visibility: core.Local,
			Commit: t.Commit, Path: "(" + t.Field + ")", Line: t.Line,
		},
	}
}

// refNameHits searches the names of the refs an update gives a commit to or sends.
func (h *hook) refNameHits(m core.KnownMatcher, names []string, kind string) []core.Hit {
	var hits []core.Hit
	for _, n := range names {
		known.MatchText(m, "ref name", "", "", []byte(n), func(t known.TextHit) { hits = append(hits, h.textHit(t, kind)) })
	}
	return hits
}

// tagHits searches the annotations of the tag objects among oids (a lightweight tag is a
// commit, and the commit's message is searched with the others).
func (h *hook) tagHits(m core.KnownMatcher, oids []string, kind string) ([]core.Hit, error) {
	if len(oids) == 0 {
		return nil, nil
	}
	objs, err := h.g.blobs(h.ctx, dedupe(oids), maxMessage)
	if err != nil {
		return nil, err
	}
	var hits []core.Hit
	for _, oid := range dedupe(oids) {
		b, ok := objs[oid]
		if !ok || !bytes.HasPrefix(b, []byte("object ")) { // a tag object starts with the object it points at
			continue
		}
		known.MatchText(m, "tag annotation", "", "", b, func(t known.TextHit) { hits = append(hits, h.textHit(t, kind)) })
	}
	return hits, nil
}

// scanMessages runs the commit-message search over a rev range in the background of the
// caller's other work. wait returns what it found; stop abandons it. The range is the one the
// patch scan reads, so a message is judged exactly when its diff is.
func (h *hook) scanMessages(m core.KnownMatcher, maxCount int, revs []string, kind string) (wait func() ([]core.Hit, error), stop func()) {
	st, err := h.g.logMessages(h.ctx, maxCount, revs)
	if err != nil {
		return func() ([]core.Hit, error) { return nil, err }, func() {}
	}
	var (
		hits []core.Hit
		serr error
	)
	done := make(chan struct{})
	go func() {
		defer close(done)
		serr = safely(func() error {
			return known.MatchMessages(m, st.r, func(t known.TextHit) { hits = append(hits, h.textHit(t, kind)) })
		})
		if ferr := st.finish(false); serr == nil {
			serr = ferr
		}
	}()
	return func() ([]core.Hit, error) {
			<-done
			return hits, serr
		}, func() {
			st.cancel()
			<-done
		}
}
