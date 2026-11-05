package sweep

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"sync"

	"keyguard/internal/core"
	"keyguard/internal/fp"
)

const (
	defaultMaxBlob     = 50 << 20 // PLAN.md: blobs up to 50 MiB, binary included; the rest are counted
	maxMatchesPerBlob  = 100      // a generated file can repeat one key a million times; a hundred sightings say it
	maxSkippedExamples = 5
	ctxSide            = 200 // bytes of line kept on each side of a match for its context
	batchFormat        = "%(objectname) %(objecttype) %(objectsize) %(rest)"
)

// GitKnown is the default BlobScanner. It streams every blob a range reaches out of git
// (rev-list --objects into cat-file --batch), so it sees binary files and blobs no diff
// shows, and runs the known matcher over each. Only when something matches does it ask git
// where the blob entered history (git log --raw), so the common case, no match anywhere,
// costs one pass over the objects.
//
// A match is reported at each commit that added the blob at a path, and only for secrets the
// blob it replaced did not already hold: an unrelated edit to a file that carries a key is
// not a new sighting. Blobs git cannot place (a merge's resolution, a blob a tag points at
// directly) are still reported, with the path git lists and no commit.
type GitKnown struct {
	Git     string // git binary; "git" when empty
	MaxBlob int64  // blobs larger than this are not read and are counted; 0 means 50 MiB
}

var _ BlobScanner = GitKnown{}

func (g GitKnown) git() string { return cmp.Or(g.Git, "git") }

func (g GitKnown) maxBlob() int64 {
	if g.MaxBlob > 0 {
		return g.MaxBlob
	}
	return defaultMaxBlob
}

// blobFound is a blob the matcher matched in, reduced to display-safe facts. No match keeps
// the bytes it matched: the context is built with each learned value already masked.
type blobFound struct {
	path    string // the path rev-list lists the blob under
	matches []found
}

type found struct {
	km      core.KnownMatch
	line    int
	ctx     string
	entropy float64
}

// ScanBlobs implements BlobScanner.
func (g GitKnown) ScanBlobs(ctx context.Context, repo string, r core.Range, m core.KnownMatcher, loc core.Location, emit core.Emit) (BlobStats, error) {
	return g.ScanBlobsSeen(ctx, repo, r, m, loc, nil, emit)
}

// ScanBlobsSeen is ScanBlobs for a caller with a blob ledger (LedgerBlobScanner). A blob the
// ledger already has is not read, and every blob that is read is handed to Note. The price is
// that a blob scanned before is not reported again where it reappears (the same file copied
// to a second path, a revert): the key is in the findings already, from the place it was
// first read, and rotating it ends every copy at once.
func (g GitKnown) ScanBlobsSeen(ctx context.Context, repo string, r core.Range, m core.KnownMatcher, loc core.Location, seen BlobSeen, emit core.Emit) (BlobStats, error) {
	args, err := revArgs(r)
	if err != nil {
		return BlobStats{}, err
	}
	hits, st, err := g.stream(ctx, repo, args, m, seen)
	if err == nil && len(hits) > 0 {
		err = g.attribute(ctx, repo, args, m, loc, hits, emit)
	}
	// The messages and refs are read whether or not a blob matched: a key in a commit message
	// is in no blob at all.
	if terr := g.scanText(ctx, repo, args, m, loc, emit); terr != nil {
		err = errors.Join(err, terr)
	}
	return st, err
}

type batchHeader struct {
	sha, typ, rest string
	size           int64
}

func parseHeader(line string) (batchHeader, bool) {
	line = strings.TrimRight(line, "\n")
	sha, rest, ok := strings.Cut(line, " ")
	if !ok {
		return batchHeader{}, false
	}
	typ, rest, ok := strings.Cut(rest, " ")
	if !ok {
		return batchHeader{}, false
	}
	sizeStr, path, _ := strings.Cut(rest, " ")
	size, err := strconv.ParseInt(sizeStr, 10, 64)
	if err != nil || size < 0 {
		return batchHeader{}, false
	}
	return batchHeader{sha: sha, typ: typ, rest: path, size: size}, true
}

// readBatch decodes `git cat-file --batch=<batchFormat>` output. A blob over limit is read
// past and handed to fn with nil data, so the stream stays in step. data is reused between
// calls; fn must not keep it.
func readBatch(r io.Reader, limit int64, fn func(h batchHeader, data []byte) error) error {
	br := bufio.NewReaderSize(r, 1<<20)
	var buf []byte
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			if errors.Is(err, io.EOF) && line == "" {
				return nil
			}
			return err
		}
		if strings.HasSuffix(line, " missing\n") {
			continue
		}
		h, ok := parseHeader(line)
		if !ok {
			return errors.New("sweep: unexpected git cat-file output")
		}
		if h.size > limit {
			if _, err := io.CopyN(io.Discard, br, h.size+1); err != nil {
				return err
			}
			if err := fn(h, nil); err != nil {
				return err
			}
			continue
		}
		if int64(cap(buf)) < h.size {
			buf = make([]byte, h.size)
		}
		data := buf[:h.size]
		if _, err := io.ReadFull(br, data); err != nil {
			return err
		}
		if _, err := br.ReadByte(); err != nil { // the LF git puts after the content
			return err
		}
		if err := fn(h, data); err != nil {
			return err
		}
	}
}

// stream runs the pipeline rev-list | cat-file --batch-check | (filter) | cat-file --batch
// and matches every blob it delivers. The filter drops everything that is not a blob and
// everything over the size limit before git has to produce its content.
func (g GitKnown) stream(ctx context.Context, repo string, args []string, m core.KnownMatcher, seen BlobSeen) (map[string]*blobFound, BlobStats, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	limit := g.maxBlob()
	st := BlobStats{Limit: limit}

	list := gitCmd(ctx, g.git(), repo, slices.Concat([]string{"rev-list", "--objects"}, args, []string{"--"})...)
	check := gitCmd(ctx, g.git(), repo, "cat-file", "--batch-check="+batchFormat)
	fetch := gitCmd(ctx, g.git(), repo, "cat-file", "--batch="+batchFormat)
	var listErr, checkErr, fetchErr tailBuffer
	list.Stderr, check.Stderr, fetch.Stderr = &listErr, &checkErr, &fetchErr

	pr, pw, err := os.Pipe()
	if err != nil {
		return nil, st, err
	}
	defer pr.Close()
	defer pw.Close()
	list.Stdout, check.Stdin = pw, pr
	checkOut, err := check.StdoutPipe()
	if err != nil {
		return nil, st, err
	}
	fetchIn, err := fetch.StdinPipe()
	if err != nil {
		return nil, st, err
	}
	fetchOut, err := fetch.StdoutPipe()
	if err != nil {
		return nil, st, err
	}

	var started []*exec.Cmd
	var filter sync.WaitGroup
	defer func() { // on every path, stop the children and reap them before returning
		cancel()
		filter.Wait()
		for _, c := range started {
			c.Wait() // the explicit waits below already collected their errors; this reaps early exits
		}
	}()
	for _, c := range []*exec.Cmd{list, check, fetch} {
		if err := c.Start(); err != nil {
			return nil, st, fmt.Errorf("sweep: start git %s: %w", c.Args[len(c.Args)-1], err)
		}
		started = append(started, c)
		switch c {
		case list:
			pw.Close() // the child owns the write end now; keeping ours would hold the pipe open forever
		case check:
			pr.Close()
		}
	}

	var (
		filterErr error
		skipped   BlobStats
		known     int // blobs the ledger already has
	)
	filter.Add(1)
	go func() {
		defer filter.Done()
		defer fetchIn.Close()
		br := bufio.NewReaderSize(checkOut, 256<<10)
		for {
			line, rerr := br.ReadString('\n')
			if h, ok := parseHeader(line); ok && h.typ == "blob" && h.size > 0 {
				switch {
				case h.size > limit:
					skipped.Skipped++
					skipped.SkippedBytes += h.size
					if len(skipped.SkippedPaths) < maxSkippedExamples {
						skipped.SkippedPaths = append(skipped.SkippedPaths, h.rest)
					}
				case seen != nil && seen.Seen(h.sha):
					known++
				default:
					if _, werr := io.WriteString(fetchIn, h.sha+" "+h.rest+"\n"); werr != nil {
						filterErr = werr
						return
					}
				}
			}
			if rerr != nil {
				if !errors.Is(rerr, io.EOF) {
					filterErr = rerr
				}
				return
			}
		}
	}()

	hits := map[string]*blobFound{}
	readErr := readBatch(fetchOut, limit, func(h batchHeader, data []byte) error {
		st.Blobs++
		st.Bytes += h.size
		if seen != nil {
			seen.Note(h.sha)
		}
		ms := m.Match(data)
		if len(ms) == 0 {
			return nil
		}
		bf := &blobFound{path: h.rest}
		if len(ms) > maxMatchesPerBlob {
			st.Truncated++
		}
		bf.matches = describeMatches(data, ms, m)
		hits[h.sha] = bf
		return nil
	})
	if readErr != nil {
		cancel() // stop the filter so it is not left writing into a pipe nobody reads
	}
	filter.Wait()
	st.Skipped, st.SkippedBytes, st.SkippedPaths = skipped.Skipped, skipped.SkippedBytes, skipped.SkippedPaths
	st.Seen = known

	// The first failing process explains the others: a bad rev fails rev-list and starves the rest.
	for _, p := range []struct {
		c    *exec.Cmd
		name string
		err  *tailBuffer
	}{{list, "rev-list", &listErr}, {check, "cat-file --batch-check", &checkErr}, {fetch, "cat-file --batch", &fetchErr}} {
		if err := p.c.Wait(); err != nil && ctx.Err() == nil {
			return nil, st, fmt.Errorf("sweep: git %s in %s: %w%s", p.name, repo, err, p.err.suffix())
		}
	}
	switch {
	case ctx.Err() != nil:
		return nil, st, ctx.Err()
	case readErr != nil:
		return nil, st, fmt.Errorf("sweep: reading blobs of %s: %w", repo, readErr)
	case filterErr != nil:
		return nil, st, fmt.Errorf("sweep: filtering blobs of %s: %w", repo, filterErr)
	}
	return hits, st, nil
}

// describeMatches turns the matcher's findings in one blob into display-safe facts: line
// number, a context with every learned value masked, the entropy of what matched.
func describeMatches(data []byte, ms []core.KnownMatch, m core.KnownMatcher) []found {
	ms = slices.Clone(ms)
	slices.SortStableFunc(ms, func(a, b core.KnownMatch) int { return cmp.Compare(a.Offset, b.Offset) })
	if len(ms) > maxMatchesPerBlob {
		ms = ms[:maxMatchesPerBlob]
	}
	out := make([]found, 0, len(ms))
	line, at := 1, 0
	for _, km := range ms {
		if km.Offset < 0 || km.Len <= 0 || km.Offset+km.Len > len(data) {
			continue
		}
		if km.Offset > at { // matches are in offset order, so count each stretch of lines once
			line += bytes.Count(data[at:km.Offset], []byte{'\n'})
			at = km.Offset
		}
		out = append(out, found{
			km: km, line: line,
			ctx:     fp.Context(maskedLine(data, km.Offset, km.Len, m), ""),
			entropy: fp.Entropy(string(data[km.Offset : km.Offset+km.Len])),
		})
	}
	return out
}

func tokenChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '+' || c == '/' || c == '=' || c == '_' || c == '-' || c == '.'
}

// maskedLine is the line around a match with every learned value in it replaced by its
// shape. Matching the window again, instead of replacing the one match, also masks a second
// copy of the key on the same long line. A window cut by the size limit starts and ends at a
// token boundary so no half-key survives at its edges.
func maskedLine(data []byte, off, n int, m core.KnownMatcher) string {
	lo, hi := max(0, off-ctxSide), min(len(data), off+n+ctxSide)
	if i := bytes.LastIndexByte(data[lo:off], '\n'); i >= 0 {
		lo += i + 1
	} else if lo > 0 {
		for lo < off && tokenChar(data[lo]) {
			lo++
		}
	}
	if i := bytes.IndexByte(data[off+n:hi], '\n'); i >= 0 {
		hi = off + n + i
	} else if hi < len(data) {
		for hi > off+n && tokenChar(data[hi-1]) {
			hi--
		}
	}
	win := data[lo:hi]
	wm := slices.Clone(m.Match(win))
	slices.SortStableFunc(wm, func(a, b core.KnownMatch) int { return cmp.Compare(a.Offset, b.Offset) })
	var b strings.Builder
	pos := 0
	for _, km := range wm {
		if km.Offset < pos || km.Len <= 0 || km.Offset+km.Len > len(win) {
			continue // an overlapping variant of a value already masked
		}
		b.WriteString(strings.ToValidUTF8(string(win[pos:km.Offset]), ""))
		b.WriteString("«" + km.Shape + "»")
		pos = km.Offset + km.Len
	}
	b.WriteString(strings.ToValidUTF8(string(win[pos:]), ""))
	return b.String()
}

// origin is one place a blob entered history: the commit, the path, and the blob it replaced.
type origin struct {
	commit, path, old, author, date string
}

func isZero(sha string) bool { return strings.Trim(sha, "0") == "" }

// origins asks git which commits added each blob in found, from `git log --raw -z`. Merge
// commits show no diff there, which is right: what a merge brings in was added by the
// commits it merges.
func (g GitKnown) origins(ctx context.Context, repo string, args []string, hits map[string]*blobFound) (map[string][]origin, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := gitCmd(ctx, g.git(), repo, slices.Concat(
		[]string{"log", "-z", "--raw", "-r", "--no-abbrev", "--no-renames", "--no-color", "--no-ext-diff", "--format=%x01%H%x1f%an%x1f%aI"},
		args, []string{"--"})...)
	var stderr tailBuffer
	cmd.Stderr = &stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	res := map[string][]origin{}
	br := bufio.NewReaderSize(out, 1<<20)
	var cur origin
	readTok := func() (string, bool, error) {
		tok, err := br.ReadString(0)
		if err != nil && !errors.Is(err, io.EOF) {
			return "", false, err
		}
		return strings.TrimSuffix(tok, "\x00"), errors.Is(err, io.EOF), nil
	}
	var parseErr error
	for {
		tok, eof, err := readTok()
		if err != nil {
			parseErr = err
			break
		}
		t := strings.TrimPrefix(tok, "\n") // the first entry of a commit follows a newline
		switch {
		case strings.HasPrefix(t, "\x01"):
			f := strings.SplitN(t[1:], "\x1f", 3)
			cur = origin{commit: f[0]}
			if len(f) == 3 {
				cur.author, cur.date = f[1], f[2]
			}
		case strings.HasPrefix(t, ":"):
			path, _, perr := readTok()
			if perr != nil {
				parseErr = perr
			}
			// ":<mode> <mode> <old> <new> <status>"
			if f := strings.Fields(t); len(f) >= 5 && !isZero(f[3]) && hits[f[3]] != nil {
				o := cur
				o.path = path
				if !isZero(f[2]) {
					o.old = f[2]
				}
				res[f[3]] = append(res[f[3]], o)
			}
		}
		if eof || parseErr != nil {
			break
		}
	}
	if parseErr != nil {
		cancel()
	}
	if err := cmd.Wait(); err != nil && ctx.Err() == nil {
		return nil, fmt.Errorf("sweep: git log in %s: %w%s", repo, err, stderr.suffix())
	}
	return res, parseErr
}

// oldSets reads the blobs that matched blobs replaced and returns the fingerprints each
// holds. A blob too large to read, or one git cannot find, has no entry, and the caller
// treats everything in the newer blob as added.
func (g GitKnown) oldSets(ctx context.Context, repo string, shas []string, m core.KnownMatcher) (map[string]map[string]bool, error) {
	if len(shas) == 0 {
		return nil, nil
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := gitCmd(ctx, g.git(), repo, "cat-file", "--batch="+batchFormat)
	cmd.Stdin = strings.NewReader(strings.Join(shas, "\n") + "\n")
	var stderr tailBuffer
	cmd.Stderr = &stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	sets := map[string]map[string]bool{}
	rerr := readBatch(out, g.maxBlob(), func(h batchHeader, data []byte) error {
		if data == nil && h.size > 0 || h.typ != "blob" {
			return nil
		}
		set := map[string]bool{}
		for _, km := range m.Match(data) {
			set[km.FP] = true
		}
		sets[h.sha] = set
		return nil
	})
	if rerr != nil {
		cancel()
	}
	if err := cmd.Wait(); err != nil && ctx.Err() == nil {
		return nil, fmt.Errorf("sweep: git cat-file in %s: %w%s", repo, err, stderr.suffix())
	}
	return sets, rerr
}

// attribute places each matched blob in history and emits its hits.
func (g GitKnown) attribute(ctx context.Context, repo string, args []string, m core.KnownMatcher, loc core.Location, hits map[string]*blobFound, emit core.Emit) error {
	origins, err := g.origins(ctx, repo, args, hits)
	if err != nil {
		return err
	}
	need := map[string]bool{}
	for _, list := range origins {
		for _, o := range list {
			if o.old != "" && hits[o.old] == nil {
				need[o.old] = true
			}
		}
	}
	old, err := g.oldSets(ctx, repo, slices.Sorted(maps.Keys(need)), m)
	if err != nil {
		return err
	}
	had := func(sha string) map[string]bool {
		if bf := hits[sha]; bf != nil {
			set := make(map[string]bool, len(bf.matches))
			for _, f := range bf.matches {
				set[f.km.FP] = true
			}
			return set
		}
		return old[sha]
	}
	for _, sha := range slices.Sorted(maps.Keys(hits)) {
		bf := hits[sha]
		if len(origins[sha]) == 0 {
			for _, f := range bf.matches {
				emit(knownHit(f, loc, origin{path: bf.path}))
			}
			continue
		}
		for _, o := range origins[sha] {
			before := had(o.old)
			for _, f := range bf.matches {
				if !before[f.km.FP] {
					emit(knownHit(f, loc, o))
				}
			}
		}
	}
	return nil
}

// knownHit is the Hit for one learned-secret match. Its length is the raw value's only when
// the raw form matched; an encoded variant is longer than the value it encodes.
func knownHit(f found, loc core.Location, o origin) core.Hit {
	l := loc
	l.Commit, l.Path, l.Line, l.Author, l.Date = o.commit, o.path, f.line, o.author, o.date
	h := core.Hit{
		Engine: "known", Rule: "known-secret", Type: typeFromName(f.km.Name), FP: f.km.FP, Shape: f.km.Shape,
		Entropy: f.entropy, Verified: core.Unverified, Context: f.ctx, Known: strings.TrimSpace(f.km.EntryID + " " + f.km.Name), Loc: l,
	}
	if f.km.Variant == "raw" || f.km.Variant == "" {
		h.Len = f.km.Len
	}
	return h
}

// providerWords maps the first word of a variable name to a provider type, so a learned
// OPENAI_API_KEY found alone still carries a type the report can use to say where to revoke
// it. Anything not listed is generic: a wrong guess would stick, because only generic types
// are replaced when an engine later names the real one.
var providerWords = map[string]string{
	"anthropic": "anthropic", "claude": "anthropic", "openai": "openai", "github": "github", "gh": "github",
	"aws": "aws", "stripe": "stripe", "slack": "slack", "discord": "discord", "telegram": "telegram",
	"google": "google", "gemini": "google", "gcp": "gcp", "firebase": "firebase", "supabase": "supabase",
	"vercel": "vercel", "cloudflare": "cloudflare", "fal": "fal", "replicate": "replicate",
	"huggingface": "huggingface", "hf": "huggingface", "groq": "groq", "xai": "xai", "openrouter": "openrouter",
	"elevenlabs": "elevenlabs", "twilio": "twilio", "sendgrid": "sendgrid", "mailgun": "mailgun",
	"shopify": "shopify", "npm": "npm", "pypi": "pypi", "dockerhub": "dockerhub", "digitalocean": "digitalocean",
	"linear": "linear", "notion": "notion", "airtable": "airtable", "zoom": "zoom", "zerobounce": "zerobounce",
}

func typeFromName(name string) string {
	first, rest, _ := strings.Cut(strings.ToLower(name), "_")
	if t, ok := providerWords[first]; ok && rest != "" {
		return t
	}
	return "generic"
}
