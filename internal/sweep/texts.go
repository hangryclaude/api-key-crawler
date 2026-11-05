package sweep

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"

	"keyguard/internal/core"
	"keyguard/internal/known"
)

// The text git keeps about a change (STEAL P0-13): the message of a commit and its author's name
// and email, the annotation of a tag, the name of a branch or a tag. A blob scan never sees any
// of it and neither does any engine (betterleaks and gitleaks found a token in none of them), so
// a key typed into a commit message would go to GitHub, and sit in a public repo, unseen by
// everything but the hooks. The sweep feeds the same matcher the hooks use: this is the third
// path the hooks stage names, the one that catches what was pushed from another machine.
//
// It runs as part of the known pass, over the same range: the messages of the commits the range
// adds, and every ref (a name is a few bytes and a tag's annotation is read, so a tag made on an
// old commit, which adds nothing to the range, is still looked at).

// scanText reads the messages of the range and the refs of the repo through the learned matcher
// and emits a hit for each learned secret in them.
func (g GitKnown) scanText(ctx context.Context, repo string, args []string, m core.KnownMatcher, loc core.Location, emit core.Emit) error {
	var errs []error
	msgs := slices.Concat([]string{"log", "-z", "--no-show-signature", "--format=" + known.MessageFormat}, args, []string{"--"})
	if err := g.pipe(ctx, repo, msgs, func(r io.Reader) error {
		return known.MatchMessages(m, r, func(t known.TextHit) { emit(textHit(t, loc, m)) })
	}); err != nil {
		errs = append(errs, fmt.Errorf("commit messages: %w", err))
	}
	refs := []string{"for-each-ref", "--format=" + known.RefFormat}
	if err := g.pipe(ctx, repo, refs, func(r io.Reader) error {
		return known.MatchRefs(m, r, func(t known.TextHit) { emit(textHit(t, loc, m)) })
	}); err != nil {
		errs = append(errs, fmt.Errorf("ref names and tag annotations: %w", err))
	}
	return errors.Join(errs...)
}

// pipe runs git and hands its standard output to read. A failing git is an error even if read
// was happy with what it got: a half-read history is not a clean one.
func (g GitKnown) pipe(ctx context.Context, repo string, args []string, read func(io.Reader) error) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := gitCmd(ctx, g.git(), repo, args...)
	var stderr tailBuffer
	cmd.Stderr = &stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start git %s: %w", args[0], err)
	}
	rerr := read(out)
	if rerr != nil {
		cancel() // stop git instead of waiting for it to finish writing to nobody
	}
	io.Copy(io.Discard, out)
	werr := cmd.Wait()
	switch {
	case rerr != nil:
		return rerr
	case werr != nil:
		return fmt.Errorf("git %s: %w%s", args[0], werr, stderr.suffix())
	}
	return nil
}

// textHit is the Hit for a learned secret found in text. The place is described in words, not as
// a path, and a ref that is a key is not named at all: its name is the secret, and a hit is
// printed in reports and journals.
func textHit(t known.TextHit, loc core.Location, m core.KnownMatcher) core.Hit {
	l := loc
	l.Commit, l.Line, l.Path = t.Commit, t.Line, "("+t.Field+")"
	if t.Ref != "" && t.Field != "ref name" && len(m.Match([]byte(t.Ref))) == 0 {
		l.Ref = t.Ref
	}
	h := core.Hit{
		Engine: "known", Rule: "known-secret", Type: typeFromName(t.Name), FP: t.FP, Shape: t.Shape,
		Verified: core.Unverified, Context: t.Context, Known: strings.TrimSpace(t.EntryID + " " + t.Name), Loc: l,
	}
	if t.Variant == "raw" || t.Variant == "" {
		h.Len = t.Len
	}
	return h
}

// maskRefs renames a ref whose name is a learned key. Ref names
// travel everywhere a scan does: the per-source state file, the ranges handed to engines, the
// coverage counts. A branch named for a key is the point of the P0-13 attack (no content scan
// reads a name), and writing that name into state/sources would put the raw key on disk, which no
// hit is allowed to do. The alias is a hash of the name, the same every time, so the tips still
// compare equal from one poll to the next and an unchanged repo is not rescanned for being unlike
// itself.
func maskRefs(refs map[string]string, m core.KnownMatcher) map[string]string {
	if m == nil || len(refs) == 0 {
		return refs
	}
	var out map[string]string
	for name, tip := range refs {
		// The matcher registers nothing shorter than known.MinLen, so a name that short once "refs/"
		// is off cannot be a key. refs/heads/main and refs/tags/v1.2.3 are most of them, and this
		// runs at the top of every scan, before an engine can start: ask about as few names as
		// possible.
		if len(strings.TrimPrefix(name, "refs/")) < known.MinLen || len(m.Match([]byte(name))) == 0 {
			continue
		}
		if out == nil {
			out = maps.Clone(refs)
		}
		delete(out, name)
		sum := sha256.Sum256([]byte(name))
		out["refs/masked/"+hex.EncodeToString(sum[:8])] = tip
	}
	if out == nil {
		return refs
	}
	return out
}
