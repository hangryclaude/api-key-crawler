package hooks

import (
	"context"

	"keyguard/internal/core"
	"keyguard/internal/known"
)

// PreCommit judges what is staged: filename rules, the learned-secret matcher over the
// added lines, and the regex engine. Any finding that is not ignored blocks (exit 1).
func PreCommit(ctx context.Context, d Deps) int {
	h := newHook(ctx, d, NamePreCommit, preCommitTimeout)
	defer h.cancel()
	return h.preCommit()
}

func (h *hook) preCommit() int {
	// The engine is by far the slowest part, so it starts first and runs while git is
	// asked for the rest. Its result is read last.
	var eng collector
	engCtx, stopEngine := context.WithCancel(h.ctx)
	defer stopEngine()
	engDone := make(chan error, 1)
	if h.d.ScanStaged != nil {
		go func() {
			engDone <- safely(func() error { return h.d.ScanStaged(engCtx, h.worktree(), eng.emit) })
		}()
	} else {
		engDone <- nil
	}

	var hits []core.Hit
	files, err := h.g.staged(h.ctx)
	if err != nil {
		// Without the list the name rules cannot run; the engine and the matcher still can.
		h.warn("could not list staged files (%s); filename rules are off", h.failText(err))
	} else if len(files) == 0 {
		stopEngine()
		return 0
	} else {
		hits = append(hits, h.filenameHits(files)...)
	}

	if kh, err := h.knownStaged(); err != nil {
		h.warn("learned-secret scan failed (%s)", h.failText(err))
	} else {
		hits = append(hits, kh...)
	}

	if err := <-engDone; err != nil {
		h.warn("regex engine failed (%s); staged changes got the other checks only", h.failText(err))
	}
	hits = append(hits, eng.hits...)

	hits = h.finalize(hits, "staged")
	hits = h.dropInherited(hits)
	if len(hits) == 0 {
		return 0
	}
	return h.block("commit blocked", hits)
}

func (h *hook) worktree() string {
	if h.d.Dir == "" {
		return "."
	}
	return h.d.Dir
}

// filenameHits applies the filename rules (PLAN.md, STEAL section 4) to the staged paths.
// Rules that look inside a file read the staged blob, not the working copy: that is what gets
// committed.
func (h *hook) filenameHits(files []stagedFile) []core.Hit {
	type candidate struct {
		f    stagedFile
		rule nameRule
	}
	var hits []core.Hit
	var cands []candidate
	var shas []string
	limit := int64(readLimit)
	for _, f := range files {
		rule, ok := classify(f.path)
		if !ok || f.mode == "160000" { // a submodule pointer holds no file
			continue
		}
		switch {
		case rule.needsBlob():
			cands = append(cands, candidate{f, rule})
			shas = append(shas, f.blob)
			if rule.action == ActWalk {
				limit = walkLimit
			}
		case rule.action == ActWarn:
			h.warn("%s: %s", cell(f.path, ""), rule.why)
		default:
			hits = append(hits, h.fileHit(f, rule))
		}
	}
	if len(cands) == 0 {
		return hits
	}
	blobs, err := h.g.blobs(h.ctx, dedupe(shas), limit)
	if err != nil {
		h.warn("could not read staged config files (%s); their content rules are off", h.failText(err))
		blobs = nil
	}
	for _, c := range cands {
		b, have := blobs[c.f.blob]
		switch c.rule.action {
		case ActBlock: // a block with an exception: only content that proves it harmless lets it through
			if !have || !c.rule.allowIf(b) {
				hits = append(hits, h.fileHit(c.f, c.rule))
			}
		case ActContent:
			if have && c.rule.content(b) {
				hits = append(hits, h.fileHit(c.f, c.rule))
			}
		case ActWarn:
			if have && c.rule.content(b) {
				h.warn("%s: %s", cell(c.f.path, ""), c.rule.why)
			}
		case ActWalk:
			if !have {
				continue
			}
			if int64(len(b)) >= limit {
				h.warn("%s is larger than %d bytes; only its start was checked for credentials", cell(c.f.path, ""), limit)
			}
			lits, err := known.Literals(c.rule.walk, b)
			if err != nil {
				h.warn("%s could not be read to the end (%s); credentials after that point were not checked", cell(c.f.path, ""), errText(err))
			}
			for _, l := range lits {
				hits = append(hits, h.literalHit(c.f, c.rule, l))
			}
		}
	}
	return hits
}

func (h *hook) fileHit(f stagedFile, r nameRule) core.Hit {
	hit := core.Hit{
		Engine: "filename", Rule: r.id, Type: r.id, Verified: core.Unverified,
		Context: r.why,
		Loc:     core.Location{Source: h.source(), Kind: "staged", Visibility: core.Local, Path: f.path},
	}
	if h.d.FP != nil {
		// Path plus blob: allowing one version of a file does not allow the next.
		hit.FP = h.d.FP.FP("kg-file\x00" + f.path + "\x00" + f.blob)
	}
	return hit
}

// literalHit is a filename hit for one credential the config walker found written out. It
// has the file's id (path plus blob: `keyguard allow` lets one version of the file through)
// and carries the shape of the value, never the value.
func (h *hook) literalHit(f stagedFile, r nameRule, l known.Literal) core.Hit {
	hit := h.fileHit(f, r)
	hit.Shape, hit.Len = l.Shape, l.Len
	hit.Context = "literal at " + clipTail(l.Path, 30)
	hit.Loc.Line = l.Line
	return hit
}

// clipTail keeps the end of a key path, where the name of the variable is.
func clipTail(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return "…" + string(r[len(r)-n+1:])
	}
	return s
}

// dropInherited drops findings on lines a merge took unchanged from MERGE_HEAD. While a
// merge waits to be committed, `git diff --cached` against HEAD shows everything the other
// side brought as added, but only a line that is new against both parents is this commit's
// doing (the reference-transaction hook judges merges the same way, through --cc). The
// other side's history was judged where it was committed, or is already on a remote.
//
// It costs nothing unless something was found and a merge is under way.
func (h *hook) dropInherited(hits []core.Hit) []core.Hit {
	type pos struct {
		path string
		line int
	}
	want := map[pos]bool{}
	for _, x := range hits {
		if x.Engine != "filename" && x.Loc.Path != "" && x.Loc.Line > 0 {
			want[pos{x.Loc.Path, x.Loc.Line}] = false
		}
	}
	if len(want) == 0 || !h.g.merging(h.ctx) {
		return hits
	}
	st, err := h.g.cachedPatch(h.ctx, "MERGE_HEAD")
	if err != nil {
		return hits
	}
	serr := scanPositions(st.r, func(path string, line int) {
		if _, ok := want[pos{path, line}]; ok {
			want[pos{path, line}] = true
		}
	})
	if ferr := st.finish(false); serr == nil {
		serr = ferr
	}
	if serr != nil {
		return hits // cannot tell which lines are new: keep them all
	}
	var out []core.Hit
	for _, x := range hits {
		if p := (pos{x.Loc.Path, x.Loc.Line}); x.Engine == "filename" || x.Loc.Path == "" || x.Loc.Line <= 0 || want[p] {
			out = append(out, x)
		}
	}
	return out
}

// knownStaged runs the learned-secret matcher over the added lines of the staged diff.
// It ignores `betterleaks:allow` comments: a learned key is never a false positive.
func (h *hook) knownStaged() ([]core.Hit, error) {
	m := h.matcher()
	if m == nil {
		return nil, nil
	}
	st, err := h.g.cachedPatch(h.ctx)
	if err != nil {
		return nil, err
	}
	var hits []core.Hit
	_, _, serr := scanAdded(st.r, m, 0, func(dm diffMatch) { hits = append(hits, h.knownHit(dm, "staged")) })
	if ferr := st.finish(false); serr == nil {
		serr = ferr
	}
	return hits, serr
}
