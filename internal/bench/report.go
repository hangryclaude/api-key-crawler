package bench

import (
	"fmt"
	"sort"
	"strings"
)

func pct(x float64) string { return fmt.Sprintf("%.1f%%", 100*x) }

func frac(found, total int) string {
	if total == 0 {
		return "·"
	}
	return fmt.Sprintf("%d/%d", found, total)
}

// all returns every scored column in table order.
func (r *Results) all() []EngineResult {
	cols := append([]EngineResult{}, r.Engines...)
	return append(cols, r.Union, r.Pipeline)
}

func variantOrder() []string {
	return []string{vEnv, vShell, vDockerfile, vPy, vJS, vTS, vGo, vJSON, vYAML, vTOML, vIpynb, vMinified, vKeyFile,
		vB64, vURLEnc, vDeleted, vBranch, vTag, vPull, vBigfile, vZip,
		vMCP, vClaudeEnv, vCodex, vHAR, vPWState, vCookies, vPostman, vNbOut, vTFState, vWPConfig, vCast, vCastTyped, vB64Basic,
		vUTF16, vTGZ, vJAR, vRename, vCommitMsg, vTagMsg, vBranchName, vTwin}
}

// Markdown renders the result tables. It shows fingerprints' display shapes and plant ids,
// never values.
func (r *Results) Markdown() string {
	var b strings.Builder
	s := r.Corpus
	fmt.Fprintf(&b, "# keyguard bench\n\nseed %d, scale %d: %d commits, %d files at main, %d blobs, %.1f MB, %d refs.\n", r.Seed, r.Scale, s.Commits, s.Files, s.Blobs, float64(s.Bytes)/1e6, s.Refs)
	fmt.Fprintf(&b, "%d provider formats; %d positive plants in %d variants (%d detectable by design); %d negatives.\n\n",
		s.ProviderFormats, s.Positives, s.PositiveVariants, s.Detectable, s.Negatives)
	for _, n := range r.Notes {
		fmt.Fprintf(&b, "> %s\n", n)
	}
	if len(r.Notes) > 0 {
		b.WriteString("\n")
	}

	b.WriteString("## Engines\n\n")
	b.WriteString("union is the regex engines together; pipeline is the engines and the known matcher after triage. Recall is over plants marked detectable by design by any engine; recall(own rules) only over plants that engine's own rules cover as planted; recall(all) over every positive. Precision is true-positive fingerprints over distinct reported fingerprints; fp: extent is the right file and line under a different fingerprint.\n\n")
	b.WriteString("| engine | version | seconds | hits | reported | recall | recall(own rules) | recall(all) | precision | fp: negative | fp: extent | fp: other | near-miss |\n|---|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|\n")
	for _, e := range r.all() {
		if e.Skipped != "" {
			fmt.Fprintf(&b, "| %s | %s | skipped: %s ||||||||||\n", e.Name, e.Version, e.Skipped)
			continue
		}
		name := e.Name
		if e.Error != "" {
			name += " (error)"
		}
		own := "·"
		if e.OwnDetectable > 0 {
			own = fmt.Sprintf("%s (%d/%d)", pct(e.RecallOwn), e.OwnFound, e.OwnDetectable)
		}
		fmt.Fprintf(&b, "| %s | %s | %.2f | %d | %d | %s (%d/%d) | %s | %s | %s | %d | %d | %d | %d |\n",
			name, e.Version, e.Seconds, e.Hits, e.Reported, pct(e.Recall), e.FoundDetectable, e.Detectable, own, pct(e.RecallAll), pct(e.Precision), e.FPNegative, e.FPExtent, e.FPOther, len(e.NearMiss))
	}
	fmt.Fprintf(&b, "\nEngines one after another: %.2f s. Side by side (slowest engine plus triage): %.2f s.\n", r.SequentialSeconds, r.ParallelSeconds)
	for _, e := range r.Engines {
		if e.Name == "known" {
			fmt.Fprintf(&b, "\nKnown matcher: %d of %d plants whose value or registered encoding is in the file as bytes (%s), %d false positives.\n", e.KnownFound, e.KnownTotal, pct(e.RecallKnown), e.FPNegative+e.FPExtent+e.FPOther)
		}
	}
	b.WriteString("\n")
	for _, e := range r.Engines {
		if e.Error != "" {
			fmt.Fprintf(&b, "- %s error: %s\n", e.Name, e.Error)
		}
	}

	cols := r.all()
	header := func(first string) {
		fmt.Fprintf(&b, "| %s | plants |", first)
		for _, c := range cols {
			fmt.Fprintf(&b, " %s |", c.Name)
		}
		b.WriteString("\n|---|--:|")
		for range cols {
			b.WriteString("--:|")
		}
		b.WriteString("\n")
	}

	b.WriteString("## Recall by type\n\nfound/plants for each engine; detectable-by-design plants only count toward the recall column above.\n\n")
	header("type")
	types := map[string]bool{}
	for _, c := range cols {
		for t, ts := range c.ByType {
			if ts.Total > 0 {
				types[t] = true
			}
		}
	}
	var tnames []string
	for t := range types {
		tnames = append(tnames, t)
	}
	sort.Strings(tnames)
	for _, t := range tnames {
		fmt.Fprintf(&b, "| %s | %d |", t, r.Union.ByType[t].Total)
		for _, c := range cols {
			if ts := c.ByType[t]; ts != nil {
				fmt.Fprintf(&b, " %s |", frac(ts.Found, ts.Total))
			} else {
				b.WriteString(" · |")
			}
		}
		b.WriteString("\n")
	}

	b.WriteString("\n## Precision by type\n\nTP/reported distinct fingerprints, attributed to the plant's type (or the engine's own type for fingerprints that match nothing).\n\n")
	b.WriteString("| type |")
	for _, c := range cols {
		fmt.Fprintf(&b, " %s |", c.Name)
	}
	b.WriteString("\n|---|")
	for range cols {
		b.WriteString("--:|")
	}
	b.WriteString("\n")
	ptypes := map[string]bool{}
	for _, c := range cols {
		for t, ts := range c.ByType {
			if ts.Reported > 0 {
				ptypes[t] = true
			}
		}
	}
	var pnames []string
	for t := range ptypes {
		pnames = append(pnames, t)
	}
	sort.Strings(pnames)
	for _, t := range pnames {
		fmt.Fprintf(&b, "| %s |", t)
		for _, c := range cols {
			if ts := c.ByType[t]; ts != nil && ts.Reported > 0 {
				fmt.Fprintf(&b, " %d/%d |", ts.TP, ts.Reported)
			} else {
				b.WriteString(" · |")
			}
		}
		b.WriteString("\n")
	}

	b.WriteString("\n## Recall by variant\n\nWhere and how the value was planted.\n\n")
	header("variant")
	for _, v := range variantOrder() {
		rs := r.Union.ByVariant[v]
		if rs == nil {
			continue
		}
		fmt.Fprintf(&b, "| %s | %d |", v, rs.Total)
		for _, c := range cols {
			if x := c.ByVariant[v]; x != nil {
				fmt.Fprintf(&b, " %s |", frac(x.Found, x.Total))
			} else {
				b.WriteString(" · |")
			}
		}
		b.WriteString("\n")
	}

	b.WriteString("\n## Misses\n\nDetectable-by-design plants each column did not find (ids; see truth.json). Misses in the held-out half are counted and not listed: rules are fitted to the tune half only.\n\n")
	for _, c := range cols {
		if c.Skipped != "" {
			continue
		}
		fmt.Fprintf(&b, "- **%s** (%d): %s\n", c.Name, len(c.Missed), r.visibleList(c.Missed, 40))
		if len(c.OwnMissed) > 0 {
			fmt.Fprintf(&b, "  - of which its own rules cover (%d): %s\n", len(c.OwnMissed), r.visibleList(c.OwnMissed, 40))
		}
	}
	fmt.Fprintf(&b, "\nUndetectable by design and not found by the union (%d): %s\n", len(r.Union.MissedOther), r.visibleList(r.Union.MissedOther, 60))
	if len(r.Gaps) > 0 {
		b.WriteString("\n### Gaps the regex engines leave\n\nPlants the union of regex engines did not report and was not expected to, by provider type. Rules for them belong in rules/keyguard.toml; the known matcher is the net for secrets the user owns.\n\n| type | plants | variants | why |\n|---|--:|---|---|\n")
		for _, g := range r.Gaps {
			fmt.Fprintf(&b, "| %s | %d | %s | %s |\n", g.Type, len(g.Plants), strings.Join(g.Variants, ", "), g.Why)
		}
	}
	if r.Union.Found > r.Union.FoundDetectable {
		fmt.Fprintf(&b, "\nFound although not marked detectable: %d (the engines out-did the design).\n", r.Union.Found-r.Union.FoundDetectable)
	}

	b.WriteString("\n## False positives\n\nPer engine, distinct fingerprints that identify no positive plant.\n\n")
	b.WriteString("| engine | negatives hit | extent | other |\n|---|--:|--:|--:|\n")
	for _, c := range cols {
		fmt.Fprintf(&b, "| %s | %d | %d | %d |\n", c.Name, c.FPNegative, c.FPExtent, c.FPOther)
	}
	for _, c := range []EngineResult{r.Union, r.Pipeline} {
		fmt.Fprintf(&b, "\n### %s (%d)\n\n", c.Name, len(c.FalsePositives))
		if len(c.FalsePositives) == 0 {
			b.WriteString("none\n")
			continue
		}
		b.WriteString("| class | rule | type | where | shape |\n|---|---|---|---|---|\n")
		for i, f := range c.FalsePositives {
			if i == 60 {
				fmt.Fprintf(&b, "| … %d more |||||\n", len(c.FalsePositives)-60)
				break
			}
			fmt.Fprintf(&b, "| %s | %s | %s | %s:%d | `%s` |\n", f.Class, f.Rule, f.Type, f.Path, f.Line, f.Shape)
		}
	}
	r.markdownP0(&b)
	return b.String()
}

// typeAcc is a row's type accuracy, or a dot for a row with no typed true positive (the known
// matcher's hits name a key, not a provider).
func typeAcc(e EngineResult) string {
	if e.TypeTotal == 0 {
		return "·"
	}
	return pct(e.TypeAccuracy)
}

// visibleList lists the ids that are not in the held-out half and says how many it left out.
func (r *Results) visibleList(ids []string, limit int) string {
	var vis []string
	hidden := 0
	for _, id := range ids {
		if r.heldOut[id] {
			hidden++
		} else {
			vis = append(vis, id)
		}
	}
	out := idList(vis, limit)
	if hidden > 0 {
		out += fmt.Sprintf(" (+%d in the held-out half, not listed)", hidden)
	}
	return out
}

// markdownP0 renders the figures docs/STEAL.md P0-23 to P0-26 ask for.
func (r *Results) markdownP0(b *strings.Builder) {
	g := r.Gate
	b.WriteString("\n## Does the corpus prove the target?\n\n")
	verdict := "no"
	if g.Sufficient {
		verdict = "yes"
	}
	fmt.Fprintf(b, "Gate (P0-25): %d detectable plants (want %d), %d formats with at least %d placements (want %d): **%s**. Zero misses prove 98%% recall at 95%% confidence from %d plants, one miss from %d.\n\n",
		g.Detectable, GateDetectable, g.FormatsReady, GatePlacements, GateFormats, verdict, g.MinZeroMiss, g.MinOneMiss)
	b.WriteString("| row | detectable | found | recall | 95% Wilson | 98% proved |\n|---|--:|--:|--:|--|--|\n")
	for _, e := range []EngineResult{r.Union, r.Pipeline} {
		proved := "no"
		if e.RecallLo >= 0.98 {
			proved = "yes"
		}
		fmt.Fprintf(b, "| %s | %d | %d | %s | %s to %s | %s |\n", e.Name, e.Detectable, e.FoundDetectable, pct(e.Recall), pct(e.RecallLo), pct(e.RecallHi), proved)
	}

	b.WriteString("\n### Detectable recall by type, with the 95% Wilson interval\n\nReport only: a type of a few plants has an interval too wide to gate on.\n\n| type | detectable | found | recall | 95% Wilson |\n|---|--:|--:|--:|--|\n")
	var tnames []string
	for t, ts := range r.Union.ByType {
		if ts.Detectable > 0 {
			tnames = append(tnames, t)
		}
	}
	sort.Strings(tnames)
	for _, t := range tnames {
		ts := r.Union.ByType[t]
		fmt.Fprintf(b, "| %s | %d | %d | %s | %s to %s |\n", t, ts.Detectable, ts.FoundDetectable, pct(ts.DetectableRecall), pct(ts.DetectableLo), pct(ts.DetectableHi))
	}

	b.WriteString("\n## Standalone, marginal and pipeline precision\n\nStandalone is each engine alone, verification off. Marginal is what it reports that no other engine does, and the plants only it finds. Type accuracy is the share of its true positives that carry the plant's type (a key found by a generic rule is found and mistyped); containment is how many true positives were credited by span and not by fingerprint.\n\n")
	b.WriteString("| row | standalone | marginal reports | marginal TP | marginal precision | only it finds | type accuracy | by containment |\n|---|--:|--:|--:|--:|--:|--:|--:|\n")
	for _, e := range r.all() {
		if e.Skipped != "" {
			continue
		}
		m := e.Marginal
		if m == nil {
			m = &Marginal{}
			fmt.Fprintf(b, "| %s | %s | · | · | · | · | %s | %d |\n", e.Name, pct(e.Precision), typeAcc(e), e.TPContained)
			continue
		}
		fmt.Fprintf(b, "| %s | %s | %d | %d | %s | %d | %s | %d |\n", e.Name, pct(e.Precision), m.Reported, m.TP, pct(m.Precision), m.Found, typeAcc(e), e.TPContained)
	}
	if r.PipelineVerified {
		b.WriteString("\nThe pipeline row comes from a run with verification on.\n")
	} else {
		b.WriteString("\nThe pipeline row comes from a run with verification off.\n")
	}

	b.WriteString("\n## The two halves\n\nThe split is frozen (see Half): a format and everything planted from it is in one half for good.\n\n| row | tune: detectable | tune recall | tune precision | held-out: detectable | held-out recall | held-out precision |\n|---|--:|--:|--:|--:|--:|--:|\n")
	for _, e := range r.all() {
		t, h := e.ByHalf[HalfTune], e.ByHalf[HalfHeldOut]
		if e.Skipped != "" || t == nil || h == nil {
			continue
		}
		fmt.Fprintf(b, "| %s | %d | %s | %s | %d | %s | %s |\n", e.Name, t.Detectable, pct(t.Recall), pct(t.Precision), h.Detectable, pct(h.Recall), pct(h.Precision))
	}
	if o := r.Overfit; o != nil {
		fmt.Fprintf(b, "\nPipeline gap, tune minus held-out: recall %+.1f points, precision %+.1f points.\n", 100*o.RecallGap, 100*o.PrecisionGap)
	}

	if r.Corpus.Lines > 0 {
		fmt.Fprintf(b, "\n## Precision where secrets are rare\n\nThe corpus holds %d plants in %d lines (one in %.0f); real code holds far fewer, and precision falls with the prevalence. False alerts are counted per million lines that hold no secret, and the precision at each prevalence follows from that and the row's recall.\n\n", r.Corpus.Positives, r.Corpus.Lines, float64(r.Corpus.Lines)/max(1, float64(r.Corpus.Positives)))
		b.WriteString("| row | false alerts per Mline | precision at 1e-3 | at 1e-5 | at 1e-6 |\n|---|--:|--:|--:|--:|\n")
		for _, e := range r.all() {
			if e.Skipped != "" || e.PrecisionAt == nil {
				continue
			}
			fmt.Fprintf(b, "| %s | %.0f | %s | %s | %s |\n", e.Name, e.FPPerMLine, pct(e.PrecisionAt["1e-3"]), pct(e.PrecisionAt["1e-5"]), pct(e.PrecisionAt["1e-6"]))
		}
	}

	if r.Corpus.Twins > 0 {
		fmt.Fprintf(b, "\n## Twins\n\n%d invalid twins sit beside valid plants: shape (two characters short, under a neutral name), floor (the right shape under the rule's entropy floor) and checksum (right in every way a pattern can see). Reports on them, per engine:\n\n| engine | shape | floor | checksum |\n|---|--:|--:|--:|\n", r.Corpus.Twins)
		for _, e := range r.all() {
			if e.Skipped != "" {
				continue
			}
			n := map[string]int{}
			for _, f := range e.FalsePositives {
				if k, ok := strings.CutPrefix(f.Class, "negative:twin-"); ok {
					n[k]++
				}
			}
			fmt.Fprintf(b, "| %s | %d | %d | %d |\n", e.Name, n["shape"], n["floor"], n["checksum"])
		}
	}

	if len(r.Speed) > 0 {
		b.WriteString("\n## Speed\n\nPer repo, not per MB: the first run is cold, the others warm. CPU is the median user plus system time of one run; memory is the largest total resident size of the engine's processes at any sample.\n\n| engine | repo | runs | cold s | warm s (median) | min s | max s | CPU s | peak RSS MB |\n|---|---|--:|--:|--:|--:|--:|--:|--:|\n")
		for _, sp := range r.Speed {
			if sp.Error != "" {
				fmt.Fprintf(b, "| %s | %s | error: %s |||||||\n", sp.Engine, sp.Repo, sp.Error)
				continue
			}
			fmt.Fprintf(b, "| %s | %s | %d | %.2f | %.2f | %.2f | %.2f | %.2f | %.0f |\n", sp.Engine, sp.Repo, sp.Runs, sp.ColdSeconds, sp.WarmSeconds, sp.MinSeconds, sp.MaxSeconds, sp.CPUSeconds, sp.PeakRSSMB)
		}
	}
}

func idList(ids []string, limit int) string {
	if len(ids) == 0 {
		return "none"
	}
	if len(ids) > limit {
		return strings.Join(ids[:limit], ", ") + fmt.Sprintf(", … +%d more", len(ids)-limit)
	}
	return strings.Join(ids, ", ")
}
