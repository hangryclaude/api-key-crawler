package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"keyguard/internal/core"
	"keyguard/internal/db"
	"keyguard/internal/fp"
	"keyguard/internal/triage"
)

// The judging of what rules cannot decide is done outside this binary, by a model that reads
// a redacted file and writes verdicts back. export-triage makes the file; import-triage
// reads the verdicts. Nothing in either direction is a secret: the model sees a shape, a
// place and a redacted line, and answers with an id and a label.

const triageSchema = "keyguard.triage/1"

var triageLabels = []string{triage.Real, triage.Test, triage.Placeholder, triage.PublicByDesign, triage.FalsePositive}

type triageLoc struct {
	Source     string `json:"source"`
	Kind       string `json:"kind"`
	Visibility string `json:"visibility"`
	Path       string `json:"path,omitempty"`
	Line       int    `json:"line,omitempty"`
	Ref        string `json:"ref,omitempty"`
}

type triageItem struct {
	ID             string      `json:"id"`
	Type           string      `json:"type"`
	Rules          []string    `json:"rules"`
	Engines        []string    `json:"engines"`
	Shape          string      `json:"shape"`
	Len            int         `json:"len"`
	Entropy        float64     `json:"entropy,omitempty"`
	Verified       string      `json:"verified"`
	Exposed        bool        `json:"exposed"`
	Severity       string      `json:"severity"`
	Triage         string      `json:"triage"`
	LocationsTotal int         `json:"locations_total"`
	Locations      []triageLoc `json:"locations"`
	Contexts       []string    `json:"contexts,omitempty"`
}

type triageExport struct {
	Schema  string            `json:"schema"`
	About   string            `json:"about"`
	Labels  map[string]string `json:"labels"`
	Reply   string            `json:"reply_with"`
	Items   []triageItem      `json:"items"`
	Omitted int               `json:"omitted,omitempty"`
}

var labelHelp = map[string]string{
	triage.Real:           "a working or plausible credential for a real service; someone must rotate it",
	triage.Test:           "a credential in test or fixture code that is not a live key (still rotate if the provider says live)",
	triage.Placeholder:    "an example or dummy value no service would accept",
	triage.PublicByDesign: "meant to be public (publishable key, site key, anon key, DSN)",
	triage.FalsePositive:  "not a credential at all: a hash, an id, a version string",
}

func (c *cli) cmdExportTriage(args []string) int {
	f := c.flagSet("export-triage", "export-triage [--out FILE] [--all] [--limit N]\n\nWrites the open findings that rules and verification could not decide, as redacted JSON for a model to judge.\nNo value is in it: a shape, the places, a redacted line.")
	out := f.String("out", "", "write here instead of stdout (0600)")
	all := f.Bool("all", false, "include every open finding, not only the unreviewed ones")
	limit := f.Int("limit", 200, "most items to export, worst first")
	if _, code, ok := c.parse(f, args); !ok {
		return code
	}
	p := c.paths()
	st, err := db.Open(p)
	if err != nil {
		return c.failf("%s", safeErr(err))
	}
	var pick []core.Secret
	for _, s := range st.Secrets() {
		if s.Status != db.StatusOpen {
			continue
		}
		if !*all && !needsReview(s) {
			continue
		}
		pick = append(pick, s)
	}
	slices.SortStableFunc(pick, func(a, b core.Secret) int {
		if a.Severity != b.Severity {
			return int(b.Severity) - int(a.Severity)
		}
		return strings.Compare(a.ID, b.ID)
	})
	exp := triageExport{
		Schema: triageSchema,
		About: "Each item is an open finding from keyguard, with the secret itself removed: only its shape, where it was found and a redacted line. " +
			"For each, decide whether it is a real credential. Reply with a JSON array of verdicts.",
		Labels: labelHelp,
		Reply:  `[{"id":"kg1a2b3c","triage":"real","why":"short reason, no secret values"}]`,
	}
	if len(pick) > *limit {
		exp.Omitted = len(pick) - *limit
		pick = pick[:*limit]
	}
	for _, s := range pick {
		it := triageItem{
			ID: s.ID, Type: orGeneric(s.Type), Rules: s.Rules, Engines: s.Engines, Shape: s.Shape, Len: s.Len,
			Verified: string(s.Verified), Exposed: s.Exposed(), Severity: s.Severity.String(), Triage: orUnreviewed(s.Triage),
			LocationsTotal: len(s.Locations),
		}
		for i, l := range s.Locations {
			if i == 5 {
				break
			}
			it.Locations = append(it.Locations, triageLoc{Source: l.Source, Kind: l.Kind, Visibility: string(l.Visibility), Path: l.Path, Line: l.Line, Ref: l.Ref})
		}
		contexts, entropy, _, _ := st.Evidence(s.FP)
		it.Entropy = entropy
		for i, cx := range contexts {
			if i == 5 {
				break
			}
			it.Contexts = append(it.Contexts, fp.Scrub(cx)) // a belt over braces: the store already redacted it
		}
		exp.Items = append(exp.Items, it)
	}
	b, err := json.MarshalIndent(exp, "", "  ")
	if err != nil {
		return c.failf("%s", safeErr(err))
	}
	b = append(b, '\n')
	if *out != "" {
		if err := db.WriteFileAtomic(*out, b, 0o600); err != nil {
			return c.failf("%s", safeErr(err))
		}
		fmt.Fprintf(c.err, "wrote %s for review (%s)\n", *out, plural(len(exp.Items), "finding", "findings"))
		return exitOK
	}
	_, _ = c.out.Write(b)
	return exitOK
}

func orUnreviewed(t string) string {
	if t == "" {
		return triage.Unreviewed
	}
	return t
}

type verdict struct {
	ID     string `json:"id"`
	Triage string `json:"triage"`
	Why    string `json:"why"`
}

func (c *cli) cmdImportTriage(args []string) int {
	f := c.flagSet("import-triage", "import-triage --by claude|codex|human [--file FILE] [--dry-run]\n\nReads verdicts (a JSON array, or an object with a \"verdicts\" array) from FILE or stdin.")
	by := f.String("by", "", "who judged: claude, codex or human (required)")
	file := f.String("file", "", "read verdicts from here instead of stdin")
	dry := f.Bool("dry-run", false, "say what would change and change nothing")
	if _, code, ok := c.parse(f, args); !ok {
		return code
	}
	switch *by {
	case triage.ByClaude, triage.ByCodex, triage.ByHuman:
	default:
		return c.usageErr(f, "--by must be claude, codex or human")
	}
	var r io.Reader = c.in
	if *file != "" {
		fh, err := os.Open(*file)
		if err != nil {
			return c.failf("%s", safeErr(err))
		}
		defer fh.Close()
		r = fh
	}
	raw, err := io.ReadAll(io.LimitReader(r, 32<<20))
	if err != nil {
		return c.failf("%s", safeErr(err))
	}
	vs, err := parseVerdicts(raw)
	if err != nil {
		return c.failf("%s", safeErr(err))
	}

	p := c.paths()
	kr, err := openKeyring(p)
	if err != nil {
		return c.failf("%s", safeErr(err))
	}
	applied, skipped := 0, 0
	apply := func(st *db.Store) error {
		tr := triage.New(triage.WithStoreEvidence(st), triage.WithFingerprinter(kr))
		for _, v := range vs {
			s, found := st.Find(v.ID)
			switch {
			case !found:
				fmt.Fprintf(c.out, "skip   %s  no such finding\n", v.ID)
			case !slices.Contains(triageLabels, v.Triage):
				fmt.Fprintf(c.out, "skip   %s  %q is not a label (%s)\n", v.ID, v.Triage, strings.Join(triageLabels, ", "))
			case s.Status == db.StatusIgnored:
				fmt.Fprintf(c.out, "skip   %s  a person already ignored it\n", s.ID)
			default:
				before := s
				s.Triage, s.TriageBy, s.TriageWhy = v.Triage, *by, strings.TrimSpace(fp.Scrub(clipRunes(v.Why, 200)))
				tr.Classify(&s)
				fmt.Fprintf(c.out, "%-6s %s  %s -> %s, severity %s -> %s\n", map[bool]string{true: "would", false: "set"}[*dry], s.ID, orUnreviewed(before.Triage), s.Triage, before.Severity, s.Severity)
				if !*dry {
					if err := st.Put(s); err != nil {
						return err
					}
				}
				applied++
				continue
			}
			skipped++
		}
		return nil
	}
	if *dry {
		st, err := db.Open(p)
		if err != nil {
			return c.failf("%s", safeErr(err))
		}
		if err := apply(st); err != nil {
			return c.failf("%s", safeErr(err))
		}
	} else if err := c.withStore(p, apply); err != nil {
		if msg, locked := lockedMessage(err); locked {
			fmt.Fprintf(c.err, "keyguard: %s\n", msg)
			return exitLocked
		}
		return c.failf("%s", safeErr(err))
	}
	fmt.Fprintf(c.out, "\n%d judged, %d skipped.\n", applied, skipped)
	return exitOK
}

func clipRunes(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return s
}

// parseVerdicts accepts a bare array or {"verdicts": [...]}, which is what a model tends to
// produce when asked for "a JSON object".
func parseVerdicts(raw []byte) ([]verdict, error) {
	var arr []verdict
	if err := json.Unmarshal(raw, &arr); err == nil {
		return arr, nil
	}
	var obj struct {
		Verdicts []verdict `json:"verdicts"`
		Items    []verdict `json:"items"`
	}
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, fmt.Errorf("the verdicts are not valid JSON (an array of {id, triage, why})")
	}
	if len(obj.Verdicts) > 0 {
		return obj.Verdicts, nil
	}
	return obj.Items, nil
}

// needsReview is the residue: what a learned key, a provider's verdict or a reviewer has not
// already decided, and that the rules did not already dismiss as a placeholder or a test.
func needsReview(s core.Secret) bool {
	if s.Known != "" || s.Verified == core.Live || s.Verified == core.Dead {
		return false
	}
	if s.TriageBy != "" && s.TriageBy != triage.ByRule {
		return false // claude, codex or a person has judged it
	}
	return s.Triage == "" || s.Triage == triage.Unreviewed || s.Severity >= core.Low
}
