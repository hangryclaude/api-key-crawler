package rules

import (
	"fmt"
	"regexp"
	"strings"
)

// Lineages are the families of rules keyguard may copy data from, each with the one licence its
// rules were published under. TruffleHog is AGPL-3.0 and is not here: nothing of its detectors,
// regular expressions, keywords or data may enter this repository, so a rule claiming that lineage
// is refused, and so is a lineage nobody has checked.
var Lineages = map[string]string{
	"betterleaks":    "MIT",
	"gitleaks":       "MIT",
	"titus":          "Apache-2.0",
	"noseyparker":    "Apache-2.0",
	"kingfisher":     "Apache-2.0",
	"veles":          "Apache-2.0",
	"detect-secrets": "Apache-2.0",
	"own":            "own",
}

// Licences are the licences a rule or a source may carry. CC-BY-4.0 is for facts taken from
// documentation (GitHub's table of token formats), with the attribution kept.
var Licences = map[string]bool{"MIT": true, "Apache-2.0": true, "own": true, "CC-BY-4.0": true}

var rewrites = map[string]bool{"": true, "none": true, "split": true, "T1": true, "T2": true, "T3": true}

var sha40 = regexp.MustCompile(`^[0-9a-f]{40}$`)

// CheckSource is the lint of one source line of rules/SOURCES.lock, or of one rule's lineage and
// licence. It returns the reasons the pair is refused, empty if it is fine.
func CheckSource(lineage, licence string) []string {
	var bad []string
	if strings.Contains(strings.ToLower(lineage), "truffle") || strings.Contains(strings.ToLower(licence), "agpl") {
		bad = append(bad, "TruffleHog and AGPL data are never a source")
	}
	want, ok := Lineages[lineage]
	if !ok {
		bad = append(bad, fmt.Sprintf("lineage %q is not one keyguard copies from", lineage))
	}
	if !Licences[licence] {
		bad = append(bad, fmt.Sprintf("licence %q is not one keyguard copies under", licence))
	} else if ok && licence != want {
		bad = append(bad, fmt.Sprintf("lineage %q is published under %s, not %s", lineage, want, licence))
	}
	return bad
}

// Lint checks a whole table: each rule has an id (unique), a lineage and licence CheckSource
// accepts, and for a rule from outside the project the upstream id and the 40-hex commit it was
// read at. A rule of our own has the kg- prefix, so it can never replace an upstream id.
func Lint(table []Rule) []string {
	var bad []string
	seen := map[string]bool{}
	for _, r := range table {
		who := r.ID
		if who == "" {
			bad = append(bad, "a rule has no id")
			continue
		}
		if seen[r.ID] {
			bad = append(bad, who+": the id is repeated")
		}
		seen[r.ID] = true
		for _, m := range CheckSource(r.Src.Lineage, r.Src.Licence) {
			bad = append(bad, who+": "+m)
		}
		if !rewrites[r.Src.Rewrite] {
			bad = append(bad, fmt.Sprintf("%s: rewrite %q is unknown", who, r.Src.Rewrite))
		}
		if r.Re == "" && r.Path == "" {
			bad = append(bad, who+": the rule matches nothing (no regex and no path)")
		}
		if r.Src.Lineage == "own" {
			if !strings.HasPrefix(r.ID, "kg-") {
				bad = append(bad, who+": a rule of our own must start with kg-, so it cannot replace an upstream id")
			}
			continue
		}
		if r.Src.UpstreamID == "" {
			bad = append(bad, who+": no upstream id")
		}
		if !sha40.MatchString(r.Src.Commit) {
			bad = append(bad, who+": the commit it was read at is not a 40-hex id")
		}
	}
	return bad
}
