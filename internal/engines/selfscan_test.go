package engines

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"keyguard/internal/core"
)

// ruleIDLine is the whole of a line of rules/src that holds a rule id: a few lower-case words joined
// by hyphens, which a loose detector fits when the id is 20 to 22 characters long (a GitLab pattern
// takes some of the GitLab ids for a token). It is the same case as providers.txt below: the dictionary
// filter that keyguard turns off for trufflehog is what keeps it quiet about words.
var ruleIDLine = regexp.MustCompile(`^\s*"id": "[a-z0-9]+(?:[-.][a-z0-9]+)*",?$`)

func isRuleIDLine(dir, path string, line int) bool {
	b, err := os.ReadFile(filepath.Join(dir, path))
	if err != nil {
		return false
	}
	lines := strings.Split(string(b), "\n")
	return line >= 1 && line <= len(lines) && ruleIDLine.MatchString(lines[line-1])
}

// PLAN invariant 2: no secret-shaped literal in source or tests. The strongest check is the
// engines themselves, run over this package and the rules file.
func TestSourceHoldsNoSecretShapes(t *testing.T) {
	f := getFixture(t)
	for _, name := range Names {
		for _, dir := range []string{".", "../../rules"} {
			t.Run(name+"/"+dir, func(t *testing.T) {
				e := newEngine(t, name, f.kr)
				resetAudit()
				var hits []core.Hit
				if err := e.ScanDir(context.Background(), dir, testOpts(), func(h core.Hit) { hits = append(hits, h) }); err != nil {
					t.Fatal(err)
				}
				for _, h := range hits {
					if h.Loc.Path == "providers.txt" && name == "trufflehog" {
						// A list of provider names. Trufflehog's dictionary filter, which keyguard turns off
						// (--results=...filtered_unverified), is what kept it quiet about words that fit a
						// detector's pattern.
						continue
					}
					if name == "trufflehog" && strings.HasPrefix(h.Loc.Path, "src/") && isRuleIDLine(dir, h.Loc.Path, h.Loc.Line) {
						continue // a rule id in the rule data, and nothing else on its line
					}
					t.Errorf("%s flags %s:%d as %s (%s)", name, h.Loc.Path, h.Loc.Line, h.Rule, h.Shape)
				}
			})
		}
	}
}
