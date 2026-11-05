package rules_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"keyguard/internal/pattern/rules"
	"keyguard/internal/pattern/rules/fidelity"
	"keyguard/internal/testkit"
)

// A second instrument for the fidelity digest. The digest says what the table does with the
// examples; this asks the real betterleaks 1.9.0, the program the rules came from, to scan the
// same examples as files and compares, example by example, whether each rule fired. A rule the
// table models completely must agree on every one. A rule with a filter the table does not carry
// (the generic ones, the token-ratio rules) may fire where betterleaks stays quiet, and never
// the other way round, because the table drops no more than upstream does.
func TestTheTableAgreesWithBetterleaksOnTheExamples(t *testing.T) {
	bl := testkit.EnginePath(t, "betterleaks")
	corpus := exampleCache(t)
	if out, err := exec.Command(bl, "version").Output(); err != nil || strings.TrimSpace(string(out)) != pinnedVersion {
		t.Skipf("the table is pinned to betterleaks %s", pinnedVersion)
	}

	type shown struct {
		rule    *rules.Rule
		file    string
		fired   bool // the table
		pos     bool
		example string // a short hash, never the text
	}
	var all []shown
	dir := t.TempDir()
	for i := range rules.All {
		r := &rules.All[i]
		set, err := fidelity.Load(corpus, r.ID)
		if err != nil {
			t.Fatal(err)
		}
		if set == nil || len(r.Needs) > 0 || r.ComponentOnly {
			continue // composite rules are checked together upstream; their parts are not rules on their own here
		}
		if r.Re == "" {
			continue // a rule about a file's name: its example is an empty file, which betterleaks does not scan
		}
		for kind, list := range map[string][]fidelity.Example{"p": set.Positives, "n": set.Negatives} {
			for j, ex := range list {
				rel := fmt.Sprintf("%s/%s%d.txt", r.ID, kind, j)
				if ex.Path != "" {
					rel = fmt.Sprintf("%s/%s%d/%s", r.ID, kind, j, strings.TrimLeft(ex.Path, "/"))
				}
				p := filepath.Join(dir, rel)
				if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, []byte(ex.Text), 0o600); err != nil {
					t.Fatal(err)
				}
				sum := sha256.Sum256([]byte(ex.Path + "\x00" + ex.Text))
				all = append(all, shown{r, p, len(fidelity.Findings(r, rules.Global, ex.Text, ex.Path)) > 0, kind == "p", hex.EncodeToString(sum[:])[:8]})
			}
		}
	}
	if len(all) < 5000 {
		t.Fatalf("only %d examples were written", len(all))
	}

	empty := t.TempDir()
	cmd := exec.Command(bl, "dir", dir, "--no-banner", "--no-color", "-l", "error", "-f", "json", "-r", "-", "--redact",
		"--exit-code", "0", "--ignore-gitleaks-allow", "--max-decode-depth", "0", "-i", empty)
	cmd.Dir = empty
	cmd.Env = append(os.Environ(), "BETTERLEAKS_CONFIG=", "GITLEAKS_CONFIG=", "BETTERLEAKS_CONFIG_TOML=", "GITLEAKS_CONFIG_TOML=")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("betterleaks: %v", err)
	}
	var reported []struct{ RuleID, File string }
	if err := json.Unmarshal(out, &reported); err != nil {
		t.Fatal(err)
	}
	theirs := map[string]bool{} // rule id + file
	for _, f := range reported {
		theirs[f.RuleID+" "+f.File] = true
	}

	// betterleaks lets a more specific rule suppress a less specific one at the same place, so a rule
	// that is quiet in the full scan is asked again on its own before it counts as a disagreement.
	alone := map[string]bool{}
	for _, s := range all {
		if s.fired && !theirs[s.rule.ID+" "+s.file] {
			alone[s.rule.ID] = true
		}
	}
	for id := range alone {
		cmd := exec.Command(bl, "dir", filepath.Join(dir, id), "--no-banner", "--no-color", "-l", "error", "-f", "json", "-r", "-", "--redact",
			"--exit-code", "0", "--ignore-gitleaks-allow", "--max-decode-depth", "0", "-i", empty, "--enable-rule", id)
		cmd.Dir = empty
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("betterleaks --enable-rule %s: %v", id, err)
		}
		var again []struct{ RuleID, File string }
		if err := json.Unmarshal(out, &again); err != nil {
			t.Fatal(err)
		}
		for _, f := range again {
			theirs[f.RuleID+" "+f.File] = true
		}
	}

	var tableOnly, upstreamOnly, modelledDisagree []string
	agree := 0
	for _, s := range all {
		up := theirs[s.rule.ID+" "+s.file]
		modelled := s.rule.Filter.Residual == 0 && s.rule.Filter.TokenRatio == 0
		switch {
		case up == s.fired:
			agree++
		case s.fired && !up:
			tableOnly = append(tableOnly, s.rule.ID)
			if modelled {
				modelledDisagree = append(modelledDisagree, fmt.Sprintf("%s example %s: the table fires, betterleaks does not", s.rule.ID, s.example))
			}
		default:
			upstreamOnly = append(upstreamOnly, fmt.Sprintf("%s example %s: betterleaks fires, the table does not", s.rule.ID, s.example))
		}
	}
	sort.Strings(tableOnly)
	t.Logf("%d examples of %d rules: %d agree, the table alone fires on %d, betterleaks alone on %d", len(all), countRules(all, func(s shown) string { return s.rule.ID }), agree, len(tableOnly), len(upstreamOnly))
	if len(upstreamOnly) > 0 {
		t.Errorf("betterleaks fires where the table does not (the table drops more than upstream):\n  %s", strings.Join(first(upstreamOnly, 20), "\n  "))
	}
	if len(modelledDisagree) > 0 {
		t.Errorf("a fully modelled rule disagrees with betterleaks:\n  %s", strings.Join(first(modelledDisagree, 20), "\n  "))
	}
}

func first(s []string, n int) []string {
	if len(s) > n {
		return append(s[:n:n], fmt.Sprintf("... and %d more", len(s)-n))
	}
	return s
}

func countRules[T any](xs []T, id func(T) string) int {
	seen := map[string]bool{}
	for _, x := range xs {
		seen[id(x)] = true
	}
	return len(seen)
}

func exampleCache(t *testing.T) string {
	t.Helper()
	corpus := os.Getenv("KEYGUARD_RULECORPUS")
	if corpus == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			t.Fatal(err)
		}
		corpus = filepath.Join(home, ".cache", "keyguard-dev", "rulecorpus")
	}
	if _, err := os.Stat(filepath.Join(corpus, "index.json")); err != nil {
		if os.Getenv(testkit.RequireEnv) == "1" {
			t.Fatalf("the example cache is missing (%s=1, so this is a failure, not a skip): run bun scripts/rulegen/extract.mjs", testkit.RequireEnv)
		}
		t.Skip("no example cache: run bun scripts/rulegen/extract.mjs to make one")
	}
	return corpus
}
