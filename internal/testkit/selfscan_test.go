package testkit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// Invariant 2 (PLAN.md): no secret-shaped literal in source or tests, so keyguard's own
// pre-commit hook never blocks keyguard's own commit and GitHub's push protection never
// sees a key-looking string in this repo. Fakes are built at run time from parts. This test
// is the standing proof: it runs two of the engines over the tree and wants no hit at all.
// What it prints is file, line and rule, never a matched value.

// repoRoot walks up from the package directory to the module root.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if b, err := os.ReadFile(filepath.Join(dir, "go.mod")); err == nil && bytes.HasPrefix(b, []byte("module keyguard")) {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod for module keyguard above the test's directory")
		}
		dir = parent
	}
}

// scanned are the trees the repo's code and documents live in.
func scanned(t *testing.T, root string) []string {
	t.Helper()
	var dirs []string
	for _, d := range []string{"cmd", "internal", "rules", "scripts", "docs"} {
		if fi, err := os.Stat(filepath.Join(root, d)); err == nil && fi.IsDir() {
			dirs = append(dirs, filepath.Join(root, d))
		}
	}
	if len(dirs) == 0 {
		t.Fatalf("none of the trees to scan exist under %s", root)
	}
	return dirs
}

func without(env []string, keys ...string) []string {
	var out []string
	for _, kv := range env {
		k, _, _ := strings.Cut(kv, "=")
		if !slices.Contains(keys, k) {
			out = append(out, kv)
		}
	}
	return out
}

// hit is where an engine found something and under which rule; nothing else about it is kept.
type hit struct {
	file string
	line int
	rule string
}

func (h hit) String() string { return fmt.Sprintf("%s:%d (%s)", h.file, h.line, h.rule) }

func report(t *testing.T, engine string, hits []hit) {
	t.Helper()
	if len(hits) == 0 {
		return
	}
	slices.SortFunc(hits, func(a, b hit) int { return strings.Compare(a.String(), b.String()) })
	lines := make([]string, len(hits))
	for i, h := range hits {
		lines[i] = h.String()
	}
	t.Errorf("%s flags %d place(s) in the tree; build the value at run time from parts:\n  %s", engine, len(hits), strings.Join(lines, "\n  "))
}

func TestTheRepoPassesBetterleaks(t *testing.T) {
	root := repoRoot(t)
	bin := EnginePath(t, "betterleaks")
	// --redact keeps a real secret, if one ever got in, out of this process too. The rules file
	// is the one keyguard's own hook scans with, so a literal it would block is caught here.
	args := append([]string{"dir"}, scanned(t, root)...)
	args = append(args, "--no-banner", "--no-color", "-l", "error", "-f", "json", "-r", "-", "--redact",
		"--exit-code", "0", "--ignore-gitleaks-allow")
	if rules := filepath.Join(root, "rules", "keyguard.toml"); fileExists(rules) {
		args = append(args, "-c", rules)
	}
	cmd := exec.Command(bin, args...)
	cmd.Dir = t.TempDir() // outside the repo, so no ignore file or config inside it can blind the scan
	cmd.Env = without(os.Environ(), "BETTERLEAKS_CONFIG", "GITLEAKS_CONFIG", "BETTERLEAKS_CONFIG_TOML", "GITLEAKS_CONFIG_TOML")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("betterleaks failed: %v\n%s", err, stderr.String())
	}
	var found []struct {
		RuleID    string
		File      string
		StartLine int
	}
	if err := json.Unmarshal(out, &found); err != nil {
		t.Fatalf("betterleaks output is not the JSON report: %v", err)
	}
	var hits []hit
	for _, f := range found {
		rel, err := filepath.Rel(root, f.File)
		if err != nil {
			rel = f.File
		}
		hits = append(hits, hit{rel, f.StartLine, f.RuleID})
	}
	report(t, "betterleaks", hits)
}

func TestTheRepoPassesTrufflehog(t *testing.T) {
	root := repoRoot(t)
	bin := EnginePath(t, "trufflehog")
	// --no-update: the binary is pinned and must never replace itself. --no-ignore-tag: a
	// trufflehog:ignore comment is no excuse. The default result filter stays: asked for
	// everything, trufflehog also flags two lowercase names in internal/engines/providers.txt
	// (the provider list) as company-hub and parsehub keys, which no literal in the tree is.
	args := append([]string{"filesystem"}, scanned(t, root)...)
	args = append(args, "--json", "--no-verification", "--no-update", "--no-color", "--log-level=-1", "--no-ignore-tag")
	cmd := exec.Command(bin, args...)
	cmd.Dir = t.TempDir()
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("trufflehog failed: %v\n%s", err, stderr.String())
	}
	var hits []hit
	for _, l := range bytes.Split(out, []byte("\n")) {
		var f struct {
			DetectorName   string
			SourceMetadata struct {
				Data struct {
					Filesystem struct {
						File string
						Line int
					}
				}
			}
		}
		if json.Unmarshal(l, &f) != nil || f.DetectorName == "" {
			continue
		}
		fs := f.SourceMetadata.Data.Filesystem
		rel, err := filepath.Rel(root, fs.File)
		if err != nil {
			rel = fs.File
		}
		hits = append(hits, hit{rel, fs.Line, f.DetectorName})
	}
	report(t, "trufflehog", hits)
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular()
}
