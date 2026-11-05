package main

import (
	"encoding/json"
	"math/rand/v2"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// A sampled string is a string the regex matches, and the same seed draws the same string.
func TestSampleMatchesItsRegex(t *testing.T) {
	for _, re := range []string{
		`[a-f0-9]{32}`,
		`[A-Za-z0-9_-]{10,40}`,
		`(?:alpha|beta)_[0-9]{4}`,
		`[a-z0-9\/=_\+\-]{20}`,
		`x(?:[a-z]+){2,3}y`,
		`[0-9]{3}-?[A-Z]{2}`,
	} {
		anchored := regexp.MustCompile(`^(?:` + re + `)$`)
		rng := rand.New(rand.NewPCG(1, 2))
		for i := 0; i < 300; i++ {
			s, err := sampleRegex(re, rng)
			if err != nil {
				t.Fatalf("%s: %v", re, err)
			}
			if !anchored.MatchString(s) {
				t.Fatalf("%s: sampled %q, which it does not match", re, s)
			}
		}
		a, _ := sampleRegex(re, rand.New(rand.NewPCG(7, 8)))
		b, _ := sampleRegex(re, rand.New(rand.NewPCG(7, 8)))
		if a != b {
			t.Errorf("%s: the same seed drew %q and %q", re, a, b)
		}
	}
}

func TestSampleRefusesWhatItCannotDraw(t *testing.T) {
	if _, err := sampleRegex(`[^\x00-\x{10FFFF}]`, rand.New(rand.NewPCG(1, 1))); err == nil {
		t.Error("an empty class was sampled")
	}
	if _, err := sampleRegex(`(`, rand.New(rand.NewPCG(1, 1))); err == nil {
		t.Error("an invalid regex was sampled")
	}
}

// A checkout in miniature: one utils package with the helpers the generator uses and one rules
// file in each of the shapes that matter (templates, literals, a helper called with arguments, a
// local function, a statement the interpreter does not evaluate).
const fixtureUtils = `package utils

import "fmt"

func Numeric(size string) string { return fmt.Sprintf("[0-9]{%s}", size) }

func GenerateSampleSecret(identifier string, secret string) string {
	return fmt.Sprintf("%s_api_token = \"%s\"", identifier, secret)
}

func GenerateSampleSecrets(identifier string, secret string) []string {
	samples := map[string]string{
		"b": "{i}_token: {s}",
		"a": "{I}_TOKEN={s}",
	}
	replacer := strings.NewReplacer("{i}", identifier, "{I}", strings.ToUpper(identifier), "{s}", secret)
	_ = samples
	_ = replacer
	return nil
}
`

const fixtureRules = `package rules

func First() *config.Rule {
	r := config.Rule{RuleID: "first-token", Keywords: []string{"first"}}
	key := secrets.NewSecretWithEntropy("[a-z0-9]{24}", 3.0)
	tps := utils.GenerateSampleSecrets("first", key)
	tps = append(tps, "FIRST="+key, utils.GenerateSampleSecret("first", key))
	fps := []string{"FIRST=" + secrets.NewSecret(utils.Numeric("4"))}
	return utils.Validate(r, tps, fps)
}

func Wrapper() *config.Rule { return helper("second-token", "2") }

func helper(id, n string) *config.Rule {
	r := config.Rule{RuleID: id}
	return utils.Validate(r, []string{"X" + localPad(3) + n}, nil)
}

func localPad(n int) string {
	const pad = "ab"
	return strings.Repeat(pad, n/len(pad)+1)[:n]
}

func Looping() *config.Rule {
	r := config.Rule{RuleID: "third-token"}
	var tps []string
	for i := 0; i < 3; i++ {
		tps = append(tps, "never")
	}
	tps = append(tps, "kept")
	return utils.Validate(r, tps, nil)
}

func Paths() *config.Rule {
	r := config.Rule{RuleID: "fourth-token"}
	return utils.ValidateWithPaths(r, map[string]string{"a/b.txt": "one"}, map[string]string{"c.txt": "two"})
}
`

func fixture(t *testing.T) string {
	t.Helper()
	src := t.TempDir()
	for path, body := range map[string]string{
		"cmd/generate/config/utils/generate.go": fixtureUtils,
		"cmd/generate/config/rules/rules.go":    fixtureRules,
	} {
		p := filepath.Join(src, path)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return src
}

type cached struct {
	Rule      string
	Source    string
	Commit    string
	Positives []example
	Negatives []example
	Errors    []string
}

func read(t *testing.T, dir, id string) cached {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, id+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var c cached
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestTheInterpreterEvaluatesTheGeneratorsShape(t *testing.T) {
	src, out := fixture(t), t.TempDir()
	if err := run(src, out, "pinned"); err != nil {
		t.Fatal(err)
	}

	first := read(t, out, "first-token")
	// two templates + the literal-with-secret + GenerateSampleSecret
	if len(first.Positives) != 4 || len(first.Negatives) != 1 || first.Commit != "pinned" || first.Source != "rules.go" {
		t.Fatalf("first-token: %d positives, %d negatives, commit %q, source %q", len(first.Positives), len(first.Negatives), first.Commit, first.Source)
	}
	var secret string
	for _, p := range first.Positives {
		if p.Secret == "" || !strings.Contains(p.Text, p.Secret) {
			if !strings.HasPrefix(p.Text, "FIRST=") { // the literal built with +, which loses the hint
				t.Errorf("an example does not carry the secret it was built around: %q", p.Text)
			}
			continue
		}
		secret = p.Secret
	}
	if !regexp.MustCompile(`^[a-z0-9]{24}$`).MatchString(secret) {
		t.Errorf("the drawn secret %q is not 24 of [a-z0-9]", secret)
	}
	// the templates come from the checkout, in source order
	if first.Positives[0].Text != "first_token: "+secret || first.Positives[1].Text != "FIRST_TOKEN="+secret {
		t.Errorf("templates: %q, %q", first.Positives[0].Text, first.Positives[1].Text)
	}
	if want := "first_api_token = \"" + secret + "\""; first.Positives[3].Text != want {
		t.Errorf("GenerateSampleSecret: %q, want %q", first.Positives[3].Text, want)
	}

	second := read(t, out, "second-token")
	if len(second.Positives) != 1 || second.Positives[0].Text != "Xaba2" {
		t.Errorf("second-token (a helper called with arguments, a local function): %+v", second.Positives)
	}

	third := read(t, out, "third-token")
	if len(third.Positives) != 1 || third.Positives[0].Text != "kept" || len(third.Errors) == 0 || !strings.Contains(third.Errors[0], "ForStmt") {
		t.Errorf("third-token: the loop should be reported and the rest kept: %+v", third)
	}

	fourth := read(t, out, "fourth-token")
	if len(fourth.Positives) != 1 || fourth.Positives[0].Path != "a/b.txt" || fourth.Negatives[0].Path != "c.txt" {
		t.Errorf("fourth-token: %+v", fourth)
	}

	// the same checkout gives the same cache
	again := t.TempDir()
	if err := run(src, again, "pinned"); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"first-token", "second-token", "third-token", "fourth-token", "index"} {
		a, _ := os.ReadFile(filepath.Join(out, id+".json"))
		b, _ := os.ReadFile(filepath.Join(again, id+".json"))
		if string(a) != string(b) || len(a) == 0 {
			t.Errorf("%s differs between two runs", id)
		}
	}
}
