// Command rulegen writes internal/pattern/rules/rules_gen.go, the rule table of the native engine,
// from rules/src/*.json (betterleaks's rules as data, written by scripts/rulegen/extract.mjs) and the
// 12 kg- rules of rules/keyguard.toml. Run it from the repository root:
//
//	go run ./internal/pattern/rulegen [-check] [-golden]
//
// It needs neither Bun nor a network: the JSON is committed, and so is its output. -check compares
// what it would write with the file on disk and fails if they differ, which is how a test keeps
// the table current. -golden also rewrites the fidelity golden from the example cache
// (~/.cache/keyguard-dev/rulecorpus), which only a person who has run extract.mjs has.
//
// It refuses what it should not copy: a source whose lineage or licence rules.CheckSource rejects, a
// rule whose regex Go's regexp cannot compile, an id used twice. If a change to the rule struct stops
// package rules from compiling, put a stub `var All []Rule` in rules_gen.go and run it again.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"keyguard/internal/pattern/rules"
	"keyguard/internal/pattern/rules/fidelity"
)

const (
	genFile    = "internal/pattern/rules/rules_gen.go"
	goldenFile = "internal/pattern/rules/testdata/fidelity.golden.json"
)

func main() {
	repo := flag.String("repo", "", "the repository root (default: the directory with go.mod above the working directory)")
	corpus := flag.String("corpus", "", "the example cache (default ~/.cache/keyguard-dev/rulecorpus)")
	check := flag.Bool("check", false, "write nothing; fail if rules_gen.go is not what would be written")
	golden := flag.Bool("golden", false, "also write the fidelity golden from the example cache")
	flag.Parse()
	if err := run(*repo, *corpus, *check, *golden); err != nil {
		fmt.Fprintln(os.Stderr, "rulegen:", err)
		os.Exit(1)
	}
}

func run(repo, corpus string, check, withGolden bool) error {
	root, err := repoRoot(repo)
	if err != nil {
		return err
	}
	out, err := generate(root)
	if err != nil {
		return err
	}
	path := filepath.Join(root, genFile)
	if check {
		have, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !bytes.Equal(have, out.source) {
			return fmt.Errorf("%s is not what rulegen writes from rules/src and rules/keyguard.toml; run go run ./internal/pattern/rulegen", genFile)
		}
		fmt.Printf("%s is current: %d rules\n", genFile, len(out.table))
		return nil
	}
	if err := os.WriteFile(path, out.source, 0o644); err != nil {
		return err
	}
	fmt.Printf("%s: %d rules (%d from betterleaks, %d of our own)\n", genFile, len(out.table), out.upstream, len(out.table)-out.upstream)
	if !withGolden {
		return nil
	}
	if corpus == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		corpus = filepath.Join(home, ".cache", "keyguard-dev", "rulecorpus")
	}
	g, err := fidelity.Build(corpus, out.table, out.global, out.commits["betterleaks"])
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(g, "", " ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(filepath.Join(root, goldenFile)), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(root, goldenFile), append(b, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Printf("%s: %d rules checked against %d examples, %d without examples\n", goldenFile, len(g.Rules), g.Examples, len(g.WithoutExamples))
	return nil
}

func repoRoot(given string) (string, error) {
	if given != "" {
		return filepath.Abs(given)
	}
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if b, err := os.ReadFile(filepath.Join(dir, "go.mod")); err == nil && bytes.HasPrefix(b, []byte("module keyguard")) {
			return dir, nil
		}
		if parent := filepath.Dir(dir); parent != dir {
			dir = parent
			continue
		}
		return "", errors.New("no go.mod for module keyguard above the working directory; pass -repo")
	}
}

// output is everything one run of the generator knows.
type output struct {
	source   []byte
	table    []rules.Rule
	global   rules.Filter
	commits  map[string]string
	upstream int
}

// What extract.mjs writes. Unknown fields are an error, so a change on that side shows up here.
type srcFile struct {
	Lineage string    `json:"lineage"`
	Licence string    `json:"licence"`
	Source  string    `json:"source"`
	Rules   []srcRule `json:"rules"`
}

type srcRule struct {
	ID          string     `json:"id"`
	Description string     `json:"description"`
	Confidence  string     `json:"confidence"`
	Regex       string     `json:"regex"`
	Split       bool       `json:"split"`
	Path        string     `json:"path"`
	Keywords    []string   `json:"keywords"`
	SecretGroup int        `json:"secretGroup"`
	Specificity int        `json:"specificity"`
	SkipReport  bool       `json:"skipReport"`
	Components  []srcNeed  `json:"components"`
	Filter      *srcFilter `json:"filter"`
	Validates   bool       `json:"validates"`
}

type srcNeed struct {
	ID       string `json:"id"`
	Within   string `json:"within"`
	Optional bool   `json:"optional"`
}

type srcFilter struct {
	Entropy *struct {
		Min    float64 `json:"min"`
		Strict bool    `json:"strict"`
	} `json:"entropy"`
	TokenRatio float64    `json:"tokenRatio"`
	DropRegex  []string   `json:"dropRegex"`
	DropWords  []string   `json:"dropWords"`
	DropSHA256 []string   `json:"dropSha256"`
	DropPath   []string   `json:"dropPath"`
	Require    [][]string `json:"require"`
	Residual   int        `json:"residual"`
}

type srcGlobal struct {
	Lineage   string     `json:"lineage"`
	Licence   string     `json:"licence"`
	Source    string     `json:"source"`
	Title     string     `json:"title"`
	MinVer    string     `json:"minVersion"`
	BLMinVer  string     `json:"betterleaksMinVersion"`
	Prefilter *srcFilter `json:"prefilter"`
	Filter    *srcFilter `json:"filter"`
}

func (f *srcFilter) toRules() rules.Filter {
	if f == nil {
		return rules.Filter{}
	}
	out := rules.Filter{TokenRatio: f.TokenRatio, DropRegex: f.DropRegex, DropWords: f.DropWords,
		DropSHA256: f.DropSHA256, DropPath: f.DropPath, Require: f.Require, Residual: f.Residual}
	if f.Entropy != nil {
		out.Entropy = rules.Floor{Min: f.Entropy.Min, Strict: f.Entropy.Strict}
	}
	return out
}

func decode(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// lockEntry is one line of rules/SOURCES.lock.
type lockEntry struct{ Name, Lineage, Repo, Ref, Commit, Licence string }

func readLock(path string) (map[string]lockEntry, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	out := map[string]lockEntry{}
	for i, line := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 8 {
			return nil, fmt.Errorf("%s:%d: %d fields, want 8", path, i+1, len(f))
		}
		e := lockEntry{f[0], f[1], f[2], f[3], f[4], f[5]}
		if bad := rules.CheckSource(e.Lineage, e.Licence); len(bad) > 0 {
			return nil, fmt.Errorf("%s:%d: source %s refused: %s", path, i+1, e.Name, strings.Join(bad, "; "))
		}
		if _, dup := out[e.Lineage]; dup {
			return nil, fmt.Errorf("%s:%d: lineage %s is pinned twice", path, i+1, e.Lineage)
		}
		out[e.Lineage] = e
	}
	return out, nil
}

func generate(root string) (*output, error) {
	lock, err := readLock(filepath.Join(root, "rules", "SOURCES.lock"))
	if err != nil {
		return nil, err
	}
	var global srcGlobal
	if err := decode(filepath.Join(root, "rules", "src", "_global.json"), &global); err != nil {
		return nil, err
	}
	files, err := filepath.Glob(filepath.Join(root, "rules", "src", "*.json"))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)

	var table []rules.Rule
	upstream := 0
	for _, f := range files {
		if filepath.Base(f) == "_global.json" {
			continue
		}
		var sf srcFile
		if err := decode(f, &sf); err != nil {
			return nil, err
		}
		pin, ok := lock[sf.Lineage]
		if !ok {
			return nil, fmt.Errorf("%s: lineage %q has no line in rules/SOURCES.lock", f, sf.Lineage)
		}
		if sf.Licence != pin.Licence {
			return nil, fmt.Errorf("%s says licence %s, rules/SOURCES.lock says %s", f, sf.Licence, pin.Licence)
		}
		for _, r := range sf.Rules {
			rw := "none"
			if r.Split {
				rw = "split"
			}
			rule := rules.Rule{
				ID: r.ID, Provider: providerOf(r.ID), Desc: r.Description, Kind: rules.Regex,
				Keywords: lowerUnique(r.Keywords), Re: r.Regex, Group: r.SecretGroup, Path: r.Path,
				Confidence: r.Confidence, Specificity: r.Specificity, Filter: r.Filter.toRules(),
				ComponentOnly: r.SkipReport, Validates: r.Validates,
				Src: rules.Src{Lineage: sf.Lineage, UpstreamID: r.ID, Commit: pin.Commit, Licence: pin.Licence, Rewrite: rw},
			}
			for _, c := range r.Components {
				rule.Needs = append(rule.Needs, rules.Need{ID: c.ID, Within: c.Within, Optional: c.Optional})
			}
			table = append(table, rule)
			upstream++
		}
	}

	ownPin, ok := lock["own"]
	if !ok {
		return nil, errors.New("rules/SOURCES.lock has no line for our own rules")
	}
	kgBytes, err := os.ReadFile(filepath.Join(root, "rules", "keyguard.toml"))
	if err != nil {
		return nil, err
	}
	_, kg, err := parseTOML(string(kgBytes))
	if err != nil {
		return nil, fmt.Errorf("rules/keyguard.toml: %w", err)
	}
	for _, t := range kg {
		id, _ := t["id"].(string)
		filter, err := parseOwnFilter(str(t["filter"]))
		if err != nil {
			return nil, fmt.Errorf("rules/keyguard.toml: %s: %w", id, err)
		}
		kws, _ := t["keywords"].([]string)
		table = append(table, rules.Rule{
			ID: id, Provider: providerOf(id), Desc: str(t["description"]), Kind: rules.Regex,
			Keywords: lowerUnique(kws), Re: str(t["regex"]), Confidence: str(t["confidence"]), Filter: filter,
			Src: rules.Src{Lineage: ownPin.Lineage, Licence: ownPin.Licence},
		})
	}

	sort.Slice(table, func(i, j int) bool { return table[i].ID < table[j].ID })
	if bad := rules.Lint(table); len(bad) > 0 {
		return nil, fmt.Errorf("the table fails its lint:\n  %s", strings.Join(bad, "\n  "))
	}
	if err := compileAll(table, global); err != nil {
		return nil, err
	}
	commits := map[string]string{}
	for l, e := range lock {
		if e.Commit != "" && e.Commit != "-" {
			commits[l] = e.Commit
		}
	}
	globalFilter := global.Filter.toRules()
	globalFilter.DropPath = global.Prefilter.toRules().DropPath // the prefilter is the global path list
	src, err := emit(table, globalFilter, commits)
	if err != nil {
		return nil, err
	}
	return &output{source: src, table: table, global: globalFilter, commits: commits, upstream: upstream}, nil
}

// compileAll fails on a regex Go's regexp cannot compile: a rule that cannot run must not be written.
func compileAll(table []rules.Rule, global srcGlobal) error {
	var bad []string
	try := func(who, re string) {
		if _, err := regexp.Compile(re); err != nil {
			bad = append(bad, who+": "+err.Error())
		}
	}
	for _, r := range table {
		if r.Re != "" {
			try(r.ID, r.Re)
		}
		if r.Path != "" {
			try(r.ID+" (path)", r.Path)
		}
		for _, list := range [][]string{r.Filter.DropRegex, r.Filter.DropPath} {
			for _, re := range list {
				try(r.ID+" (filter)", re)
			}
		}
		for _, g := range r.Filter.Require {
			for _, re := range g {
				try(r.ID+" (require)", re)
			}
		}
	}
	for _, list := range [][]string{global.Filter.toRules().DropRegex, global.Prefilter.toRules().DropPath} {
		for _, re := range list {
			try("global", re)
		}
	}
	if len(bad) > 0 {
		return fmt.Errorf("%d regular expressions do not compile in Go:\n  %s", len(bad), strings.Join(bad, "\n  "))
	}
	return nil
}

func str(v any) string { s, _ := v.(string); return s }

// providerOf is the first word of a rule id, without the kg- of ours: a heuristic that groups
// rules by the service they are for.
func providerOf(id string) string {
	id = strings.TrimPrefix(id, "kg-")
	if i := strings.IndexAny(id, "-."); i > 0 {
		return id[:i]
	}
	return id
}

// lowerUnique lower-cases keywords, which betterleaks does when it loads them, and drops repeats.
func lowerUnique(in []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, k := range in {
		k = strings.ToLower(k)
		if !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	return out
}
