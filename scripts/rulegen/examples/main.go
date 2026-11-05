// Command examples extracts the strings betterleaks's rule generator checks each rule against
// (the true positives that must fire and the false positives that must not) and writes them
// to a cache outside the repository.
//
//	go run ./scripts/rulegen/examples -src CLONE -out CORPUS
//
// CLONE is a checkout of betterleaks, and CORPUS is normally ~/.cache/keyguard-dev/rulecorpus.
// scripts/rulegen/extract.mjs runs it after it has written rules/src.
//
// The examples are made-up secrets inside test strings. Invariant 2 of the project says no
// secret-shaped literal lives in source, tests or testdata, so they are never committed:
// internal/pattern/rules reads them from CORPUS when it is there and checks the generated table
// against a digest of what each rule did with them, which is committed.
//
// The generator builds its strings with Go code. This command reads that code as syntax and
// evaluates the part it uses (see interp.go); a random secret is drawn from the regex it names
// with a generator seeded from the call's position in the source, so the same checkout always
// gives the same cache. One file per rule is written, <rule id>.json, and index.json lists them.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
)

func main() {
	src := flag.String("src", "", "a betterleaks checkout")
	out := flag.String("out", "", "the cache directory to write (made if missing; files in it are replaced)")
	commit := flag.String("commit", "", "the commit of the checkout, recorded in the index")
	flag.Parse()
	if *src == "" || *out == "" {
		fmt.Fprintln(os.Stderr, "usage: examples -src CLONE -out CORPUS [-commit SHA]")
		os.Exit(2)
	}
	if err := run(*src, *out, *commit); err != nil {
		fmt.Fprintln(os.Stderr, "examples:", err)
		os.Exit(1)
	}
}

func run(src, out, commit string) error {
	in := &interp{fset: token.NewFileSet()}
	rulesDir := filepath.Join(src, "cmd", "generate", "config", "rules")
	utilsDir := filepath.Join(src, "cmd", "generate", "config", "utils")
	var err error
	if in.rules, err = load(in.fset, rulesDir); err != nil {
		return err
	}
	if in.utils, err = load(in.fset, utilsDir); err != nil {
		return err
	}
	if in.samples, err = templates(in); err != nil {
		return err
	}

	var entries []*ast.FuncDecl
	for _, fd := range in.rules.funcs {
		if fd.Type.Params.NumFields() == 0 && returnsRule(fd) {
			entries = append(entries, fd)
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Pos() < entries[j].Pos() })
	for _, fd := range entries {
		in.run(fd)
	}

	byID := map[string]*record{}
	for _, r := range in.records {
		if old, ok := byID[r.Rule]; ok { // one rule checked in two functions: keep both sets
			old.Positives = append(old.Positives, r.Positives...)
			old.Negatives = append(old.Negatives, r.Negatives...)
			old.Errors = append(old.Errors, r.Errors...)
			continue
		}
		byID[r.Rule] = r
	}
	return write(out, commit, byID)
}

// load parses the non-test Go files of a directory into one package.
func load(fset *token.FileSet, dir string) (*pkg, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil || len(files) == 0 {
		return nil, fmt.Errorf("no Go files in %s", dir)
	}
	p := &pkg{funcs: map[string]*ast.FuncDecl{}, decls: map[string]ast.Expr{}, cache: map[string]any{}, busy: map[string]bool{}}
	slices.Sort(files)
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, parser.SkipObjectResolution)
		if err != nil {
			return nil, err
		}
		for _, d := range af.Decls {
			switch d := d.(type) {
			case *ast.FuncDecl:
				if d.Recv == nil && d.Body != nil {
					p.funcs[d.Name.Name] = d
				}
			case *ast.GenDecl:
				if d.Tok != token.CONST && d.Tok != token.VAR {
					continue
				}
				for _, sp := range d.Specs {
					vs := sp.(*ast.ValueSpec)
					for i, n := range vs.Names {
						if i < len(vs.Values) {
							p.decls[n.Name] = vs.Values[i]
						}
					}
				}
			}
		}
	}
	return p, nil
}

func returnsRule(fd *ast.FuncDecl) bool {
	if fd.Type.Results == nil || len(fd.Type.Results.List) != 1 {
		return false
	}
	star, ok := fd.Type.Results.List[0].Type.(*ast.StarExpr)
	if !ok {
		return false
	}
	sel, ok := star.X.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "Rule"
}

// templates reads the assignment templates out of utils.GenerateSampleSecrets: the map literal
// its body starts with. The three placeholders it replaces are checked to still be there.
func templates(in *interp) (*omap, error) {
	fd, ok := in.utils.funcs["GenerateSampleSecrets"]
	if !ok {
		return nil, fmt.Errorf("utils.GenerateSampleSecrets is not in the checkout")
	}
	ev := &env{vars: map[string]any{}, pkg: in.utils, fn: fd.Name.Name}
	for _, st := range fd.Body.List {
		as, ok := st.(*ast.AssignStmt)
		if !ok || len(as.Rhs) != 1 {
			continue
		}
		cl, ok := as.Rhs[0].(*ast.CompositeLit)
		if !ok {
			continue
		}
		if _, ok := cl.Type.(*ast.MapType); !ok {
			continue
		}
		v, err := in.composite(cl, ev)
		if err != nil {
			return nil, err
		}
		m := v.(*omap)
		seen := map[string]bool{}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if bl, ok := n.(*ast.BasicLit); ok && bl.Kind == token.STRING {
				if u, err := strconv.Unquote(bl.Value); err == nil {
					seen[u] = true
				}
			}
			return true
		})
		for _, ph := range []string{"{i}", "{I}", "{s}"} {
			if !seen[ph] {
				return nil, fmt.Errorf("GenerateSampleSecrets no longer replaces %s; interp.go must follow", ph)
			}
		}
		if len(m.keys) == 0 {
			return nil, fmt.Errorf("GenerateSampleSecrets has no templates")
		}
		return m, nil
	}
	return nil, fmt.Errorf("GenerateSampleSecrets has no template map")
}

type index struct {
	Commit string                `json:"commit"`
	Rules  map[string]indexEntry `json:"rules"`
	Errors []string              `json:"errors,omitempty"`
}

type indexEntry struct {
	Positives int    `json:"positives"`
	Negatives int    `json:"negatives"`
	Errors    int    `json:"errors,omitempty"`
	Source    string `json:"source"`
}

type file struct {
	record
	Commit string `json:"commit"`
}

func write(out, commit string, byID map[string]*record) error {
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	idx := index{Commit: commit, Rules: map[string]indexEntry{}}
	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		r := byID[id]
		if strings.ContainsAny(id, "/\\") || id == "index" {
			return fmt.Errorf("rule id %q cannot name a file", id)
		}
		idx.Rules[id] = indexEntry{Positives: len(r.Positives), Negatives: len(r.Negatives), Errors: len(r.Errors), Source: r.Source}
		for _, e := range r.Errors {
			if len(idx.Errors) < 300 {
				idx.Errors = append(idx.Errors, id+": "+e)
			}
		}
		if err := writeJSON(filepath.Join(out, id+".json"), file{*r, commit}); err != nil {
			return err
		}
	}
	return writeJSON(filepath.Join(out, "index.json"), idx)
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", " ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}
