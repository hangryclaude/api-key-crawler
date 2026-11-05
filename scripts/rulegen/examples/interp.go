package main

import (
	"fmt"
	"go/ast"
	"go/token"
	"hash/fnv"
	"math/rand/v2"
	"strconv"
	"strings"
)

// The generator checks every rule against test strings it builds in Go: literals, the
// assignment templates of utils.GenerateSampleSecrets, and secrets drawn from a regex. This is
// a small interpreter for exactly the part of Go those functions use, run on the syntax tree of
// the upstream source, so the strings come from the upstream code and not from a copy of it.
// Whatever it cannot evaluate (a loop, a type conversion) is reported against its rule and
// left out; it never guesses.
//
// Values are string, int64, float64, bool, []any, *omap, *exVal, *structVal and nil.

// omap is a map literal with its keys in source order, so that a run is deterministic.
type omap struct {
	keys []string
	vals map[string]any
}

// exVal is a sample string with the secret it was built around, when the generator knew it.
type exVal struct{ text, secret string }

// structVal is a composite literal of a type the interpreter only reads the rule id of.
type structVal struct{ ruleID any }

type pkg struct {
	funcs map[string]*ast.FuncDecl
	decls map[string]ast.Expr // package-level const and var initialisers
	cache map[string]any
	busy  map[string]bool
}

type env struct {
	vars map[string]any
	pkg  *pkg
	fn   string
	errs []string
}

type example struct {
	Text   string `json:"text"`
	Path   string `json:"path,omitempty"`
	Secret string `json:"secret,omitempty"`
}

type record struct {
	Rule      string    `json:"rule"`
	Source    string    `json:"source"`
	Positives []example `json:"positives"`
	Negatives []example `json:"negatives"`
	Errors    []string  `json:"errors,omitempty"`
}

type interp struct {
	fset    *token.FileSet
	rules   *pkg
	utils   *pkg
	records []*record
	// samples are the assignment templates of utils.GenerateSampleSecrets, read from its source.
	samples *omap
}

func (in *interp) at(n ast.Node) string {
	p := in.fset.Position(n.Pos())
	return fmt.Sprintf("%s:%d", baseName(p.Filename), p.Line)
}

func baseName(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}

func (in *interp) rngAt(n ast.Node) *rand.Rand {
	p := in.fset.Position(n.Pos())
	h := fnv.New64a()
	fmt.Fprintf(h, "%s:%d", baseName(p.Filename), p.Offset)
	s := h.Sum64()
	return rand.New(rand.NewPCG(s, s^0x9e3779b97f4a7c15))
}

// run executes a rule function that takes no arguments; every utils.Validate it reaches records
// the rule's examples.
func (in *interp) run(fd *ast.FuncDecl) {
	ev := &env{vars: map[string]any{}, pkg: in.rules, fn: fd.Name.Name}
	in.exec(fd.Body, ev)
}

func (in *interp) exec(b *ast.BlockStmt, ev *env) (any, bool) {
	for _, st := range b.List {
		switch s := st.(type) {
		case *ast.AssignStmt:
			in.assign(s, ev)
		case *ast.DeclStmt:
			in.decl(s, ev)
		case *ast.ReturnStmt:
			if len(s.Results) == 0 {
				return nil, true
			}
			v, err := in.eval(s.Results[0], ev)
			if err != nil {
				ev.errs = append(ev.errs, in.at(s)+": "+err.Error())
			}
			return v, true
		case *ast.ExprStmt, *ast.EmptyStmt:
		case *ast.BlockStmt:
			if v, done := in.exec(s, ev); done {
				return v, true
			}
		default:
			ev.errs = append(ev.errs, fmt.Sprintf("%s: statement %T is not evaluated", in.at(st), st))
		}
	}
	return nil, false
}

func (in *interp) assign(s *ast.AssignStmt, ev *env) {
	if len(s.Lhs) != len(s.Rhs) {
		ev.errs = append(ev.errs, in.at(s)+": a multi-value assignment is not evaluated")
		return
	}
	for i, l := range s.Lhs {
		id, ok := l.(*ast.Ident)
		if !ok {
			ev.errs = append(ev.errs, in.at(s)+": assignment to a non-name is not evaluated")
			continue
		}
		v, err := in.eval(s.Rhs[i], ev)
		if err != nil {
			ev.errs = append(ev.errs, in.at(s)+": "+err.Error())
			continue
		}
		if s.Tok == token.ADD_ASSIGN {
			old, ok := ev.vars[id.Name]
			if !ok {
				ev.errs = append(ev.errs, in.at(s)+": += on an unset name")
				continue
			}
			if v, err = add(old, v); err != nil {
				ev.errs = append(ev.errs, in.at(s)+": "+err.Error())
				continue
			}
		}
		if id.Name != "_" {
			ev.vars[id.Name] = v
		}
	}
}

func (in *interp) decl(s *ast.DeclStmt, ev *env) {
	gd, ok := s.Decl.(*ast.GenDecl)
	if !ok || (gd.Tok != token.VAR && gd.Tok != token.CONST) {
		return
	}
	for _, sp := range gd.Specs {
		vs := sp.(*ast.ValueSpec)
		for i, n := range vs.Names {
			if len(vs.Values) == 0 {
				ev.vars[n.Name] = []any(nil) // `var examples []string`
				continue
			}
			if i >= len(vs.Values) {
				ev.errs = append(ev.errs, in.at(vs)+": a multi-value declaration is not evaluated")
				continue
			}
			v, err := in.eval(vs.Values[i], ev)
			if err != nil {
				ev.errs = append(ev.errs, in.at(vs)+": "+err.Error())
				continue
			}
			ev.vars[n.Name] = v
		}
	}
}

func (in *interp) eval(e ast.Expr, ev *env) (any, error) {
	switch x := e.(type) {
	case *ast.BasicLit:
		switch x.Kind {
		case token.STRING:
			return strconv.Unquote(x.Value)
		case token.INT:
			return strconv.ParseInt(x.Value, 0, 64)
		case token.FLOAT:
			return strconv.ParseFloat(x.Value, 64)
		}
	case *ast.ParenExpr:
		return in.eval(x.X, ev)
	case *ast.Ident:
		return in.ident(x, ev)
	case *ast.BinaryExpr:
		l, err := in.eval(x.X, ev)
		if err != nil {
			return nil, err
		}
		r, err := in.eval(x.Y, ev)
		if err != nil {
			return nil, err
		}
		return arith(x.Op, l, r)
	case *ast.SliceExpr:
		return in.slice(x, ev)
	case *ast.UnaryExpr:
		if x.Op == token.AND {
			return in.eval(x.X, ev)
		}
	case *ast.CompositeLit:
		return in.composite(x, ev)
	case *ast.CallExpr:
		return in.call(x, ev)
	}
	return nil, fmt.Errorf("%T is not evaluated", e)
}

func (in *interp) ident(x *ast.Ident, ev *env) (any, error) {
	switch x.Name {
	case "true":
		return true, nil
	case "false":
		return false, nil
	case "nil":
		return nil, nil
	}
	if v, ok := ev.vars[x.Name]; ok {
		return v, nil
	}
	p := ev.pkg
	if v, ok := p.cache[x.Name]; ok {
		return v, nil
	}
	init, ok := p.decls[x.Name]
	if !ok {
		return nil, fmt.Errorf("name %s is not defined", x.Name)
	}
	if p.busy[x.Name] {
		return nil, fmt.Errorf("name %s is defined in terms of itself", x.Name)
	}
	p.busy[x.Name] = true
	v, err := in.eval(init, &env{vars: map[string]any{}, pkg: p, fn: x.Name})
	delete(p.busy, x.Name)
	if err != nil {
		return nil, err
	}
	p.cache[x.Name] = v
	return v, nil
}

// arith is the operators the example code uses: + on strings and numbers, and integer - * /.
func arith(op token.Token, l, r any) (any, error) {
	if op == token.ADD {
		return add(l, r)
	}
	a, aok := l.(int64)
	b, bok := r.(int64)
	if !aok || !bok {
		return nil, fmt.Errorf("%v of %T and %T is not evaluated", op, l, r)
	}
	switch op {
	case token.SUB:
		return a - b, nil
	case token.MUL:
		return a * b, nil
	case token.QUO:
		if b == 0 {
			return nil, fmt.Errorf("division by zero")
		}
		return a / b, nil
	}
	return nil, fmt.Errorf("operator %v is not evaluated", op)
}

// slice is s[lo:hi] on a string.
func (in *interp) slice(x *ast.SliceExpr, ev *env) (any, error) {
	v, err := in.eval(x.X, ev)
	if err != nil {
		return nil, err
	}
	s, ok := text(v)
	if !ok || x.Slice3 {
		return nil, fmt.Errorf("slice of %T is not evaluated", v)
	}
	bound := func(e ast.Expr, def int) (int, error) {
		if e == nil {
			return def, nil
		}
		b, err := in.eval(e, ev)
		if err != nil {
			return 0, err
		}
		n, ok := b.(int64)
		if !ok || n < 0 || int(n) > len(s) {
			return 0, fmt.Errorf("slice bound %v out of range", b)
		}
		return int(n), nil
	}
	lo, err := bound(x.Low, 0)
	if err != nil {
		return nil, err
	}
	hi, err := bound(x.High, len(s))
	if err != nil {
		return nil, err
	}
	if lo > hi {
		return nil, fmt.Errorf("slice bounds %d:%d", lo, hi)
	}
	return s[lo:hi], nil
}

func add(l, r any) (any, error) {
	switch a := l.(type) {
	case string:
		if b, ok := r.(string); ok {
			return a + b, nil
		}
	case int64:
		if b, ok := r.(int64); ok {
			return a + b, nil
		}
	case float64:
		if b, ok := r.(float64); ok {
			return a + b, nil
		}
	case *exVal:
		if b, ok := r.(string); ok {
			return a.text + b, nil
		}
	}
	return nil, fmt.Errorf("+ of %T and %T is not evaluated", l, r)
}

// text is the string a value stands for when it is joined into a bigger one.
func text(v any) (string, bool) {
	switch x := v.(type) {
	case string:
		return x, true
	case *exVal:
		return x.text, true
	}
	return "", false
}

func (in *interp) composite(x *ast.CompositeLit, ev *env) (any, error) {
	switch t := x.Type.(type) {
	case *ast.ArrayType:
		var out []any
		for _, el := range x.Elts {
			v, err := in.eval(el, ev)
			if err != nil {
				ev.errs = append(ev.errs, in.at(el)+": "+err.Error())
				continue
			}
			out = append(out, v)
		}
		return out, nil
	case *ast.MapType:
		m := &omap{vals: map[string]any{}}
		for _, el := range x.Elts {
			kv, ok := el.(*ast.KeyValueExpr)
			if !ok {
				return nil, fmt.Errorf("%T in a map literal", el)
			}
			k, err := in.eval(kv.Key, ev)
			if err != nil {
				return nil, err
			}
			ks, ok := k.(string)
			if !ok {
				return nil, fmt.Errorf("a map key of type %T", k)
			}
			v, err := in.eval(kv.Value, ev)
			if err != nil {
				ev.errs = append(ev.errs, in.at(kv)+": "+err.Error())
				continue
			}
			if _, dup := m.vals[ks]; !dup {
				m.keys = append(m.keys, ks)
			}
			m.vals[ks] = v
		}
		return m, nil
	case *ast.SelectorExpr:
		// config.Rule{...}: only the id is read; the regex and the filters come from the generated TOML.
		sv := &structVal{}
		for _, el := range x.Elts {
			if kv, ok := el.(*ast.KeyValueExpr); ok {
				if k, ok := kv.Key.(*ast.Ident); ok && k.Name == "RuleID" {
					v, err := in.eval(kv.Value, ev)
					if err != nil {
						return nil, err
					}
					sv.ruleID = v
				}
			}
		}
		return sv, nil
	default:
		return nil, fmt.Errorf("composite literal of %T is not evaluated", t)
	}
}

func (in *interp) args(c *ast.CallExpr, ev *env) ([]any, error) {
	var out []any
	for i, a := range c.Args {
		v, err := in.eval(a, ev)
		if err != nil {
			return nil, err
		}
		if c.Ellipsis.IsValid() && i == len(c.Args)-1 {
			l, ok := v.([]any)
			if !ok && v != nil {
				return nil, fmt.Errorf("spread of %T", v)
			}
			out = append(out, l...)
			continue
		}
		out = append(out, v)
	}
	return out, nil
}

func (in *interp) call(c *ast.CallExpr, ev *env) (any, error) {
	switch f := c.Fun.(type) {
	case *ast.Ident:
		if f.Name == "len" && len(c.Args) == 1 {
			v, err := in.eval(c.Args[0], ev)
			if err != nil {
				return nil, err
			}
			if t, ok := text(v); ok {
				return int64(len(t)), nil
			}
			if l, ok := v.([]any); ok {
				return int64(len(l)), nil
			}
			return nil, fmt.Errorf("len of %T", v)
		}
		if f.Name == "append" {
			if len(c.Args) == 0 {
				return nil, fmt.Errorf("append without arguments")
			}
			base, err := in.eval(c.Args[0], ev)
			if err != nil {
				return nil, err
			}
			l, ok := base.([]any)
			if !ok && base != nil {
				return nil, fmt.Errorf("append to %T", base)
			}
			// An element that cannot be evaluated is left out and reported; the others still count.
			out := append([]any(nil), l...)
			for i, a := range c.Args[1:] {
				v, err := in.eval(a, ev)
				if err != nil {
					ev.errs = append(ev.errs, in.at(a)+": "+err.Error())
					continue
				}
				if c.Ellipsis.IsValid() && i == len(c.Args)-2 {
					spread, ok := v.([]any)
					if !ok && v != nil {
						ev.errs = append(ev.errs, in.at(a)+": spread of a non-list")
						continue
					}
					out = append(out, spread...)
					continue
				}
				out = append(out, v)
			}
			return out, nil
		}
		fd, ok := ev.pkg.funcs[f.Name]
		if !ok {
			return nil, fmt.Errorf("function %s is not defined", f.Name)
		}
		args, err := in.args(c, ev)
		if err != nil {
			return nil, err
		}
		return in.callFunc(fd, ev.pkg, args)
	case *ast.SelectorExpr:
		pk, ok := f.X.(*ast.Ident)
		if !ok {
			break
		}
		return in.pkgCall(pk.Name, f.Sel.Name, c, ev)
	}
	return nil, fmt.Errorf("call of %T is not evaluated", c.Fun)
}

func (in *interp) callFunc(fd *ast.FuncDecl, p *pkg, args []any) (any, error) {
	ev := &env{vars: map[string]any{}, pkg: p, fn: fd.Name.Name}
	i := 0
	for _, field := range fd.Type.Params.List {
		for _, n := range field.Names {
			if i >= len(args) {
				return nil, fmt.Errorf("%s called with too few arguments", fd.Name.Name)
			}
			ev.vars[n.Name] = args[i]
			i++
		}
	}
	v, _ := in.exec(fd.Body, ev)
	return v, nil
}

func (in *interp) pkgCall(pk, name string, c *ast.CallExpr, ev *env) (any, error) {
	args, err := in.args(c, ev)
	if err != nil {
		return nil, err
	}
	str := func(i int) (string, error) {
		if i >= len(args) {
			return "", fmt.Errorf("%s.%s: missing argument %d", pk, name, i)
		}
		s, ok := text(args[i])
		if !ok {
			return "", fmt.Errorf("%s.%s: argument %d is a %T", pk, name, i, args[i])
		}
		return s, nil
	}
	switch pk + "." + name {
	case "fmt.Sprintf":
		f, err := str(0)
		if err != nil {
			return nil, err
		}
		vs := make([]any, 0, len(args)-1)
		for _, a := range args[1:] {
			if s, ok := text(a); ok {
				a = s
			}
			vs = append(vs, a)
		}
		return fmt.Sprintf(f, vs...), nil
	case "strings.Repeat":
		s, err := str(0)
		n, ok := args[1].(int64)
		if err != nil || !ok || n < 0 || n > 1<<20 {
			return nil, fmt.Errorf("strings.Repeat: bad arguments")
		}
		return strings.Repeat(s, int(n)), nil
	case "strings.ToUpper", "strings.ToLower":
		s, err := str(0)
		if err != nil {
			return nil, err
		}
		if name == "ToUpper" {
			return strings.ToUpper(s), nil
		}
		return strings.ToLower(s), nil
	case "strconv.Itoa":
		n, ok := args[0].(int64)
		if !ok {
			return nil, fmt.Errorf("strconv.Itoa of %T", args[0])
		}
		return strconv.FormatInt(n, 10), nil
	case "secrets.NewSecret":
		re, err := str(0)
		if err != nil {
			return nil, err
		}
		return sampleRegex(re, in.rngAt(c))
	case "secrets.NewSecretWithEntropy":
		re, err := str(0)
		if err != nil {
			return nil, err
		}
		min, ok := args[1].(float64)
		if !ok {
			if n, isInt := args[1].(int64); isInt {
				min, ok = float64(n), true
			}
		}
		if !ok {
			return nil, fmt.Errorf("secrets.NewSecretWithEntropy: entropy is a %T", args[1])
		}
		rng := in.rngAt(c)
		for range 2000 {
			s, err := sampleRegex(re, rng)
			if err != nil {
				return nil, err
			}
			if entropy(s) >= min {
				return s, nil
			}
		}
		return nil, fmt.Errorf("no draw of the regex reaches entropy %.1f", min)
	case "utils.GenerateSampleSecrets":
		id, err := str(0)
		if err != nil {
			return nil, err
		}
		secret, err := str(1)
		if err != nil {
			return nil, err
		}
		return in.sampleSecrets(id, secret), nil
	case "utils.GenerateSampleSecret":
		fd, ok := in.utils.funcs[name]
		if !ok {
			return nil, fmt.Errorf("utils.%s is not defined", name)
		}
		t, err := in.callFunc(fd, in.utils, args)
		if err != nil {
			return nil, err
		}
		ts, _ := t.(string)
		secret, _ := str(1)
		return &exVal{text: ts, secret: secret}, nil
	case "utils.Validate", "utils.ValidateWithPaths":
		return in.validate(name, c, args, ev)
	}
	if pk == "utils" {
		fd, ok := in.utils.funcs[name]
		if !ok {
			return nil, fmt.Errorf("utils.%s is not defined", name)
		}
		return in.callFunc(fd, in.utils, args)
	}
	return nil, fmt.Errorf("%s.%s is not evaluated", pk, name)
}

// sampleSecrets is utils.GenerateSampleSecrets: each template of the upstream function with
// {i} the identifier, {I} the upper-cased identifier and {s} the secret.
func (in *interp) sampleSecrets(id, secret string) []any {
	r := strings.NewReplacer("{i}", id, "{I}", strings.ToUpper(id), "{s}", secret)
	var out []any
	for _, k := range in.samples.keys {
		if t, ok := in.samples.vals[k].(string); ok {
			out = append(out, &exVal{text: r.Replace(t), secret: secret})
		}
	}
	return out
}

func (in *interp) validate(name string, c *ast.CallExpr, args []any, ev *env) (any, error) {
	if len(args) != 3 {
		return nil, fmt.Errorf("utils.%s with %d arguments", name, len(args))
	}
	sv, ok := args[0].(*structVal)
	if !ok {
		return nil, fmt.Errorf("utils.%s: the rule is a %T", name, args[0])
	}
	id, ok := sv.ruleID.(string)
	if !ok || id == "" {
		return nil, fmt.Errorf("utils.%s: the rule has no id", name)
	}
	rec := &record{Rule: id, Source: baseName(in.fset.Position(c.Pos()).Filename), Errors: append([]string(nil), ev.errs...)}
	rec.Positives = in.examples(args[1], rec)
	rec.Negatives = in.examples(args[2], rec)
	in.records = append(in.records, rec)
	return sv, nil
}

func (in *interp) examples(v any, rec *record) []example {
	var out []example
	switch x := v.(type) {
	case nil:
	case []any:
		for _, el := range x {
			switch e := el.(type) {
			case string:
				out = append(out, example{Text: e})
			case *exVal:
				out = append(out, example{Text: e.text, Secret: e.secret})
			case []any:
				// utils.GenerateSampleSecrets(...)... spread into a list, or a list inside a list
				out = append(out, in.examples(e, rec)...)
			default:
				rec.Errors = append(rec.Errors, fmt.Sprintf("a list element of type %T is not an example", el))
			}
		}
	case *omap:
		for _, k := range x.keys {
			if s, ok := text(x.vals[k]); ok {
				out = append(out, example{Text: s, Path: k})
			}
		}
	default:
		rec.Errors = append(rec.Errors, fmt.Sprintf("examples of type %T are not evaluated", v))
	}
	return out
}
