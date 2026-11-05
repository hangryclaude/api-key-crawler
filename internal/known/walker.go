package known

import (
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"

	"keyguard/internal/fp"
)

// The agent and MCP config walker (STEAL P0-15, section 4.2). Keys pasted into an MCP or
// agent file never reach a .env, so learn and the engines both miss them: a UUID in a URL
// query, a Postgres DSN in `--dsn`, a bearer token in an `env` block. One reader per syntax
// (JSON, TOML, YAML) feeds one set of position rules, and two things use the result:
//
//   - learn registers every credential the rules find, so the key is protected wherever else
//     it turns up (Credentials);
//   - the pre-commit hook blocks a staged config file that holds one written out, unless the
//     vendor's environment-reference form stands in its place (Literals).
//
// Both readers are tolerant: they pull out what they can understand and report the first
// thing they could not, and a caller treats that as "partly checked", never as "clean".

// Format is a structured syntax the walker reads.
type Format int

const (
	JSON Format = iota + 1 // .json and .jsonc: comments and trailing commas are tolerated
	TOML
	YAML
)

// FormatOf picks the reader for a file by its extension.
func FormatOf(path string) (Format, bool) {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json", ".jsonc":
		return JSON, true
	case ".toml":
		return TOML, true
	case ".yml", ".yaml":
		return YAML, true
	}
	return 0, false
}

// agentConfigs are the config files of coding agents and MCP clients whose env, headers and
// args hold keys (STEAL section 4.1, the walk entries), anchored on their directory so a
// stray settings.json elsewhere is not one of them.
var agentConfigs = []struct {
	suffix string
	f      Format
}{
	{".cursor/mcp.json", JSON}, {".vscode/mcp.json", JSON}, {".copilot/mcp-config.json", JSON},
	{".kiro/settings/mcp.json", JSON}, {".devin/mcp_config.json", JSON},
	{".continue/config.yaml", YAML}, {".continue/config.json", JSON},
	{".codex/config.toml", TOML}, {".claude/settings.json", JSON},
}

// AgentConfigFormat says whether path is a coding agent's or MCP client's config file and
// how to read it. The names are the single list behind both learn and the hook's walk rule.
func AgentConfigFormat(path string) (Format, bool) {
	p := strings.ToLower(filepath.ToSlash(path))
	switch p[strings.LastIndexByte(p, '/')+1:] {
	case ".mcp.json", "opencode.json", "opencode.jsonc", "claude_desktop_config.json":
		return JSON, true
	case ".aider.conf.yml":
		return YAML, true
	}
	for _, c := range agentConfigs {
		if p == c.suffix || strings.HasSuffix(p, "/"+c.suffix) {
			return c.f, true
		}
	}
	return 0, false
}

// Literal is a credential written out in a config file. It carries where it is and a shape,
// never the value: the pre-commit message that shows it lands in terminals and transcripts.
type Literal struct {
	Path  string // key path, such as mcpServers.supabase.env.SUPABASE_ACCESS_TOKEN
	Line  int    // 1-based line of the value
	Kind  string // env | header | arg | url-password | url-param | key
	Shape string // fp.Shape of the value
	Len   int
}

// Literals reads one config file and returns the credentials it holds written out. A value
// that is an environment reference in the vendor's form (${VAR}, ${env:NAME}, {env:VAR}, a
// ${{ secrets.NAME }} expression) or a placeholder is not one. The error says the file could
// not be read to the end; the literals found before it are still returned.
func Literals(f Format, data []byte) (out []Literal, err error) {
	seen := map[string]bool{}
	err = walk(f, data, &walker{emit: func(c cred) {
		l, ok := c.literal()
		if !ok || seen[l.Path+"|"+l.Kind] {
			return
		}
		seen[l.Path+"|"+l.Kind] = true
		out = append(out, l)
	}})
	return out, err
}

// Credentials reads one config file and hands learn every value that sits where a credential
// does, under the name that places it. Learn's own filters decide which of them are worth
// keeping. A value that is only a reference is not passed on.
func Credentials(f Format, data []byte, fn func(name, value string)) error {
	return walk(f, data, &walker{emit: func(c cred) {
		if v, ok := c.learnable(); ok {
			fn(c.label(), v)
		}
	}})
}

// ArgLiterals reports the literal credentials in an argument vector: a flag such as
// --api-key, --token, --key, --dsn, --password or --auth with its value, -e NAME=value,
// -H "Name: value", and URLs that carry a password or a secret query parameter.
func ArgLiterals(args []string) (out []Literal) {
	es := make([]elem, len(args))
	for i, a := range args {
		es[i] = elem{v: a, ok: true}
	}
	w := &walker{emit: func(c cred) {
		if l, ok := c.literal(); ok {
			out = append(out, l)
		}
	}}
	safeRun(func() { w.list([]string{"args"}, es) })
	return out
}

// Placeholder reports a value that is a stand-in and not a secret: YOUR_*, <...>, "...",
// changeme, xxxxxxxx, a template hole. The pre-commit rules that look inside a file use the
// same list as learn.
func Placeholder(v string) bool { return isPlaceholder(v) }

// PairLiteral reports whether a NAME=value environment entry (kind "env") or a "Name: value"
// header (kind "header") holds a credential written out.
func PairLiteral(kind, name, value string) (Literal, bool) {
	return cred{path: name, name: name, kind: kind, value: value}.literal()
}

// walk dispatches to the reader of f. A panic in a reader is an error: the walker runs inside
// hooks that must fail open and inside learn, which must not die on one odd file.
func walk(f Format, data []byte, w *walker) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("walker: internal error: %v", r)
		}
	}()
	switch f {
	case JSON:
		err = walkJSON(data, w)
		if err != nil {
			// opencode.jsonc and friends: comments and trailing commas. Start over on the
			// cleaned text; what the strict pass emitted is emitted again, which callers dedupe.
			if c := stripJSONC(data); string(c) != string(data) {
				err = walkJSON(c, w)
			}
		}
	case TOML:
		err = walkTOML(data, w)
	case YAML:
		err = walkYAML(data, w)
	default:
		err = errors.New("walker: unknown format")
	}
	return err
}

func safeRun(fn func()) {
	defer func() { _ = recover() }()
	fn()
}

// cred is one value in a position that says credential, before anyone decides whether it is
// written out.
type cred struct {
	path   string // key path, for display
	name   string // the env var, header, flag or key that names the value
	kind   string // env | header | arg | url-password | url-param | key
	value  string
	line   int
	strong bool // the position itself says credential, whatever the name: the value of --token
}

func (c cred) label() string { return fp.Scrub(c.name) + " (" + c.kind + ")" }

// learnable is the value learn should consider: scheme words are left for learn to unwrap
// (it also decodes Basic), but anything that holds a reference is not final.
func (c cred) learnable() (string, bool) {
	v := strings.TrimSpace(c.value)
	if v == "" {
		return "", false
	}
	if _, had := stripRefs(v); had {
		return "", false
	}
	return v, true
}

// literal reports whether the value is written out, and where.
func (c cred) literal() (Literal, bool) {
	v := stripScheme(strings.TrimSpace(c.value))
	if rest, had := stripRefs(v); had {
		if trivial(rest) {
			return Literal{}, false
		}
		v = strings.TrimSpace(rest)
	}
	// A URL is judged by its password and parameters, which arrive as creds of their own; a
	// host called example.com must not make the whole of it a placeholder.
	isURL := strings.Contains(v, "://")
	if v == "" || !isURL && isPlaceholder(v) || publicByDesign(v) || isNumberish(v) {
		return Literal{}, false
	}
	var is bool
	switch {
	case strings.Contains(v, "PRIVATE KEY-----"):
		is = true
	case c.kind == "url-password" || c.kind == "url-param":
		// A local default (user postgres, password postgres, host localhost) is not a key; a
		// password with digits or capitals in it is a choice somebody made.
		is = len(v) >= 8 && !wordLike(v)
	case isURL:
		// What is left to say about a URL is a webhook-style secret in its path, under a name
		// that says secret.
		is = secretName(c.name) && urlSecretPath(v)
	case c.strong || strongName(c.name):
		// ANTHROPIC_AUTH_TOKEN=ollama and OPENAI_API_KEY=lm-studio are how a local relay is
		// told to accept anything: a short lower-case word under a token name is a stand-in,
		// where "hunter2" and a long phrase are somebody's password.
		is = len(v) >= 6 && !(wordLike(v) && len(v) < 16)
	default:
		is = credentialShaped(v)
	}
	if !is {
		return Literal{}, false
	}
	return Literal{Path: c.path, Line: c.line, Kind: c.kind, Shape: fp.Shape(v), Len: len(v)}, true
}

// ---- the position rules (STEAL 4.2) ----

// elem is one element of an array. A non-string keeps its place so that the neighbours of a
// number are still neighbours.
type elem struct {
	v    string
	line int
	ok   bool
}

// walker is what the three readers drive.
type walker struct {
	emit func(cred)
	// any, when set, hears every string leaf with the key it sits under (an array's strings
	// take the key of the array). Learn's generic pass uses it, so a JSON file is read once.
	any func(key, value string)
}

// maxListElems bounds what is remembered of one array: argument vectors are short, and a
// config that holds a million strings should not cost a million elems.
const maxListElems = 4096

// containers are keys whose children are NAME: value pairs.
var containers = map[string]string{"env": "env", "environment": "env", "headers": "header", "http_headers": "header"}

// holdsNames reports a path inside a key whose value is the NAME of an environment variable,
// not a secret: Codex's bearer_token_env_var, env_http_headers and env_key (STEAL 4.2).
func holdsNames(path []string) bool {
	for _, seg := range path {
		if nameHolder(seg) {
			return true
		}
	}
	return false
}

// nameHolder: a key whose value is the name of an environment variable (or a map of header
// names to such names). Learning one would put "OPENAI_API_KEY" in the store and make every
// commit that spells the variable a finding.
func nameHolder(key string) bool {
	s := strings.ToLower(key)
	return s == "env_key" || s == "env_http_headers" || s == "env_var" || s == "env_vars" ||
		strings.HasSuffix(s, "_env_var") || strings.HasSuffix(s, "_env_vars") || strings.HasSuffix(s, "_env_key")
}

func lastKey(path []string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] != "[]" {
			return path[i]
		}
	}
	return ""
}

// containerKind is the kind of the nearest env/headers map above the last key.
func containerKind(path []string) string {
	for i := len(path) - 2; i >= 0; i-- {
		if k, ok := containers[strings.ToLower(path[i])]; ok {
			return k
		}
	}
	return ""
}

func pathString(path []string) string {
	var b strings.Builder
	for _, seg := range path {
		if seg == "[]" {
			b.WriteString("[]")
			continue
		}
		if b.Len() > 0 {
			b.WriteByte('.')
		}
		b.WriteString(fp.Scrub(seg))
	}
	return b.String()
}

func with(path []string, segs ...string) []string {
	return append(append(make([]string, 0, len(path)+len(segs)), path...), segs...)
}

// value is a string under a key; path ends with that key.
func (w *walker) value(path []string, v string, line int) {
	key := lastKey(path)
	if holdsNames(path) {
		return
	}
	if w.any != nil {
		w.any(key, v)
	}
	if kind := containerKind(path); kind != "" {
		w.emit(cred{path: pathString(path), name: key, kind: kind, value: v, line: line})
	} else if strongName(key) {
		w.emit(cred{path: pathString(path), name: key, kind: "key", value: v, line: line})
	}
	w.urls(path, v, line)
}

// list is the string elements of an array under path. Its flags are the args rule of STEAL
// 4.2: the element after --api-key, --token, --key, --dsn, --password or --auth (and any flag
// whose name says secret) is a credential, as is the NAME=value after -e/--env and the
// "Name: value" after -H/--header.
func (w *walker) list(path []string, es []elem) {
	if holdsNames(path) {
		return
	}
	for _, e := range es {
		if e.ok {
			w.urls(path, e.v, e.line)
		}
	}
	// The docker-compose spelling: environment: [NAME=value, ...].
	if kind := containers[strings.ToLower(lastKey(path))]; kind != "" {
		for _, e := range es {
			if n, v, ok := splitPair(kind, e.v); e.ok && ok {
				w.emit(cred{path: pathString(path) + "." + fp.Scrub(n), name: n, kind: kind, value: v, line: e.line})
			}
		}
	}
	for i := 0; i < len(es); i++ {
		e := es[i]
		if !e.ok || !isFlag(e.v) {
			continue
		}
		flag, inline, hasEq := strings.Cut(e.v, "=")
		name := strings.TrimLeft(flag, "-")
		at := pathString(path) + " " + flag
		switch kind := pairFlags[flag]; {
		case kind != "":
			// -e KEY=value, --header "Name: value": options that take several, so read on until
			// the next flag.
			vals := []elem{}
			if hasEq {
				vals = append(vals, elem{v: inline, line: e.line, ok: true})
			}
			for j, start := i+1, i; !hasEq && j < len(es) && es[j].ok && !isFlag(es[j].v) && j <= start+16; j++ {
				vals = append(vals, es[j])
				i = j
			}
			for _, p := range vals {
				if n, v, ok := splitPair(kind, p.v); ok {
					w.emit(cred{path: at + " " + fp.Scrub(n), name: n, kind: kind, value: v, line: p.line})
				}
			}
		case secretName(name):
			strong := namedFlags[name] || strongName(name)
			switch {
			case hasEq:
				w.emit(cred{path: at, name: name, kind: "arg", value: inline, line: e.line, strong: strong})
			case i+1 < len(es) && es[i+1].ok && !isFlag(es[i+1].v):
				w.emit(cred{path: at, name: name, kind: "arg", value: es[i+1].v, line: es[i+1].line, strong: strong})
				i++
			}
		}
	}
}

// pairFlags are the options whose values are pairs, and how to split them.
var pairFlags = map[string]string{"-e": "env", "--env": "env", "-H": "header", "--header": "header", "--headers": "header"}

// namedFlags are the flags STEAL 4.2 lists: the position is a credential whatever the value
// looks like. Any other flag whose name says secret is judged by its name's strength.
var namedFlags = map[string]bool{"api-key": true, "token": true, "key": true, "dsn": true, "password": true, "auth": true}

func isFlag(s string) bool {
	if len(s) < 2 || s[0] != '-' {
		return false
	}
	return !(s[1] >= '0' && s[1] <= '9') // -1 is a number
}

// splitPair splits NAME=value for an env entry and "Name: value" for a header.
func splitPair(kind, s string) (name, value string, ok bool) {
	sep := "="
	if kind == "header" {
		sep = ":"
	}
	n, v, found := strings.Cut(s, sep)
	n = strings.TrimSpace(n)
	if !found || n == "" || strings.ContainsAny(n, " \t=\"'") && kind == "env" {
		return "", "", false
	}
	return n, strings.TrimSpace(v), true
}

// urlParamKeys are the query keys STEAL 4.2 names; secretName widens them.
var urlParamKeys = map[string]bool{"key": true, "api_key": true, "apikey": true, "token": true, "secret": true, "sig": true}

// urls applies the URL rule to any string: the userinfo password, and the secret query
// parameters.
func (w *walker) urls(path []string, v string, line int) {
	if !strings.Contains(v, "://") {
		return
	}
	base := pathString(path)
	for _, pw := range urlPasswords(v) {
		w.emit(cred{path: base, name: "password", kind: "url-password", value: pw, line: line})
	}
	for from := 0; ; {
		j := strings.Index(v[from:], "://")
		if j < 0 {
			break
		}
		from += j + 3
		rest := v[from:]
		end := strings.IndexAny(rest, "#\"'` \t\r\n<>)]}")
		if end >= 0 {
			rest = rest[:end]
		}
		_, query, ok := strings.Cut(rest, "?")
		if !ok {
			continue
		}
		for _, pair := range strings.FieldsFunc(query, func(r rune) bool { return r == '&' || r == ';' }) {
			k, val, ok := strings.Cut(pair, "=")
			if !ok {
				continue
			}
			if dk, err := url.QueryUnescape(k); err == nil {
				k = dk
			}
			if dv, err := url.QueryUnescape(val); err == nil {
				val = dv
			}
			if lk := strings.ToLower(k); urlParamKeys[lk] || secretName(k) {
				w.emit(cred{path: base + "?" + fp.Scrub(k), name: k, kind: "url-param", value: val, line: line})
			}
		}
	}
}

// ---- names and values ----

// strongSuffixes end a name that is a credential whatever else is in it: apiKey, X-Api-Key,
// OPENAI_API_KEY, GITHUB_PERSONAL_ACCESS_TOKEN, client_secret, DB_PASSWORD.
var strongSuffixes = []string{
	"apikey", "accesskey", "secretkey", "privatekey", "authkey", "token", "secret", "password",
	"passwd", "pwd", "passphrase", "authorization", "bearer", "credential", "credentials",
}

// weakWords make a name worth a look but prove nothing alone: a bare "key" may be a keyboard
// shortcut and "auth" a mode.
var weakWords = map[string]bool{
	"key": true, "keys": true, "auth": true, "session": true, "cookie": true, "sid": true, "sig": true,
	"signature": true, "signing": true, "cred": true, "creds": true, "dsn": true, "webhook": true, "pass": true,
}

func squeeze(name string) string {
	return strings.Map(func(r rune) rune {
		if r == '_' || r == '-' || r == '.' || r == ' ' {
			return -1
		}
		if r >= 'A' && r <= 'Z' {
			return r + 32
		}
		return r
	}, name)
}

// strongName: the name says the value is a credential.
func strongName(name string) bool {
	s := squeeze(name)
	if len(s) > 80 {
		return false
	}
	for _, suf := range strongSuffixes {
		if strings.HasSuffix(s, suf) {
			return true
		}
	}
	return false
}

// secretName: the name says it may be one.
func secretName(name string) bool {
	if strongName(name) {
		return true
	}
	for _, w := range splitName(name) {
		if weakWords[w] {
			return true
		}
	}
	return false
}

// splitName splits a name into lower-case words at delimiters and at camelCase boundaries.
func splitName(name string) []string {
	var words []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			words = append(words, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}
	prevLower := false
	for _, r := range name {
		switch {
		case r == '_' || r == '-' || r == '.' || r == ' ' || r == ':' || r == '/':
			flush()
			prevLower = false
		case r >= 'A' && r <= 'Z':
			if prevLower {
				flush()
			}
			cur = append(cur, r)
			prevLower = false
		default:
			cur = append(cur, r)
			prevLower = r >= 'a' && r <= 'z' || r >= '0' && r <= '9'
		}
	}
	flush()
	return words
}

var (
	reGHExpr   = regexp.MustCompile(`\$\{\{[^}]*\}\}`)        // Continue: ${{ secrets.NAME }}
	reDollarBr = regexp.MustCompile(`\$\{[^}]*\}`)            // ${VAR}, ${VAR:-default} (Claude Code); ${env:NAME} (Cursor); ${VARIABLE_NAME} (Kiro)
	reBrace    = regexp.MustCompile(`\{(?:env|file):[^}]*\}`) // opencode: {env:VAR}, {file:path}
	reDollarID = regexp.MustCompile(`^\$[A-Za-z_][A-Za-z0-9_]*$`)
)

// stripRefs removes the vendor environment-reference forms from v and says whether any was
// there. A ${VAR:-default} keeps its default: it is written out in the file, and a secret
// there is as exposed as any other.
func stripRefs(v string) (string, bool) {
	had := false
	if strings.Contains(v, "${{") {
		n := reGHExpr.ReplaceAllString(v, "")
		had, v = had || n != v, n
	}
	if strings.Contains(v, "${") {
		v = reDollarBr.ReplaceAllStringFunc(v, func(m string) string {
			had = true
			inner := m[2 : len(m)-1]
			if name, def, ok := strings.Cut(inner, ":-"); ok && isIdent(name) {
				return def
			}
			return ""
		})
	}
	if strings.Contains(v, "{env:") || strings.Contains(v, "{file:") {
		n := reBrace.ReplaceAllString(v, "")
		had, v = had || n != v, n
	}
	if reDollarID.MatchString(strings.TrimSpace(v)) {
		return "", true
	}
	return v, had
}

// trivial: nothing left that could be a secret once the references are gone (a colon between
// two of them, a space).
func trivial(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
			return false
		}
	}
	return true
}

// stripScheme drops an Authorization scheme word, so the token is judged and not "Bearer".
func stripScheme(v string) string {
	for _, scheme := range []string{"bearer ", "basic ", "token "} {
		if len(v) > len(scheme) && strings.EqualFold(v[:len(scheme)], scheme) {
			return strings.TrimSpace(v[len(scheme):])
		}
	}
	return v
}

// wordLike: lower-case words and separators only, which is how a mode or a slug looks and
// nothing like a key (a random 20-character alphanumeric has no digit or capital about one
// time in 10^8).
func wordLike(v string) bool {
	for i := 0; i < len(v); i++ {
		c := v[i]
		if !(c >= 'a' && c <= 'z' || c == '-' || c == '_' || c == ' ' || c == '.' || c == '/' || c == ':') {
			return false
		}
	}
	return true
}

// credentialShaped: a value that looks like a key whatever its name is. Long, no spaces,
// not a path or a URL, not words, and random enough.
func credentialShaped(v string) bool {
	if len(v) < 20 || strings.ContainsAny(v, " \t\n") || isPath(v) || plainURL(v) || wordLike(v) {
		return false
	}
	return fp.Entropy(v) >= 3.3
}
