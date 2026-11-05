package hooks

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"

	"keyguard/internal/known"
)

// Action is what a filename rule does when it matches (STEAL section 4).
type Action int

const (
	ActBlock   Action = iota + 1 // the name alone is a finding
	ActContent                   // a finding when the content test passes
	ActWalk                      // a finding for each credential the config walker finds written out
	ActGuard                     // scanner config: staging it is a finding, and the agent guard refuses to write it
	ActWarn                      // printed, never blocks
)

// nameRule is one filename rule from PLAN.md or STEAL section 4.1. A rule with a content test
// only fires when the staged blob passes it: `*.pem` is fine until it holds a private key.
type nameRule struct {
	id      string
	why     string
	action  Action
	content func(b []byte) bool // ActContent: the finding. ActWarn: warn only when it passes (nil: always)
	allowIf func(b []byte) bool // ActBlock: content that makes the file fine after all (dotenvx ciphertext)
	walk    known.Format        // ActWalk: the syntax to read it as
}

// needsBlob: the verdict depends on what is in the file, so the staged blob has to be read.
func (r nameRule) needsBlob() bool {
	return r.content != nil || r.allowIf != nil || r.action == ActWalk
}

// Rule is the part of a filename rule other packages may see. The agent guard refuses to
// write a path whose rule is ActGuard.
type Rule struct {
	ID     string
	Why    string
	Action Action
}

// PathRule says which filename rule, if any, applies to a repo-relative path.
func PathRule(p string) (Rule, bool) {
	r, ok := classify(p)
	return Rule{ID: r.id, Why: r.why, Action: r.action}, ok
}

// readLimit bounds how much of a candidate file is read for a content test. Key and
// credential files are small; this only stops a pathological blob from stalling a commit.
const readLimit = 2 << 20

// walkLimit is the same for the config files the walker reads whole: a JSON file cut in the
// middle does not parse.
const walkLimit = 8 << 20

// envTemplates are the .env.<suffix> names that document a variable list. They are not
// blocked by name, but their content is still scanned like any other file. A .dev.vars.<suffix>
// is the same kind of file.
var envTemplates = []string{"example", "sample", "template", "dist", "defaults"}

// classify returns the rule that applies to a staged path, if any. Matching is on the
// lower-cased path: macOS volumes are case-insensitive, so `.ENV` is a `.env`.
func classify(p string) (nameRule, bool) {
	lp := strings.ToLower(p)
	base := lp[strings.LastIndexByte(lp, '/')+1:]
	switch {
	// ---- PLAN.md ----
	case base == ".env" || strings.HasPrefix(base, ".env."):
		if isEnvTemplate(base) {
			return nameRule{}, false
		}
		return nameRule{id: "env-file", why: "env file: holds real values", action: ActBlock, allowIf: dotenvxCiphertext}, true
	case isSSHKeyName(base):
		return block("ssh-key", "SSH private key file"), true
	case hasAnySuffix(base, ".p12", ".pfx", ".jks", ".keystore"):
		return block("keystore", "certificate or key store bundle"), true
	case base == ".git-credentials":
		return block("git-credentials", "git stores logins in this file"), true
	case base == ".netrc":
		return block("netrc", "netrc holds logins"), true
	case strings.HasSuffix(base, ".tfstate"):
		return block("tfstate", "terraform state keeps secrets in plain text"), true
	case hasAnySuffix(base, ".pem", ".key"):
		return withContent("pem-key", "file holds a private key", contains("PRIVATE KEY")), true
	case base == ".npmrc":
		return withContent("npmrc-token", "npm auth token in .npmrc", npmrcToken), true
	case base == ".pypirc":
		return withContent("pypirc-token", "PyPI password or token in .pypirc", pypircPassword), true
	case isServiceAccountName(base):
		return withContent("service-account", "service account key file", contains("private_key")), true

	// ---- STEAL 4.1: scanner suppression. Staging one is a finding; `keyguard allow` lets one
	// version of the file through. The agent guard refuses to write them at all.
	case base == ".betterleaksignore" || base == ".gitleaksignore" || base == ".trufflehogignore":
		return guarded("ignore-file", "scanner ignore file: a line here hides a finding"), true
	case base == ".betterleaks.toml" || base == ".gitleaks.toml":
		return guarded("scanner-config", "scanner config: an allowlist here switches it off"), true
	case base == ".secrets.baseline" || base == ".gitguardian.yaml" || base == ".gitguardian.yml":
		return guarded("baseline", "scanner baseline: it silences findings"), true
	case pathEnd(lp, ".github/secret_scanning.yml") || pathEnd(lp, ".github/secret_scanning.yaml"):
		return guarded("gh-scan-config", "paths-ignore here exempts files from GitHub scanning"), true

	// ---- STEAL 4.1: things that can rewire or blind the hooks. Printed only.
	case base == ".pre-commit-config.yaml" || base == "lefthook.yml" || under(lp, ".husky"):
		return nameRule{id: "hook-manager", why: "can rewire local hooks; keyguard's still run beside it", action: ActWarn}, true
	case base == ".gitattributes":
		return nameRule{id: "gitattributes", why: ".gitattributes hides paths from diff-reading scanners", action: ActWarn, content: blindsDiff}, true

	// ---- STEAL 4.1: agent and MCP configs. Walked: a literal credential blocks, a reference
	// in the vendor's form does not.
	case pathEnd(lp, ".claude/settings.local.json"):
		return block("claude-local", "Claude Code personal settings: keys live here"), true
	case pathEnd(lp, ".devin/mcp_config.local.json"):
		return block("devin-local", "Devin local MCP config: keys live here"), true
	case pathEnd(lp, ".codex/auth.json"):
		return block("codex-auth", "Codex login tokens"), true
	case isAgentConfigName(lp):
		f, _ := known.AgentConfigFormat(lp)
		id := "mcp-config"
		if pathEnd(lp, ".claude/settings.json") {
			id = "claude-settings"
		}
		return nameRule{id: id, why: "config file with a credential written out", action: ActWalk, walk: f}, true

	// ---- STEAL 4.1: transcripts, captures and browser state.
	case base == ".aider.chat.history.md" || base == ".aider.input.history" || base == ".aider.llm.history" || under(lp, ".specstory"):
		return block("agent-history", "agent chat history: full prompts and outputs"), true
	case under(lp, ".claude/projects") || under(lp, ".claude/file-history") || under(lp, ".claude/paste-cache") ||
		under(lp, ".codex/sessions") || pathEnd(lp, ".claude/history.jsonl") || pathEnd(lp, ".codex/history.jsonl"):
		return block("claude-state", "agent transcript or file history"), true
	case strings.HasSuffix(base, ".heapsnapshot"):
		return block("heapsnapshot", "heap snapshot: holds the whole conversation"), true
	case under(lp, "playwright/.auth") || strings.HasPrefix(base, "storagestate") && strings.HasSuffix(base, ".json"):
		return block("pw-state", "browser session: cookies and local storage"), true
	case strings.HasSuffix(base, ".har"):
		return block("har", "HAR capture: auth and cookie headers"), true
	case base == "cookies.txt":
		return block("cookies-txt", "browser cookies: live session tokens"), true
	case strings.Contains(base, "cookie") && strings.HasSuffix(base, ".json"):
		return withContent("cookie-json", "browser cookie export", cookieJSON), true
	case strings.Contains(base, "cookie") && !strings.HasSuffix(base, ".json"):
		return withContent("cookies-txt", "browser cookies: live session tokens", netscapeCookies), true
	case strings.HasSuffix(base, ".postman_environment.json"):
		return block("postman-env", "Postman environment: values are plain text"), true
	case strings.HasSuffix(base, ".bru"):
		return withContent("bruno", "Bruno file with an auth block or plain vars", bruCredentials), true
	case under(lp, "cassettes") && hasAnySuffix(base, ".yml", ".yaml", ".json"):
		return block("vcr", "recorded HTTP cassette: requests and responses"), true

	// ---- STEAL 4.1: Terraform and Cloudflare.
	case strings.Contains(base, ".tfstate."):
		return block("tfstate-x", "terraform state backup keeps secrets in plain text"), true
	case hasAnySuffix(base, ".tfvars", ".tfvars.json"):
		return block("tfvars", "terraform variables may hold secrets"), true
	case base == "crash.log" || strings.HasPrefix(base, "crash.") && strings.HasSuffix(base, ".log"):
		return block("tf-crash", "terraform crash log carries state and variables"), true
	case base == ".terraformrc" || base == "terraform.rc":
		return block("tf-cli", "terraform CLI credentials"), true
	case under(lp, ".terraform"):
		return block("tf-dir", ".terraform holds cached backend config"), true
	case base == ".dev.vars" || strings.HasPrefix(base, ".dev.vars."):
		if isEnvTemplate(base) {
			return nameRule{}, false
		}
		return block("dev-vars", "Wrangler local secrets"), true
	case strings.HasSuffix(base, ".p8"):
		return withContent("apple-p8", "Apple AuthKey private key", contains("PRIVATE KEY")), true
	case base == "wp-config.php":
		return withContent("wp-config", "wp-config.php holds the database password or salts", wpConfigSecret), true
	}
	return nameRule{}, false
}

func block(id, why string) nameRule   { return nameRule{id: id, why: why, action: ActBlock} }
func guarded(id, why string) nameRule { return nameRule{id: id, why: why, action: ActGuard} }
func withContent(id, why string, test func([]byte) bool) nameRule {
	return nameRule{id: id, why: why, action: ActContent, content: test}
}

// under reports whether dir (one or more path segments) is a directory above the file.
func under(lp, dir string) bool {
	return strings.HasPrefix(lp, dir+"/") || strings.Contains(lp, "/"+dir+"/")
}

// pathEnd reports whether the path is, or ends in, tail as whole segments.
func pathEnd(lp, tail string) bool { return lp == tail || strings.HasSuffix(lp, "/"+tail) }

func isAgentConfigName(lp string) bool {
	_, ok := known.AgentConfigFormat(lp)
	return ok
}

func isEnvTemplate(base string) bool {
	suffix := base[strings.LastIndexByte(base, '.')+1:]
	for _, t := range envTemplates {
		if suffix == t {
			return true
		}
	}
	return false
}

// isSSHKeyName matches the default key names exactly; `id_rsa.pub` is a public key. A key
// saved under another name still holds a PEM block, which the engines catch.
func isSSHKeyName(base string) bool {
	switch base {
	case "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519":
		return true
	}
	return false
}

func isServiceAccountName(base string) bool {
	if base == "credentials.json" {
		return true
	}
	return strings.HasSuffix(base, ".json") &&
		(strings.Contains(base, "service-account") || strings.Contains(base, "-firebase-adminsdk-"))
}

func hasAnySuffix(s string, suffixes ...string) bool {
	for _, x := range suffixes {
		if strings.HasSuffix(s, x) {
			return true
		}
	}
	return false
}

func contains(needle string) func([]byte) bool {
	n := []byte(needle)
	return func(b []byte) bool { return bytes.Contains(b, n) }
}

// npmrcToken is true when a line sets _authToken, _auth or _password to a literal. A
// reference such as ${NPM_TOKEN} is how a .npmrc is meant to be committed.
func npmrcToken(b []byte) bool {
	for _, line := range strings.Split(string(b), "\n") {
		key, val, ok := keyValue(line)
		if !ok {
			continue
		}
		k := strings.ToLower(key)
		if (strings.HasSuffix(k, "_authtoken") || strings.HasSuffix(k, "_auth") || strings.HasSuffix(k, "_password")) && isLiteral(val) {
			return true
		}
	}
	return false
}

// pypircPassword is true when a `password` line holds a literal; PyPI tokens go there as
// `password = pypi-...` next to `username = __token__`.
func pypircPassword(b []byte) bool {
	for _, line := range strings.Split(string(b), "\n") {
		if key, val, ok := keyValue(line); ok && strings.EqualFold(key, "password") && isLiteral(val) {
			return true
		}
	}
	return false
}

// keyValue splits "key = value" or "key: value", skipping comments.
func keyValue(line string) (key, val string, ok bool) {
	line = strings.TrimSpace(line)
	if line == "" || line[0] == '#' || line[0] == ';' {
		return "", "", false
	}
	// `//registry.npmjs.org/:_authToken=x` has a colon inside the key, so for those lines
	// only "=" separates; base64 padding after it is part of the value.
	sep := "=:"
	if strings.HasPrefix(line, "//") {
		sep = "="
	}
	i := strings.IndexAny(line, sep)
	if i < 0 {
		return "", "", false
	}
	key = strings.TrimSpace(line[:i])
	val = strings.Trim(strings.TrimSpace(line[i+1:]), `"'`)
	return key, val, true
}

// isLiteral says a value is a real credential rather than empty, a ${VAR} / $VAR
// reference or a <placeholder>.
func isLiteral(v string) bool {
	if v == "" || strings.HasPrefix(v, "$") || strings.Contains(v, "${") {
		return false
	}
	if strings.HasPrefix(v, "<") && strings.HasSuffix(v, ">") {
		return false
	}
	return !strings.HasPrefix(v, "%(")
}

// dotenvxCiphertext: a .env whose every value starts with `encrypted:` and which carries the
// DOTENV_PUBLIC_KEY is ciphertext, and dotenvx says to commit it (STEAL 4.1 allow-if, K13).
// A plain .env.<mode> stays blocked.
func dotenvxCiphertext(b []byte) bool {
	pub, values := false, 0
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}
		line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return false
		}
		if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(k)), "DOTENV_PUBLIC_KEY") {
			pub = true
			continue
		}
		if !strings.HasPrefix(strings.Trim(strings.TrimSpace(v), `"'`), "encrypted:") {
			return false
		}
		values++
	}
	return pub && values > 0
}

// blindsDiff: a .gitattributes line that turns diffing off (or points it at a converter) for
// a path that holds secrets, which hides the path from a scanner that reads diffs.
func blindsDiff(b []byte) bool {
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || strings.HasPrefix(f[0], "#") || !secretClassPattern(strings.ToLower(f[0])) {
			continue
		}
		for _, a := range f[1:] {
			a = strings.ToLower(a)
			if a == "-diff" || a == "binary" || strings.HasPrefix(a, "diff=") || strings.Contains(a, "textconv") {
				return true
			}
		}
	}
	return false
}

func secretClassPattern(p string) bool {
	if p == "*" || p == "**" {
		return true
	}
	for _, w := range []string{".env", ".pem", ".key", "secret", "credential", "token", "id_rsa", "id_ed25519", ".p12", ".pfx", ".npmrc", ".netrc", "password"} {
		if strings.Contains(p, w) {
			return true
		}
	}
	return false
}

// netscapeCookies: a curl or wget cookie jar says so on its first line.
func netscapeCookies(b []byte) bool {
	head := strings.TrimSpace(string(b[:min(len(b), 128)]))
	return strings.HasPrefix(head, "# Netscape HTTP Cookie File") || strings.HasPrefix(head, "# HTTP Cookie File")
}

// cookieJSON: a JSON array of objects with name, value, domain and path, which is what the
// browser extensions that export cookies write.
func cookieJSON(b []byte) bool {
	dec := json.NewDecoder(bytes.NewReader(b))
	if t, err := dec.Token(); err != nil || t != json.Delim('[') {
		return false
	}
	var first map[string]json.RawMessage
	if err := dec.Decode(&first); err != nil {
		return false
	}
	for _, k := range []string{"name", "value", "domain", "path"} {
		if _, ok := first[k]; !ok {
			return false
		}
	}
	return true
}

// bruCredentials: a Bruno file with an auth block, plain vars or headers that hold a literal
// credential. Only `vars:secret [ names ]` is safe, and Bruno's {{variable}} is a reference.
func bruCredentials(b []byte) bool {
	block := ""
	for _, line := range strings.Split(string(b), "\n") {
		t := strings.TrimSpace(line)
		if block == "" {
			if strings.HasSuffix(t, "{") {
				block = strings.TrimSpace(strings.TrimSuffix(t, "{"))
			}
			continue
		}
		if t == "}" {
			block = ""
			continue
		}
		kind := ""
		switch {
		case strings.HasPrefix(block, "auth"), strings.HasPrefix(block, "vars") && block != "vars:secret":
			kind = "env"
		case block == "headers":
			kind = "header"
		default:
			continue
		}
		k, v, ok := strings.Cut(t, ":")
		v = strings.TrimSpace(v)
		if !ok || v == "" || strings.HasPrefix(v, "{{") {
			continue
		}
		if _, lit := known.PairLiteral(kind, strings.TrimSpace(strings.TrimPrefix(k, "~")), v); lit {
			return true
		}
	}
	return false
}

// wpConfigSecret: wp-config.php with a database password or an AUTH_KEY-style salt written
// out. The sample file's "put your unique phrase here" and getenv() are not.
var wpDefine = regexp.MustCompile(`(?i)define\(\s*['"](DB_PASSWORD|AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|NONCE_KEY|AUTH_SALT|SECURE_AUTH_SALT|LOGGED_IN_SALT|NONCE_SALT)['"]\s*,\s*['"]([^'"]*)['"]`)

func wpConfigSecret(b []byte) bool {
	for _, m := range wpDefine.FindAllSubmatch(b, -1) {
		v := strings.TrimSpace(string(m[2]))
		if v != "" && !known.Placeholder(v) && !strings.Contains(strings.ToLower(v), "put your unique phrase") && !strings.HasSuffix(strings.ToLower(v), "_here") {
			return true
		}
	}
	return false
}
