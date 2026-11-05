package hooks

import (
	"regexp"
	"strings"
	"testing"
)

var kgID = regexp.MustCompile(`kg[0-9a-f]{6}`)

// STEAL section 4.1, row by row. Each line is a path, the rule id it must get and what that
// rule does; the negatives after it are the near-misses that must stay quiet.
func TestSection41Classification(t *testing.T) {
	for _, c := range []struct {
		path string
		id   string
		act  Action
	}{
		{".betterleaksignore", "ignore-file", ActGuard}, {"a/b/.gitleaksignore", "ignore-file", ActGuard},
		{".trufflehogignore", "ignore-file", ActGuard}, {".BETTERLEAKSIGNORE", "ignore-file", ActGuard},
		{".betterleaks.toml", "scanner-config", ActGuard}, {"x/.gitleaks.toml", "scanner-config", ActGuard},
		{".secrets.baseline", "baseline", ActGuard}, {".gitguardian.yaml", "baseline", ActGuard}, {".gitguardian.yml", "baseline", ActGuard},
		{".github/secret_scanning.yml", "gh-scan-config", ActGuard}, {"mono/.github/secret_scanning.yml", "gh-scan-config", ActGuard},

		{".pre-commit-config.yaml", "hook-manager", ActWarn}, {"lefthook.yml", "hook-manager", ActWarn},
		{".husky/pre-commit", "hook-manager", ActWarn}, {"a/.husky/_/husky.sh", "hook-manager", ActWarn},
		{".gitattributes", "gitattributes", ActWarn},

		{".mcp.json", "mcp-config", ActWalk}, {"app/.mcp.json", "mcp-config", ActWalk}, {".cursor/mcp.json", "mcp-config", ActWalk},
		{".vscode/mcp.json", "mcp-config", ActWalk}, {".copilot/mcp-config.json", "mcp-config", ActWalk},
		{".kiro/settings/mcp.json", "mcp-config", ActWalk}, {".devin/mcp_config.json", "mcp-config", ActWalk},
		{"opencode.json", "mcp-config", ActWalk}, {"opencode.jsonc", "mcp-config", ActWalk},
		{".continue/config.yaml", "mcp-config", ActWalk}, {".continue/config.json", "mcp-config", ActWalk},
		{".aider.conf.yml", "mcp-config", ActWalk}, {".codex/config.toml", "mcp-config", ActWalk},
		{"claude_desktop_config.json", "mcp-config", ActWalk},
		{".claude/settings.json", "claude-settings", ActWalk}, {"proj/.claude/settings.json", "claude-settings", ActWalk},

		{".claude/settings.local.json", "claude-local", ActBlock}, {".devin/mcp_config.local.json", "devin-local", ActBlock},
		{".codex/auth.json", "codex-auth", ActBlock},
		{".aider.chat.history.md", "agent-history", ActBlock}, {".aider.input.history", "agent-history", ActBlock},
		{".aider.llm.history", "agent-history", ActBlock}, {".specstory/history/2026-01-01.md", "agent-history", ActBlock},
		{".claude/projects/-Users-x/abc.jsonl", "claude-state", ActBlock}, {".claude/file-history/s/f", "claude-state", ActBlock},
		{".claude/paste-cache/abc", "claude-state", ActBlock}, {".claude/history.jsonl", "claude-state", ActBlock},
		{".codex/sessions/2026/11/x.jsonl", "claude-state", ActBlock}, {".codex/history.jsonl", "claude-state", ActBlock},
		{"Heap-1.heapsnapshot", "heapsnapshot", ActBlock},
		{"playwright/.auth/user.json", "pw-state", ActBlock}, {"tests/storageState.json", "pw-state", ActBlock}, {"storageState.admin.json", "pw-state", ActBlock},
		{"capture.har", "har", ActBlock}, {"CAPTURE.HAR", "har", ActBlock},
		{"cookies.txt", "cookies-txt", ActBlock},
		{"cookies.json", "cookie-json", ActContent}, {"export/my-cookies.json", "cookie-json", ActContent},
		{"dev.postman_environment.json", "postman-env", ActBlock},
		{"request.bru", "bruno", ActContent},
		{"cassettes/a.yml", "vcr", ActBlock}, {"tests/cassettes/sub/a.json", "vcr", ActBlock}, {"cassettes/a.yaml", "vcr", ActBlock},
		{"terraform.tfstate.backup", "tfstate-x", ActBlock}, {"x.tfstate.1234.backup", "tfstate-x", ActBlock},
		{"prod.tfvars", "tfvars", ActBlock}, {"a/b.tfvars.json", "tfvars", ActBlock},
		{"crash.log", "tf-crash", ActBlock}, {"crash.2024-01-01.log", "tf-crash", ActBlock},
		{".terraformrc", "tf-cli", ActBlock}, {"terraform.rc", "tf-cli", ActBlock},
		{".terraform/providers/x/y", "tf-dir", ActBlock}, {"env/.terraform/modules/modules.json", "tf-dir", ActBlock},
		{".dev.vars", "dev-vars", ActBlock}, {"worker/.dev.vars.production", "dev-vars", ActBlock},
		{"AuthKey_ABC123.p8", "apple-p8", ActContent},
		{"wp-config.php", "wp-config", ActContent},
		// A name with `cookie` in it is read, not blocked: only a cookie export is a finding.
		{"docs/cookie-policy.md", "cookies-txt", ActContent},
	} {
		r, ok := PathRule(c.path)
		if !ok || r.ID != c.id || r.Action != c.act || r.Why == "" {
			t.Errorf("PathRule(%q) = %+v ok=%v; want %s %d", c.path, r, ok, c.id, c.act)
		}
	}
	for _, p := range []string{
		".terraform.lock.hcl", ".dev.vars.example", ".dev.vars.template", "settings.json", "package.json", "x/mcp.json", "mcp.json",
		"crash.txt", "my.har.md", "cassettes.md", "tests/cassettes/readme.md", ".cursor/rules/style.mdc", ".claude/commands/x.md",
		".claude/settings.json.bak", ".github/workflows/ci.yml", ".github/secret_scanning.md", ".huskyrc", ".pre-commit-hooks.yaml",
		"lefthook-local.yml", "x.heapsnapshots", ".gitignore", "config.toml", ".continue/rules/x.md", "tfvars", "storage.json",
		"notes/cast.md", "demo.cast", ".envrc", "wp-config-sample.php",
	} {
		if r, ok := PathRule(p); ok {
			t.Errorf("PathRule(%q) = %+v; want no rule", p, r)
		}
	}
	// STEAL 4.1 `scan`: a recording and direnv's file are content-scanned, never name-blocked.
	for _, p := range []string{"demo.cast", ".envrc"} {
		if _, ok := PathRule(p); ok {
			t.Errorf("%s must not be name-blocked", p)
		}
	}
}

func TestSection41ContentTests(t *testing.T) {
	key := randString(40, alnum)
	cases := []struct {
		name, path, content string
		want                bool
	}{
		{"cookie export", "cookies.json", `[{"name":"sid","value":"` + key + `","domain":".example.com","path":"/","secure":true}]`, true},
		{"cookie export, other fields first", "my-cookies.json", `[{"domain":".x.com","path":"/","name":"a","value":"b","hostOnly":true}]`, true},
		{"a json object, not an array", "cookies.json", `{"name":"x","value":"y","domain":"d","path":"/"}`, false},
		{"array of other objects", "cookies.json", `[{"name":"x","value":"y"}]`, false},
		{"empty array", "cookies.json", `[]`, false},
		{"not json", "cookies.json", `name,value,domain,path`, false},
		{"netscape jar", "cookies.curl", "# Netscape HTTP Cookie File\n.example.com\tTRUE\t/\tFALSE\t0\tsid\t" + key + "\n", true},
		{"curl's own header", "my-cookie-jar", "# HTTP Cookie File\n", true},
		{"a note about cookies", "cookie-policy.md", "# Cookie policy\nwe use cookies\n", false},

		{"bruno bearer literal", "r.bru", "meta {\n  name: x\n}\n\nauth:bearer {\n  token: " + key + "\n}\n", true},
		{"bruno bearer variable", "r.bru", "auth:bearer {\n  token: {{token}}\n}\n", false},
		{"bruno basic password", "r.bru", "auth:basic {\n  username: me\n  " + "pass" + "word: " + key + "\n}\n", true},
		{"bruno plain vars", "r.bru", "vars:pre-request {\n  api_key: " + key + "\n  base: https://x.test\n}\n", true},
		{"bruno secret vars are names only", "r.bru", "vars:secret [\n  api_key,\n  token\n]\n", false},
		{"bruno header literal", "r.bru", "headers {\n  X-Api-Key: " + key + "\n}\n", true},
		{"bruno harmless header", "r.bru", "headers {\n  Content-Type: application/json\n}\n", false},
		{"bruno no auth", "r.bru", "get {\n  url: https://x.test\n}\n", false},

		{"wp-config password", "wp-config.php", "define( 'DB_NAME', 'wp' );\ndefine( 'DB_PASSWORD', '" + key + "' );\n", true},
		{"wp-config salt", "wp-config.php", "define('AUTH_KEY',         '" + key + "');\n", true},
		{"wp-config sample", "wp-config.php", "define( 'DB_PASSWORD', 'password_here' );\ndefine( 'AUTH_KEY', 'put your unique phrase here' );\n", false},
		{"wp-config from the environment", "wp-config.php", "define( 'DB_PASSWORD', getenv('DB_PASSWORD') );\n", false},
		{"wp-config name only", "wp-config.php", "define( 'DB_NAME', 'wordpress' );\n", false},

		{"p8 key", "AuthKey_X.p8", "-----BEGIN " + "PRIVATE KEY-----\nxx\n", true},
		{"p8 without a key", "AuthKey_X.p8", "nothing\n", false},

		{"gitattributes hides env", ".gitattributes", "*.env -diff\n", true},
		{"gitattributes binary pem", ".gitattributes", "secrets/*.pem binary\n", true},
		{"gitattributes textconv", ".gitattributes", "*.key diff=sops\n", true},
		{"gitattributes everything", ".gitattributes", "* -diff\n", true},
		{"gitattributes lfs is fine", ".gitattributes", "*.png filter=lfs diff=lfs merge=lfs -text\n", false},
		{"gitattributes eol is fine", ".gitattributes", "*.sh text eol=lf\n", false},
		{"gitattributes comment", ".gitattributes", "# *.env -diff\n", false},
	}
	for _, c := range cases {
		r, ok := classify(c.path)
		if !ok || r.content == nil {
			t.Errorf("%s: %s has no content test", c.name, c.path)
			continue
		}
		if got := r.content([]byte(c.content)); got != c.want {
			t.Errorf("%s: %s: got %v, want %v", c.name, c.path, got, c.want)
		}
	}
}

func TestDotenvxCiphertextIsTheOnlyEnvException(t *testing.T) {
	r, _ := classify(".env.production")
	if r.allowIf == nil {
		t.Fatal("env-file has no exception")
	}
	enc := "encrypted:BG" + randString(60, alnum)
	for _, c := range []struct {
		name, content string
		want          bool
	}{
		{"all ciphertext with the public key", "#/---BEGIN DOTENV ENCRYPTED---/\nDOTENV_PUBLIC_KEY_PRODUCTION=\"03" + randString(30, "0123456789abcdef") + "\"\nAPI_KEY=\"" + enc + "\"\nDB=" + enc + "\n", true},
		{"one plain value", "DOTENV_PUBLIC_KEY=\"03aa\"\nA=" + enc + "\nB=" + randString(30, alnum) + "\n", false},
		{"no public key", "A=" + enc + "\n", false},
		{"public key only", "DOTENV_PUBLIC_KEY=\"03aa\"\n", false},
		{"plain env", "A=1\n", false},
		{"not an assignment", "garbage\n", false},
	} {
		if got := r.allowIf([]byte(c.content)); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

// ---- through real git ----

func TestPreCommitSection41(t *testing.T) {
	t.Parallel()
	e := newTenv(t)
	key := fakeAnthropic()
	pl := randString(36, alnum)
	cases := []struct {
		name    string
		path    string
		content string
		blocked bool
		want    string // text the output must hold
	}{
		{"ignore file", ".gitleaksignore", "src/a.py:generic-api-key:12\n", true, "ignore-file"},
		{"betterleaks ignore file", "sub/.betterleaksignore", "x\n", true, "ignore-file"},
		{"scanner config allowlist", ".gitleaks.toml", "[allowlist]\nregexes = ['.*']\n", true, "scanner-config"},
		{"baseline", ".secrets.baseline", "{}\n", true, "baseline"},
		{"github scanning config", ".github/secret_scanning.yml", "paths-ignore:\n  - '**'\n", true, "gh-scan-config"},
		{"claude local settings", ".claude/settings.local.json", `{"env":{"A":"b"}}`, true, "claude-local"},
		{"codex auth", ".codex/auth.json", "{}\n", true, "codex-auth"},
		{"har", "trace.har", "{}\n", true, "har"},
		{"playwright state", "playwright/.auth/user.json", "{}\n", true, "pw-state"},
		{"cookie file", "cookies.txt", "# Netscape HTTP Cookie File\n", true, "cookies-txt"},
		{"cassette", "tests/cassettes/api.yml", "interactions: []\n", true, "vcr"},
		{"tfvars", "prod.tfvars", "region = \"us-east-1\"\n", true, "tfvars"},
		{"terraform backup state", "terraform.tfstate.backup", "{}\n", true, "tfstate-x"},
		{"dev vars", ".dev.vars", "A=1\n", true, "dev-vars"},
		{"heap snapshot", "x.heapsnapshot", "{}\n", true, "heapsnapshot"},
		{"agent history", ".aider.chat.history.md", "# chat\n", true, "agent-history"},
		{"claude transcript", ".claude/projects/p/s.jsonl", "{}\n", true, "claude-state"},
		{"postman environment", "dev.postman_environment.json", "{}\n", true, "postman-env"},
		{"wp-config with a password", "wp-config.php", "define( 'DB_PASSWORD', '" + pl + "' );\n", true, "wp-config"},
		{"apple key", "AuthKey_A.p8", "-----BEGIN " + "PRIVATE KEY-----\nabc\n", true, "apple-p8"},
		{"cookie export", "cookies.json", `[{"name":"a","value":"b","domain":"d","path":"/"}]`, true, "cookie-json"},
		{"bruno with a token", "r.bru", "auth:bearer {\n  token: " + pl + "\n}\n", true, "bruno"},
		{"plain dotenv mode", ".env.production", "A=1\n", true, "env-file"},

		{"dotenvx ciphertext", ".env.production", "DOTENV_PUBLIC_KEY_PRODUCTION=\"03abc\"\nA=\"encrypted:BG" + pl + "\"\n", false, ""},
		{"example dev vars", ".dev.vars.example", "A=changeme\n", false, ""},
		{"lock file is not the directory", ".terraform.lock.hcl", "# lock\n", false, ""},
		{"plain config", "config/app.toml", "name = \"x\"\n", false, ""},
		{"wp-config sample values", "wp-config.php", "define( 'DB_PASSWORD', 'password_here' );\n", false, ""},
		{"cookie policy", "docs/cookie-policy.md", "# cookies\n", false, ""},
		{"bruno without auth", "r.bru", "get {\n  url: https://x.test\n}\n", false, ""},
		{"hook manager warns only", ".husky/pre-commit", "npm test\n", false, "can rewire local hooks"},
		{"pre-commit config warns only", ".pre-commit-config.yaml", "repos: []\n", false, "can rewire local hooks"},
		{"gitattributes warns only", ".gitattributes", "*.env -diff\n", false, "hides paths from diff-reading scanners"},
		{"harmless gitattributes is silent", ".gitattributes", "*.sh text eol=lf\n", false, ""},
	}
	for _, c := range cases {
		repo := e.initRepo(strings.NewReplacer("/", "_", ".", "_", " ", "_").Replace(c.name) + randString(4, alnum))
		e.write(repo, c.path, c.content)
		e.must(repo, "add", "-f", "--", c.path)
		r := e.git(repo, "commit", "-m", "x")
		if c.blocked && r.code == 0 {
			t.Errorf("%s: %s went through", c.name, c.path)
		} else if !c.blocked && r.code != 0 {
			t.Errorf("%s: %s was blocked:\n%s", c.name, c.path, r)
		}
		if c.want != "" && !strings.Contains(r.err, c.want) {
			t.Errorf("%s: output lacks %q:\n%s", c.name, c.want, r.err)
		}
		if c.blocked && !kgID.MatchString(r.err) {
			t.Errorf("%s: no id to allow it with:\n%s", c.name, r.err)
		}
		assertNoLeak(t, c.name, r.err+r.out, key, pl)
	}
}

// A filename hit is allowed per content, like any other: the id the block printed lets that
// version of the file through, and the next version is a new id.
func TestGuardClassFilesCanBeAllowedByAHumanOnly(t *testing.T) {
	t.Parallel()
	e := newTenv(t)
	repo := e.initRepo("r")
	e.write(repo, ".gitleaksignore", "a:b:1\n")
	e.must(repo, "add", ".gitleaksignore")
	r := e.git(repo, "commit", "-m", "ignore")
	if r.code == 0 {
		t.Fatal("a staged scanner ignore file went through")
	}
	if !strings.Contains(r.err, "keyguard allow kg") {
		t.Errorf("no id to allow it with:\n%s", r.err)
	}
	// What `keyguard allow <id>` does: the file's fingerprint (path plus blob) joins the list.
	e.extra["KG_TEST_IGNORE"] = testKeyring.FP("kg-file\x00.gitleaksignore\x00" + e.must(repo, "rev-parse", ":.gitleaksignore"))
	if r := e.git(repo, "commit", "-m", "ignore"); r.code != 0 {
		t.Errorf("the allowed version was still blocked:\n%s", r)
	}
	e.write(repo, ".gitleaksignore", "a:b:1\nc:d:2\n")
	e.must(repo, "add", ".gitleaksignore")
	if r := e.git(repo, "commit", "-m", "more"); r.code == 0 {
		t.Error("the next version of an allowed ignore file went through")
	}
}
