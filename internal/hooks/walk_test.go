package hooks

import (
	"fmt"
	"strings"
	"testing"
)

// The agent and MCP config rule (STEAL P0-15), end to end: git stages the file, the real
// hook reads the staged blob and runs the walker over it.
func TestPreCommitBlocksALiteralInAnAgentConfig(t *testing.T) {
	t.Parallel()
	e := newTenv(t)
	key := fakeGitHub()
	cases := []struct {
		name, path, content string
		line                int
		where               string // part of the WHY column
	}{
		{"mcp env", ".mcp.json", "{\n  \"mcpServers\": {\n    \"x\": {\n      \"command\": \"npx\",\n      \"env\": { \"X_API_KEY\": \"" + key + "\" }\n    }\n  }\n}\n", 5, "env.X_API_KEY"},
		{"cursor header", ".cursor/mcp.json", `{"mcpServers":{"api":{"url":"https://h.test/mcp","headers":{"Authorization":"Bearer ` + key + `"}}}}`, 1, "headers.Authorization"},
		{"claude settings env", ".claude/settings.json", "{\n  \"env\": {\n    \"ANTHROPIC_AUTH_TOKEN\": \"" + key + "\"\n  }\n}\n", 3, "env.ANTHROPIC_AUTH_TOKEN"},
		{"codex env table", ".codex/config.toml", "model = \"gpt-5\"\n\n[mcp_servers.supabase.env]\nSUPABASE_ACCESS_TOKEN = \"" + key + "\"\n", 4, "SUPABASE_ACCESS_TOKEN"},
		{"codex bearer", ".codex/config.toml", "[mcp_servers.r]\nurl = \"https://h.test\"\nexperimental_bearer_token = \"" + key + "\"\n", 3, "experimental_bearer_token"},
		{"continue yaml", ".continue/config.yaml", "mcpServers:\n  - name: gh\n    env:\n      GITHUB_TOKEN: " + key + "\n", 4, "GITHUB_TOKEN"},
		{"aider key", ".aider.conf.yml", "model: gpt-4o\nopenai-api-key: " + key + "\n", 2, "openai-api-key"},
		{"opencode with comments", "opencode.jsonc", "{\n  // keys\n  \"mcp\": { \"x\": { \"environment\": { \"A_TOKEN\": \"" + key + "\", }, }, },\n}\n", 3, "A_TOKEN"},
		{"argument after --api-key", "app/.mcp.json", `{"mcpServers":{"x":{"command":"npx","args":["x-mcp","--api-key","` + key + `"]}}}`, 1, "--api-key"},
		{"docker -e pair", ".vscode/mcp.json", `{"servers":{"x":{"command":"docker","args":["run","-e","GITHUB_PERSONAL_ACCESS_TOKEN=` + key + `","img"]}}}`, 1, "GITHUB_PERSONAL_ACCESS_TOKEN"},
		{"query parameter", ".kiro/settings/mcp.json", `{"mcpServers":{"x":{"url":"https://h.test/sse?api_key=` + key + `"}}}`, 1, "api_key"},
		{"password in a dsn", ".devin/mcp_config.json", `{"mcpServers":{"pg":{"args":["pg-mcp","--dsn","postgresql://app:` + key + `@db.internal.test/app"]}}}`, 1, ""},
	}
	for _, c := range cases {
		repo := e.initRepo(strings.NewReplacer("/", "_", ".", "_", " ", "_").Replace(c.name) + randString(4, alnum))
		e.write(repo, c.path, c.content)
		e.must(repo, "add", "-f", "--", c.path)
		r := e.git(repo, "commit", "-m", "x")
		if r.code == 0 {
			t.Errorf("%s: a literal credential in %s went through", c.name, c.path)
			continue
		}
		for _, want := range []string{"commit blocked", c.path, fmt.Sprint(c.line), "ghp_…", "literal at"} {
			if !strings.Contains(r.err, want) {
				t.Errorf("%s: message lacks %q:\n%s", c.name, want, r.err)
			}
		}
		if c.where != "" && !strings.Contains(r.err, c.where) {
			t.Errorf("%s: message does not name %q:\n%s", c.name, c.where, r.err)
		}
		assertNoLeak(t, c.name, r.err+r.out, key)
	}
}

func TestPreCommitLetsTheVendorsReferencesThrough(t *testing.T) {
	t.Parallel()
	e := newTenv(t)
	files := map[string]string{
		".mcp.json":               `{"mcpServers":{"x":{"command":"npx","args":["x-mcp","--api-key","${X_API_KEY}"],"env":{"X_API_KEY":"${X_API_KEY}","MODE":"fast"},"headers":{"Authorization":"Bearer ${X_API_KEY}"}}}}`,
		".cursor/mcp.json":        `{"mcpServers":{"x":{"env":{"A_TOKEN":"${env:A_TOKEN}"}}}}`,
		".claude/settings.json":   `{"permissions":{"allow":["Bash(ls)"]},"env":{"ANTHROPIC_AUTH_TOKEN":"${ANTHROPIC_AUTH_TOKEN}","CLAUDE_CODE_MAX_OUTPUT_TOKENS":"32000"}}`,
		".codex/config.toml":      "[mcp_servers.r]\nurl = \"https://h.test\"\nbearer_token_env_var = \"R_TOKEN\"\nenv_http_headers = { \"X-Api-Key\" = \"R_KEY\" }\n",
		".continue/config.yaml":   "mcpServers:\n  - name: gh\n    env:\n      GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}\n",
		"opencode.json":           `{"mcp":{"x":{"environment":{"A_TOKEN":"{env:A_TOKEN}","B_TOKEN":"{file:~/.secrets/b}"}}}}`,
		".aider.conf.yml":         "model: gpt-4o\nopenai-api-key: <your key here>\n",
		".kiro/settings/mcp.json": `{"mcpServers":{"x":{"env":{"A_TOKEN":"YOUR_TOKEN_HERE","B_TOKEN":"changeme","C_TOKEN":"..."}}}}`,
		"x/.vscode/mcp.json":      `{"servers":{"x":{"url":"https://h.test/mcp?mode=fast","args":["--port","3000"]}}}`,
	}
	for path, content := range files {
		repo := e.initRepo(strings.NewReplacer("/", "_", ".", "_").Replace(path) + randString(4, alnum))
		e.write(repo, path, content)
		e.must(repo, "add", "-f", "--", path)
		if r := e.git(repo, "commit", "-m", "x"); r.code != 0 {
			t.Errorf("%s was blocked:\n%s", path, r)
		}
	}
}

// Two credentials on the one line of a minified config are two findings, not one.
func TestPreCommitListsEveryCredentialOnAMinifiedLine(t *testing.T) {
	t.Parallel()
	e := newTenv(t)
	repo := e.initRepo("r")
	a, b := fakeGitHub(), fakeGitHub()
	e.write(repo, ".mcp.json", `{"mcpServers":{"x":{"env":{"A_TOKEN":"`+a+`","B_TOKEN":"`+b+`"}}}}`)
	e.must(repo, "add", ".mcp.json")
	r := e.git(repo, "commit", "-m", "x")
	if r.code == 0 {
		t.Fatal("two literals on one line went through")
	}
	if !strings.Contains(r.err, "A_TOKEN") || !strings.Contains(r.err, "B_TOKEN") {
		t.Errorf("both credentials should be listed:\n%s", r.err)
	}
	assertNoLeak(t, "stderr", r.err, a, b)
}

// A file the walker cannot read to the end is said so, not waved through as clean: the
// credentials before the break still block, and a break alone warns.
func TestPreCommitSaysWhenAConfigCannotBeReadToTheEnd(t *testing.T) {
	t.Parallel()
	e := newTenv(t)
	key := fakeGitHub()

	repo := e.initRepo("broken-with-key")
	e.write(repo, ".mcp.json", `{"mcpServers":{"x":{"env":{"A_TOKEN":"`+key+`"}}}, "oops": [`)
	e.must(repo, "add", ".mcp.json")
	r := e.git(repo, "commit", "-m", "x")
	if r.code == 0 {
		t.Fatalf("a literal before the break went through:\n%s", r)
	}
	if !strings.Contains(r.err, "could not be read to the end") {
		t.Errorf("no warning about the break:\n%s", r.err)
	}
	assertNoLeak(t, "stderr", r.err, key)

	repo = e.initRepo("broken-clean")
	e.write(repo, ".mcp.json", `{"mcpServers": {`)
	e.must(repo, "add", ".mcp.json")
	r = e.git(repo, "commit", "-m", "x")
	if r.code != 0 {
		t.Errorf("a broken file with nothing in it blocked the commit:\n%s", r)
	}
	if !strings.Contains(r.err, ".mcp.json could not be read to the end") {
		t.Errorf("a break was not mentioned:\n%s", r.err)
	}
}

// What is staged is judged, not the working copy.
func TestPreCommitWalksTheStagedBlobNotTheWorkingCopy(t *testing.T) {
	t.Parallel()
	e := newTenv(t)
	repo := e.initRepo("r")
	key := fakeGitHub()
	e.write(repo, ".mcp.json", `{"mcpServers":{"x":{"env":{"A_TOKEN":"`+key+`"}}}}`)
	e.must(repo, "add", ".mcp.json")
	e.write(repo, ".mcp.json", `{"mcpServers":{"x":{"env":{"A_TOKEN":"${A_TOKEN}"}}}}`) // fixed afterwards, not staged
	if r := e.git(repo, "commit", "-m", "x"); r.code == 0 {
		t.Fatal("the staged literal went through because the working copy was clean")
	}
	e.must(repo, "add", ".mcp.json")
	if r := e.git(repo, "commit", "-m", "x"); r.code != 0 {
		t.Errorf("the fixed file was blocked:\n%s", r)
	}
}
