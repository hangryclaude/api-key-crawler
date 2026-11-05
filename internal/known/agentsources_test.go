package known

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every agent and MCP store the P0-15 row lists, planted with keys in the positions the
// name filter alone never reached: an argument after --api-key, a header passed as an
// argument, a query parameter, a docker -e pair, a TOML inline table. Before the walker none
// of these values was learned (and several of the files were not read at all).
func TestLearnReadsTheAgentAndMCPStores(t *testing.T) {
	f := newFixture(t)
	v := func(name string) string { return f.secret("sk-proj-", 36, name) }

	claude := v("X_API_KEY")
	f.write(".claude.json", fmt.Sprintf(`{"numStartups":3,"projects":{"/p":{"mcpServers":{"x":{"command":"npx","args":["-y","x-mcp"],"env":{"X_API_KEY":%q}}}}}}`, claude))

	oauth, refresh := v("accessToken"), v("refreshToken")
	f.write(".claude/.credentials.json", fmt.Sprintf(`{"claudeAiOauth":{"accessToken":%q,"refreshToken":%q,"expiresAt":1}}`, oauth, refresh))

	backup := v("OLD_API_KEY")
	f.write(".claude/backups/.claude.json.backup.1730000000000", fmt.Sprintf(`{"mcpServers":{"old":{"env":{"OLD_API_KEY":%q}}}}`, backup))

	settings, local := v("ANTHROPIC_AUTH_TOKEN"), v("SUPABASE_SERVICE_KEY")
	f.write("dev/app/.claude/settings.json", fmt.Sprintf(`{"env":{"ANTHROPIC_AUTH_TOKEN":%q}}`, settings))
	f.write("dev/app/.claude/settings.local.json", fmt.Sprintf(`{"env":{"SUPABASE_SERVICE_KEY":%q}}`, local))

	desktopHeader := v("Authorization")
	f.write("Library/Application Support/Claude/claude_desktop_config.json",
		fmt.Sprintf(`{"mcpServers":{"remote":{"command":"npx","args":["mcp-remote","https://h.test/mcp","--header","Authorization: Bearer %s"]}}}`, desktopHeader))

	cursorArg := v("api-key (arg)")
	f.write(".cursor/mcp.json", fmt.Sprintf(`{"mcpServers":{"c":{"command":"npx","args":["c-mcp","--api-key","%s"]}}}`, cursorArg))

	copilotURL := v("api_key (url-param)")
	f.write(".copilot/mcp-config.json", fmt.Sprintf(`{"mcpServers":{"c":{"type":"http","url":"https://h.test/mcp?api_key=%s&mode=fast"}}}`, copilotURL))

	kiroDocker := v("GITHUB_PERSONAL_ACCESS_TOKEN (env)")
	f.write(".kiro/settings/mcp.json", fmt.Sprintf(`{"mcpServers":{"gh":{"command":"docker","args":["run","-i","--rm","-e","GITHUB_PERSONAL_ACCESS_TOKEN=%s","gh-mcp"]}}}`, kiroDocker))

	devin := v("X-Api-Key (header)")
	f.write(".config/devin/mcp_config.json", fmt.Sprintf(`{"mcpServers":{"d":{"command":"npx","args":["d-mcp","-H","X-Api-Key: %s"]}}}`, devin))

	opencode := v("OC_TOKEN")
	f.write(".config/opencode/opencode.json", fmt.Sprintf(`{
  // opencode accepts comments
  "mcp": { "oc": { "type": "local", "command": ["npx", "oc-mcp"], "environment": { "OC_TOKEN": %q, }, }, },
}`, opencode))

	codexEnv, codexHeader, codexBearer, codexArg := v("SUPABASE_ACCESS_TOKEN"), v("X-Api-Key"), v("experimental_bearer_token"), v("token (arg)")
	f.write(".codex/config.toml", fmt.Sprintf(`model = "gpt-5"

[mcp_servers.supabase]
command = "npx"
args = ["-y", "supabase-mcp", "--token", "%[4]s"]

[mcp_servers.supabase.env]
SUPABASE_ACCESS_TOKEN = "%[1]s"

[mcp_servers.remote]
url = "https://h.test/mcp"
http_headers = { "X-Api-Key" = "%[2]s" }
experimental_bearer_token = "%[3]s"
`, codexEnv, codexHeader, codexBearer, codexArg))

	aider := v("openai-api-key")
	f.write(".aider.conf.yml", "model: gpt-4o\nopenai-api-key: "+aider+"\n")

	devVars, devVarsProd := v("RESEND_API_KEY"), v("TURNSTILE_SECRET")
	f.write("dev/worker/.dev.vars", "RESEND_API_KEY="+devVars+"\n")
	f.write("dev/worker/.dev.vars.production", "TURNSTILE_SECRET="+devVarsProd+"\n")

	projMCP, projDSN := v("MCP_TOKEN"), v("password")
	f.write("dev/app/.mcp.json", fmt.Sprintf(`{"mcpServers":{"p":{"command":"npx","args":["pg-mcp","--dsn","postgresql://app:%s@db.internal.test:5432/app"],"env":{"MCP_TOKEN":%q}}}}`, projDSN, projMCP))

	// What these files hold but must not teach learn: references and placeholders.
	f.write("elsewhere/mcp.json", fmt.Sprintf(`{"env":{"LEFT_ALONE_TOKEN":%q}}`, f.reject("sk-proj-", 36, "a file in a place learn does not read")))
	f.write("dev/app/.cursor/mcp.json", `{"mcpServers":{"r":{"env":{"A_TOKEN":"${A_TOKEN}","B_TOKEN":"${env:B_TOKEN}","C_TOKEN":"YOUR_TOKEN_HERE"},"headers":{"Authorization":"Bearer ${A_TOKEN}"}}}}`)

	rep, log := f.learn(Options{})
	f.check()
	if rep.Files < 15 {
		t.Errorf("only %d files were read", rep.Files)
	}
	for _, rel := range []string{".claude.json", ".claude/backups/.claude.json.backup.1730000000000", "dev/worker/.dev.vars.production"} {
		if !strings.Contains(log, filepath.Join(f.home, filepath.FromSlash(rel))) {
			t.Errorf("%s was not read", rel)
		}
	}

	// Learn never stores or prints a value: no 12-byte window of any planted value, in any
	// form learn registers, appears in what it says or what it keeps.
	outputs := map[string][]byte{"summary": []byte(rep.Summary()), "log": []byte(log)}
	err := filepath.Walk(f.root, func(p string, info os.FileInfo, err error) error {
		if err == nil && info.Mode().IsRegular() {
			b, _ := os.ReadFile(p)
			outputs[p] = b
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(outputs) < 3 {
		t.Fatalf("the audit saw only %d outputs", len(outputs))
	}
	var values []string
	for val := range f.want {
		values = append(values, val)
	}
	assertNoValue(t, values, outputs)
}

// The walker's positions, read from each syntax, reach learn by name.
func TestLearnWalkerPositionsInEverySyntax(t *testing.T) {
	f := newFixture(t)
	a, b, c, d := f.secret("sk-proj-", 36, "token (arg)"), f.secret("sk-proj-", 36, "sig (url-param)"), f.secret("sk-proj-", 36, "API_KEY (env)"), f.secret("sk-proj-", 36, "password")
	f.write(".config/tool/a.json", fmt.Sprintf(`{"args":["--token","%s"],"u":"https://h.test/x?sig=%s"}`, a, b))
	f.write(".config/tool/b.toml", fmt.Sprintf("args = [\"run\", \"-e\", \"API_KEY=%s\"]\nurl = \"postgresql://u:%s@h.test/db\"\n", c, d))
	rep, _ := f.learn(Options{})
	f.check()
	if rep.Added != 4 {
		t.Errorf("added %d secrets, want 4:\n%s", rep.Added, rep.Summary())
	}
}

func TestLearnYAMLConfigs(t *testing.T) {
	f := newFixture(t)
	a, b := f.secret("sk-proj-", 36, "GITHUB_TOKEN"), f.secret("sk-proj-", 36, "api-key (arg)")
	f.write(".config/continue/config.yaml", fmt.Sprintf("name: cfg\nmcpServers:\n  - name: gh\n    command: npx\n    args:\n      - -y\n      - gh-mcp\n      - --api-key\n      - %s\n    env:\n      GITHUB_TOKEN: %s\n", b, a))
	f.learn(Options{})
	f.check()
}

// Codex (and others) name the environment variable to read, in bearer_token_env_var, env_key
// and env_http_headers. Those values are names. Learning one would put OPENAI_API_KEY in the
// store, and every commit that spells the variable would be a finding.
func TestLearnDoesNotLearnTheNamesOfVariables(t *testing.T) {
	f := newFixture(t)
	names := []string{"SUPABASE_ACCESS_TOKEN_FOR_CODEX", "OPENAI_API_KEY_FOR_THE_TEAM", "ANOTHER_LONG_VARIABLE_NAME_X", "YET_ANOTHER_SECRET_NAME_Y"}
	for _, n := range names {
		if why := rejection(n); why != "" {
			t.Fatalf("the test needs names learn's value filters accept; %q is rejected as %s", n, why)
		}
		f.values = append(f.values, n)
		f.not[n] = "the name of an environment variable"
	}
	real := f.secret("sk-proj-", 36, "SUPABASE_ACCESS_TOKEN")
	f.write(".codex/config.toml", fmt.Sprintf("[mcp_servers.s]\nurl = \"https://h.test/mcp\"\nbearer_token_env_var = %q\nenv_http_headers = { \"X-Api-Key\" = %q }\nenv_key = %q\n\n[mcp_servers.s.env]\nSUPABASE_ACCESS_TOKEN = %q\n",
		names[0], names[1], names[2], real))
	f.write(".config/tool/settings.json", fmt.Sprintf(`{"provider":{"api_key_env_var":%q,"env_vars":[%q]}}`, names[3], names[3]))
	f.write(".config/tool/settings.yaml", fmt.Sprintf("provider:\n  api_key_env_var: %s\n  env_key: %s\n", names[3], names[1]))
	f.learn(Options{})
	f.check()
}
