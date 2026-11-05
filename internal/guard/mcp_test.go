package guard

import (
	"strings"
	"testing"
)

// `claude mcp add` and its relatives with a credential written out (STEAL P0-15). The vendors'
// own examples teach the unsafe form; a reference in single quotes is the safe one.
func TestMCPAddWithALiteralCredentialIsRefused(t *testing.T) {
	k := fakeToken()
	table := []row{
		block("--env", "claude mcp add my-server --env API_KEY="+k+" -- npx my-mcp", KindMCP),
		block("-e", "claude mcp add my-server -e API_KEY="+k+" -- npx my-mcp", KindMCP),
		block("-e after the name", "claude mcp add my-server -e GITHUB_PERSONAL_ACCESS_TOKEN="+k+" -- npx my-mcp", KindMCP),
		block("--env=", "claude mcp add --env=API_KEY="+k+" my-server -- npx my-mcp", KindMCP),
		block("several -e, the second is the key", "claude mcp add s -e MODE=fast -e SUPABASE_ACCESS_TOKEN="+k+" -- npx x", KindMCP),
		block("variadic env", "claude mcp add s --env MODE=fast API_KEY="+k+" -- npx x", KindMCP),
		block("--header bearer", `claude mcp add --transport http corridor https://app.corridor.dev/api/mcp --header "Authorization: Bearer `+k+`"`, KindMCP),
		block("-H api key", `claude mcp add --transport http s https://h.test/mcp -H "X-Api-Key: `+k+`"`, KindMCP),
		block("--header=", `claude mcp add --transport http s https://h.test/mcp "--header=Authorization: Bearer `+k+`"`, KindMCP),
		block("server --api-key", "claude mcp add s -- npx -y some-mcp --api-key "+k, KindMCP),
		block("server --token=", "claude mcp add s -- npx -y some-mcp --token="+k, KindMCP),
		block("server --dsn with a password", "claude mcp add pg -- npx pg-mcp --dsn postgresql://app:"+k+"@db.internal.test:5432/app", KindMCP),
		block("server url argument with a password", "claude mcp add pg -- npx pg-mcp postgresql://app:"+k+"@db.internal.test/app", KindMCP),
		block("url with a secret parameter", "claude mcp add --transport sse s 'https://h.test/sse?api_key="+k+"'", KindMCP),
		block("add-json env", `claude mcp add-json s '{"command":"npx","args":["x"],"env":{"A_TOKEN":"`+k+`"}}'`, KindMCP),
		block("add-json header", `claude mcp add-json s '{"type":"http","url":"https://h.test","headers":{"Authorization":"Bearer `+k+`"}}'`, KindMCP),
		block("codex", "codex mcp add s --env API_KEY="+k+" -- npx x", KindMCP),
		block("scope first", "claude mcp add -s user --env API_KEY="+k+" s -- npx x", KindMCP),
		block("in a chain", "cd /p && claude mcp add s -e API_KEY="+k+" -- npx x", KindMCP),
		block("through bash -c", `bash -c "claude mcp add s -e API_KEY=`+k+` -- npx x"`, KindMCP),

		// The forms that keep the key out of the config: references, placeholders, inherited
		// variables, flags with no secret in them.
		allow("single-quoted reference", `claude mcp add s --env 'API_KEY=${API_KEY}' -- npx x`),
		allow("env var in the shell", `claude mcp add s --env API_KEY=$API_KEY -- npx x`),
		allow("bearer reference", `claude mcp add --transport http s https://h.test/mcp --header 'Authorization: Bearer ${TOKEN}'`),
		allow("placeholder", "claude mcp add s -e API_KEY=YOUR_API_KEY -- npx x"),
		allow("plain setting", "claude mcp add s -e LOG_LEVEL=debug -e PORT=3000 -- npx x"),
		allow("inherited variable", "claude mcp add s -e API_KEY -- npx x"),
		allow("no credentials", "claude mcp add --transport http sentry https://mcp.sentry.dev/mcp"),
		allow("server flags with no secret", "claude mcp add s -- npx -y some-mcp --port 3000 --verbose"),
		allow("dsn without a password", "claude mcp add pg -- npx pg-mcp --dsn postgresql://localhost/db"),
		allow("list", "claude mcp list"),
		allow("remove", "claude mcp remove s"),
		allow("get", "claude mcp get s"),
		allow("add-json with references", `claude mcp add-json s '{"command":"npx","env":{"A_TOKEN":"${A_TOKEN}"}}'`),
		allow("not mcp", "claude --model opus -p 'say hi'"),
		allow("text that mentions the command", `echo "run claude mcp add s -e API_KEY=abc"`),
	}
	for _, r := range table {
		t.Run(r.name, func(t *testing.T) {
			d := Decide(r.cmd)
			if d.Block != r.block {
				t.Fatalf("Decide(%q): block=%v (%s), want %v", strings.ReplaceAll(r.cmd, k, "…"), d.Block, d.Reason, r.block)
			}
			if r.block {
				if d.Kind != r.kind || d.Reason == "" {
					t.Errorf("kind %q reason %q, want %q", d.Kind, d.Reason, r.kind)
				}
				noWindow(t, "reason", d.Reason, k)
			}
		})
	}
	// The reason shown to the model carries the position and the way out, never the value.
	o := hook(t, event(t, "Bash", map[string]any{"command": "claude mcp add s -e SUPABASE_ACCESS_TOKEN=" + k + " -- npx x"}), Options{Known: learned(t, nil)})
	if o.code != ExitBlock {
		t.Fatalf("exit %d", o.code)
	}
	reason := o.decision(t)
	for _, want := range []string{"SUPABASE_ACCESS_TOKEN", "single quotes", "${NAME}"} {
		if !strings.Contains(reason, want) {
			t.Errorf("reason lacks %q:\n%s", want, reason)
		}
	}
	noWindow(t, "reason", reason, k)
	noWindow(t, "stderr", o.errout, k)
}
