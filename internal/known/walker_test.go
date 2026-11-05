package known

import (
	"fmt"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
)

// literalsOf reads doc and returns "path|kind" for each literal credential, in file order.
func literalsOf(t *testing.T, f Format, doc string) []string {
	t.Helper()
	ls, err := Literals(f, []byte(doc))
	if err != nil {
		t.Fatalf("Literals: %v\n%s", err, doc)
	}
	var out []string
	for _, l := range ls {
		out = append(out, l.Path+"|"+l.Kind)
	}
	return out
}

// anyKey is a key-shaped fake built at run time: no secret-shaped literal sits in this file.
func anyKey(t testing.TB, prefix string) string {
	return prefix + randFrom(newRNG(t), alnum, 36)
}

type walkCase struct {
	name string
	f    Format
	doc  string // %[1]s is a fake key
	want []string
}

func TestWalkerFindsLiteralsInEveryFormat(t *testing.T) {
	cases := []walkCase{
		// JSON: Claude Code, Cursor, Claude Desktop, Copilot, Kiro, Devin all share mcpServers.
		{"json env block", JSON, `{"mcpServers":{"supabase":{"command":"npx","args":["-y","@supabase/mcp"],"env":{"SUPABASE_ACCESS_TOKEN":"%[1]s","LOG_LEVEL":"debug"}}}}`,
			[]string{"mcpServers.supabase.env.SUPABASE_ACCESS_TOKEN|env"}},
		{"json header", JSON, `{"mcpServers":{"api":{"type":"http","url":"https://mcp.example.com/mcp","headers":{"Authorization":"Bearer %[1]s"}}}}`,
			[]string{"mcpServers.api.headers.Authorization|header"}},
		{"json arg after --api-key", JSON, `{"mcpServers":{"x":{"command":"npx","args":["-y","some-mcp","--api-key","%[1]s"]}}}`,
			[]string{"mcpServers.x.args --api-key|arg"}},
		{"json --token=value", JSON, `{"mcpServers":{"x":{"command":"npx","args":["some-mcp","--token=%[1]s"]}}}`,
			[]string{"mcpServers.x.args --token|arg"}},
		{"json docker -e", JSON, `{"mcpServers":{"x":{"command":"docker","args":["run","-i","--rm","-e","GITHUB_PERSONAL_ACCESS_TOKEN=%[1]s","image"]}}}`,
			[]string{"mcpServers.x.args -e GITHUB_PERSONAL_ACCESS_TOKEN|env"}},
		{"json docker --header", JSON, `{"mcpServers":{"x":{"command":"npx","args":["mcp-remote","https://h.example/mcp","--header","Authorization: Bearer %[1]s"]}}}`,
			[]string{"mcpServers.x.args --header Authorization|header"}},
		{"json dsn with a password", JSON, `{"mcpServers":{"pg":{"command":"npx","args":["pg-mcp","--dsn","postgresql://app:%[1]s@db.example.com:5432/app"]}}}`,
			[]string{"mcpServers.pg.args|url-password"}},
		{"json dsn in libpq keywords", JSON, `{"mcpServers":{"pg":{"command":"npx","args":["pg-mcp","--dsn","host=db.internal.test user=app password=%[1]s dbname=app"]}}}`,
			[]string{"mcpServers.pg.args --dsn|arg"}},
		{"json url query", JSON, `{"mcpServers":{"x":{"url":"https://mcp.example.com/sse?api_key=%[1]s&mode=fast"}}}`,
			[]string{"mcpServers.x.url?api_key|url-param"}},
		{"json settings env", JSON, `{"permissions":{"allow":["Bash(ls)"]},"env":{"ANTHROPIC_AUTH_TOKEN":"%[1]s"}}`,
			[]string{"env.ANTHROPIC_AUTH_TOKEN|env"}},
		{"json top-level apiKey", JSON, `{"model":"x","apiKey":"%[1]s"}`, []string{"apiKey|key"}},
		{"json in an array of servers", JSON, `{"servers":[{"name":"a","env":{"A_TOKEN":"%[1]s"}}]}`,
			[]string{"servers[].env.A_TOKEN|env"}},

		// TOML: Codex.
		{"toml env table", TOML, "[mcp_servers.supabase]\ncommand = \"npx\"\n\n[mcp_servers.supabase.env]\nSUPABASE_ACCESS_TOKEN = \"%[1]s\"\nMODE = \"fast\"\n",
			[]string{"mcp_servers.supabase.env.SUPABASE_ACCESS_TOKEN|env"}},
		{"toml inline env", TOML, "[mcp_servers.x]\ncommand = \"npx\"\nenv = { A_TOKEN = \"%[1]s\", MODE = \"fast\" }\n",
			[]string{"mcp_servers.x.env.A_TOKEN|env"}},
		{"toml http_headers", TOML, "[mcp_servers.x]\nurl = \"https://mcp.example.com\"\nhttp_headers = { \"X-Api-Key\" = \"%[1]s\" }\n",
			[]string{"mcp_servers.x.http_headers.X-Api-Key|header"}},
		{"toml experimental_bearer_token", TOML, "[mcp_servers.x]\nurl = \"https://mcp.example.com\"\nexperimental_bearer_token = \"%[1]s\"\n",
			[]string{"mcp_servers.x.experimental_bearer_token|key"}},
		{"toml args across lines", TOML, "[mcp_servers.x]\ncommand = \"npx\"\nargs = [\n  \"-y\",\n  \"some-mcp\", # the server\n  \"--password\",\n  \"%[1]s\",\n]\n",
			[]string{"mcp_servers.x.args --password|arg"}},
		{"toml literal string", TOML, "[mcp_servers.x.env]\nAPI_KEY = '%[1]s'\n", []string{"mcp_servers.x.env.API_KEY|env"}},
		{"toml multi-line string", TOML, "[mcp_servers.x.env]\nAPI_KEY = \"\"\"\n%[1]s\"\"\"\n", []string{"mcp_servers.x.env.API_KEY|env"}},
		{"toml quoted table key", TOML, "[mcp_servers.\"my server\".env]\nAPI_KEY = \"%[1]s\"\n", []string{"mcp_servers.my server.env.API_KEY|env"}},
		{"toml array of tables", TOML, "[[servers]]\nname = \"a\"\n[servers.env]\nA_TOKEN = \"%[1]s\"\n", []string{"servers.env.A_TOKEN|env"}},
		{"toml dotted key", TOML, "[mcp_servers.x]\nenv.A_TOKEN = \"%[1]s\"\n", []string{"mcp_servers.x.env.A_TOKEN|env"}},

		// YAML: Continue, Aider.
		{"yaml env map", YAML, "mcpServers:\n  - name: gh\n    command: npx\n    args:\n      - -y\n      - gh-mcp\n    env:\n      GITHUB_TOKEN: %[1]s\n      MODE: fast\n",
			[]string{"mcpServers[].env.GITHUB_TOKEN|env"}},
		{"yaml quoted value", YAML, "mcpServers:\n  gh:\n    env:\n      GITHUB_TOKEN: \"%[1]s\"\n", []string{"mcpServers.gh.env.GITHUB_TOKEN|env"}},
		{"yaml flow map", YAML, "mcpServers:\n  gh:\n    env: {GITHUB_TOKEN: %[1]s, MODE: fast}\n", []string{"mcpServers.gh.env.GITHUB_TOKEN|env"}},
		{"yaml flow args", YAML, "server:\n  args: [\"-y\", \"pkg\", \"--api-key\", \"%[1]s\"]\n", []string{"server.args --api-key|arg"}},
		{"yaml block args", YAML, "server:\n  args:\n    - pkg\n    - --token\n    - %[1]s\n", []string{"server.args --token|arg"}},
		{"yaml aider api key", YAML, "model: gpt-4o\nopenai-api-key: %[1]s\n", []string{"openai-api-key|key"}},
		{"yaml sequence at the key's indent", YAML, "servers:\n- name: a\n  env:\n    A_TOKEN: %[1]s\n", []string{"servers[].env.A_TOKEN|env"}},
		{"yaml block scalar", YAML, "env:\n  A_TOKEN: |\n    %[1]s\n", []string{"env.A_TOKEN|env"}},
		{"yaml compose-style list", YAML, "services:\n  app:\n    environment:\n      - MODE=fast\n      - A_TOKEN=%[1]s\n", []string{"services.app.environment.A_TOKEN|env"}},
		{"json list of pairs", JSON, `{"mcpServers":{"x":{"env":["MODE=fast","A_TOKEN=%[1]s"]}}}`, []string{"mcpServers.x.env.A_TOKEN|env"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := fmt.Sprintf(c.doc, anyKey(t, "sk-"))
			if got := literalsOf(t, c.f, doc); !slices.Equal(got, c.want) {
				t.Errorf("literals\n got %q\nwant %q\ndoc:\n%s", got, c.want, redact(doc))
			}
		})
	}
}

// redact keeps a failing test's output free of the fake it planted.
func redact(s string) string { return strings.NewReplacer("sk-", "sk-…").Replace(s) }

func TestWalkerAcceptsTheVendorsEnvironmentReferences(t *testing.T) {
	cases := []walkCase{
		{"Claude Code ${VAR}", JSON, `{"mcpServers":{"x":{"env":{"A_TOKEN":"${A_TOKEN}"},"headers":{"Authorization":"Bearer ${A_TOKEN}"}}}}`, nil},
		{"Claude Code ${VAR:-} with an empty default", JSON, `{"env":{"A_TOKEN":"${A_TOKEN:-}"}}`, nil},
		{"Claude Code default that is a placeholder", JSON, `{"env":{"A_TOKEN":"${A_TOKEN:-changeme}"}}`, nil},
		{"Cursor ${env:NAME}", JSON, `{"mcpServers":{"x":{"env":{"A_TOKEN":"${env:A_TOKEN}"},"headers":{"X-Api-Key":"${env:KEY}"}}}}`, nil},
		{"Kiro ${VARIABLE_NAME}", JSON, `{"mcpServers":{"x":{"env":{"A_TOKEN":"${A_TOKEN}"}}}}`, nil},
		{"opencode {env:VAR} and {file:path}", JSON, `{"mcp":{"x":{"environment":{"A_TOKEN":"{env:A_TOKEN}","B_TOKEN":"{file:~/.secrets/b}"}}}}`, nil},
		{"Continue secrets expression", YAML, "mcpServers:\n  - name: x\n    env:\n      A_TOKEN: ${{ secrets.A_TOKEN }}\n", nil},
		{"Codex names", TOML, "[mcp_servers.x]\nurl = \"https://mcp.example.com\"\nbearer_token_env_var = \"A_TOKEN_NAME\"\nenv_http_headers = { \"X-Api-Key\" = \"B_TOKEN_NAME\" }\nenv_key = \"OPENAI_API_KEY\"\nenv_vars = [\"A_TOKEN\", \"B_TOKEN\"]\n", nil},
		{"$VAR is not a value anyone typed", JSON, `{"env":{"A_TOKEN":"$A_TOKEN"}}`, nil},
		{"placeholders", JSON, `{"env":{"A_TOKEN":"YOUR_TOKEN_HERE","B_TOKEN":"<paste your token>","C_TOKEN":"...","D_TOKEN":"changeme","E_API_KEY":"your-api-key","F_TOKEN":"xxxxxxxxxxxxxxxx"}}`, nil},
		{"empty values", JSON, `{"env":{"A_TOKEN":""},"apiKey":""}`, nil},
		{"stand-ins for a local relay", JSON, `{"env":{"ANTHROPIC_AUTH_TOKEN":"ollama","OPENAI_API_KEY":"lm-studio","ANTHROPIC_BASE_URL":"http://localhost:11434"}}`, nil},
		{"modes under a name that says auth", JSON, `{"mcpServers":{"x":{"env":{"AUTH_MODE":"device_code","SESSION_STORE":"memory"}}}}`, nil},
		{"things that are not credentials", JSON, `{"env":{"NODE_ENV":"production","LOG_LEVEL":"debug","PORT":"3000","HOME_DIR":"/Users/someone/dev/project"},"mcpServers":{"x":{"command":"npx","args":["-y","@scope/some-mcp-server@latest","--port","3000","--keyboard-layout","dvorak"]}}}`, nil},
		{"public by design", JSON, `{"env":{"SUPABASE_ANON_KEY":"` + jwtRole("anon") + `"}}`, nil},
		{"-e inherits the variable", JSON, `{"mcpServers":{"x":{"command":"docker","args":["run","-e","GITHUB_TOKEN","image"]}}}`, nil},
		{"plain url with no credential", JSON, `{"mcpServers":{"x":{"url":"https://mcp.example.com/v1/mcp?mode=fast"}}}`, nil},
		{"local default password", JSON, `{"mcpServers":{"pg":{"args":["pg-mcp","` + dsn("postgres", "postgres", "localhost:5432/db") + `"]}}}`, nil},
		{"templated url password", JSON, `{"mcpServers":{"pg":{"args":["pg-mcp","postgresql://app:${DB_PASSWORD}@db.example.com/app"]}}}`, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := literalsOf(t, c.f, c.doc); len(got) != 0 {
				t.Errorf("flagged references or non-credentials: %q", got)
			}
		})
	}
}

// jwtRole is a JWT whose payload has the role, built at run time.
func jwtRole(role string) string {
	return jwtWithRole(rand.New(rand.NewPCG(7, 9)), role)
}

// dsn joins a connection URL from its parts, so that no credential URI sits in this source
// for a scanner to find (PLAN invariant 2).
func dsn(user, pass, rest string) string { return "postgresql://" + user + ":" + pass + "@" + rest }

// pw is a config that sets a value under a name that says password; the name is joined for
// the same reason.
func pw(v string) string { return `{"env":{"DB_` + "PASS" + `WORD":"` + v + `"}}` }

// A short lower-case word under a token name is a stand-in; a password somebody chose is not.
func TestWalkerTellsAStandInFromAChosenPassword(t *testing.T) {
	for doc, want := range map[string]int{
		pw("hunter2"):                   1,
		pw("Tr0ub4dor"):                 1,
		pw("correcthorsebatterystaple"): 1,
		pw("ollama"):                    0,
		pw("changeme"):                  0,
		pw("pass" + "word"):             0,
		`{"env":{"ANTHROPIC_AUTH_TOKEN":"lm-studio"}}`:                             0,
		`{"mcpServers":{"x":{"args":["--pass` + `word","correct-horse-staple"]}}}`: 1,
	} {
		if got := len(literalsOf(t, JSON, doc)); got != want {
			t.Errorf("%s: %d literals, want %d", doc, got, want)
		}
	}
}

func TestWalkerJudgesTheDefaultOfAReference(t *testing.T) {
	// ${VAR:-default} keeps the default in the file: a key there is written out.
	doc := fmt.Sprintf(`{"env":{"A_TOKEN":"${A_TOKEN:-%s}"}}`, anyKey(t, "sk-"))
	if got := literalsOf(t, JSON, doc); !slices.Equal(got, []string{"env.A_TOKEN|env"}) {
		t.Errorf("a default that is a key was not flagged: %q", got)
	}
}

func TestWalkerReportsLinesAndNeverTheValue(t *testing.T) {
	key := anyKey(t, "sk-proj-")
	docs := map[Format]string{
		JSON: "{\n  \"mcpServers\": {\n    \"x\": {\n      \"env\": {\n        \"A_TOKEN\": \"" + key + "\"\n      }\n    }\n  }\n}\n",
		TOML: "# codex\n\n[mcp_servers.x.env]\n# the key\nA_TOKEN = \"" + key + "\"\n",
		YAML: "# aider\nmcpServers:\n  x:\n    env:\n      # the key\n      A_TOKEN: " + key + "\n",
	}
	wantLine := map[Format]int{JSON: 5, TOML: 5, YAML: 6}
	for f, doc := range docs {
		ls, err := Literals(f, []byte(doc))
		if err != nil || len(ls) != 1 {
			t.Fatalf("format %d: %v %v", f, ls, err)
		}
		if ls[0].Line != wantLine[f] {
			t.Errorf("format %d: line %d, want %d", f, ls[0].Line, wantLine[f])
		}
		if ls[0].Len != len(key) || !strings.HasPrefix(ls[0].Shape, "sk-proj-…") {
			t.Errorf("format %d: len %d shape %q", f, ls[0].Len, ls[0].Shape)
		}
		assertNoValue(t, []string{key}, map[string][]byte{"the literal": []byte(fmt.Sprintf("%+v", ls))})
	}
}

func TestWalkerReadsJSONWithComments(t *testing.T) {
	key := anyKey(t, "sk-")
	doc := "{\n  // opencode.jsonc\n  \"mcp\": {\n    \"x\": {\n      /* the key */\n      \"environment\": { \"A_TOKEN\": \"" + key + "\", },\n    },\n  },\n}\n"
	ls, err := Literals(JSON, []byte(doc))
	if err != nil || len(ls) != 1 || ls[0].Path != "mcp.x.environment.A_TOKEN" || ls[0].Line != 6 {
		t.Fatalf("%+v %v", ls, err)
	}
	// A comment marker inside a string is not a comment.
	doc = `{"env":{"A_TOKEN":"` + key + `","URL":"https://x.example/a//b"}}`
	if got := literalsOf(t, JSON, doc); len(got) != 1 {
		t.Errorf("literals %q", got)
	}
}

// A key pasted as the name of a field is as secret as one pasted as a value, and the path of
// a literal is printed in the block message.
func TestWalkerNeverShowsAKeyUsedAsAFieldName(t *testing.T) {
	name, val := anyKey(t, "sk-proj-"), anyKey(t, "ghp_")
	doc := fmt.Sprintf(`{"mcpServers":{"x":{"env":{%q:%q}}}}`, name, val)
	ls, err := Literals(JSON, []byte(doc))
	if err != nil || len(ls) != 1 {
		t.Fatalf("%+v %v", ls, err)
	}
	var credNames []string
	if err := Credentials(JSON, []byte(doc), func(n, v string) { credNames = append(credNames, n) }); err != nil {
		t.Fatal(err)
	}
	assertNoValue(t, []string{name}, map[string][]byte{
		"the literal": []byte(fmt.Sprintf("%+v", ls)), "learn's label": []byte(strings.Join(credNames, "|")),
	})
}

func TestWalkerFailsOpenAndSaysSo(t *testing.T) {
	key := anyKey(t, "sk-")
	good := `"env":{"A_TOKEN":"` + key + `"}`
	// Broken after the key: what was read is returned with the error.
	ls, err := Literals(JSON, []byte(`{`+good+`, "oops": [1, 2`))
	if err == nil || len(ls) != 1 {
		t.Errorf("truncated JSON: %d literals, err %v", len(ls), err)
	}
	ls, err = Literals(TOML, []byte("[env]\nA_TOKEN = \""+key+"\"\nbroken = = =\n[also\n"))
	if err == nil || len(ls) != 1 {
		t.Errorf("broken TOML: %d literals, err %v", len(ls), err)
	}
	ls, err = Literals(YAML, []byte("env:\n  A_TOKEN: "+key+"\n  broken: [1, 2\n"))
	if err == nil || len(ls) != 1 {
		t.Errorf("broken YAML: %d literals, err %v", len(ls), err)
	}
	for _, f := range []Format{JSON, TOML, YAML} {
		if ls, err := Literals(f, nil); err != nil || len(ls) != 0 {
			t.Errorf("empty input, format %d: %v %v", f, ls, err)
		}
	}
}

func TestFormatOfAndAgentConfigFormat(t *testing.T) {
	for p, want := range map[string]Format{"a.json": JSON, "a.JSONC": JSON, "a.toml": TOML, "a.yml": YAML, "a.yaml": YAML} {
		if got, ok := FormatOf(p); !ok || got != want {
			t.Errorf("FormatOf(%q) = %v %v", p, got, ok)
		}
	}
	if _, ok := FormatOf("a.txt"); ok {
		t.Error("a.txt is not structured")
	}
	for p, want := range map[string]Format{
		".mcp.json": JSON, "x/.mcp.json": JSON, ".cursor/mcp.json": JSON, "p/.vscode/mcp.json": JSON,
		".copilot/mcp-config.json": JSON, ".kiro/settings/mcp.json": JSON, ".devin/mcp_config.json": JSON,
		"opencode.json": JSON, "a/opencode.jsonc": JSON, ".continue/config.yaml": YAML, ".continue/config.json": JSON,
		".aider.conf.yml": YAML, ".codex/config.toml": TOML, "Claude_Desktop_Config.json": JSON, ".claude/settings.json": JSON,
	} {
		if got, ok := AgentConfigFormat(p); !ok || got != want {
			t.Errorf("AgentConfigFormat(%q) = %v %v, want %v", p, got, ok, want)
		}
	}
	for _, p := range []string{"settings.json", "mcp.json", "config.toml", "x/.cursor/rules.json", "package.json", ".claude/settings.local.json"} {
		if _, ok := AgentConfigFormat(p); ok {
			t.Errorf("AgentConfigFormat(%q) should not match", p)
		}
	}
}

func TestArgLiteralsAndPairLiteral(t *testing.T) {
	key := anyKey(t, "sk-")
	if got := ArgLiterals([]string{"npx", "-y", "pkg", "--api-key", key}); len(got) != 1 || got[0].Kind != "arg" {
		t.Errorf("--api-key: %+v", got)
	}
	if got := ArgLiterals([]string{"--api-key", "${KEY}", "--token", "YOUR_TOKEN", "-y"}); len(got) != 0 {
		t.Errorf("references flagged: %+v", got)
	}
	if l, ok := PairLiteral("env", "OPENAI_API_KEY", key); !ok || l.Kind != "env" {
		t.Errorf("env pair: %+v %v", l, ok)
	}
	if _, ok := PairLiteral("header", "Authorization", "Bearer ${TOKEN}"); ok {
		t.Error("a header that references the environment was flagged")
	}
	if l, ok := PairLiteral("header", "X-Api-Key", key); !ok || l.Kind != "header" {
		t.Errorf("header pair: %+v %v", l, ok)
	}
}

func TestCredentialsHandsLearnTheValuesByPosition(t *testing.T) {
	a, b, c := anyKey(t, "sk-"), anyKey(t, "tok_"), anyKey(t, "pw")
	doc := fmt.Sprintf(`{"mcpServers":{"x":{"args":["-y","pkg","--api-key","%s","postgresql://u:%s@h/db?sig=%s"],"env":{"R":"${R}"}}}}`, a, b, c)
	got := map[string]string{}
	if err := Credentials(JSON, []byte(doc), func(name, value string) { got[value] = name }); err != nil {
		t.Fatal(err)
	}
	for v, name := range map[string]string{a: "api-key (arg)", b: "password (url-password)", c: "sig (url-param)"} {
		if got[v] != name {
			t.Errorf("a value planted for %q came back as %q", name, got[v])
		}
	}
	for v := range got {
		if strings.Contains(v, "${") {
			t.Error("a reference was handed to learn")
		}
	}
}

// Garbage in every syntax must neither panic nor hang: the walker runs inside a hook.
func FuzzWalker(f *testing.F) {
	seeds := []string{
		`{"env":{"A_TOKEN":"x"}}`, "[a.b]\nc = {d = [1, \"x\"]}\n", "a:\n  - b: [c, {d: e}]\n  - |\n    x\n", "[", "{", `"`, "'''", `"""`,
		"- - -", "a: &x !t [", "\x00\xff", "[[a]]\n[[a.b]]\nc=\"d\"", "a = [\n[\n[\n", "k: {a: {b: {c: ",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		for _, fm := range []Format{JSON, TOML, YAML} {
			_, _ = Literals(fm, []byte(s))
			_ = Credentials(fm, []byte(s), func(string, string) {})
		}
	})
}
