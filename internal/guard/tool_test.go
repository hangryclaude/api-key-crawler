package guard

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"keyguard/internal/core"
	"keyguard/internal/fp"
	"keyguard/internal/known"
)

// event is a PreToolUse event with every field Claude Code sends
// (code.claude.com/docs/en/hooks, "Common input fields" and "PreToolUse input").
func event(t testing.TB, tool string, input any) *bytes.Reader {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"session_id": "abc123", "prompt_id": "550e8400-e29b-41d4-a716-446655440000",
		"transcript_path": "/home/user/.claude/projects/p/transcript.jsonl", "cwd": "/home/user/my-project",
		"permission_mode": "default", "hook_event_name": "PreToolUse",
		"tool_name": tool, "tool_input": input, "tool_use_id": "toolu_01ABC123",
	})
	if err != nil {
		t.Fatal(err)
	}
	return bytes.NewReader(b)
}

// learned builds a matcher over throwaway-salt registrations of the values, the way selftest
// does: no store on disk, no real key.
func learned(t testing.TB, vals map[string]string) func() (core.KnownMatcher, error) {
	t.Helper()
	kr := fp.NewEphemeral()
	var es []known.Entry
	for name, v := range vals {
		es = append(es, known.EntriesFor(kr, name, "test", []byte(v))...)
	}
	m, err := known.NewMatcher(kr, es)
	if err != nil {
		t.Fatal(err)
	}
	return func() (core.KnownMatcher, error) { return m, nil }
}

type outcome struct {
	code        int
	out, errout string
}

func hook(t testing.TB, in *bytes.Reader, o Options) outcome {
	t.Helper()
	var out, errw bytes.Buffer
	code := Hook(context.Background(), in, &out, &errw, o)
	return outcome{code, out.String(), errw.String()}
}

// decision decodes stdout as Claude Code reads it and checks its exact shape: one JSON
// document whose hookSpecificOutput holds the event name, "deny" and a reason, and nothing
// else in it. The only other field a decision may share the document with is systemMessage.
func (o outcome) decision(t testing.TB) string {
	t.Helper()
	var top map[string]json.RawMessage
	if err := json.Unmarshal([]byte(o.out), &top); err != nil {
		t.Fatalf("stdout is not one JSON object: %v\n%q", err, o.out)
	}
	for k := range top {
		if k != "hookSpecificOutput" && k != "systemMessage" {
			t.Fatalf("stdout has a field %q Claude Code does not read for this event", k)
		}
	}
	if top["hookSpecificOutput"] == nil {
		t.Fatalf("stdout has fields %v, want hookSpecificOutput", keysOf(top))
	}
	var inner map[string]string
	if err := json.Unmarshal(top["hookSpecificOutput"], &inner); err != nil {
		t.Fatalf("hookSpecificOutput: %v", err)
	}
	if len(inner) != 3 || inner["hookEventName"] != "PreToolUse" || inner["permissionDecision"] != "deny" || inner["permissionDecisionReason"] == "" {
		t.Fatalf("hookSpecificOutput is %v", inner)
	}
	return inner["permissionDecisionReason"]
}

func keysOf(m map[string]json.RawMessage) []string {
	var ks []string
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}

// systemMessage decodes stdout as the "NOT scanned" notice.
func (o outcome) systemMessage(t testing.TB) string {
	t.Helper()
	var m map[string]string
	if err := json.Unmarshal([]byte(o.out), &m); err != nil || len(m) != 1 || m["systemMessage"] == "" {
		t.Fatalf("stdout is not a systemMessage: %q (%v)", o.out, err)
	}
	return m["systemMessage"]
}

// noWindow fails when any 10-character window of the key appears in text. The shape shows a
// short public prefix and at most four trailing characters, so no window of ten can
// legitimately appear.
func noWindow(t testing.TB, where, text, key string) {
	t.Helper()
	for i := 0; i+10 <= len(key); i++ {
		if strings.Contains(text, key[i:i+10]) {
			t.Errorf("%s shows part of the key (window at %d):\n%s", where, i, text)
			return
		}
	}
}

func key(r *rand.Rand, prefix string) string {
	const alnum = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := []byte(prefix)
	for range 40 {
		b = append(b, alnum[r.IntN(len(alnum))])
	}
	return string(b)
}

func rng() *rand.Rand { return rand.New(rand.NewPCG(rand.Uint64(), rand.Uint64())) }

// A learned key in any string of the input of the tools the guard watches is refused, in the
// shape Claude Code reads, with a reason made of a name, a shape and a place.
func TestAKeyInAnyToolInputIsDenied(t *testing.T) {
	k := key(rng(), "sk-")
	cases := []struct {
		name  string
		tool  string
		input any
		leaf  string // part of the place the reason names
	}{
		{"Write content", "Write", map[string]any{"file_path": "/p/app.py", "content": "import os\nTOKEN = \"" + k + "\"\n"}, "content line 2"},
		{"Edit new_string", "Edit", map[string]any{"file_path": "/p/app.py", "old_string": "x = 1", "new_string": "x = \"" + k + "\""}, "new_string"},
		{"Edit old_string", "Edit", map[string]any{"file_path": "/p/app.py", "old_string": "x = \"" + k + "\"", "new_string": "x = 1"}, "old_string"},
		{"MultiEdit second edit", "MultiEdit", map[string]any{"file_path": "/p/a", "edits": []any{
			map[string]any{"old_string": "a", "new_string": "b"}, map[string]any{"old_string": "c", "new_string": "d " + k}}}, "edits[1].new_string"},
		{"NotebookEdit", "NotebookEdit", map[string]any{"notebook_path": "/p/n.ipynb", "new_source": "key = '" + k + "'", "cell_type": "code"}, "new_source"},
		{"Bash command", "Bash", map[string]any{"command": "curl -H 'Authorization: Bearer " + k + "' https://api.example.test/v1", "description": "call it"}, "command"},
		{"Bash description", "Bash", map[string]any{"command": "ls -la /tmp", "description": "use " + k}, "description"},
		{"MCP nested argument", "mcp__github__create_issue", map[string]any{"owner": "o", "repo": "r", "body": map[string]any{"text": []any{"fine", "note: " + k}}}, "body.text[1]"},
		{"MCP a key as a field name", "mcp__memory__create_entities", map[string]any{"entities": []any{map[string]any{k: "x"}}}, "{name}"},
		{"plugin MCP server", "mcp__plugin_my-plugin_db__query", map[string]any{"sql": "select '" + k + "'"}, "sql"},
	}
	for _, c := range cases {
		o := hook(t, event(t, c.tool, c.input), Options{Known: learned(t, map[string]string{"OPENAI_API_KEY": k})})
		if o.code != ExitBlock {
			t.Errorf("%s: exit %d, stdout %q", c.name, o.code, o.out)
			continue
		}
		reason := o.decision(t)
		if o.errout != reason {
			t.Errorf("%s: stderr is not the reason", c.name)
		}
		for _, want := range []string{"BLOCKED by keyguard", "this " + c.tool, "OPENAI_API_KEY", "sk-…", "kg", c.leaf} {
			if !strings.Contains(reason, want) {
				t.Errorf("%s: reason lacks %q:\n%s", c.name, want, reason)
			}
		}
		noWindow(t, c.name+" reason", reason, k)
		noWindow(t, c.name+" stdout", o.out, k)
		noWindow(t, c.name+" stderr", o.errout, k)
	}
}

// What the matcher registers as variants of a key is found in a tool call as well.
func TestTheVariantsOfAKeyAreFoundToo(t *testing.T) {
	k := key(rng(), "sk-")
	for name, text := range map[string]string{
		"base64":       "Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("user:"+k)),
		"base64url":    base64.RawURLEncoding.EncodeToString([]byte(k)),
		"in a url":     "https://x.test/hook?token=" + k,
		"json escaped": `{"k":"` + k + `"}`,
	} {
		o := hook(t, event(t, "Write", map[string]any{"file_path": "/p/a", "content": text}), Options{Known: learned(t, map[string]string{"K": k})})
		if o.code != ExitBlock {
			t.Errorf("%s: exit %d", name, o.code)
		}
	}
}

func TestACleanCallIsLeftAlone(t *testing.T) {
	k := key(rng(), "sk-")
	loads := 0
	load := func() (core.KnownMatcher, error) { loads++; return learned(t, map[string]string{"K": k})() }
	for _, c := range []struct {
		tool  string
		input any
	}{
		{"Write", map[string]any{"file_path": "/p/a.go", "content": "package main\n\nfunc main() { println(\"hello world\") }\n"}},
		{"Edit", map[string]any{"file_path": "/p/a.go", "old_string": "hello world", "new_string": "goodbye world"}},
		{"MultiEdit", map[string]any{"file_path": "/p/a.go", "edits": []any{map[string]any{"old_string": "a b c d e f g", "new_string": "h i j k l m n"}}}},
		{"Bash", map[string]any{"command": "git status --short && ls -la", "description": "look around"}},
		{"mcp__memory__search", map[string]any{"query": "what did we decide about the deploy"}},
	} {
		o := hook(t, event(t, c.tool, c.input), Options{Known: load})
		if o.code != ExitAllow || o.out != "" || o.errout != "" {
			t.Errorf("%s: exit %d stdout %q stderr %q", c.tool, o.code, o.out, o.errout)
		}
	}
	if loads == 0 {
		t.Error("the store was never asked for: nothing was searched")
	}
	// Tools the guard does not read never load the store; neither does a call with nothing to search.
	loads = 0
	for _, c := range []struct {
		tool  string
		input any
	}{
		{"Read", map[string]any{"file_path": "/p/" + k}},
		{"Grep", map[string]any{"pattern": k}},
		{"WebFetch", map[string]any{"url": "https://x.test/?" + k}},
		{"Write", map[string]any{"file_path": "/p/a", "content": "short"}},
		{"Bash", map[string]any{"command": "ls"}},
	} {
		if o := hook(t, event(t, c.tool, c.input), Options{Known: load}); o.code != ExitAllow || o.out != "" {
			t.Errorf("%s: exit %d stdout %q", c.tool, o.code, o.out)
		}
	}
	if loads != 0 {
		t.Errorf("the store was loaded %d times for calls with nothing to search", loads)
	}
}

// Fail open, and say so where the user sees it: a systemMessage, never a silent pass.
func TestWhenItCannotLookItSaysNotScanned(t *testing.T) {
	k := key(rng(), "sk-")
	write := func() *bytes.Reader {
		return event(t, "Write", map[string]any{"file_path": "/p/a", "content": "text that is long enough to be searched: " + k})
	}

	broken := func() (core.KnownMatcher, error) {
		return nil, errors.New("known: root /x: store was built with a different salt; run keyguard learn")
	}
	o := hook(t, write(), Options{Known: broken})
	if o.code != ExitAllow {
		t.Errorf("a store that did not load blocked: %d", o.code)
	}
	if msg := o.systemMessage(t); !strings.Contains(msg, "NOT scanned") || !strings.Contains(msg, "different salt") {
		t.Errorf("message: %q", msg)
	}

	// Part of the store loads: it is used, and what failed is said.
	partial := func() (core.KnownMatcher, error) {
		m, _ := learned(t, map[string]string{"K": k})()
		return m, errors.New("known: root /extra: 3 malformed entries ignored")
	}
	o = hook(t, event(t, "Write", map[string]any{"file_path": "/p/a", "content": "this holds " + k}), Options{Known: partial})
	if o.code != ExitBlock {
		t.Fatalf("the part that loaded did not match: exit %d", o.code)
	}
	// One document carries the decision and the notice, because Claude Code reads one.
	reason := o.decision(t)
	var both map[string]any
	if err := json.Unmarshal([]byte(o.out), &both); err != nil || both["systemMessage"] == nil {
		t.Errorf("a partial load should put the notice in the decision's document: %q", o.out)
	}
	if !strings.Contains(reason, "ghp") && !strings.Contains(reason, "sk-") {
		t.Errorf("the reason does not show a shape: %s", reason)
	}

	// A store that holds nothing yet is not an error: nothing is learned, nothing to say.
	empty := func() (core.KnownMatcher, error) { return learned(t, nil)() }
	if o := hook(t, write(), Options{Known: empty}); o.code != ExitAllow || o.out != "" {
		t.Errorf("an empty store: exit %d stdout %q", o.code, o.out)
	}

	for name, in := range map[string]*bytes.Reader{
		"not json":    bytes.NewReader([]byte("{nope")),
		"empty":       bytes.NewReader(nil),
		"input type":  bytes.NewReader([]byte(`{"tool_name":"Write","tool_input":"just a string"}`)),
		"oversize":    bytes.NewReader(bytes.Repeat([]byte("x"), maxInput+10)),
		"input array": bytes.NewReader([]byte(`{"tool_name":"mcp__x__y","tool_input":[1,2`)),
	} {
		o := hook(t, in, Options{Known: learned(t, map[string]string{"K": k})})
		if o.code != ExitAllow {
			t.Errorf("%s: exit %d", name, o.code)
		}
		if name != "input type" && !strings.Contains(o.out, "NOT scanned") {
			t.Errorf("%s: no notice: %q", name, o.out)
		}
	}

	// A panic anywhere inside is an allow with a notice, not exit 2.
	panics := func() (core.KnownMatcher, error) { panic("loader bug") }
	o = hook(t, write(), Options{Known: panics})
	if o.code != ExitAllow || !strings.Contains(o.systemMessage(t), "NOT scanned") {
		t.Errorf("panic: exit %d stdout %q", o.code, o.out)
	}
}

// The default loader reads the stores of the data roots, the real one and $KEYGUARD_HOME
// (invariant 4), and refuses a call that holds a key from either.
func TestTheDefaultLoaderReadsTheStoresOfTheDataRoots(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(t.TempDir(), "kg")
	k := key(rng(), "sk-proj-")
	if err := os.WriteFile(filepath.Join(home, ".env"), []byte("OPENAI_API_KEY="+k+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := known.Learn(known.Options{Home: home, Root: root, GHUsers: []string{}}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KEYGUARD_HOME", root)
	write := func() *bytes.Reader {
		return event(t, "Write", map[string]any{"file_path": "/p/a", "content": "export KEY=" + k + "\n"})
	}
	o := hook(t, write(), Options{})
	if o.code != ExitBlock {
		t.Fatalf("the learned key was not found through core.KnownRoots: exit %d %q", o.code, o.out)
	}
	if reason := o.decision(t); !strings.Contains(reason, "OPENAI_API_KEY") {
		t.Errorf("reason: %s", reason)
	}
	// And Run, the old signature, finds it the same way and blocks with the same text.
	var errw bytes.Buffer
	if code := Run(context.Background(), write(), &errw, nil); code != ExitBlock || !strings.Contains(errw.String(), "OPENAI_API_KEY") {
		t.Errorf("Run: exit %d, stderr %q", code, errw.String())
	}
	t.Setenv("KEYGUARD_HOME", filepath.Join(t.TempDir(), "elsewhere"))
	if o := hook(t, write(), Options{}); o.code != ExitAllow {
		t.Errorf("with no store anywhere the call was blocked: %d", o.code)
	}
}

// A bash command that the rules block is blocked in the same shape, and the reason echoes the
// command only as the old guard did: clipped, with random-looking tokens masked.
func TestBashRulesDenyInTheSameShape(t *testing.T) {
	o := hook(t, event(t, "Bash", map[string]any{"command": "git commit --no-verify -m x"}), Options{Known: learned(t, nil)})
	if o.code != ExitBlock {
		t.Fatalf("exit %d", o.code)
	}
	reason := o.decision(t)
	if !strings.Contains(reason, "pre-commit") || o.errout != reason {
		t.Errorf("reason %q, stderr %q", reason, o.errout)
	}
	// The old entry point gives the same exit code and the same text on stderr.
	var errw bytes.Buffer
	if code := Run(context.Background(), event(t, "Bash", map[string]any{"command": "git commit --no-verify -m x"}), &errw, nil); code != ExitBlock || errw.String() != reason {
		t.Errorf("Run: exit %d, stderr differs", code)
	}
}

// Garbage in a tool call must neither panic (the recover would hide it as an allow with a
// notice, which is what this checks for) nor hang.
func FuzzHook(f *testing.F) {
	for _, s := range []string{
		`{"tool_name":"Write","tool_input":{"file_path":"/p/a","content":"some text long enough to search"}}`,
		`{"tool_name":"Bash","tool_input":{"command":"git commit --no-verify -m x && claude mcp add s -e A=b -- npx x"}}`,
		`{"tool_name":"mcp__a__b","tool_input":{"x":[1,{"y":["z",null,true]}],"path":".gitleaksignore"}}`,
		`{"tool_name":"MultiEdit","tool_input":{"file_path":"/p","edits":[{"old_string":"a","new_string":"pragma: allowlist secret"}]}}`,
		`{"tool_name":"Edit","tool_input":[`, `{"tool_name":7}`, `[]`, `null`, `{"tool_name":"Bash","tool_input":{"command":7}}`,
	} {
		f.Add(s)
	}
	load := learned(f, map[string]string{"K": "sk-" + strings.Repeat("a1B2c3", 8)})
	f.Fuzz(func(t *testing.T, s string) {
		var out, errw bytes.Buffer
		code := Hook(context.Background(), strings.NewReader(s), &out, &errw, Options{Known: load})
		if strings.Contains(out.String(), "internal error") || strings.Contains(errw.String(), "internal error") {
			t.Fatalf("the guard panicked on %q", s)
		}
		if code != ExitAllow && code != ExitBlock {
			t.Fatalf("exit %d", code)
		}
	})
}
