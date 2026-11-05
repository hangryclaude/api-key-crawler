package guard

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func payload(t *testing.T, tool, command, cwd string) *bytes.Reader {
	t.Helper()
	m := map[string]any{
		"session_id": "s", "hook_event_name": "PreToolUse", "tool_name": tool, "cwd": cwd,
		"tool_input": map[string]any{"command": command, "description": "d"},
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.NewReader(b)
}

// recorder is a fake publish check that records what it was asked about.
type recorder struct {
	targets []string
	clean   bool
	detail  string
	err     error
	ctxDL   time.Time
}

func (r *recorder) check(ctx context.Context, target string) (bool, string, error) {
	r.targets = append(r.targets, target)
	r.ctxDL, _ = ctx.Deadline()
	return r.clean, r.detail, r.err
}

func run(t *testing.T, in *bytes.Reader, check PublishCheck) (int, string) {
	t.Helper()
	var errw bytes.Buffer
	code := Run(context.Background(), in, &errw, check)
	return code, errw.String()
}

func TestRunAllowsAndBlocks(t *testing.T) {
	code, out := run(t, payload(t, "Bash", "git status", "/r"), nil)
	if code != ExitAllow || out != "" {
		t.Errorf("clean command: code %d, stderr %q", code, out)
	}

	code, out = run(t, payload(t, "Bash", "git commit -n -m x", "/r"), nil)
	if code != ExitBlock {
		t.Fatalf("--no-verify: code %d, want %d", code, ExitBlock)
	}
	for _, want := range []string{"BLOCKED by keyguard", "pre-commit", "git commit -n -m x", "keyguard allow"} {
		if !strings.Contains(out, want) {
			t.Errorf("block message lacks %q:\n%s", want, out)
		}
	}

	code, out = run(t, payload(t, "Bash", "git config core.hooksPath /dev/null", "/r"), nil)
	if code != ExitBlock || !strings.Contains(out, "tell the user") {
		t.Errorf("config: code %d, stderr:\n%s", code, out)
	}
}

func TestRunIgnoresWhatItCannotRead(t *testing.T) {
	cases := map[string]*bytes.Reader{
		"not json":          bytes.NewReader([]byte("{nope")),
		"empty input":       bytes.NewReader(nil),
		"other tool":        payload(t, "Edit", "git commit -n", "/r"),
		"empty command":     payload(t, "Bash", "", "/r"),
		"blank command":     payload(t, "Bash", "  \n ", "/r"),
		"command not text":  bytes.NewReader([]byte(`{"tool_name":"Bash","tool_input":{"command":42}}`)),
		"no tool_input":     bytes.NewReader([]byte(`{"tool_name":"Bash"}`)),
		"unreadable syntax": payload(t, "Bash", `git commit --no-verify -m "oops`, "/r"),
	}
	for name, in := range cases {
		if code, out := run(t, in, nil); code != ExitAllow {
			t.Errorf("%s: code %d, stderr %q; want allow", name, code, out)
		}
	}
}

// The model reads the block message and so does every transcript: a key typed into the
// command must not be echoed back whole.
func TestBlockMessageDoesNotEchoKeys(t *testing.T) {
	tok := fakeToken()
	_, out := run(t, payload(t, "Bash", "OPENAI_API_KEY="+tok+" git commit --no-verify -m x", "/r"), nil)
	if out == "" {
		t.Fatal("expected a block")
	}
	if strings.Contains(out, tok) {
		t.Errorf("block message echoes the key:\n%s", out)
	}
}

func TestPublishGate(t *testing.T) {
	cwd := t.TempDir()

	t.Run("clean target passes", func(t *testing.T) {
		r := &recorder{clean: true}
		code, out := run(t, payload(t, "Bash", "gh repo create x --public --source .", cwd), r.check)
		if code != ExitAllow || out != "" {
			t.Fatalf("code %d, stderr %q", code, out)
		}
		if len(r.targets) != 1 || r.targets[0] != filepath.Clean(cwd) {
			t.Errorf("checked %q, want the working directory %q", r.targets, cwd)
		}
		if left := time.Until(r.ctxDL); left < 100*time.Second || left > 121*time.Second {
			t.Errorf("publish check deadline in %v, want about 120s", left)
		}
	})

	t.Run("relative source is made absolute", func(t *testing.T) {
		r := &recorder{clean: true}
		run(t, payload(t, "Bash", "gh repo create x --public --source=./app", cwd), r.check)
		if want := filepath.Join(cwd, "app"); len(r.targets) != 1 || r.targets[0] != want {
			t.Errorf("checked %q, want %q", r.targets, want)
		}
	})

	t.Run("repo targets pass through", func(t *testing.T) {
		r := &recorder{clean: true}
		run(t, payload(t, "Bash", "gh repo edit o/n --visibility public", cwd), r.check)
		if len(r.targets) != 1 || r.targets[0] != "o/n" {
			t.Errorf("checked %q, want o/n", r.targets)
		}
	})

	t.Run("findings block and show the report", func(t *testing.T) {
		r := &recorder{detail: "kg3f9a1c  openai  sk-…ab12  src/app.py:12\nkg00aa11  aws  AKIA…QRST  .env:3"}
		code, out := run(t, payload(t, "Bash", "gh repo create x --public --source .", cwd), r.check)
		if code != ExitBlock {
			t.Fatalf("code %d, want block", code)
		}
		for _, want := range []string{"found secrets", "kg3f9a1c", "src/app.py:12", ".env:3", "rotate"} {
			if !strings.Contains(out, want) {
				t.Errorf("message lacks %q:\n%s", want, out)
			}
		}
	})

	t.Run("a check that cannot run blocks", func(t *testing.T) {
		r := &recorder{err: errors.New("exec: no such binary")}
		code, out := run(t, payload(t, "Bash", "gh repo create x --public --source .", cwd), r.check)
		if code != ExitBlock || !strings.Contains(out, "could not run") {
			t.Errorf("code %d, stderr:\n%s", code, out)
		}
	})

	t.Run("no check wired in blocks", func(t *testing.T) {
		code, out := run(t, payload(t, "Bash", "gh repo create x --public --source .", cwd), nil)
		if code != ExitBlock || !strings.Contains(out, "no check is wired") {
			t.Errorf("code %d, stderr:\n%s", code, out)
		}
	})

	t.Run("every target is checked and the first failure wins", func(t *testing.T) {
		r := &recorder{clean: false, detail: "x"}
		code, _ := run(t, payload(t, "Bash", "gh repo create a --public --source=./a && gh repo create b --public --source=./b", cwd), r.check)
		if code != ExitBlock || len(r.targets) != 1 {
			t.Errorf("code %d, checked %q", code, r.targets)
		}
		r2 := &recorder{clean: true}
		run(t, payload(t, "Bash", "gh repo create a --public --source=./a && gh repo create b --public --source=./b", cwd), r2.check)
		if len(r2.targets) != 2 {
			t.Errorf("checked %q, want both", r2.targets)
		}
	})

	t.Run("a private create is never checked", func(t *testing.T) {
		r := &recorder{}
		code, _ := run(t, payload(t, "Bash", "gh repo create x --private --source .", cwd), r.check)
		if code != ExitAllow || len(r.targets) != 0 {
			t.Errorf("code %d, checked %q", code, r.targets)
		}
	})

	t.Run("a hard block comes before any publish check", func(t *testing.T) {
		r := &recorder{clean: true}
		code, _ := run(t, payload(t, "Bash", "git commit -n -m x && gh repo create x --public --source .", cwd), r.check)
		if code != ExitBlock || len(r.targets) != 0 {
			t.Errorf("code %d, checked %q", code, r.targets)
		}
	})
}

func TestTargetResolve(t *testing.T) {
	home, _ := os.UserHomeDir()
	cases := []struct {
		t    Target
		cwd  string
		want string
	}{
		{Target{Repo: "o/n"}, "/w", "o/n"},
		{Target{Path: "."}, "/w", "/w"},
		{Target{Path: "sub/dir"}, "/w", "/w/sub/dir"},
		{Target{Path: "../up"}, "/w/x", "/w/up"},
		{Target{Path: "/abs/p"}, "/w", "/abs/p"},
		{Target{Path: "~/proj"}, "/w", filepath.Join(home, "proj")},
		{Target{Path: "$(…)"}, "/w", "/w"},
		{Target{Path: "sub"}, "", "sub"},
	}
	for _, c := range cases {
		if got := c.t.resolve(c.cwd); got != c.want {
			t.Errorf("%+v in %q -> %q, want %q", c.t, c.cwd, got, c.want)
		}
	}
}

// ExecPublishCheck against a stand-in binary: 0 clean, 1 found secrets, other = broken.
func TestExecPublishCheck(t *testing.T) {
	dir := t.TempDir()
	script := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	ctx := context.Background()

	clean, detail, err := ExecPublishCheck(script("ok", "exit 0\n"))(ctx, "t")
	if !clean || detail != "" || err != nil {
		t.Errorf("exit 0: %v %q %v", clean, detail, err)
	}

	clean, detail, err = ExecPublishCheck(script("found", `echo "args: $1 $2 $3"; echo "kg3f9a1c openai" >&2; exit 1`+"\n"))(ctx, "/some/dir")
	if clean || err != nil || !strings.Contains(detail, "args: publish-check -- /some/dir") || !strings.Contains(detail, "kg3f9a1c") {
		t.Errorf("exit 1: %v %q %v", clean, detail, err)
	}

	clean, _, err = ExecPublishCheck(script("broken", "echo boom >&2; exit 3\n"))(ctx, "t")
	if clean || err == nil || !strings.Contains(err.Error(), "boom") {
		t.Errorf("exit 3: %v %v", clean, err)
	}

	if _, _, err = ExecPublishCheck(filepath.Join(dir, "missing"))(ctx, "t"); err == nil {
		t.Errorf("missing binary: want an error")
	}

	// A report longer than the cap is cut, not buffered whole.
	_, detail, _ = ExecPublishCheck(script("loud", `i=0; while [ $i -lt 4000 ]; do echo "line $i of the report goes on and on"; i=$((i+1)); done; exit 1`+"\n"))(ctx, "t")
	if len(detail) > 16<<10 {
		t.Errorf("report is %d bytes, want at most 16 KiB", len(detail))
	}
}

// A bug in the guard must never block the model's commands: a Go panic exits with 2, the
// code that means "block". A publish check that panics is different: it did not clear the
// publish, so the publish waits.
func TestRunSurvivesPanics(t *testing.T) {
	old := decide
	defer func() { decide = old }()
	decide = func(string) Decision { panic("parser bug") }
	code, out := run(t, payload(t, "Bash", "git status", "/r"), nil)
	if code != ExitAllow || !strings.Contains(out, "internal error") {
		t.Errorf("parser panic: code %d, stderr %q", code, out)
	}
	decide = old

	boom := func(context.Context, string) (bool, string, error) { panic("checker bug") }
	code, out = run(t, payload(t, "Bash", "gh repo create x --public --source .", "/r"), boom)
	if code != ExitBlock || !strings.Contains(out, "could not run") {
		t.Errorf("check panic: code %d, stderr %q", code, out)
	}
}

// The seeds keep the shapes that matter as a regular test; `go test -fuzz=FuzzDecide`
// goes further.
func FuzzDecide(f *testing.F) {
	for _, tbl := range [][]row{table, keyguardTable, scannerTable, githubTable, reviewTable} {
		for _, r := range tbl {
			f.Add(r.cmd)
		}
	}
	for _, s := range fuzzSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, cmd string) {
		Decide(cmd)
		_, _ = Tokenize(cmd)
	})
}

var fuzzSeeds = []string{
	"$(", "`", "${", "$((", "<<", "<<EOF", "<<-'X'\n", "'", `"`, `\`, "$'\\x", "((", "))", "a|&b",
	";;", "&>", ">&", "<(", ">(", "\x00", "git -c", "gh api", "bash -c", "env -S", "xargs -I",
	"claude mcp add -e", "claude mcp add-json s {", "go run", "go run -tags", "tee", "cp -t", "sed -i", "dd of=", "> ", ">> ",
	"curl -X PATCH", "gh api -X PATCH repos/o/n --input -", "http PATCH",
}
