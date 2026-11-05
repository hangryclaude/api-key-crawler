package guard

import (
	"strings"
	"testing"
)

// marker builds an allow marker from its two halves, so this file can be written through the
// guard it tests.
func marker(tool, rest string) string { return tool + ":" + rest }

// The files that decide what a scanner ignores, and keyguard's own (STEAL P0-12).
func TestAgentsCannotWriteScannerConfigOrKeyguardsOwnFiles(t *testing.T) {
	denied := []string{
		".gitleaksignore", "sub/dir/.betterleaksignore", "/repo/.trufflehogignore", ".BETTERLEAKSIGNORE",
		".gitleaks.toml", "/repo/.betterleaks.toml", ".secrets.baseline", ".gitguardian.yaml", ".gitguardian.yml",
		".github/secret_scanning.yml", "/repo/.github/secret_scanning.yml",
		"/Users/me/.keyguard/state/ignore.json", "/Users/me/.keyguard/state/known/known.json",
		"/Users/me/.keyguard/state/known/salt", "/Users/me/.keyguard/state/config.json",
		"/Users/me/.keyguard/rules/keyguard.toml", "/Users/me/.keyguard/bin/keyguard",
		"/Users/me/.keyguard/state/../state/ignore.json", "/Users/me/.KEYGUARD/state/ignore.json",
	}
	allowed := []string{
		"/repo/README.md", "/repo/.gitignore", "/repo/.github/workflows/ci.yml", "/repo/.gitleaksignore.md",
		"/repo/docs/gitleaksignore.txt", "/Users/me/.keyguard/logs/poll.log", "/Users/me/.keyguard/report/index.html",
		"/Users/me/.keyguard/state/findings.json", "/Users/me/.keyguard/cache/mirrors/x", "/tmp/x.keyguard/state/ignore.json",
	}
	for _, tool := range []struct{ name, field string }{{"Write", "file_path"}, {"Edit", "file_path"}, {"MultiEdit", "file_path"}, {"NotebookEdit", "notebook_path"}} {
		for _, p := range denied {
			o := hook(t, event(t, tool.name, map[string]any{tool.field: p, "content": "a\n", "new_string": "a", "old_string": "b", "new_source": "x"}), Options{Known: learned(t, nil)})
			if o.code != ExitBlock {
				t.Errorf("%s %s: exit %d", tool.name, p, o.code)
				continue
			}
			if reason := o.decision(t); !strings.Contains(reason, "the user") {
				t.Errorf("%s %s: the reason does not send the agent to the user:\n%s", tool.name, p, reason)
			}
		}
		for _, p := range allowed {
			if o := hook(t, event(t, tool.name, map[string]any{tool.field: p, "content": "a\n", "new_string": "a", "old_string": "b", "new_source": "x"}), Options{Known: learned(t, nil)}); o.code != ExitAllow {
				t.Errorf("%s %s was refused: %s", tool.name, p, o.out)
			}
		}
	}
	// An MCP tool that writes a file is held to the same list through the fields it names paths in.
	for _, c := range []struct {
		tool  string
		input map[string]any
		want  int
	}{
		{"mcp__github__create_or_update_file", map[string]any{"owner": "o", "repo": "r", "path": ".gitleaksignore", "content": "x"}, ExitBlock},
		{"mcp__fs__write_file", map[string]any{"file_path": "/Users/me/.keyguard/state/ignore.json", "content": "{}"}, ExitBlock},
		{"mcp__github__push_files", map[string]any{"owner": "o", "repo": "r", "files": []any{"src/a.go", ".betterleaksignore"}}, ExitBlock},
		{"mcp__github__create_or_update_file", map[string]any{"path": "src/main.go", "content": "package main"}, ExitAllow},
		{"mcp__search__web", map[string]any{"query": ".gitleaksignore"}, ExitAllow}, // a query is not a path
	} {
		if o := hook(t, event(t, c.tool, c.input), Options{Known: learned(t, nil)}); o.code != c.want {
			t.Errorf("%s %v: exit %d, want %d", c.tool, c.input, o.code, c.want)
		}
	}
}

func TestInlineAllowMarkersAreRefusedInWrittenText(t *testing.T) {
	line := func(m string) string { return "export TOKEN=abc123 # " + m + "\n" }
	for _, m := range []string{
		marker("betterleaks", "allow"), marker("gitleaks", "allow"), marker("trufflehog", "ignore"),
		strings.ToUpper(marker("gitleaks", "allow")), marker("GitLeaks", "Allow"),
		"pragma: allowlist secret", "pragma:allowlist secret", "pragma: allowlist nextline secret", "PRAGMA: ALLOWLIST SECRET",
		"pragma: allowlist-secret",
	} {
		for _, c := range []struct {
			tool  string
			input map[string]any
		}{
			{"Write", map[string]any{"file_path": "/p/a.sh", "content": line(m)}},
			{"Edit", map[string]any{"file_path": "/p/a.sh", "old_string": "export TOKEN=abc123", "new_string": line(m)}},
			{"MultiEdit", map[string]any{"file_path": "/p/a.sh", "edits": []any{map[string]any{"old_string": "a", "new_string": "b"}, map[string]any{"old_string": "export TOKEN=abc123", "new_string": line(m)}}}},
			{"NotebookEdit", map[string]any{"notebook_path": "/p/n.ipynb", "new_source": line(m)}},
			{"mcp__github__create_or_update_file", map[string]any{"path": "a.sh", "content": line(m)}},
		} {
			o := hook(t, event(t, c.tool, c.input), Options{Known: learned(t, nil)})
			if o.code != ExitBlock {
				t.Errorf("%s with %q: exit %d", c.tool, m, o.code)
				continue
			}
			if reason := o.decision(t); !strings.Contains(strings.ToLower(reason), "inline allow marker") {
				t.Errorf("%s with %q: reason %q", c.tool, m, reason)
			}
		}
	}
	// The shortest text that is a marker is still one.
	for _, tool := range []string{"Write", "mcp__x__y"} {
		if o := hook(t, event(t, tool, map[string]any{"file_path": "/p/a", "content": marker("gitleaks", "allow")}), Options{Known: learned(t, nil)}); o.code != ExitBlock {
			t.Errorf("%s with only the marker: exit %d", tool, o.code)
		}
	}
	// Taking a marker out is the right edit, and a marker in a command is not a write.
	for _, c := range []struct {
		name, tool string
		input      map[string]any
	}{
		{"removing a marker", "Edit", map[string]any{"file_path": "/p/a.sh", "old_string": line(marker("gitleaks", "allow")), "new_string": "export TOKEN=${TOKEN}\n"}},
		{"searching for markers", "Bash", map[string]any{"command": "rg -n '" + marker("gitleaks", "allow") + "' ."}},
		{"words near it", "Write", map[string]any{"file_path": "/p/a.md", "content": "betterleaks is a scanner; allow lists are discussed elsewhere\n"}},
		{"pragma without allowlist", "Write", map[string]any{"file_path": "/p/a.py", "content": "# pragma: no cover\nx = 1\n"}},
	} {
		if o := hook(t, event(t, c.tool, c.input), Options{Known: learned(t, nil)}); o.code != ExitAllow {
			t.Errorf("%s was refused: %s", c.name, o.out)
		}
	}
}

var scannerTable = []row{
	// Writing a scanner's files from the shell.
	block("redirect into an ignore file", "echo 'a.py:generic-api-key:3' >> .gitleaksignore", KindScanner),
	block("truncating redirect", "printf x > .betterleaksignore", KindScanner),
	block("redirect after cat", "cat <<EOF > .gitleaks.toml\n[allowlist]\nEOF", KindScanner),
	block("&> redirect", "echo x &> .trufflehogignore", KindScanner),
	block("redirect with a path", "echo x > sub/dir/.secrets.baseline", KindScanner),
	block("redirect inside bash -c", `bash -c 'echo x >> .gitleaksignore'`, KindScanner),
	block("redirect in a subshell", "(cd sub && echo x > .gitleaksignore)", KindScanner),
	block("bare redirect creates the file", "> .gitleaksignore", KindScanner),
	block("tee", "echo x | tee .gitleaksignore", KindScanner),
	block("tee -a", "echo x | tee -a sub/.betterleaksignore", KindScanner),
	block("sudo tee", "echo x | sudo tee .gitleaks.toml", KindScanner),
	block("touch", "touch .betterleaksignore", KindScanner),
	block("cp to the file", "cp /tmp/mine .gitleaksignore", KindScanner),
	block("cp into the directory", "cp /tmp/.gitleaksignore .", KindScanner),
	block("mv onto it", "mv /tmp/new .gitleaks.toml", KindScanner),
	block("install", "install -m 644 /tmp/x .github/secret_scanning.yml", KindScanner),
	block("ln", "ln -s /tmp/x .gitleaksignore", KindScanner),
	block("sed -i", "sed -i '' 's/a/b/' .gitleaksignore", KindScanner),
	block("sed -i.bak", "sed -i.bak '$a x' .betterleaksignore", KindScanner),
	block("sed --in-place", "sed --in-place s/a/b/ .secrets.baseline", KindScanner),
	block("perl -pi", "perl -pi -e 's/a/b/' .gitleaks.toml", KindScanner),
	block("dd of=", "dd if=/tmp/x of=.gitleaksignore", KindScanner),
	block("truncate", "truncate -s 0 .gitleaksignore", KindScanner),
	block("env wrapper", "env FOO=1 tee .gitleaksignore", KindScanner),
	block("github scanning config", "echo 'paths-ignore: [\"**\"]' > .github/secret_scanning.yml", KindScanner),

	// Keyguard's own files.
	block("redirect over the allowlist", "echo '{}' > ~/.keyguard/state/ignore.json", KindOwner),
	block("redirect with $HOME", `echo '{}' > "$HOME/.keyguard/state/ignore.json"`, KindOwner),
	block("redirect with an absolute path", "echo '{}' >> /Users/me/.keyguard/state/ignore.json", KindOwner),
	block("tee over the store", "cat x | tee ~/.keyguard/state/known/known.json", KindOwner),
	block("cp over the config", "cp /tmp/c ~/.keyguard/state/config.json", KindOwner),
	block("mv the binary away", "mv ~/.keyguard/bin/keyguard /tmp/kg", KindOwner),
	block("rm the store", "rm ~/.keyguard/state/known/known.json", KindOwner),
	block("rm -f the allowlist", "rm -f ~/.keyguard/state/ignore.json", KindOwner),
	block("sed -i over the rules", "sed -i s/a/b/ ~/.keyguard/rules/keyguard.toml", KindOwner),
	block("go run keyguard allow", "go run ./cmd/keyguard allow kg1a2b3c", KindOwner),
	block("go run with flags", "go run -tags x ./cmd/keyguard allow kg1a2b3c --reason y", KindOwner),
	block("go run the main file", "go run cmd/keyguard/main.go uninstall", KindOwner),
	block("go run in a chain", "cd /repo && go run ./cmd/keyguard known forget kg1a2b3c", KindOwner),

	// Reading is for anyone, and so is taking a scanner's file away: that only adds protection.
	allow("cat the ignore file", "cat .gitleaksignore"),
	allow("grep the ignore file", "grep -n generic .betterleaksignore"),
	allow("cp from the ignore file", "cp .gitleaksignore /tmp/backup"),
	allow("mv from the ignore file", "mv .gitleaksignore /tmp/old"),
	allow("rm the ignore file", "rm .gitleaksignore"),
	allow("diff", "diff .gitleaksignore /tmp/other"),
	allow("ls", "ls -la .github/"),
	allow("redirect elsewhere", "echo x > notes.txt"),
	allow("redirect to a descriptor", "echo x >&2 && ls 2>&1"),
	allow("redirect to null", "go test ./... > /dev/null 2>&1"),
	allow("sed without -i", "sed 's/a/b/' .gitleaksignore"),
	allow("a keyguard log", "tail -f ~/.keyguard/logs/poll.log"),
	allow("reading the allowlist", "cat ~/.keyguard/state/ignore.json"),
	allow("go run something else", "go run ./cmd/server allow all"),
	allow("go run keyguard, read-only", "go run ./cmd/keyguard allow --list"),
	allow("go test", "go test ./internal/guard"),
}

func TestScannerFilesAndKeyguardsOwnFilesFromTheShell(t *testing.T) {
	for _, r := range scannerTable {
		t.Run(r.name, func(t *testing.T) {
			d := Decide(r.cmd)
			if d.Block != r.block {
				t.Fatalf("Decide(%q): block=%v (%s), want %v", r.cmd, d.Block, d.Reason, r.block)
			}
			if r.block && (d.Kind != r.kind || d.Reason == "") {
				t.Errorf("Decide(%q): kind %q reason %q, want kind %q", r.cmd, d.Kind, d.Reason, r.kind)
			}
		})
	}
	// Through the hook, in the shape Claude Code reads.
	o := hook(t, event(t, "Bash", map[string]any{"command": "echo 'x' >> .gitleaksignore"}), Options{Known: learned(t, nil)})
	if o.code != ExitBlock {
		t.Fatalf("exit %d", o.code)
	}
	if reason := o.decision(t); !strings.Contains(reason, "keyguard allow") || !strings.Contains(reason, "the user") {
		t.Errorf("reason: %s", reason)
	}
}

func TestTokenizeStillSkipsBareRedirections(t *testing.T) {
	cmds, err := Tokenize("> f\necho hi > g")
	if err != nil || len(cmds) != 1 || len(cmds[0]) != 2 {
		t.Errorf("Tokenize = %v, %v", cmds, err)
	}
}
