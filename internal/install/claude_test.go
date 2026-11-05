package install

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// runBang runs a `! ...` line the way Claude Code does: through sh, with HOME set.
func runBang(t *testing.T, home, line string) {
	t.Helper()
	cmd := exec.Command("sh", "-c", strings.TrimPrefix(line, "! "))
	cmd.Env = append(os.Environ(), "HOME="+home)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("running %q: %v\n%s", line, err, out)
	}
}

func TestClaudeRegistrationLineAddsTheGuardOnceAndKeepsEverythingElse(t *testing.T) {
	home := t.TempDir()
	settings := filepath.Join(home, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(settings), 0o755); err != nil {
		t.Fatal(err)
	}
	// Other hooks, an env block with a (fake) secret, and a model: none of it may change.
	secretish := "sk-fake-" + randStr(t, alnum, 30)
	orig := `{"model":"opus","env":{"X_API_KEY":"` + secretish + `"},"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"python3 /x/guard.py"}]}],"Stop":[{"hooks":[{"type":"command","command":"echo done"}]}]}}`
	if err := os.WriteFile(settings, []byte(orig), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(home, ".keyguard", "bin", "keyguard")

	if ok, err := ClaudeRegistered(settings, bin); ok || err != nil {
		t.Fatalf("before registration: %v %v", ok, err)
	}
	line := ClaudeRegistration(bin)
	if !strings.HasPrefix(line, "! ") || strings.Contains(line, "\n") {
		t.Fatalf("the registration must be one `!` line, got %q", line)
	}
	runBang(t, home, line)
	if ok, err := ClaudeRegistered(settings, bin); !ok || err != nil {
		t.Fatalf("after registration: %v %v", ok, err)
	}
	once, _ := os.ReadFile(settings)
	runBang(t, home, line)
	twice, _ := os.ReadFile(settings)
	if string(once) != string(twice) {
		t.Errorf("running the line twice changed the file:\n%s\n%s", once, twice)
	}

	var doc map[string]any
	if err := json.Unmarshal(twice, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["model"] != "opus" || doc["env"].(map[string]any)["X_API_KEY"] != secretish {
		t.Errorf("unrelated settings changed: %v", doc)
	}
	pre := doc["hooks"].(map[string]any)["PreToolUse"].([]any)
	if len(pre) != 2 || !strings.Contains(string(twice), "python3 /x/guard.py") || !strings.Contains(string(twice), `"Stop"`) {
		t.Errorf("another hook was lost or the guard was added twice: %s", twice)
	}
	// Every run keeps its own dated backup (none overwrites another), and the first run's
	// is the original, byte for byte.
	backups, _ := filepath.Glob(settings + ".keyguard-backup-*")
	if len(backups) != 2 {
		t.Fatalf("two runs should leave two backups, found %d", len(backups))
	}
	if !slices.ContainsFunc(backups, func(p string) bool { b, _ := os.ReadFile(p); return string(b) == orig }) {
		t.Error("no backup is the original, byte for byte")
	}

	// And the reverse removes only keyguard's entry.
	runBang(t, home, ClaudeUnregistration(bin))
	if ok, _ := ClaudeRegistered(settings, bin); ok {
		t.Error("still registered after unregistering")
	}
	after, _ := os.ReadFile(settings)
	if !strings.Contains(string(after), "python3 /x/guard.py") || strings.Contains(string(after), "guard claude") {
		t.Errorf("unregistration removed the wrong thing: %s", after)
	}
}

func TestClaudeRegistrationOnASettingsFileWithNoHooks(t *testing.T) {
	home := t.TempDir()
	settings := filepath.Join(home, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(settings), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settings, []byte(`{"theme":"light"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := "/Users/me/.keyguard/bin/keyguard"
	runBang(t, home, ClaudeRegistration(bin))
	if ok, err := ClaudeRegistered(settings, bin); !ok || err != nil {
		t.Fatalf("not registered: %v %v", ok, err)
	}
}

func TestClaudeRegisteredIsReadOnlyAndCarefulAboutBadFiles(t *testing.T) {
	dir := t.TempDir()
	if ok, err := ClaudeRegistered(filepath.Join(dir, "missing.json"), "/b"); ok || err != nil {
		t.Errorf("a missing file is simply not registered: %v %v", ok, err)
	}
	bad := filepath.Join(dir, "bad.json")
	secretish := "sk-fake-" + randStr(t, alnum, 30)
	if err := os.WriteFile(bad, []byte(`{"env":{"K":"`+secretish+`"`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := ClaudeRegistered(bad, "/b")
	if err == nil || strings.Contains(err.Error(), secretish) {
		t.Errorf("a bad file must be an error that does not quote it: %v", err)
	}
	// A different install's guard is not this one's.
	other := filepath.Join(dir, "other.json")
	os.WriteFile(other, []byte(`{"hooks":{"PreToolUse":[{"hooks":[{"command":"/elsewhere/keyguard guard claude"}]}]}}`), 0o600)
	if ok, _ := ClaudeRegistered(other, "/mine/keyguard"); ok {
		t.Error("another binary's guard counted as registered")
	}
}

func TestShellQuote(t *testing.T) {
	for in, want := range map[string]string{
		"/Users/me/.keyguard/bin/keyguard": "/Users/me/.keyguard/bin/keyguard",
		"/a b/c":                           "'/a b/c'",
		"/it's/here":                       `'/it'\''s/here'`,
		"":                                 "''",
		"$HOME/x":                          "'$HOME/x'",
	} {
		if got := shellQuote(in); got != want {
			t.Errorf("shellQuote(%q) = %s, want %s", in, got, want)
		}
	}
}
