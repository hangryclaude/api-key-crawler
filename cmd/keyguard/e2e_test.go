package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestUsageAndExitCodes(t *testing.T) {
	m := newMachine(t)
	if r := m.kg(); r.code != exitUsage || !strings.Contains(r.out, "never leak a key to GitHub") {
		t.Errorf("no arguments: %d %q", r.code, r.out)
	}
	if r := m.kg("help"); r.code != exitOK || !strings.Contains(r.out, "doctor") {
		t.Errorf("help: %d %q", r.code, r.out)
	}
	r := m.kg("pol")
	if r.code != exitUsage || !strings.Contains(r.out, "did you mean `keyguard poll`") {
		t.Errorf("a typo should be refused with a hint: %d %q", r.code, r.out)
	}
	if r := m.kg("known"); r.code != exitUsage {
		t.Errorf("known without a subcommand: %d", r.code)
	}
	if r := m.kg("scan", "--full", "--incremental"); r.code != exitUsage {
		t.Errorf("contradicting flags: %d %q", r.code, r.out)
	}
	if r := m.kg("hook"); r.code != exitUsage {
		t.Errorf("hook with no name: %d", r.code)
	}
	if r := m.kg("guard", "codex"); r.code != exitUsage {
		t.Errorf("guard for another tool: %d", r.code)
	}
	if r := m.kg("version", "--json"); r.code != 0 {
		t.Errorf("version --json: %d", r.code)
	} else {
		var v map[string]any
		if err := json.Unmarshal([]byte(r.out), &v); err != nil || v["version"] != version || v["go"] == "" {
			t.Errorf("version json: %q %v", r.out, err)
		}
	}
	if r := m.kg("-v"); r.code != 0 || !strings.HasPrefix(r.out, "keyguard "+version) {
		t.Errorf("-v: %d %q", r.code, r.out)
	}
}

func TestInstallDoctorUninstall(t *testing.T) {
	m := newMachine(t)
	original, _ := os.ReadFile(m.gitconfig)

	// Before anything: the doctor says so, exits 1, and names fixes.
	r := m.kg("doctor", "--json", "--quick")
	if r.code != 1 {
		t.Fatalf("doctor on an empty machine exited %d", r.code)
	}
	var rep struct {
		SchemaVersion int  `json:"schema_version"`
		Healthy       bool `json:"healthy"`
		Failures      int  `json:"failures"`
		Checks        []struct {
			ID, Status, Fix string
		} `json:"checks"`
	}
	if err := json.Unmarshal([]byte(r.out), &rep); err != nil || rep.SchemaVersion != 1 || rep.Healthy || rep.Failures == 0 {
		t.Fatalf("doctor json: %v %s", err, r.out)
	}

	if r := m.kg("install", "--dry-run", "--launchd-dir", m.launch); r.code != 0 || !strings.Contains(r.out, "would have installed") {
		t.Fatalf("dry run: %d\n%s", r.code, r.out)
	}
	if b, _ := os.ReadFile(m.gitconfig); string(b) != string(original) {
		t.Fatal("the dry run changed the git config")
	}
	if _, err := os.Stat(m.root); err == nil {
		t.Fatal("the dry run created the data root")
	}

	r = m.kg("install", "--no-bootstrap", "--launchd-dir", m.launch)
	if r.code != 0 || !strings.Contains(r.out, "installed") || !strings.Contains(r.out, "! f=") {
		t.Fatalf("install: %d\n%s", r.code, r.out)
	}
	if r := m.kg("install", "--no-bootstrap", "--launchd-dir", m.launch); r.code != 0 || !strings.Contains(r.out, "already installed") {
		t.Fatalf("a second install: %d\n%s", r.code, r.out)
	}

	// The doctor, given the plists' real home through the install record, finds the gates.
	r = m.kg("doctor", "--json", "--quick")
	rep.Checks = nil
	if err := json.Unmarshal([]byte(r.out), &rep); err != nil {
		t.Fatal(err)
	}
	status := map[string]string{}
	for _, c := range rep.Checks {
		status[c.ID] = c.Status
	}
	for _, id := range []string{"hooks.precommit", "hooks.prepush", "hooks.reftx", "hooks.binary", "git.version", "rules"} {
		if status[id] != "ok" {
			t.Errorf("%s is %q after install", id, status[id])
		}
	}
	if status["launchd.poll"] != "fail" {
		t.Errorf("--no-bootstrap leaves the agents unloaded, and the doctor must say so: %q", status["launchd.poll"])
	}
	if r := m.kg("doctor", "--explain", "hooks.binary"); r.code != 0 || !strings.Contains(r.out, `"id": "hooks.binary"`) {
		t.Errorf("--explain: %d %s", r.code, r.out)
	}
	if r := m.kg("doctor", "--explain", "nope"); r.code != exitFailed || !strings.Contains(r.out, "hooks.binary") {
		t.Errorf("--explain of a missing check should list the real ones: %d %s", r.code, r.out)
	}
	if r := m.kg("doctor", "health"); r.code != 1 || !strings.Contains(r.out, "failing") {
		t.Errorf("health: %d %q", r.code, r.out)
	}
	if r := m.kg("doctor", "capabilities"); r.code != 0 || !strings.Contains(r.out, `"read_only": true`) {
		t.Errorf("capabilities: %d %s", r.code, r.out)
	}
	if r := m.kg("doctor", "robot-docs"); r.code != 0 || !strings.Contains(r.out, "hooks.binary") {
		t.Errorf("robot-docs: %d", r.code)
	}

	r = m.kg("uninstall")
	if r.code != 0 || !strings.Contains(r.out, "uninstalled") || !strings.Contains(r.out, "jq --arg c") {
		t.Fatalf("uninstall: %d\n%s", r.code, r.out)
	}
	if b, _ := os.ReadFile(m.gitconfig); string(b) != string(original) {
		t.Errorf("the git config is not back to what it was:\n%s", b)
	}
	if r := m.kg("uninstall"); r.code != 0 || !strings.Contains(r.out, "nothing to uninstall") {
		t.Errorf("a second uninstall: %d\n%s", r.code, r.out)
	}

	// And it is really off: a staged .env, which the gate refuses, now commits.
	repo := m.repo("after")
	m.write("after/.env", "PORT=1\n")
	m.mustGit(repo, "add", "-f", ".env")
	if r := m.git(repo, "commit", "-q", "-m", "env"); r.code != 0 {
		t.Errorf("after uninstall the gates must be gone, but the commit was refused:\n%s", r.out)
	}
}

func TestLearnKnownMatchForget(t *testing.T) {
	m := newMachine(t)
	val := fakeKey(t, "sk-proj-", 48)
	m.learn("OPENAI_API_KEY", val)

	r := m.kg("known", "list", "--json")
	var rows []struct {
		ID, Name, Shape string
		Forms           int
		FP              string
	}
	if err := json.Unmarshal([]byte(r.out), &rows); err != nil || len(rows) != 1 || rows[0].Name != "OPENAI_API_KEY" || rows[0].Forms < 3 {
		t.Fatalf("known list: %v\n%s", err, r.out)
	}
	if strings.Contains(r.out, val) {
		t.Fatal("known list printed the value")
	}
	id := rows[0].ID
	if r := m.kg("known", "list"); !strings.Contains(r.out, id) || strings.Contains(r.out, val) || !strings.Contains(r.out, "1 secret learned") {
		t.Errorf("known list table: %s", r.out)
	}

	// match: exit 1 and where, never what; every encoding the store registers is found.
	for name, body := range map[string]string{
		"raw":       "export K=" + val + "\n",
		"base64":    "auth: " + base64.StdEncoding.EncodeToString([]byte(val)) + "\n",
		"base64url": "t=" + base64.RawURLEncoding.EncodeToString([]byte(val)) + "\n",
	} {
		p := m.write("probe-"+name+".txt", "line one\nline two\n"+body)
		r := m.kg("match", p)
		if r.code != exitFound || !strings.Contains(r.out, ":3  "+id+"  OPENAI_API_KEY") || strings.Contains(r.out, val) {
			t.Errorf("match on %s: %d %q", name, r.code, r.out)
		}
	}
	if r := m.kgIn("clean text only\n", "match"); r.code != exitOK || strings.TrimSpace(r.out) != "" {
		t.Errorf("match on stdin with nothing: %d %q", r.code, r.out)
	}
	if r := m.kgIn("K="+val+"\n", "match", "--quiet"); r.code != exitFound || r.out != "" {
		t.Errorf("match --quiet: %d %q", r.code, r.out)
	}
	if r := m.kgIn("K="+val+"\n", "match", "--json"); r.code != exitFound || !strings.Contains(r.out, `"line": 1`) || strings.Contains(r.out, val) {
		t.Errorf("match --json: %d %q", r.code, r.out)
	}

	// forget stops matching at once, and a second forget says so.
	if r := m.kg("known", "forget", id); r.code != 0 || !strings.Contains(r.out, "forgot "+id) {
		t.Fatalf("forget: %d %s", r.code, r.out)
	}
	if r := m.kgIn("K="+val+"\n", "match"); r.code != exitFailed || !strings.Contains(r.out, "nothing is learned") {
		t.Errorf("after forgetting the only secret, match must not claim 'clean': %d %q", r.code, r.out)
	}
	if r := m.kg("known", "forget", id); r.code != exitFound {
		t.Errorf("forgetting twice: %d %s", r.code, r.out)
	}
	if r := m.kg("known", "list"); !strings.Contains(r.out, "nothing is learned") {
		t.Errorf("list after forgetting: %s", r.out)
	}
}

func TestLearnOutputNeverHoldsTheValue(t *testing.T) {
	m := newMachine(t)
	val := fakeKey(t, "sk-ant-api03-", 60)
	m.write(filepath.Join(m.home, "dev", "app", ".env"), "ANTHROPIC_API_KEY="+val+"\nDEBUG=true\n")
	m.write(filepath.Join(m.home, ".zshrc"), "export GITHUB_TOKEN="+fakeKey(t, "ghp_", 36)+"\n")
	r := m.kg("learn", "-v", "--no-engine", "--no-gh")
	if r.code != 0 || strings.Contains(r.out, val) {
		t.Fatalf("learn: %d\n%s", r.code, r.out)
	}
	if !strings.Contains(r.out, "ANTHROPIC_API_KEY") || !strings.Contains(r.out, "GITHUB_TOKEN") {
		t.Errorf("learn does not say what it learned:\n%s", r.out)
	}
	// And nothing it wrote holds it either.
	filepath.WalkDir(m.root, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if b, _ := os.ReadFile(p); strings.Contains(string(b), val) {
				t.Errorf("%s holds the value", p)
			}
		}
		return nil
	})
}

var allowID = regexp.MustCompile(`keyguard allow (kg[0-9a-f]{6})`)

func TestCommitGateBlocksThenAllowLetsItThrough(t *testing.T) {
	m := newMachine(t)
	m.install()
	repo := m.repo("app")
	m.write("app/README.md", "hello\n")
	m.mustGit(repo, "add", "-A")
	m.mustGit(repo, "commit", "-q", "-m", "clean")

	tok := fakeKey(t, "ghp_", 36)
	m.write("app/config.py", "TOKEN = \""+tok+"\"\n")
	m.mustGit(repo, "add", "config.py")
	r := m.git(repo, "commit", "-q", "-m", "oops")
	if r.code == 0 {
		t.Fatalf("a commit carrying a token went through:\n%s", r.out)
	}
	if strings.Contains(r.out, tok) || !strings.Contains(r.out, "ghp_…") || !strings.Contains(r.out, "config.py") {
		t.Fatalf("the block message must show the file and the shape and never the value:\n%s", r.out)
	}
	mm := allowID.FindStringSubmatch(r.out)
	if mm == nil {
		t.Fatalf("no id to allow in the block message:\n%s", r.out)
	}

	// The id resolves although the hook never wrote to the findings: the block is journaled.
	if r := m.kg("allow", mm[1], "--reason", "test fixture"); r.code != 0 || !strings.Contains(r.out, "ignored "+mm[1]) {
		t.Fatalf("allow: %d\n%s", r.code, r.out)
	}
	if r := m.kg("allow", "--list"); !strings.Contains(r.out, mm[1]) || !strings.Contains(r.out, "test fixture") {
		t.Errorf("allow --list: %s", r.out)
	}
	if r := m.git(repo, "commit", "-q", "-m", "allowed"); r.code != 0 {
		t.Fatalf("the allowed commit was still blocked:\n%s", r.out)
	}
	// Taking it off the list blocks it again.
	m.write("app/other.py", "TOKEN = \""+tok+"\"\n")
	m.mustGit(repo, "add", "other.py")
	if r := m.git(repo, "commit", "-q", "-m", "again"); r.code != 0 {
		t.Fatalf("the same value elsewhere should stay allowed:\n%s", r.out)
	}
	if r := m.kg("allow", "--remove", mm[1]); r.code != 0 {
		t.Fatalf("allow --remove: %d %s", r.code, r.out)
	}
	m.write("app/third.py", "TOKEN = \""+tok+"\"\n")
	m.mustGit(repo, "add", "third.py")
	if r := m.git(repo, "commit", "-q", "-m", "third"); r.code == 0 {
		t.Fatalf("after --remove the token should block again")
	}

	// An id nobody has is refused with the way out.
	if r := m.kg("allow", "kgffffff"); r.code != exitFailed || !strings.Contains(r.out, "full fingerprint") {
		t.Errorf("allow of an unknown id: %d %s", r.code, r.out)
	}
	if r := m.kg("allow"); r.code != exitUsage {
		t.Errorf("allow with no id: %d", r.code)
	}
}

func TestFilenameRuleBlocksDotEnv(t *testing.T) {
	m := newMachine(t)
	m.install()
	repo := m.repo("app")
	m.write("app/.env", "PORT=8080\n")
	m.mustGit(repo, "add", "-f", ".env")
	r := m.git(repo, "commit", "-q", "-m", "env")
	if r.code == 0 || !strings.Contains(r.out, ".env") || !strings.Contains(r.out, "env-file") {
		t.Fatalf("a staged .env must be refused by name: %d\n%s", r.code, r.out)
	}
	m.mustGit(repo, "reset", "-q")
	m.write("app/.env.example", "PORT=\n")
	m.mustGit(repo, "add", ".env.example")
	if r := m.git(repo, "commit", "-q", "-m", "example"); r.code != 0 {
		t.Fatalf(".env.example is meant to be committed:\n%s", r.out)
	}
}

func TestRefGateBlocksNoVerifyForALearnedKey(t *testing.T) {
	m := newMachine(t)
	m.install()
	val := fakeKey(t, "sk-proj-", 48)
	m.learn("OPENAI_API_KEY", val)

	repo := m.repo("app")
	m.write("app/README.md", "hi\n")
	m.mustGit(repo, "add", "-A")
	m.mustGit(repo, "commit", "-q", "-m", "init")
	head := m.mustGit(repo, "rev-parse", "HEAD")

	m.write("app/deploy.sh", "export OPENAI_API_KEY="+val+"\n")
	m.mustGit(repo, "add", "deploy.sh")
	r := m.git(repo, "commit", "-q", "--no-verify", "-m", "sneaky")
	if r.code == 0 {
		t.Fatalf("--no-verify skipped the gate:\n%s", r.out)
	}
	if strings.Contains(r.out, val) {
		t.Fatalf("the message holds the value:\n%s", r.out)
	}
	if got := m.mustGit(repo, "rev-parse", "HEAD"); got != head {
		t.Fatal("the commit exists although the ref hook refused it")
	}
	// In base64 too: the matcher registers the encodings.
	m.write("app/deploy.sh", "AUTH="+base64.StdEncoding.EncodeToString([]byte(val))+"\n")
	m.mustGit(repo, "add", "deploy.sh")
	if r := m.git(repo, "commit", "-q", "--no-verify", "-m", "sneaky b64"); r.code == 0 {
		t.Fatalf("the base64 form got through:\n%s", r.out)
	}
	m.mustGit(repo, "reset", "-q")
	m.write("app/deploy.sh", "nothing to see\n")
	m.mustGit(repo, "add", "deploy.sh")
	if r := m.git(repo, "commit", "-q", "--no-verify", "-m", "fine"); r.code != 0 {
		t.Fatalf("a clean --no-verify commit was blocked:\n%s", r.out)
	}
}

func TestPushGateStopsWhatSlippedPast(t *testing.T) {
	m := newMachine(t)
	m.install()
	repo := m.repo("app")
	remote := filepath.Join(m.dir, "remote.git")
	m.mustGit(m.dir, "init", "-q", "--bare", "-b", "main", remote)
	m.mustGit(repo, "remote", "add", "origin", remote)
	m.write("app/README.md", "hi\n")
	m.mustGit(repo, "add", "-A")
	m.mustGit(repo, "commit", "-q", "-m", "init")
	if r := m.git(repo, "push", "-q", "origin", "main"); r.code != 0 {
		t.Fatalf("a clean push was blocked:\n%s", r.out)
	}

	tok := fakeKey(t, "ghp_", 36)
	m.write("app/settings.py", "API = \""+tok+"\"\n")
	m.mustGit(repo, "add", "settings.py")
	m.mustGit(repo, "commit", "-q", "--no-verify", "-m", "oops") // pre-commit skipped; only a scanner knows this token
	r := m.git(repo, "push", "origin", "main")
	if r.code == 0 || strings.Contains(r.out, tok) {
		t.Fatalf("the push of a token: exit %d\n%s", r.code, r.out)
	}
	if n := len(strings.Fields(m.mustGit(remote, "rev-list", "--all"))); n != 1 {
		t.Fatalf("the remote has %d commits after the refused push, want 1", n)
	}
}

func TestGuardClaude(t *testing.T) {
	m := newMachine(t)
	call := func(command string) result {
		b, _ := json.Marshal(map[string]any{"tool_name": "Bash", "tool_input": map[string]string{"command": command}, "cwd": m.dir})
		return m.kgIn(string(b), "guard", "claude")
	}
	for _, c := range []string{"git commit --no-verify -m x", "git push --no-verify origin main", "git -c core.hooksPath=/dev/null commit -m x"} {
		if r := call(c); r.code != 2 || strings.TrimSpace(r.out) == "" {
			t.Errorf("%q should be blocked with a reason: %d %q", c, r.code, r.out)
		}
	}
	// An agent that is stopped by a gate must not be able to open it with keyguard's own
	// commands: those are the user's to run, and the message says so.
	for _, c := range []string{"keyguard allow kg1a2b3c", m.root + "/bin/keyguard allow kg1a2b3c --reason x", "keyguard known forget kg1a2b3c", "keyguard uninstall"} {
		r := call(c)
		if r.code != 2 || !strings.Contains(r.out, "the user") {
			t.Errorf("%q should be refused and point at the user: %d %q", c, r.code, r.out)
		}
	}
	for _, c := range []string{"keyguard allow --list", "keyguard known list", "keyguard doctor --quick", "keyguard match f.txt", "keyguard learn"} {
		if r := call(c); r.code != 0 {
			t.Errorf("%q only reads or adds protection and should pass: %d %q", c, r.code, r.out)
		}
	}
	for _, c := range []string{"git status", "git commit -m fine", "echo hello"} {
		if r := call(c); r.code != 0 {
			t.Errorf("%q should pass: %d %q", c, r.code, r.out)
		}
	}
	// What it cannot read, it allows: a hook that blocks real work gets switched off.
	if r := m.kgIn("not json", "guard", "claude"); r.code != 0 {
		t.Errorf("garbage input: %d %s", r.code, r.out)
	}
	b, _ := json.Marshal(map[string]any{"tool_name": "Read", "tool_input": map[string]string{"file_path": "/etc/hosts"}})
	if r := m.kgIn(string(b), "guard", "claude"); r.code != 0 {
		t.Errorf("another tool: %d", r.code)
	}
}

func TestPublishCheckExitCodes(t *testing.T) {
	m := newMachine(t)
	dirty := m.repo("dirty")
	tok := fakeKey(t, "ghp_", 36)
	m.write("dirty/app.py", "T = \""+tok+"\"\n")
	m.mustGit(dirty, "add", "-A")
	m.mustGit(dirty, "commit", "-q", "-m", "oops")
	m.write("dirty/app.py", "T = os.environ['T']\n")
	m.mustGit(dirty, "commit", "-qam", "fix") // gone from the tip, still in history

	r := m.kg("publish-check", "--no-verify", dirty)
	if r.code != exitFound || !strings.Contains(r.out, "NOT clean") || !strings.Contains(r.out, "ghp_…") || strings.Contains(r.out, tok) {
		t.Fatalf("a repo with a token in history: %d\n%s", r.code, r.out)
	}
	if !strings.Contains(r.out, "app.py") {
		t.Errorf("the report should say where:\n%s", r.out)
	}
	rj := m.kg("publish-check", "--no-verify", "--json", dirty)
	var doc struct {
		Clean    bool `json:"clean"`
		Blocking []struct {
			ID, Severity, Type, Shape string
			Where                     []string
		} `json:"blocking"`
	}
	if rj.code != exitFound || json.Unmarshal([]byte(rj.out), &doc) != nil || doc.Clean || len(doc.Blocking) != 1 || doc.Blocking[0].Severity == "" {
		t.Fatalf("--json: %d\n%s", rj.code, rj.out)
	}
	// Allowing it by id makes the next check pass: the ignore list is honored.
	if r := m.kg("allow", doc.Blocking[0].ID, "--reason", "fixture"); r.code != 0 {
		t.Fatalf("allow: %s", r.out)
	}
	if r := m.kg("publish-check", "--no-verify", dirty); r.code != 0 || !strings.Contains(r.out, "clean") {
		t.Errorf("after allow: %d\n%s", r.code, r.out)
	}

	clean := m.repo("clean")
	m.write("clean/README.md", "nothing\n")
	m.mustGit(clean, "add", "-A")
	m.mustGit(clean, "commit", "-q", "-m", "init")
	if r := m.kg("publish-check", "--no-verify", clean); r.code != 0 || !strings.HasPrefix(r.out, "clean:") {
		t.Errorf("a clean repo: %d\n%s", r.code, r.out)
	}
	if r := m.kg("publish-check", "--no-verify", filepath.Join(m.dir, "does-not-exist")); r.code != exitFailed {
		t.Errorf("a target that is neither a repo nor owner/name must be a failure, not 'clean': %d\n%s", r.code, r.out)
	}
	if r := m.kg("publish-check"); r.code != exitUsage {
		t.Errorf("no target: %d", r.code)
	}
}

func TestSelftestPassesOnAThrowawayMachine(t *testing.T) {
	m := newMachine(t)
	// The speed checks time hooks against budgets, which a Mac busy with other work can miss
	// for reasons that are not the hooks'. They have their own test in internal/selftest.
	r := m.kg("selftest", "--json", "--no-latency")
	var rec struct {
		OK     bool `json:"ok"`
		Layers []struct {
			Name   string
			OK     bool
			Detail string
		}
		Gates struct {
			OK     bool `json:"ok"`
			Binary string
			Checks []struct {
				ID     string
				OK     bool
				Detail string
			}
		}
	}
	if err := json.Unmarshal([]byte(r.out), &rec); err != nil {
		t.Fatalf("selftest --json: %v\n%s", err, r.out)
	}
	for _, l := range rec.Layers {
		if !l.OK {
			t.Errorf("layer %q failed: %s", l.Name, l.Detail)
		}
	}
	for _, c := range rec.Gates.Checks {
		if !c.OK {
			t.Errorf("gate check %q failed: %s", c.ID, c.Detail)
		}
	}
	if r.code != 0 || !rec.OK || !rec.Gates.OK || len(rec.Layers) < 10 || len(rec.Gates.Checks) < 28 {
		t.Fatalf("selftest: exit %d ok=%v gates ok=%v layers=%d gate checks=%d", r.code, rec.OK, rec.Gates.OK, len(rec.Layers), len(rec.Gates.Checks))
	}
	if rec.Gates.Binary != binPath {
		t.Errorf("the gates tested %s, not the binary that was run (%s)", rec.Gates.Binary, binPath)
	}
	gateLayers := 0
	for _, l := range rec.Layers {
		if strings.HasPrefix(l.Name, "git gates: ") {
			gateLayers++
		}
	}
	if gateLayers < 6 {
		t.Errorf("the record the doctor reads has %d gate groups, want the sections of the gates", gateLayers)
	}
	// It recorded the result where the doctor looks, in this machine's root and nowhere else.
	if _, err := os.Stat(filepath.Join(m.root, "state", "selftest.json")); err != nil {
		t.Errorf("no selftest record: %v", err)
	}
	if r := m.kg("doctor", "--quick", "--json"); !strings.Contains(r.out, `"id": "selftest.last"`) || !strings.Contains(r.out, "selftest passed") {
		t.Errorf("the doctor does not see the selftest:\n%s", r.out)
	}
}
