package guard

import (
	"strings"
	"testing"
)

var keyguardTable = []row{
	// Let a finding through, or take protection away: the user's to run.
	block("allow an id", "keyguard allow kg1a2b3c", KindOwner),
	block("allow with a reason", `keyguard allow kg1a2b3c --reason "test fixture"`, KindOwner),
	block("allow, flag first", "keyguard allow --reason x kg1a2b3c", KindOwner),
	block("allow a full fingerprint", "keyguard allow 0123456789abcdef0123456789abcdef", KindOwner),
	block("allow --remove", "keyguard allow --remove kg1a2b3c", KindOwner),
	block("allow --list=false is not a list", "keyguard allow --list=false kg1a2b3c", KindOwner),
	block("installed binary by path", "/Users/me/.keyguard/bin/keyguard allow kg1a2b3c", KindOwner),
	block("relative binary", "./bin/keyguard allow kg1a2b3c", KindOwner),
	block("env prefix", "KEYGUARD_HOME=/tmp/x keyguard allow kg1a2b3c", KindOwner),
	block("env wrapper", "env FOO=1 keyguard allow kg1a2b3c", KindOwner),
	block("sudo wrapper", "sudo keyguard allow kg1a2b3c", KindOwner),
	block("after &&", "git status && keyguard allow kg1a2b3c", KindOwner),
	block("after a pipe", "echo x | keyguard allow kg1a2b3c", KindOwner),
	block("inside bash -c", `bash -c "keyguard allow kg1a2b3c"`, KindOwner),
	block("inside sh -c with quotes", `sh -c 'cd /tmp && keyguard allow kg1a2b3c'`, KindOwner),
	block("inside $(...)", `echo $(keyguard allow kg1a2b3c)`, KindOwner),
	block("quoted subcommand", `keyguard "allow" kg1a2b3c`, KindOwner),
	block("on a retry loop", "for i in 1 2; do keyguard allow kg1a2b3c; done", KindOwner),
	block("known forget", "keyguard known forget kg1a2b3c", KindOwner),
	block("known forget, flag between", "keyguard known --json forget kg1a2b3c", KindOwner),
	block("learn --prune", "keyguard learn --prune", KindOwner),
	block("learn -prune", "keyguard learn -prune", KindOwner),
	block("uninstall", "keyguard uninstall", KindOwner),
	block("uninstall --dry-run=false", "keyguard uninstall --dry-run=false", KindOwner),
	block("import-triage", "keyguard import-triage --by claude --file v.json", KindOwner),

	// Reading, adding protection and scanning are for anyone.
	allow("allow --list", "keyguard allow --list"),
	allow("allow -list", "keyguard allow -list"),
	allow("known list", "keyguard known list"),
	allow("known list json", "keyguard known list --json"),
	allow("match", "keyguard match file.txt"),
	allow("learn", "keyguard learn"),
	allow("learn, no prune", "keyguard learn --no-engine --no-gh -v"),
	allow("doctor", "keyguard doctor --json"),
	allow("selftest", "keyguard selftest"),
	allow("install", "keyguard install"),
	allow("install dry run", "keyguard install --dry-run"),
	allow("uninstall dry run", "keyguard uninstall --dry-run"),
	allow("uninstall dry run, single dash", "keyguard uninstall -dry-run"),
	allow("import-triage dry run", "keyguard import-triage --by claude --dry-run"),
	allow("export-triage", "keyguard export-triage --out /tmp/e.json"),
	allow("poll", "keyguard poll"),
	allow("scan", "keyguard scan --full --repo github.com/o/n"),
	allow("publish-check", "keyguard publish-check ."),
	allow("github-settings apply", "keyguard github-settings --apply"),
	allow("bench", "keyguard bench --seed 3"),
	allow("version", "keyguard version"),
	allow("no arguments", "keyguard"),
	allow("only flags", "keyguard --help"),

	// Text that merely mentions the command is not the command.
	allow("echo mentions it", `echo "ask the user to run keyguard allow kg1a2b3c"`),
	allow("commit message mentions it", `git commit -m "keyguard allow kg1a2b3c was needed"`),
	allow("grep for it", "grep -rn 'keyguard allow' docs/"),
	allow("another program called allow", "iptables allow kg1a2b3c"),
	allow("a directory named keyguard", "cd keyguard && ls allow"),
	allow("a file argument named keyguard", "cat keyguard allow"),
}

func TestKeyguardOwnerCommands(t *testing.T) {
	for _, r := range keyguardTable {
		t.Run(r.name, func(t *testing.T) {
			d := Decide(r.cmd)
			if d.Block != r.block {
				t.Fatalf("Decide(%q): block=%v (%s), want %v", r.cmd, d.Block, d.Reason, r.block)
			}
			if r.block {
				if d.Kind != r.kind || d.Reason == "" {
					t.Errorf("Decide(%q): kind %q reason %q, want kind %q and a reason", r.cmd, d.Kind, d.Reason, r.kind)
				}
				return
			}
			if len(d.Publish) != 0 {
				t.Errorf("Decide(%q): unexpected publish targets %+v", r.cmd, d.Publish)
			}
		})
	}
}

func TestOwnerCommandMessageSendsTheAgentToTheUser(t *testing.T) {
	code, out := run(t, payload(t, "Bash", "keyguard allow kg1a2b3c --reason fixture", "/r"), nil)
	if code != ExitBlock {
		t.Fatalf("code %d, want %d", code, ExitBlock)
	}
	for _, want := range []string{"BLOCKED by keyguard", "lets a finding through", "the user", "themselves", "! in Claude Code"} {
		if !strings.Contains(out, want) {
			t.Errorf("message lacks %q:\n%s", want, out)
		}
	}
	// The same advice appears when a --no-verify is stopped: the agent is told to go to the user,
	// not to run the command it is told about.
	_, out = run(t, payload(t, "Bash", "git commit -n -m x", "/r"), nil)
	if !strings.Contains(out, "tell the user the id") || !strings.Contains(out, "keyguard allow <id>") {
		t.Errorf("the --no-verify message should hand the id to the user:\n%s", out)
	}
}

func TestOwnerReasonsNameTheCommand(t *testing.T) {
	for cmd, want := range map[string]string{
		"keyguard allow kg1a2b3c":      "keyguard allow",
		"keyguard known forget kg1a2b": "known forget",
		"keyguard learn --prune":       "--prune",
		"keyguard uninstall":           "uninstall",
		"keyguard import-triage":       "import-triage",
	} {
		if d := Decide(cmd); !d.Block || !strings.Contains(d.Reason, want) {
			t.Errorf("Decide(%q) reason %q lacks %q", cmd, d.Reason, want)
		}
	}
}
