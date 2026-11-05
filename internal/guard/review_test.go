package guard

import "testing"

// What the review of the guard left by the earlier duplicate agent changed (docs/LEDGER.md,
// 2026-11-03 22:20-22:31). Each row fails on the code as it was.
var reviewTable = []row{
	// The env that hides the global git config was refused only for commit and push, but the
	// reference-transaction hook runs for every command that moves a ref.
	block("tag with GIT_CONFIG_GLOBAL", "GIT_CONFIG_GLOBAL=/dev/null git tag -a v1 -m x", KindConfig),
	block("update-ref with HOME", "HOME=/tmp/empty git update-ref refs/heads/x abc", KindConfig),
	block("merge with GIT_CONFIG_COUNT", "GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=hook.keyguard-reftx.enabled GIT_CONFIG_VALUE_0=false git merge topic", KindConfig),
	block("branch through env", "env HOME=/tmp git branch topic", KindConfig),
	block("rebase with XDG_CONFIG_HOME", "XDG_CONFIG_HOME=/tmp/x git rebase main", KindConfig),
	block("cherry-pick through sudo", "sudo HOME=/tmp git cherry-pick abc", KindConfig),
	block("stash", "GIT_CONFIG_GLOBAL=/dev/null git stash", KindConfig),
	block("checkout -b", "GIT_CONFIG_GLOBAL=/dev/null git checkout -b topic", KindConfig),
	allow("clone with a private home", "HOME=/tmp/empty git clone https://example.test/r.git"),
	allow("status with a private home", "HOME=/tmp/empty git status"),
	allow("log with GIT_CONFIG_GLOBAL", "GIT_CONFIG_GLOBAL=/dev/null git log --oneline"),
	allow("ls-remote", "HOME=/tmp git ls-remote origin"),
	allow("a different variable", "GIT_AUTHOR_NAME=x git tag v1"),

	// --no-verify on a merge skips the commit-msg hook, as it does on a commit.
	block("merge --no-verify", "git merge --no-verify topic", KindBypass),
	block("merge --no-v", "git merge --no-v topic", KindBypass),
	block("merge flag last", "git merge topic --no-verify", KindBypass),
	block("merge in a chain", "git fetch && git merge --no-verify origin/main", KindBypass),
	allow("merge message that looks like it", "git merge -m --no-verify topic"),
	allow("merge --message", "git merge --message --no-verify topic"),
	allow("merge -n is --no-stat", "git merge -n topic"),
	allow("plain merge", "git merge --no-ff --no-edit topic"),
	allow("merge --no-verify-signatures", "git merge --no-verify-signatures topic"),
}

func TestReviewOfTheEarlierGuard(t *testing.T) {
	for _, r := range reviewTable {
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
}
