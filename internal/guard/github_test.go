package guard

import (
	"strings"
	"testing"
)

// GitHub's bypass and disable paths (STEAL P0-19). Both gh logins hold classic repo scope, so
// one POST gets a blocked push through and one PATCH turns scanning off.
var githubTable = []row{
	// The push-protection bypass endpoint, whoever carries the request.
	block("gh api POST", "gh api -X POST repos/hangryclaude/x/secret-scanning/push-protection-bypasses -f reason=false_positive -f placeholder_id=abc", KindGitHub),
	block("gh api with --method", "gh api --method POST /repos/o/n/secret-scanning/push-protection-bypasses -f reason=used_in_tests", KindGitHub),
	block("gh api with placeholders", "gh api repos/{owner}/{repo}/secret-scanning/push-protection-bypasses -f reason=x", KindGitHub),
	block("gh api GET of it", "gh api repos/o/n/secret-scanning/push-protection-bypasses", KindGitHub),
	block("gh api with -R", "gh -R o/n api repos/o/n/secret-scanning/push-protection-bypasses", KindGitHub),
	block("curl", "curl -X POST -H 'Authorization: Bearer tok' https://api.github.com/repos/o/n/secret-scanning/push-protection-bypasses -d '{\"reason\":\"false_positive\"}'", KindGitHub),
	block("curl -XPOST", "curl -XPOST https://api.github.com/repos/o/n/secret-scanning/push-protection-bypasses", KindGitHub),
	block("wget", "wget --method=POST --body-data='{}' https://api.github.com/repos/o/n/secret-scanning/push-protection-bypasses", KindGitHub),
	block("httpie", "http POST api.github.com/repos/o/n/secret-scanning/push-protection-bypasses reason=x", KindGitHub),
	block("upper case path", "curl https://api.github.com/REPOS/o/n/Secret-Scanning/Push-Protection-Bypasses", KindGitHub),
	block("through bash -c", `bash -c "gh api repos/o/n/secret-scanning/push-protection-bypasses -X POST"`, KindGitHub),
	block("in a pipeline", "echo go && gh api repos/o/n/secret-scanning/push-protection-bypasses -X POST | cat", KindGitHub),
	block("with an env prefix", "GH_TOKEN=x gh api repos/o/n/secret-scanning/push-protection-bypasses -X POST", KindGitHub),

	// A PATCH that sets security_and_analysis to disabled.
	block("gh api -f field", "gh api -X PATCH repos/o/n -f 'security_and_analysis[secret_scanning][status]=disabled'", KindGitHub),
	block("gh api push protection field", "gh api --method PATCH repos/o/n -F 'security_and_analysis[secret_scanning_push_protection][status]=disabled'", KindGitHub),
	block("gh api placeholders", "gh api -X PATCH repos/{owner}/{repo} -f 'security_and_analysis[secret_scanning][status]=disabled'", KindGitHub),
	block("gh api --input - with echo", `echo '{"security_and_analysis":{"secret_scanning":{"status":"disabled"}}}' | gh api -X PATCH repos/o/n --input -`, KindGitHub),
	block("gh api --input - with a heredoc", "gh api -X PATCH repos/o/n --input - <<EOF\n{\"security_and_analysis\":{\"secret_scanning\":{\"status\":\"disabled\"}}}\nEOF", KindGitHub),
	block("gh api --input - with a here-string", `gh api -X PATCH repos/o/n --input - <<< '{"security_and_analysis":{"secret_scanning":{"status":"disabled"}}}'`, KindGitHub),
	block("curl PATCH with a body", `curl -X PATCH -H 'Authorization: Bearer t' https://api.github.com/repos/o/n -d '{"security_and_analysis":{"secret_scanning":{"status":"disabled"}}}'`, KindGitHub),
	block("curl --request PATCH", `curl --request PATCH https://api.github.com/repos/o/n --data '{"security_and_analysis":{"secret_scanning_push_protection":{"status":"disabled"}}}'`, KindGitHub),
	block("curl -XPATCH", `curl -XPATCH https://api.github.com/repos/o/n -d '{"security_and_analysis":{"secret_scanning":{"status":"disabled"}}}'`, KindGitHub),
	block("wget PATCH", `wget --method=PATCH --body-data='{"security_and_analysis":{"secret_scanning":{"status":"disabled"}}}' https://api.github.com/repos/o/n`, KindGitHub),
	block("httpie PATCH", `http PATCH https://api.github.com/repos/o/n 'security_and_analysis[secret_scanning][status]=disabled'`, KindGitHub),
	block("gh repo edit", "gh repo edit o/n --enable-secret-scanning=false", KindGitHub),
	block("gh repo edit push protection", "gh repo edit --enable-secret-scanning-push-protection=false", KindGitHub),
	block("gh repo edit advanced security", "gh repo edit o/n --enable-advanced-security=false", KindGitHub),

	// Turning scanning on, reading the alerts, and unrelated requests are for anyone.
	allow("enable through the API", "gh api -X PATCH repos/o/n -f 'security_and_analysis[secret_scanning][status]=enabled' -f 'security_and_analysis[secret_scanning_push_protection][status]=enabled'"),
	allow("gh repo edit enable", "gh repo edit o/n --enable-secret-scanning --enable-secret-scanning-push-protection"),
	allow("gh repo edit enable explicit", "gh repo edit o/n --enable-secret-scanning=true"),
	allow("list alerts", "gh api 'repos/o/n/secret-scanning/alerts?hide_secret=true'"),
	allow("alert locations", "gh api repos/o/n/secret-scanning/alerts/3/locations"),
	allow("read the settings", "gh api repos/o/n --jq .security_and_analysis"),
	allow("patch the description", "gh api -X PATCH repos/o/n -f description='a repo'"),
	allow("patch on another endpoint", "gh api -X PATCH repos/o/n/branches/main/protection -f 'security_and_analysis=disabled'"),
	allow("disabled in another field", "gh api -X PATCH repos/o/n -f 'has_issues=false' -f description=disabled"),
	allow("curl GET", "curl -s https://api.github.com/repos/o/n"),
	allow("curl PATCH of a description", `curl -X PATCH https://api.github.com/repos/o/n -d '{"description":"x"}'`),
	allow("grep for the endpoint", "grep -rn 'push-protection-bypasses' docs/"),
	allow("echo mentions it", `echo "the push-protection-bypasses endpoint is blocked"`),
	allow("commit message mentions it", `git commit -m "document /secret-scanning/push-protection-bypasses"`),
	allow("ordinary gh", "gh pr list && gh issue view 3"),
}

func TestGitHubBypassAndDisablePathsAreRefused(t *testing.T) {
	for _, r := range githubTable {
		t.Run(r.name, func(t *testing.T) {
			d := Decide(r.cmd)
			if d.Block != r.block {
				t.Fatalf("Decide(%q): block=%v (%s), want %v", r.cmd, d.Block, d.Reason, r.block)
			}
			if r.block && (d.Kind != r.kind || d.Reason == "") {
				t.Errorf("kind %q reason %q, want kind %q", d.Kind, d.Reason, r.kind)
			}
		})
	}
	// Through the hook: the decision Claude Code reads, with a reason that sends the agent to the user.
	o := hook(t, event(t, "Bash", map[string]any{"command": "gh api -X POST repos/o/n/secret-scanning/push-protection-bypasses -f reason=false_positive"}), Options{Known: learned(t, nil)})
	if o.code != ExitBlock {
		t.Fatalf("exit %d", o.code)
	}
	reason := o.decision(t)
	for _, want := range []string{"push-protection bypass", "the user"} {
		if !strings.Contains(reason, want) {
			t.Errorf("reason lacks %q:\n%s", want, reason)
		}
	}
}
