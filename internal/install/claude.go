package install

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"regexp"
	"strings"
)

// guardCommand is the PreToolUse hook command keyguard registers with Claude Code.
func guardCommand(bin string) string { return bin + " guard claude" }

// GuardMatcher is the PreToolUse matcher keyguard registers (STEAL P0-14): the tools a key can
// travel through on its way into a transcript or a file. Claude Code calls the hook only for
// tools the matcher names, so a Bash-only matcher leaves Write, Edit and every MCP server
// unguarded. The guard itself ignores any other tool in microseconds.
const GuardMatcher = "Bash|Write|Edit|MultiEdit|NotebookEdit|mcp__.*"

// guardTools are the tools a registration has to cover. An MCP tool is named mcp__<server>__<tool>,
// so one made-up example stands for all of them.
var guardTools = []struct{ name, show string }{
	{"Bash", "Bash"}, {"Write", "Write"}, {"Edit", "Edit"}, {"MultiEdit", "MultiEdit"},
	{"NotebookEdit", "NotebookEdit"}, {"mcp__server__tool", "mcp__*"},
}

// ClaudeSnippet is the settings.json fragment the registration line adds, for the user to read
// before they run anything: install prints it beside the line and never writes the file.
func ClaudeSnippet(bin string) string {
	b, _ := json.MarshalIndent(map[string]any{
		"hooks": map[string]any{
			"PreToolUse": []any{map[string]any{
				"matcher": GuardMatcher,
				"hooks":   []any{map[string]any{"type": "command", "command": guardCommand(bin)}},
			}},
		},
	}, "", "  ")
	return string(b)
}

// jqOurs picks out the PreToolUse groups that run keyguard's guard. They are found by that
// command, so a hand-written entry of the user's own is never touched, and a registration that is
// already right is left exactly as it is, which keeps the line idempotent.
const jqOurs = `def ours: any(.hooks[]?; .command == $c);`

// ClaudeRegistration is the shell line the user runs (with the `!` prefix, in Claude Code) to
// register the agent guard in their settings. Install prints it and never runs it: that file
// is guarded on purpose, so editing it is a deliberate step by them.
//
// The line keeps a dated backup of the file first. Running it twice changes nothing; running it
// on a Bash-only registration from before widens the matcher to GuardMatcher, so the doctor's
// "guard.matcher" warning has a line that clears it. It replaces the file only if jq succeeded.
func ClaudeRegistration(bin string) string {
	c := shellQuote(guardCommand(bin))
	m := shellQuote(GuardMatcher)
	const jq = `'` + jqOurs + ` (.hooks.PreToolUse // []) as $g | if ($g | map(select(ours)) | length) == 1 and any($g[]; ours and (.hooks | length) == 1 and .matcher == $m) then . else .hooks.PreToolUse = (($g | map(.hooks |= map(select(.command != $c))) | map(select((.hooks | length) > 0))) + [{matcher:$m,hooks:[{type:"command",command:$c}]}]) end'`
	return `! f="$HOME/.claude/settings.json"; cp "$f" "$f.keyguard-backup-$(date +%Y%m%d%H%M%S)-$$" && jq --arg c ` + c + ` --arg m ` + m + ` ` + jq + ` "$f" > "$f.keyguard-new" && mv "$f.keyguard-new" "$f"`
}

// ClaudeUnregistration is the reverse: it drops only the keyguard entry and leaves every
// other hook alone, again behind a dated backup.
func ClaudeUnregistration(bin string) string {
	c := shellQuote(guardCommand(bin))
	const jq = `'.hooks.PreToolUse |= ((. // []) | map(.hooks |= map(select(.command != $c))) | map(select((.hooks | length) > 0)))'`
	return `! f="$HOME/.claude/settings.json"; cp "$f" "$f.keyguard-backup-$(date +%Y%m%d%H%M%S)-$$" && jq --arg c ` + c + ` ` + jq + ` "$f" > "$f.keyguard-new" && mv "$f.keyguard-new" "$f"`
}

// claudeEntries are the PreToolUse groups of a settings file that run bin's guard, with the
// matcher each was registered under. Only hooks.PreToolUse is decoded, so nothing else in the
// file (the settings can hold an env block) is ever held.
func claudeEntries(path, bin string) (matchers []string, err error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var doc struct {
		Hooks struct {
			PreToolUse []struct {
				Matcher string `json:"matcher"`
				Hooks   []struct {
					Command string `json:"command"`
				} `json:"hooks"`
			} `json:"PreToolUse"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, errors.New("settings.json is not valid JSON")
	}
	want := guardCommand(bin)
	for _, m := range doc.Hooks.PreToolUse {
		for _, h := range m.Hooks {
			// The registered command may be quoted or carry arguments; the suffix is what makes
			// it keyguard's guard, and the binary path says it is this install's.
			if strings.Contains(h.Command, "guard claude") && (h.Command == want || strings.Contains(h.Command, bin)) {
				matchers = append(matchers, m.Matcher)
				break
			}
		}
	}
	return matchers, nil
}

// ClaudeRegistered reports whether the settings file at path has a PreToolUse hook that
// runs bin's `guard claude`.
func ClaudeRegistered(path, bin string) (bool, error) {
	ms, err := claudeEntries(path, bin)
	return len(ms) > 0, err
}

// ClaudeUncovered names the tools the registration in the settings file at path does not call
// the guard for: the guard sees a tool call only if some keyguard group's matcher names the
// tool. registered is false when the file has no keyguard hook at all.
func ClaudeUncovered(path, bin string) (uncovered []string, registered bool, err error) {
	ms, err := claudeEntries(path, bin)
	if err != nil || len(ms) == 0 {
		return nil, false, err
	}
	for _, tool := range guardTools {
		covered := false
		for _, m := range ms {
			if matcherNames(m, tool.name) {
				covered = true
				break
			}
		}
		if !covered {
			uncovered = append(uncovered, tool.show)
		}
	}
	return uncovered, true, nil
}

// matcherNames mirrors how Claude Code reads a matcher: empty or "*" names every tool, anything
// else is a regular expression that has to match the whole tool name (docs: "Write" matches only
// the Write tool, "Edit|Write" matches either). An expression that does not compile names nothing.
func matcherNames(matcher, tool string) bool {
	if matcher == "" || matcher == "*" {
		return true
	}
	re, err := regexp.Compile(`^(?:` + matcher + `)$`)
	return err == nil && re.MatchString(tool)
}
