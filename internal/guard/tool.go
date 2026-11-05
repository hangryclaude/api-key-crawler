package guard

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"keyguard/internal/core"
	"keyguard/internal/fp"
	"keyguard/internal/known"
)

// The tool calls the guard reads (STEAL P0-14): the file tools, the shell, and every MCP
// tool. A learned key in any string of a tool's input lands in the transcript, which is plain
// text, and the tools that write files and messages carry it onward.

// scannedTool: the calls the guard looks inside. Read, Grep, Glob and the web tools pass
// untouched; a registration that sends them here costs a JSON decode and nothing else.
func scannedTool(name string) bool {
	switch name {
	case "Bash", "Write", "Edit", "MultiEdit", "NotebookEdit":
		return true
	}
	return strings.HasPrefix(name, "mcp__")
}

// fileTool: the tool writes a file named in file_path or notebook_path.
func fileTool(name string) bool {
	switch name {
	case "Write", "Edit", "MultiEdit", "NotebookEdit":
		return true
	}
	return false
}

// leaf is one string in a tool's input, named by where it sits.
type leaf struct {
	name string // content, edits[1].new_string, args.apiKey
	text string
}

// leavesOf lists every string of a decoded JSON value, in a stable order. The keys of an
// object are searched too: a key can be pasted as the name of a field.
func leavesOf(v any) []leaf {
	var out []leaf
	var walk func(name string, v any)
	walk = func(name string, v any) {
		switch x := v.(type) {
		case string:
			out = append(out, leaf{name, x})
		case []any:
			for i, e := range x {
				walk(name+"["+strconv.Itoa(i)+"]", e)
			}
		case map[string]any:
			keys := make([]string, 0, len(x))
			for k := range x {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				child := k
				if name != "" {
					child = name + "." + k
				}
				if len(k) >= known.MinLen {
					out = append(out, leaf{child + ".{name}", k})
				}
				walk(child, x[k])
			}
		}
	}
	walk("", v)
	return out
}

// stringField reads one top-level string of the input.
func stringField(input any, key string) string {
	if m, ok := input.(map[string]any); ok {
		if s, ok := m[key].(string); ok {
			return s
		}
	}
	return ""
}

// found is a learned key in a leaf, as the reason shows it: a name, a shape and a place.
type found struct {
	leaf  string
	line  int
	name  string
	id    string
	shape string
}

// scanLeaves runs the learned-secret matcher over every leaf and reports each key once per
// leaf.
func scanLeaves(m core.KnownMatcher, ls []leaf) []found {
	var out []found
	seen := map[string]bool{}
	for _, l := range ls {
		if len(l.text) < known.MinLen {
			continue
		}
		text := []byte(l.text)
		for _, km := range m.Match(text) {
			k := l.name + "|" + km.FP
			if seen[k] {
				continue
			}
			seen[k] = true
			out = append(out, found{
				leaf: l.name, line: 1 + bytes.Count(text[:max(0, min(km.Offset, len(text)))], []byte{'\n'}),
				name: km.Name, id: km.EntryID, shape: km.Shape,
			})
		}
	}
	return out
}

// secretReason is the text the model reads when a learned key is in its tool call. It names
// the keys by what the user called them and shows their shapes, never a value, and never the
// command or the text around the key either: that is where the key is.
func secretReason(tool string, fs []found) string {
	distinct := map[string]bool{}
	for _, f := range fs {
		distinct[f.id] = true
	}
	var b strings.Builder
	fmt.Fprintf(&b, "BLOCKED by keyguard: this %s holds %d of your learned key%s: ", tool, len(distinct), plural(len(distinct)))
	for i, f := range fs {
		if i == 6 {
			fmt.Fprintf(&b, ", and %d more", len(fs)-i)
			break
		}
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%s (%s, id %s) in %s line %d", clip(oneLine(fp.Scrub(f.name)), 40), f.shape, f.id, clip(oneLine(fp.Scrub(f.leaf)), 48), f.line)
	}
	b.WriteString(".\n\nKeys stay out of tool calls: this text is kept in the transcript, and the call may write it into a file or a message that leaves the Mac. Read the value from the environment, or from a gitignored .env the program loads, and leave it out of what you send.")
	for _, f := range fs {
		if strings.HasSuffix(f.leaf, "old_string") {
			b.WriteString("\n\nTo take a key out of a file, ask the user, or rewrite the file around it with Write: quoting the key in old_string puts it in the transcript again.")
			break
		}
	}
	b.WriteString("\n")
	return b.String()
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// allowMarkers are the inline comments the scanners honour by default. keyguard honours none
// of them (the engines are told to ignore them), so one in a file is dead weight at best and
// an agent trying to get a blocked commit through at worst (STEAL P0-12).
var allowMarkers = []string{"betterleaks:allow", "gitleaks:allow", "trufflehog:ignore"}

// findMarker returns the allow marker in text, or "". detect-secrets' `pragma: allowlist
// secret` (and `allowlist nextline secret`) is matched through its optional words.
func findMarker(text string) string {
	if len(text) < len("gitleaks:allow") {
		return ""
	}
	l := strings.ToLower(text)
	for _, m := range allowMarkers {
		if strings.Contains(l, m) {
			return m
		}
	}
	for i := 0; ; {
		j := strings.Index(l[i:], "pragma:")
		if j < 0 {
			return ""
		}
		i += j + len("pragma:")
		rest := strings.TrimLeft(l[i:], " \t")
		if !strings.HasPrefix(rest, "allowlist") {
			continue
		}
		rest = strings.TrimLeft(rest[len("allowlist"):], " \t-")
		rest = strings.TrimLeft(strings.TrimPrefix(rest, "nextline"), " \t-")
		if strings.HasPrefix(rest, "secret") {
			return "pragma: allowlist secret"
		}
	}
}

// pathLeaf: an MCP tool's field that names a file. The file tools name theirs file_path or
// notebook_path.
func pathLeaf(name string) bool {
	n := strings.ToLower(name[strings.LastIndexByte(name, '.')+1:])
	n = strings.TrimRight(n, "0123456789[]") // paths[0]
	switch n {
	case "path", "paths", "file_path", "filepath", "filename", "file", "files", "notebook_path":
		return true
	}
	return false
}

// denial is the PreToolUse decision in the shape Claude Code reads: hookSpecificOutput with
// the event name, permissionDecision "deny" and the reason the model is shown
// (code.claude.com/docs/en/hooks, "PreToolUse decision control"). systemMessage, when there
// is something the user should see, shares the one object: Claude Code reads a single document.
type denial struct {
	HookSpecificOutput struct {
		HookEventName            string `json:"hookEventName"`
		PermissionDecision       string `json:"permissionDecision"`
		PermissionDecisionReason string `json:"permissionDecisionReason"`
	} `json:"hookSpecificOutput"`
	SystemMessage string `json:"systemMessage,omitempty"`
}

func writeJSON(w io.Writer, v any) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	_, _ = w.Write(b.Bytes())
}

// noticeText is what the user is shown when a tool call was not, or not wholly, searched.
func noticeText(notes []string) string {
	if len(notes) == 0 {
		return ""
	}
	return "keyguard: NOT scanned: " + clip(oneLine(fp.Scrub(strings.Join(notes, "; "))), 400)
}

// deny blocks the call both ways Claude Code reads: the JSON decision on stdout, and exit 2
// with the same reason on stderr. Exit 2 blocks even if the JSON were refused as malformed
// (the documentation says so), so a change in the JSON schema cannot turn a block into an
// allow; and when both arrive, the JSON's reason is the one the model is shown.
func deny(out, errw io.Writer, reason string, notes []string) int {
	var d denial
	d.HookSpecificOutput.HookEventName = "PreToolUse"
	d.HookSpecificOutput.PermissionDecision = "deny"
	d.HookSpecificOutput.PermissionDecisionReason = reason
	d.SystemMessage = noticeText(notes)
	writeJSON(out, d)
	_, _ = io.WriteString(errw, reason)
	return ExitBlock
}

// notScanned lets the call run and says so where the user sees it: systemMessage is shown to
// the user, and the model never reads it. A guard that fails open without a word would be
// indistinguishable from one that works.
func notScanned(out, errw io.Writer, notes []string) {
	msg := noticeText(notes)
	writeJSON(out, struct {
		SystemMessage string `json:"systemMessage"`
	}{msg})
	fmt.Fprintln(errw, msg)
}
