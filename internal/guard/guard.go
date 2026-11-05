package guard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"keyguard/internal/core"
	"keyguard/internal/fp"
	"keyguard/internal/known"
)

// Exit codes of the Claude Code PreToolUse hook contract, as ~/.claude/hooks/guard.py
// uses them: 2 blocks the tool call and feeds stderr to the model; 0 lets it run.
const (
	ExitAllow = 0
	ExitBlock = 2
)

const (
	publishTimeout = 120 * time.Second
	maxInput       = 16 << 20 // a heredoc can make a Bash command very long
)

// PublishCheck runs `keyguard publish-check` on a target (a directory, or owner/name).
// clean is false when it found secrets, and detail is its redacted report. err means the
// check itself could not run, which blocks too: publishing cannot be taken back.
type PublishCheck func(ctx context.Context, target string) (clean bool, detail string, err error)

// hookInput is the part of the PreToolUse payload the guard reads: the tool and its input
// (code.claude.com/docs/en/hooks, "PreToolUse input").
type hookInput struct {
	ToolName  string          `json:"tool_name"`
	ToolInput json.RawMessage `json:"tool_input"`
	Cwd       string          `json:"cwd"`
}

// Options wires the guard to what it needs from outside the package.
type Options struct {
	// Check is the publish gate. nil blocks a publish: it cannot be taken back.
	Check PublishCheck
	// Known loads the learned-secret matcher. It is called at most once, and only for a tool
	// call that has text to search. nil loads the stores of core.KnownRoots(). The matcher
	// may come back with an error and still hold part of the store (known.LoadMatcher does
	// that on purpose); the guard searches with what loaded and says what did not.
	Known func() (core.KnownMatcher, error)
}

// Run is the guard with the old signature: it reads the PreToolUse JSON from in, writes the
// reason to errw and returns the exit code. Nothing it writes reaches stdout, so the JSON
// decision and the visible "NOT scanned" message of Hook are dropped; the exit code and the
// stderr text are the same.
func Run(ctx context.Context, in io.Reader, errw io.Writer, check PublishCheck) int {
	return Hook(ctx, in, io.Discard, errw, Options{Check: check})
}

// Hook is the entry point of `keyguard guard claude`: Claude Code's PreToolUse hook for Bash,
// Write, Edit, MultiEdit, NotebookEdit and mcp__* (PLAN.md L2). It reads the event on in and
// answers on out and errw:
//
//   - allow: exit 0 and nothing on out, which leaves the decision to Claude Code's own
//     permissions;
//   - deny: exit 2, the decision {"hookSpecificOutput":{"hookEventName":"PreToolUse",
//     "permissionDecision":"deny","permissionDecisionReason":...}} on out and the same reason on
//     errw. The reason holds shapes and names, never a value;
//   - could not look: exit 0 and {"systemMessage":"keyguard: NOT scanned: ..."} on out, shown
//     to the user. The guard is default-allow, like ~/.claude/hooks/guard.py: a guard that blocks
//     real work gets switched off. It fails open, and loudly. When a call is both refused and
//     only partly searched, the decision and the notice share the one JSON document.
//
// A tool call is searched for the learned keys in every string of its input; a Bash command
// is also read for what it would run (Decide), and the Write and Edit family for the files it
// would write (scanner ignore files, keyguard's own files) and for inline allow markers.
func Hook(ctx context.Context, in io.Reader, out, errw io.Writer, o Options) (code int) {
	if out == nil {
		out = io.Discard
	}
	g := &call{o: o}
	// One JSON object answers a call, whatever happened on the way: Claude Code reads a single
	// document on stdout, so a notice and a decision travel together.
	defer func() {
		if r := recover(); r != nil {
			// A Go panic exits with status 2, which Claude Code reads as "block this tool call": a
			// bug in the parser would then block every Bash command the model runs.
			g.reason = ""
			g.note("internal error (" + fmt.Sprint(r) + ")")
		}
		code = g.render(out, errw)
	}()
	raw, err := io.ReadAll(io.LimitReader(in, maxInput+1))
	if err != nil {
		g.note("could not read the hook input")
		return
	}
	if len(raw) > maxInput {
		g.note(fmt.Sprintf("the tool call is larger than %d MB", maxInput>>20))
		return
	}
	var hi hookInput
	if json.Unmarshal(raw, &hi) != nil {
		g.note("could not read the hook input")
		return
	}
	if !scannedTool(hi.ToolName) || len(hi.ToolInput) == 0 {
		return
	}
	var input any
	if json.Unmarshal(hi.ToolInput, &input) != nil {
		g.note("could not read the tool input of " + oneLine(fp.Scrub(hi.ToolName)))
		return
	}
	g.tool, g.input, g.cwd = hi.ToolName, input, hi.Cwd
	g.leaves = leavesOf(input)

	if g.rules() || g.keys() {
		return
	}
	g.publish(ctx)
	return
}

// call is one tool call being judged. A rule that refuses it sets reason; what could not be
// looked at goes to notes.
type call struct {
	o      Options
	tool   string
	input  any
	cwd    string
	leaves []leaf

	command string
	pubs    []Target

	reason string
	notes  []string
}

func (g *call) note(why string) { g.notes = append(g.notes, why) }

// refuse records the reason a call is blocked and reports that the judging is over.
func (g *call) refuse(reason string) bool {
	g.reason = reason
	return true
}

// refuseKind renders the block message of a kind of rule, with the subject it names.
func (g *call) refuseKind(k Kind, reason, subject, detail string) bool {
	var b strings.Builder
	blocked(&b, k, reason, subject, detail)
	return g.refuse(b.String())
}

// render writes the answer and returns the exit code.
func (g *call) render(out, errw io.Writer) int {
	if g.reason != "" {
		return deny(out, errw, g.reason, g.notes)
	}
	if len(g.notes) > 0 {
		notScanned(out, errw, g.notes)
	}
	return ExitAllow
}

// rules applies what needs no learned store: what a command would run, the files a file tool
// would write, the inline allow markers. It reports whether the call is refused.
func (g *call) rules() bool {
	if g.tool == "Bash" {
		g.command = stringField(g.input, "command")
		if strings.TrimSpace(g.command) == "" {
			return false
		}
		dec := decide(g.command)
		if dec.Block {
			return g.refuseKind(dec.Kind, dec.Reason, g.command, "")
		}
		g.pubs = dec.Publish
		return false
	}

	// The files the call writes: a path field of a file tool, or one an MCP tool names.
	var paths []string
	if fileTool(g.tool) {
		for _, k := range []string{"file_path", "notebook_path"} {
			if p := stringField(g.input, k); p != "" {
				paths = append(paths, p)
			}
		}
	}
	if strings.HasPrefix(g.tool, "mcp__") {
		for _, l := range g.leaves {
			if pathLeaf(l.name) && len(l.text) < 400 && !strings.ContainsAny(l.text, "\n") {
				paths = append(paths, l.text)
			}
		}
	}
	for _, p := range paths {
		switch r, ok := scannerFile(p); {
		case keyguardOwn(p):
			return g.refuseKind(KindOwner, ownReason, g.tool+" "+p, "")
		case ok:
			return g.refuseKind(KindScanner, scannerReason(p, r), g.tool+" "+p, "")
		}
	}

	// An allow marker in text that is being written. Text that is being replaced does not
	// count: taking a marker out of a file is the right edit.
	for _, l := range g.leaves {
		if strings.HasSuffix(l.name, "old_string") || pathLeaf(l.name) {
			continue
		}
		if m := findMarker(l.text); m != "" {
			return g.refuseKind(KindScanner, "This "+g.tool+" writes an inline allow marker ("+m+"). keyguard ignores such markers on purpose: they hide a finding from the scanner they are written for and from nothing else, and a blocked agent is the one who would add one.", g.tool, "")
		}
	}
	return false
}

// keys searches every string of the call for the user's learned keys. It reports whether the
// call is refused.
func (g *call) keys() bool {
	load := g.o.Known
	if load == nil {
		load = func() (core.KnownMatcher, error) { return known.LoadMatcher(core.KnownRoots()) }
	}
	hasText := false
	for _, l := range g.leaves {
		if len(l.text) >= known.MinLen {
			hasText = true
			break
		}
	}
	if !hasText {
		return false
	}
	m, err := load()
	switch {
	case m == nil || m.Len() == 0:
		if err != nil {
			g.note("the learned-key store did not load (" + errText(err) + "): this " + g.tool + " was not searched for your keys")
		}
		return false
	case err != nil:
		g.note("part of the learned-key store did not load (" + errText(err) + "): this " + g.tool + " was searched with the rest")
	}
	if fs := scanLeaves(m, g.leaves); len(fs) > 0 {
		return g.refuse(secretReason(g.tool, fs))
	}
	return false
}

// publish holds a publish command until `keyguard publish-check` says what it would make
// public is clean.
func (g *call) publish(ctx context.Context) {
	for _, t := range g.pubs {
		target := t.resolve(g.cwd)
		if g.o.Check == nil {
			g.refuseKind(KindPublish, "Publishing "+target+" needs `keyguard publish-check`, and no check is wired in.", g.command, "")
			return
		}
		cctx, cancel := context.WithTimeout(ctx, publishTimeout)
		clean, detail, err := safeCheck(cctx, g.o.Check, target)
		cancel()
		switch {
		case err != nil:
			g.refuseKind(KindPublish, "keyguard publish-check could not run on "+target+" ("+oneLine(fp.Scrub(err.Error()))+"). Nothing is published until it can.", g.command, "")
			return
		case !clean:
			g.refuseKind(KindPublish, "keyguard publish-check found secrets in "+target+". Publishing would leak them.", g.command, detail)
			return
		}
	}
}

func errText(err error) string { return clip(oneLine(fp.Scrub(err.Error())), 160) }

// decide is Decide, as a variable so a test can make it fail.
var decide = Decide

// safeCheck runs a publish check; a panic inside it counts as "could not run", which
// blocks, unlike a panic in the guard's own parsing, which allows.
func safeCheck(ctx context.Context, check PublishCheck, target string) (clean bool, detail string, err error) {
	defer func() {
		if r := recover(); r != nil {
			clean, err = false, fmt.Errorf("panic: %v", r)
		}
	}()
	return check(ctx, target)
}

// resolve turns a target into the argument for publish-check: owner/name as is, a path
// made absolute against the command's working directory so the check cannot mistake
// `sub/dir` for a repository name.
func (t Target) resolve(cwd string) string {
	if t.Repo != "" {
		return t.Repo
	}
	p := t.Path
	if p == "" || strings.ContainsAny(p, "$`") { // a path the guard could not read
		p = "."
	}
	if p == "~" || strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			p = filepath.Join(home, p[1:])
		}
	}
	if !filepath.IsAbs(p) && cwd != "" {
		p = filepath.Join(cwd, p)
	}
	return filepath.Clean(p)
}

// blocked writes the message the model reads. The command is echoed clipped and with
// random-looking tokens masked: it may hold a key, and this text lands in transcripts.
func blocked(w io.Writer, k Kind, reason, command, detail string) {
	var b strings.Builder
	b.WriteString("BLOCKED by keyguard: " + reason + "\n\n")
	if command != "" {
		b.WriteString("  " + clip(oneLine(fp.Scrub(command)), 160) + "\n\n")
	}
	if detail != "" {
		lines := strings.Split(strings.TrimSpace(detail), "\n")
		if len(lines) > 40 {
			lines = append(lines[:40], fmt.Sprintf("... and %d more lines", len(lines)-40))
		}
		for _, l := range lines {
			b.WriteString("  " + oneLine(l) + "\n")
		}
		b.WriteString("\n")
	}
	switch k {
	case KindBypass:
		b.WriteString("keyguard's hooks scan every commit and push for API keys. Fix what they flag:\n" +
			"move the value to a gitignored .env and read it from the environment.\n" +
			"A false positive: tell the user the id (it is in the hook's block message); they run\n" +
			"`keyguard allow <id>` themselves.\n")
	case KindOwner:
		b.WriteString("Letting a finding through, forgetting a learned key, taking keyguard out and re-judging\n" +
			"findings are the user's calls. Tell them the id and what it is; they run the command themselves,\n" +
			"in a terminal or with ! in Claude Code.\n")
	case KindConfig:
		b.WriteString("Leave git's hook settings alone. If a hook is broken or in the way, tell the user\n" +
			"what failed instead of switching it off.\n")
	case KindPublish:
		b.WriteString("Remove or rotate every secret it lists, then try again.\n")
	case KindScanner:
		b.WriteString("If a finding is a false positive, tell the user the id (it is in the hook's block message);\n" +
			"they run `keyguard allow <id>` themselves, in a terminal or with ! in Claude Code.\n")
	case KindGitHub:
		b.WriteString("If something is in the way of a push, tell the user what it is; they decide.\n")
	}
	_, _ = io.WriteString(w, b.String())
}

func oneLine(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}

func clip(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return s
}

// ExecPublishCheck runs `<bin> publish-check <target>`: exit 0 is clean, exit 1 is "found
// secrets" with a redacted report on its output, anything else is a failure to run.
func ExecPublishCheck(bin string) PublishCheck {
	return func(ctx context.Context, target string) (bool, string, error) {
		// "--" so that a target which looks like an option (-h makes keyguard exit 0) is read as
		// the thing to check and never as a way to skip the check.
		cmd := exec.CommandContext(ctx, bin, "publish-check", "--", target)
		var out capBuf
		cmd.Stdout, cmd.Stderr = &out, &out
		err := cmd.Run()
		var ee *exec.ExitError
		switch {
		case err == nil:
			return true, "", nil
		case errors.As(err, &ee) && ee.ExitCode() == 1:
			return false, out.String(), nil
		default:
			return false, "", fmt.Errorf("%v: %s", err, clip(oneLine(out.String()), 200))
		}
	}
}

// capBuf keeps the first 16 KiB of what a command prints.
type capBuf struct{ b []byte }

func (c *capBuf) Write(p []byte) (int, error) {
	if room := 16<<10 - len(c.b); room > 0 {
		c.b = append(c.b, p[:min(room, len(p))]...)
	}
	return len(p), nil
}

func (c *capBuf) String() string { return string(c.b) }
