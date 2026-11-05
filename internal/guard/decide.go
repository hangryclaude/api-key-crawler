// Package guard is keyguard's Claude Code PreToolUse guard (PLAN.md layer L2). For Bash it
// stops an agent from switching the git hooks off, from letting a finding through and from
// writing a scanner's ignore file, and holds a publish command until `keyguard publish-check`
// says the thing being published is clean. For Bash, Write, Edit, MultiEdit, NotebookEdit and
// every MCP tool it keeps the user's learned keys out of the call (Hook, in guard.go).
//
// Default-allow, like ~/.claude/hooks/guard.py: a guard that blocks real work gets
// disabled, and a disabled guard protects nothing. It only reasons about commands it can
// read; anything it cannot parse is allowed, and the layers behind it (pre-push, the
// reference-transaction hook, the GitHub poll) still apply.
package guard

import (
	"path"
	"strings"
)

// Kind says what sort of rule fired, so the block message can say what to do instead.
type Kind string

const (
	KindBypass  Kind = "bypass"  // --no-verify
	KindConfig  Kind = "config"  // git config / -c / env that disables hooks
	KindOwner   Kind = "owner"   // a keyguard command that only the user runs (allow, uninstall, ...), or a file of keyguard's own
	KindPublish Kind = "publish" // publish-check failed (set by Run, never by Decide)

	KindScanner Kind = "scanner" // writing a scanner's ignore file or config, or an inline allow marker (STEAL P0-12)
	KindGitHub  Kind = "github"  // GitHub's push-protection bypass, or switching its scanning off (STEAL P0-19)
	KindMCP     Kind = "mcp"     // a credential written out in `claude mcp add` (STEAL P0-15)
	KindSecret  Kind = "secret"  // one of the user's learned keys in a tool call (STEAL P0-14); set by Hook, never by Decide
)

// Decision is the verdict on one command line.
type Decision struct {
	Block   bool
	Kind    Kind
	Reason  string
	Publish []Target // must pass `keyguard publish-check` before the command may run
}

// Target is something a publish command would make public.
type Target struct {
	Path string // a local directory, relative to the command's working directory or absolute
	Repo string // owner/name on GitHub
}

// Decide reads one Bash command line and says whether to block it, and what it would
// publish. Compound commands, quoted text, $(...), bash -c, env/sudo/xargs wrappers and
// here-documents are all looked through; text that merely mentions a command (echo,
// grep, a commit message) is not.
func Decide(command string) Decision {
	d := &decider{}
	d.text(command, 0)
	return Decision{Block: d.reason != "", Kind: d.kind, Reason: d.reason, Publish: d.publish}
}

type decider struct {
	reason  string
	kind    Kind
	publish []Target
}

func (d *decider) deny(k Kind, reason string) {
	if d.reason == "" {
		d.reason, d.kind = reason, k
	}
}

func (d *decider) addPublish(t Target) {
	for _, x := range d.publish {
		if x == t {
			return
		}
	}
	d.publish = append(d.publish, t)
}

func (d *decider) text(s string, depth int) {
	if d.reason != "" || depth > maxDepth {
		return
	}
	sc, _ := parse(s) // on a syntax error: only the lines bash would already have run
	d.script(sc, depth)
}

func (d *decider) script(sc *script, depth int) {
	for i, c := range sc.cmds {
		if d.reason != "" {
			return
		}
		d.command(sc, i, c, depth)
	}
}

func (d *decider) subs(ss []*script, depth int) {
	for _, s := range ss {
		d.script(s, depth+1)
	}
}

func (d *decider) command(sc *script, idx int, c *cmd, depth int) {
	// A substitution runs wherever it sits, even as an argument to echo.
	for _, w := range c.words {
		d.subs(w.subs, depth)
	}
	d.subs(c.extra, depth)

	argv := make([]string, len(c.words))
	for i, w := range c.words {
		argv[i] = w.text
	}
	// A redirection writes whatever command it is on, or none.
	for _, t := range c.targets {
		d.target(t.text, false)
	}
	argv, assigns := stripPrefix(argv)
	d.exec(sc, idx, c, argv, assigns, depth)
}

// shellKeywords may stand in front of a command: `then git commit -n`, `! git ...`.
var shellKeywords = map[string]bool{
	"!": true, "{": true, "}": true, "if": true, "then": true, "else": true, "elif": true,
	"while": true, "until": true, "do": true, "done": true, "fi": true, "esac": true, "case": true,
	"for": true, "select": true, "function": true, "coproc": true,
}

// stripPrefix removes keywords and NAME=VALUE assignments from the front of a command.
func stripPrefix(argv []string) (rest, assigns []string) {
	for len(argv) > 0 {
		switch {
		case shellKeywords[argv[0]]:
			argv = argv[1:]
		case isAssign(argv[0]):
			assigns = append(assigns, argv[0])
			argv = argv[1:]
		default:
			return argv, assigns
		}
	}
	return argv, assigns
}

func isAssign(s string) bool {
	name, _, ok := strings.Cut(s, "=")
	name = strings.TrimSuffix(name, "+") // FOO+=bar
	if !ok || name == "" {
		return false
	}
	for j := 0; j < len(name); j++ {
		c := name[j]
		if !(c == '_' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || j > 0 && c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

var shells = map[string]bool{"bash": true, "sh": true, "zsh": true, "dash": true, "ksh": true, "ash": true, "mksh": true, "fish": true}

func (d *decider) exec(sc *script, idx int, c *cmd, argv, assigns []string, depth int) {
	for hop := 0; hop < 12 && len(argv) > 0 && d.reason == ""; hop++ {
		prog := path.Base(argv[0])
		d.writes(prog, argv)
		switch {
		case prog == "git":
			d.git(argv, assigns, depth)
			return
		case prog == "gh":
			d.gh(argv[1:], stdinOf{sc, idx, c})
			return
		case prog == "curl" || prog == "wget" || prog == "http" || prog == "https" || prog == "xh" || prog == "xhs":
			d.web(argv[1:], stdinOf{sc, idx, c})
			return
		case prog == "keyguard":
			d.keyguard(argv[1:])
			return
		case prog == "go":
			// `go run ./cmd/keyguard allow ...` is the same command with a longer name.
			if kg, ok := goRunKeyguard(argv[1:]); ok {
				d.keyguard(kg)
			}
			return
		case prog == "claude" || prog == "codex":
			d.agentCLI(argv[1:])
			return
		case shells[prog]:
			d.shell(sc, idx, c, argv, depth)
			return
		case prog == "eval":
			d.text(strings.Join(argv[1:], " "), depth+1)
			return
		case prog == "export" || prog == "declare" || prog == "typeset" || prog == "readonly":
			for _, a := range argv[1:] {
				if name, _, ok := strings.Cut(a, "="); ok && hidesHooks(name) {
					d.deny(KindConfig, "Exporting "+name+" hides the git config that holds keyguard's hooks, so commits and pushes would go unscanned.")
				}
			}
			return
		}
		w, ok := wrappers[prog]
		if !ok {
			return
		}
		rest, more, run := w.unwrap(prog, argv)
		if !run {
			return
		}
		argv, assigns = rest, append(assigns, more...)
	}
}

// hidesHooks reports environment variables that make git ignore the global config, or
// inject config, either of which switches the keyguard hooks off.
func hidesHooks(name string) bool {
	switch name {
	case "GIT_CONFIG_GLOBAL", "GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS":
		return true
	}
	return strings.HasPrefix(name, "GIT_CONFIG_KEY_") || strings.HasPrefix(name, "GIT_CONFIG_VALUE_")
}

// shell looks inside `bash -c '...'`, and at a script fed to a shell on stdin.
func (d *decider) shell(sc *script, idx int, c *cmd, argv []string, depth int) {
	for i := 1; i < len(argv); i++ {
		a := argv[i]
		switch {
		case a == "--":
			i = len(argv)
		case a == "-o" || a == "+o" || a == "-O" || a == "+O" || a == "--rcfile" || a == "--init-file":
			i++
		case len(a) > 1 && a[0] == '-' && a[1] != '-' && strings.Contains(a, "c"):
			if i+1 < len(argv) {
				d.text(argv[i+1], depth+1)
			}
			return
		case strings.HasPrefix(a, "-") || strings.HasPrefix(a, "+"):
		default:
			return // a script file; its contents are not on the command line
		}
	}
	// No -c: the shell reads a script from stdin.
	for _, h := range c.hereDocs {
		d.text(h.body, depth+1)
	}
	for _, w := range c.hereStr {
		d.text(w.text, depth+1)
	}
	if c.piped && idx > 0 {
		prev := sc.cmds[idx-1]
		for _, h := range prev.hereDocs { // cat <<EOF | sh
			d.text(h.body, depth+1)
		}
		pw := make([]string, len(prev.words))
		for i, w := range prev.words {
			pw[i] = w.text
		}
		if len(pw) > 1 && (path.Base(pw[0]) == "echo" || path.Base(pw[0]) == "printf") {
			args := pw[1:]
			for len(args) > 0 && strings.HasPrefix(args[0], "-") {
				args = args[1:]
			}
			d.text(strings.Join(args, " "), depth+1)
		}
	}
}

// wrapper describes a command that runs another command: how many words it takes before
// the command it runs.
type wrapper struct {
	valued map[string]bool // options that take the next word as their value
	skip   int             // positional words before the command (timeout's duration)
	assign bool            // NAME=VALUE words may sit in front of the command
	query  []string        // options that make it print instead of run (command -v)
}

func set(ss ...string) map[string]bool {
	m := make(map[string]bool, len(ss))
	for _, s := range ss {
		m[s] = true
	}
	return m
}

var wrappers = map[string]wrapper{
	"env":        {valued: set("-u", "--unset", "-C", "--chdir", "-P"), assign: true},
	"command":    {query: []string{"-v", "-V"}},
	"builtin":    {},
	"exec":       {valued: set("-a")},
	"nohup":      {},
	"time":       {valued: set("-o", "-f", "--output", "--format")},
	"nice":       {valued: set("-n", "--adjustment")},
	"ionice":     {valued: set("-c", "-n", "-p", "-P", "-u")},
	"sudo":       {valued: set("-u", "-g", "-h", "-p", "-C", "-D", "-R", "-T", "-U", "-r", "-t"), assign: true},
	"doas":       {valued: set("-u", "-C")},
	"timeout":    {valued: set("-s", "-k", "--signal", "--kill-after"), skip: 1},
	"stdbuf":     {valued: set("-i", "-o", "-e")},
	"setsid":     {},
	"caffeinate": {valued: set("-t", "-w")},
	"arch":       {valued: set("-e", "-c")},
	"xcrun":      {valued: set("--sdk", "-sdk", "--toolchain", "-toolchain")},
	"xargs":      {valued: set("-I", "-L", "-n", "-P", "-s", "-E", "-d", "-a", "-J")},
	"watch":      {valued: set("-n", "--interval")},
}

// dropsHome reports an env option that starts the command without a HOME: -i and
// --ignore-environment empty the whole environment, -u HOME (or --unset HOME, --unset=HOME)
// takes out just that one. later is what follows the option, for the name -u takes.
func dropsHome(opt string, later []string) bool {
	switch {
	case opt == "--ignore-environment" || opt == "--unset=HOME":
		return true
	case opt == "-u" || opt == "--unset":
		return len(later) > 0 && later[0] == "HOME"
	case strings.HasPrefix(opt, "--"):
		return false
	}
	// A group of short options: -i, -iv, -uHOME, -iuFOO.
	for j := 1; j < len(opt); j++ {
		switch opt[j] {
		case 'i':
			return true
		case 'u':
			rest := opt[j+1:]
			if rest == "" && len(later) > 0 {
				rest = later[0]
			}
			return rest == "HOME"
		}
	}
	return false
}

// unwrap returns what the wrapper runs. run is false when it does not run anything
// (`command -v git`).
func (w wrapper) unwrap(name string, argv []string) (rest, assigns []string, run bool) {
	i := 1
loop:
	for i < len(argv) {
		a := argv[i]
		switch {
		case a == "--":
			i++
			break loop
		case name == "env" && (a == "-S" || a == "--split-string" || strings.HasPrefix(a, "--split-string=")):
			// env -S 'git commit -n': the string is a command line of its own.
			s := strings.TrimPrefix(a, "--split-string=")
			if s == a {
				if i+1 >= len(argv) {
					return nil, nil, false
				}
				s = argv[i+1]
				i++
			}
			sc, _ := parse(s)
			if len(sc.cmds) == 0 {
				return nil, nil, false
			}
			var words []string
			for _, wd := range sc.cmds[0].words {
				words = append(words, wd.text)
			}
			return append(words, argv[i+1:]...), assigns, true
		case name == "env" && a == "-":
			// The old spelling of -i.
			assigns = append(assigns, "HOME=")
			i++
		case len(a) > 1 && a[0] == '-':
			for _, q := range w.query {
				if a == q {
					return nil, nil, false
				}
			}
			if name == "env" && dropsHome(a, argv[i+1:]) {
				// git run without a HOME reads no ~/.gitconfig, which is where keyguard's three
				// hooks are: the same as HOME=/tmp in front of the command, which is refused.
				assigns = append(assigns, "HOME=")
			}
			if w.valued[a] {
				i++
			}
			i++
		case w.assign && isAssign(a):
			assigns = append(assigns, a)
			i++
		default:
			break loop
		}
	}
	i = min(i+w.skip, len(argv))
	return argv[i:], assigns, true
}
