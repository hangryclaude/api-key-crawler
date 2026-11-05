package guard

import (
	"strings"

	"keyguard/internal/known"
)

// `claude mcp add` and `codex mcp add` (STEAL P0-15). Both vendors' examples teach the unsafe
// form: `--env KEY=value`, `--header "Authorization: Bearer ..."`, `--dsn` with the password
// inside the URL. Each writes the value into a config file that leaks the day it is copied
// into a repository, and into the transcript of the session that ran it. The guard refuses a
// literal; a reference is fine. The value never appears in the reason, only where it was.

const mcpReason = "That would write a credential into the MCP config and the transcript. Pass it as a reference the client expands at run time instead, in single quotes so the shell leaves it alone: --env 'NAME=${NAME}' or --header 'Authorization: Bearer ${NAME}', with the real value in your environment."

// mcpAddValued are the options of `mcp add` whose next word is their value and not a
// positional (-e/--env and -H/--header take several, handled apart).
var mcpAddValued = set("-s", "--scope", "-t", "--transport", "--client-id", "--callback-port")

// agentCLI reads `claude ...` and `codex ...` (args exclude the program name).
func (d *decider) agentCLI(args []string) {
	// Global options may come first; the command words are the first positionals.
	var words []string
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			words = append(words, a)
			if len(words) == 3 {
				break
			}
		}
	}
	if len(words) < 2 || words[0] != "mcp" {
		return
	}
	i := indexOf(args, "mcp")
	switch words[1] {
	case "add":
		d.mcpAdd(args[i+1:])
	case "add-json":
		d.mcpAddJSON(args[i+1:])
	}
}

func indexOf(ss []string, x string) int {
	for i, s := range ss {
		if s == x {
			return i
		}
	}
	return 0
}

// mcpAdd reads `mcp add [options] <name> <commandOrUrl> [args...]` (args start at "add").
func (d *decider) mcpAdd(args []string) {
	if len(args) > 0 && args[0] == "add" {
		args = args[1:]
	}
	var pairs [][2]string // kind, text
	var tail []string     // the server's command line: its URL or program, and its flags
	positional := 0
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			tail = append(tail, args[i+1:]...)
			i = len(args)
		case a == "-e" || a == "--env" || a == "-H" || a == "--header":
			kind := "env"
			if a == "-H" || a == "--header" {
				kind = "header"
			}
			// Variadic: every word up to the next option belongs to it.
			for i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				i++
				pairs = append(pairs, [2]string{kind, args[i]})
			}
		case strings.HasPrefix(a, "--env=") || strings.HasPrefix(a, "--header="):
			kind, v, _ := strings.Cut(a, "=")
			pairs = append(pairs, [2]string{strings.TrimPrefix(kind, "--"), v})
		case mcpAddValued[a]:
			i++
		case strings.HasPrefix(a, "-"):
		default:
			positional++
			if positional > 1 { // the first is the server's name
				tail = append(tail, a)
			}
		}
	}
	for _, p := range pairs {
		kind := p[0]
		sep := "="
		if kind == "header" {
			sep = ":"
		}
		name, value, ok := strings.Cut(p[1], sep)
		if !ok {
			continue
		}
		if _, lit := known.PairLiteral(kind, strings.TrimSpace(name), strings.TrimSpace(value)); lit {
			d.deny(KindMCP, "`mcp add --"+kind+" "+strings.TrimSpace(name)+"` has the credential written out. "+mcpReason)
			return
		}
	}
	if lits := known.ArgLiterals(tail); len(lits) > 0 {
		d.deny(KindMCP, "The server's own arguments have a credential written out ("+lits[0].Kind+" at "+lits[0].Path+"). "+mcpReason)
	}
}

// mcpAddJSON reads `mcp add-json <name> '<json>'`.
func (d *decider) mcpAddJSON(args []string) {
	for _, a := range args {
		if !strings.HasPrefix(a, "{") {
			continue
		}
		if lits, _ := known.Literals(known.JSON, []byte(a)); len(lits) > 0 {
			d.deny(KindMCP, "The JSON has a credential written out ("+lits[0].Kind+" at "+lits[0].Path+"). "+mcpReason)
			return
		}
	}
}
