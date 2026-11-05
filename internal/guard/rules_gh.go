package guard

import (
	"strings"
)

// The publish gate: commands that make content public (a new public repo with the local
// tree pushed into it, a repo flipped to public, the same through the raw API). The guard
// does not judge the content; it hands the target to `keyguard publish-check`.

// options is a command line split into positional words and flags. flags maps a flag as
// typed (--source, -s) to its values; a flag with no value is present with a nil slice.
type options struct {
	pos   []string
	flags map[string][]string
}

// scanOptions splits args. valued lists the flags that take a value (the next word, or
// attached as --flag=value / -fvalue); every other flag is a boolean.
func scanOptions(args []string, valued map[string]bool) options {
	o := options{flags: map[string][]string{}}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			o.pos = append(o.pos, args[i+1:]...)
			return o
		case strings.HasPrefix(a, "--"):
			name, val, attached := strings.Cut(a, "=")
			switch {
			case attached:
				o.flags[name] = append(o.flags[name], val)
			case valued[name] && i+1 < len(args):
				i++
				o.flags[name] = append(o.flags[name], args[i])
			default:
				o.flags[name] = append(o.flags[name], "")
			}
		case len(a) > 1 && a[0] == '-':
			name := a[:2]
			switch {
			case !valued[name]:
				o.flags[a] = append(o.flags[a], "")
			case len(a) > 2:
				o.flags[name] = append(o.flags[name], strings.TrimPrefix(a[2:], "="))
			case i+1 < len(args):
				i++
				o.flags[name] = append(o.flags[name], args[i])
			default:
				o.flags[name] = append(o.flags[name], "")
			}
		default:
			o.pos = append(o.pos, a)
		}
	}
	return o
}

// value is the last value given for any of the flag spellings.
func (o options) value(names ...string) string {
	v := ""
	for _, n := range names {
		for _, x := range o.flags[n] {
			if x != "" {
				v = x
			}
		}
	}
	return v
}

// on reports a boolean flag that is present and not switched off with =false.
func (o options) on(name string) bool {
	vals, ok := o.flags[name]
	if !ok {
		return false
	}
	for _, v := range vals {
		if strings.EqualFold(v, "false") {
			return false
		}
	}
	return true
}

var (
	ghCreateValued = set("--description", "-d", "--gitignore", "-g", "--homepage", "-h", "--license", "-l",
		"--remote", "-r", "--source", "-s", "--team", "-t", "--template", "-p", "--visibility")
	ghEditValued = set("--add-topic", "--remove-topic", "--default-branch", "--description", "-d",
		"--homepage", "-h", "--visibility")
	ghAPIValued = set("-X", "--method", "-H", "--header", "-f", "--raw-field", "-F", "--field", "--input",
		"-q", "--jq", "-t", "--template", "--hostname", "--cache", "-p", "--preview")
)

// stdinOf reaches what a command reads on its standard input when the shell line says so: a
// here-document, a here-string, the words of the command piped into it.
type stdinOf struct {
	sc  *script
	idx int
	c   *cmd
}

func (s stdinOf) text() string {
	if s.c == nil {
		return ""
	}
	var b strings.Builder
	add := func(c *cmd) {
		for _, h := range c.hereDocs {
			b.WriteString(h.body + "\n")
		}
		for _, w := range c.hereStr {
			b.WriteString(w.text + "\n")
		}
	}
	add(s.c)
	if s.c.piped && s.sc != nil && s.idx > 0 && s.idx <= len(s.sc.cmds) {
		prev := s.sc.cmds[s.idx-1]
		add(prev)
		for _, w := range prev.words {
			b.WriteString(w.text + " ")
		}
	}
	return b.String()
}

// pushProtectionBypass is the REST path that lets a blocked push through. Both gh logins
// hold classic repo scope, so one POST to it from an agent undoes GitHub's push protection
// (STEAL P0-19).
const pushProtectionBypass = "/secret-scanning/push-protection-bypasses"

func hasBypassPath(args []string) bool {
	for _, a := range args {
		if strings.Contains(strings.ToLower(a), pushProtectionBypass) {
			return true
		}
	}
	return false
}

const (
	bypassReason  = "That is GitHub's push-protection bypass: one request lets a blocked push through, which is the user's call and nobody else's."
	disableReason = "That turns off GitHub secret scanning or push protection for a repository. Turning it on is welcome (keyguard github-settings --apply); turning it off is the user's call."
)

// gh reads `gh [flags] <command> <subcommand> ...` (args exclude the program name).
func (d *decider) gh(args []string, in stdinOf) {
	if hasBypassPath(args) {
		d.deny(KindGitHub, bypassReason)
		return
	}
	// gh's own -R/--repo and --help-style flags may come first; the command words are the
	// first positionals.
	o := scanOptions(args, set("-R", "--repo", "--hostname"))
	if len(o.pos) == 0 {
		return
	}
	switch {
	case o.pos[0] == "repo" && len(o.pos) > 1 && o.pos[1] == "create":
		d.ghRepoCreate(rest(args, "create"))
	case o.pos[0] == "repo" && len(o.pos) > 1 && o.pos[1] == "edit":
		d.ghRepoEdit(rest(args, "edit"))
	case o.pos[0] == "api":
		d.ghAPI(rest(args, "api"), in)
	}
}

// web reads curl, wget and the HTTP clients that do the same job: the bypass endpoint, and a
// PATCH that turns scanning off, are refused whichever tool carries them.
func (d *decider) web(args []string, in stdinOf) {
	if hasBypassPath(args) {
		d.deny(KindGitHub, bypassReason)
		return
	}
	patch := false
	for i, a := range args {
		switch strings.ToUpper(a) {
		case "-XPATCH", "--REQUEST=PATCH", "--METHOD=PATCH":
			patch = true
		case "PATCH": // httpie and xh take the method as a word; curl and wget as the value of an option
			patch = patch || i == 0 || args[i-1] == "-X" || args[i-1] == "--request" || args[i-1] == "--method"
		}
	}
	if !patch {
		return
	}
	body := strings.ToLower(strings.Join(args, " ") + " " + in.text())
	if strings.Contains(body, "/repos/") && disablesScanning(body) {
		d.deny(KindGitHub, disableReason)
	}
}

// disablesScanning: a request body (or field list) that sets security_and_analysis to disabled.
func disablesScanning(lowerText string) bool {
	return strings.Contains(lowerText, "security_and_analysis") && strings.Contains(lowerText, "disabled")
}

// rest returns the arguments after the first occurrence of word.
func rest(args []string, word string) []string {
	for i, a := range args {
		if a == word {
			return args[i+1:]
		}
	}
	return nil
}

func isPublic(v string) bool { return strings.EqualFold(strings.TrimSpace(v), "public") }

// gh repo create <name> --public [--source <dir>] [--template <repo>]: content only
// reaches the new repo from --source (pushed straight away) or from a template. Without
// either the repo is created empty and there is nothing to leak.
func (d *decider) ghRepoCreate(args []string) {
	o := scanOptions(args, ghCreateValued)
	if !o.on("--public") && !isPublic(o.value("--visibility")) {
		return
	}
	switch {
	case o.value("--source", "-s") != "":
		d.addPublish(Target{Path: o.value("--source", "-s")})
	case o.value("--template", "-p") != "":
		d.addPublish(Target{Repo: repoName(o.value("--template", "-p"))})
	}
}

// gh repo edit [<repo>] --visibility public. It also refuses the flags that switch GitHub's
// scanning off (--enable-secret-scanning=false and its relatives): the same PATCH as the API's.
func (d *decider) ghRepoEdit(args []string) {
	o := scanOptions(args, ghEditValued)
	for _, f := range []string{"--enable-secret-scanning", "--enable-secret-scanning-push-protection", "--enable-advanced-security"} {
		if _, given := o.flags[f]; given && !o.on(f) {
			d.deny(KindGitHub, disableReason)
			return
		}
	}
	if !isPublic(o.value("--visibility")) {
		return
	}
	if len(o.pos) > 0 {
		d.addPublish(Target{Repo: repoName(o.pos[0])})
	} else {
		d.addPublish(Target{Path: "."}) // the repository in the working directory
	}
}

// gh api repos/<o>/<n> -f private=false  (or -f visibility=public). A PATCH on repos/<o>/<n>
// that sets security_and_analysis to disabled is refused: the fields can be -f/-F values or a
// JSON body on stdin (--input -).
func (d *decider) ghAPI(args []string, in stdinOf) {
	o := scanOptions(args, ghAPIValued)
	if len(o.pos) > 0 && strings.EqualFold(o.value("-X", "--method"), "PATCH") && repoUpdateEndpoint(o.pos[0]) {
		var fields []string
		for _, n := range []string{"-f", "-F", "--field", "--raw-field"} {
			fields = append(fields, o.flags[n]...)
		}
		body := strings.ToLower(strings.Join(fields, " "))
		if _, given := o.flags["--input"]; given {
			body += " " + strings.ToLower(in.text())
		}
		if disablesScanning(body) {
			d.deny(KindGitHub, disableReason)
			return
		}
	}
	public := false
	for _, n := range []string{"-f", "-F", "--field", "--raw-field"} {
		for _, f := range o.flags[n] {
			switch strings.ToLower(strings.ReplaceAll(f, " ", "")) {
			case "private=false", "visibility=public":
				public = true
			}
		}
	}
	if !public || len(o.pos) == 0 {
		return
	}
	switch repo, placeholder := endpointRepo(o.pos[0]); {
	case placeholder:
		d.addPublish(Target{Path: "."})
	case repo != "":
		d.addPublish(Target{Repo: repo})
	}
}

// endpointRepo pulls owner/name out of repos/<owner>/<name>[/...]. {owner}/{repo} are
// gh's placeholders for the repository in the working directory. Endpoints that create a
// new repository (user/repos, orgs/x/repos) carry no existing content and give "".
func endpointRepo(ep string) (repo string, placeholder bool) {
	ep, _, _ = strings.Cut(ep, "?")
	i := strings.Index(ep, "repos/")
	if i < 0 || (i > 0 && ep[i-1] != '/') {
		return "", false
	}
	seg := strings.Split(strings.Trim(ep[i+len("repos/"):], "/"), "/")
	if len(seg) < 2 || seg[0] == "" || seg[1] == "" {
		return "", false
	}
	if strings.ContainsAny(seg[0]+seg[1], "{}$") {
		return "", true
	}
	return seg[0] + "/" + seg[1], false
}

// repoUpdateEndpoint: repos/<owner>/<name> and nothing after it, which is what PATCH updates a
// repository through. Placeholders ({owner}/{repo}) count.
func repoUpdateEndpoint(ep string) bool {
	ep, _, _ = strings.Cut(ep, "?")
	i := strings.Index(ep, "repos/")
	if i < 0 || (i > 0 && ep[i-1] != '/') {
		return false
	}
	seg := strings.Split(strings.Trim(ep[i+len("repos/"):], "/"), "/")
	return len(seg) == 2 && seg[0] != "" && seg[1] != ""
}

// repoName reduces a repository argument (owner/name, a URL, with or without .git) to
// owner/name.
func repoName(s string) string {
	s = strings.TrimSuffix(strings.TrimSpace(s), ".git")
	for _, p := range []string{"https://github.com/", "http://github.com/", "git@github.com:", "github.com/"} {
		s = strings.TrimPrefix(s, p)
	}
	return s
}
