package guard

import "strings"

// git global options that take a separate value (git.c handle_options).
var gitGlobalValued = set("-C", "--git-dir", "--work-tree", "--namespace", "--super-prefix", "--attr-source")

// splitGit separates `git [global options] <subcommand> <args>` and collects the config
// that the global options inject (-c name=value, --config-env=name=ENVVAR).
func splitGit(argv []string) (sub string, rest, cfg []string) {
	for i := 1; i < len(argv); i++ {
		a := argv[i]
		switch {
		case a == "-c":
			if i+1 < len(argv) {
				cfg = append(cfg, argv[i+1])
			}
			i++
		case a == "--config-env":
			if i+1 < len(argv) {
				cfg = append(cfg, argv[i+1])
			}
			i++
		case strings.HasPrefix(a, "--config-env="):
			cfg = append(cfg, strings.TrimPrefix(a, "--config-env="))
		case gitGlobalValued[a]:
			i++
		case strings.HasPrefix(a, "-"):
		default:
			return a, argv[i+1:], cfg
		}
	}
	return "", nil, cfg
}

func (d *decider) git(argv, assigns []string, depth int) {
	if depth > maxDepth {
		return
	}
	sub, rest, cfg := splitGit(argv)
	for _, kv := range cfg {
		if hookConfig(kv, true) {
			d.deny(KindConfig, "git -c cannot set core.hooksPath, core.bare, include paths or hook.* settings: keyguard's pre-commit, pre-push and reference-transaction hooks have to run.")
			return
		}
	}
	// The reference-transaction hook is how a key is stopped from landing on a branch or tag,
	// whichever command moves the ref; hiding the global config switches it off for all of them.
	if gitMovesRefs[sub] && hidingEnv(assigns) {
		d.deny(KindConfig, "Setting HOME or GIT_CONFIG_* for git "+sub+" hides the global git config that holds keyguard's hooks, so the ref it moves goes unchecked.")
		return
	}
	switch sub {
	case "commit":
		if hidingEnv(assigns) {
			d.deny(KindConfig, "Setting HOME or GIT_CONFIG_* for a commit hides the global git config that holds keyguard's hooks.")
		} else if commitSkipsHooks(rest) {
			d.deny(KindBypass, "git commit --no-verify (or -n, also inside a flag group like -anm) skips keyguard's pre-commit scan.")
		}
	case "push":
		if hidingEnv(assigns) {
			d.deny(KindConfig, "Setting HOME or GIT_CONFIG_* for a push hides the global git config that holds keyguard's hooks.")
		} else if pushSkipsHooks(rest) {
			d.deny(KindBypass, "git push --no-verify skips keyguard's pre-push scan.")
		}
	case "merge":
		// --no-verify on a merge skips the commit-msg hook, as it does on a commit.
		if mergeSkipsHooks(rest) {
			d.deny(KindBypass, "git merge --no-verify skips keyguard's commit-msg scan.")
		}
	case "config":
		d.gitConfig(rest)
	case "":
	default:
		// `-c alias.ci=commit ... ci -n`: an alias given on this very command line.
		for _, kv := range cfg {
			name, val, _ := strings.Cut(kv, "=")
			if sec, sb, vr, ok := splitKey(name); ok && sec == "alias" && sb == "" && strings.EqualFold(vr, sub) {
				if strings.HasPrefix(val, "!") {
					d.text(val[1:]+" "+strings.Join(shellQuote(rest), " "), depth+1)
				} else if sc, _ := parse(val); len(sc.cmds) > 0 {
					var words []string
					for _, w := range sc.cmds[0].words {
						words = append(words, w.text)
					}
					d.git(append(append([]string{"git"}, words...), rest...), assigns, depth+1)
				}
				return
			}
		}
	}
}

// gitMovesRefs are the subcommands that move a branch or tag, and so run the
// reference-transaction hook.
var gitMovesRefs = set("merge", "rebase", "cherry-pick", "revert", "pull", "am", "tag", "branch", "switch", "checkout",
	"reset", "update-ref", "stash", "notes", "worktree", "symbolic-ref", "replace", "bisect", "filter-branch", "fast-import")

// mergeValued are the options of git merge that take a value, as the next word or attached.
var (
	mergeValuedLong  = set("--message", "--file", "--strategy", "--strategy-option", "--cleanup", "--into-name")
	mergeValuedShort = "mFsX"
)

// mergeSkipsHooks finds --no-verify (or an unambiguous abbreviation) in a merge command line,
// reading the option grammar so that `-m --no-verify` (a message) is not flagged. In git
// merge -n is --no-stat, so it is not flagged either.
func mergeSkipsHooks(args []string) bool {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			return false
		case strings.HasPrefix(a, "--"):
			name, _, attached := strings.Cut(a, "=")
			if isNoVerify(name) {
				return true
			}
			if mergeValuedLong[name] && !attached {
				i++
			}
		case len(a) > 1 && a[0] == '-':
			for j := 1; j < len(a); j++ {
				if strings.IndexByte(mergeValuedShort, a[j]) >= 0 {
					if j == len(a)-1 {
						i++
					}
					break
				}
			}
		}
	}
	return false
}

func shellQuote(ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
	}
	return out
}

func hidingEnv(assigns []string) bool {
	for _, a := range assigns {
		name, _, _ := strings.Cut(a, "=")
		if hidesHooks(name) || name == "HOME" || name == "XDG_CONFIG_HOME" {
			return true
		}
	}
	return false
}

// splitKey splits a git config key: section and variable names are case-insensitive, the
// subsection between them is not (hook.<name>.enabled has the hook's name in the middle).
func splitKey(name string) (section, sub, variable string, ok bool) {
	first, last := strings.IndexByte(name, '.'), strings.LastIndexByte(name, '.')
	if first < 0 {
		return "", "", "", false
	}
	if last > first {
		sub = name[first+1 : last]
	}
	return strings.ToLower(name[:first]), sub, strings.ToLower(name[last+1:]), true
}

// hookConfig reports a config key that can switch keyguard's hooks off or route around
// them. With valueMatters (the -c form) an explicit hook.<n>.enabled=true is harmless;
// editing the key with `git config` is refused whatever the value.
func hookConfig(kv string, valueMatters bool) bool {
	name, val, hasVal := strings.Cut(kv, "=")
	sec, sub, vr, ok := splitKey(strings.TrimSpace(name))
	if !ok {
		return false
	}
	switch {
	case sec == "core" && sub == "" && vr == "hookspath":
		return true
	case sec == "core" && sub == "" && vr == "bare":
		// The reference-transaction hook leaves bare repositories alone (history that
		// arrives by clone or push), so declaring a working repository bare would
		// switch it off.
		return true
	case sec == "hook" && strings.HasPrefix(sub, "keyguard-"):
		return true
	case sec == "hook" && vr == "enabled":
		if !valueMatters {
			return true
		}
		switch strings.ToLower(strings.TrimSpace(val)) {
		case "true", "yes", "on", "1":
			return false
		}
		return hasVal // a bare `-c hook.x.enabled` means true
	case (sec == "include" || sec == "includeif") && vr == "path":
		return true
	}
	return false
}

// commit options that take a value, as the next word or attached.
var commitValued = set("--reuse-message", "--reedit-message", "--file", "--message", "--template",
	"--author", "--date", "--cleanup", "--pathspec-from-file", "--trailer", "--fixup", "--squash")

const (
	commitShortValue    = "mFCct" // -m msg, -mmsg: the rest of the flag group is the value
	commitShortOptional = "uS"    // -uno, -SKEYID: the rest of the group is the value, never the next word
)

// isNoVerify accepts --no-verify and the abbreviations git accepts (--no-v ... --no-verif).
func isNoVerify(name string) bool {
	return len(name) >= len("--no-v") && strings.HasPrefix("--no-verify", name)
}

// commitSkipsHooks finds --no-verify or a -n in a flag group, reading git commit's own
// option grammar so that `-m 'use -n'`, `-m -n` and `-mn` (all messages) are not flagged.
func commitSkipsHooks(args []string) bool {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			return false
		case strings.HasPrefix(a, "--"):
			name, _, attached := strings.Cut(a, "=")
			if isNoVerify(name) {
				return true
			}
			if commitValued[name] && !attached {
				i++
			}
		case len(a) > 1 && a[0] == '-':
			for j := 1; j < len(a); j++ {
				c := a[j]
				if c == 'n' {
					return true
				}
				if strings.IndexByte(commitShortValue, c) >= 0 {
					if j == len(a)-1 {
						i++
					}
					break
				}
				if strings.IndexByte(commitShortOptional, c) >= 0 {
					break
				}
			}
		}
	}
	return false
}

var pushValued = set("--receive-pack", "--exec", "--repo", "--push-option")

// pushSkipsHooks finds --no-verify. In git push -n is --dry-run, so it is not flagged.
func pushSkipsHooks(args []string) bool {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			return false
		case strings.HasPrefix(a, "--"):
			name, _, attached := strings.Cut(a, "=")
			if isNoVerify(name) {
				return true
			}
			if pushValued[name] && !attached {
				i++
			}
		case len(a) > 1 && a[0] == '-':
			if k := strings.IndexByte(a, 'o'); k >= 0 && k == len(a)-1 { // -o <push-option>
				i++
			}
		}
	}
	return false
}

// gitConfig refuses edits to the keys that carry or bypass the hooks, and allows reads.
func (d *decider) gitConfig(args []string) {
	var pos []string
	action := ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			pos = append(pos, args[i+1:]...)
			i = len(args)
		case a == "--unset" || a == "--unset-all":
			action = "unset"
		case a == "--add" || a == "--replace-all":
			action = "set"
		case a == "--rename-section":
			action = "rename"
		case a == "--remove-section":
			action = "remove"
		case a == "-e" || a == "--edit":
			action = "edit"
		case a == "-l" || a == "--list" || strings.HasPrefix(a, "--get"):
			action = "get"
		case a == "--file" || a == "-f" || a == "--blob" || a == "--default" || a == "--type" || a == "--comment":
			i++
		case strings.HasPrefix(a, "-") && len(a) > 1:
		default:
			pos = append(pos, a)
		}
	}
	// git 2.46+ subcommands: config set / unset / get / list / ...
	if action == "" && len(pos) > 0 {
		switch pos[0] {
		case "set", "unset", "get", "list", "edit", "rename-section", "remove-section":
			action = map[string]string{"set": "set", "unset": "unset", "get": "get", "list": "get", "edit": "edit",
				"rename-section": "rename", "remove-section": "remove"}[pos[0]]
			pos = pos[1:]
		}
	}
	if action == "" {
		action = "get"
		if len(pos) >= 2 {
			action = "set" // `git config key value`
		}
	}
	var keys []string
	switch action {
	case "set", "unset":
		if len(pos) > 0 {
			keys = pos[:1]
		}
	case "rename":
		keys = pos[:min(2, len(pos))]
	case "remove":
		keys = pos[:min(1, len(pos))]
	}
	for _, k := range keys {
		guarded := hookConfig(k, false)
		if action == "rename" || action == "remove" {
			// A section name has no variable: hook.keyguard-precommit, include, ...
			sec, sub, _, ok := splitKey(k + ".x")
			guarded = ok && (sec == "hook" && strings.HasPrefix(sub, "keyguard-") || sec == "include" || sec == "includeif")
		}
		if guarded {
			d.deny(KindConfig, "git config cannot change core.hooksPath, core.bare, include paths or hook.* settings: that is how keyguard's git hooks get switched off. If a hook is broken, tell the user.")
			return
		}
	}
}
