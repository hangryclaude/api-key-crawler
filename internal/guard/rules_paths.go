package guard

import (
	"path"
	"strings"

	"keyguard/internal/hooks"
)

// Files an agent does not write (STEAL P0-12). Each scanner has its own way to be told to
// stay quiet: an inline comment, an ignore file, a baseline, a config with an allowlist. A
// blocked agent that wants its commit to pass needs one edit of any of them, so the
// scanners are told to ignore the comments (the engines pass --ignore-gitleaks-allow and
// --no-ignore-tag on every call) and the files are the guard's to keep: the filename rules in
// internal/hooks decide which paths are scanner configuration, and this package refuses to
// write them. The one allowlist is state/ignore.json, written by `keyguard allow`, which the
// owner rules refuse as well, and so are the files that hold the learned keys and the binary.

// keyguardOwn reports a path in keyguard's own data directory that carries protection or
// decides what is let through: the allowlist, the learned-secret store, the config, the
// rules, the installed binary. Logs, caches and reports are not in the list.
func keyguardOwn(p string) bool {
	p = strings.ToLower(path.Clean(strings.ReplaceAll(p, "\\", "/")))
	i := strings.Index(p, ".keyguard/")
	if i < 0 || i > 0 && p[i-1] != '/' {
		return false
	}
	rest := p[i+len(".keyguard/"):]
	switch {
	case rest == "state/ignore.json", rest == "state/config.json", strings.HasPrefix(rest, "state/known/"),
		strings.HasPrefix(rest, "rules/"), strings.HasPrefix(rest, "bin/"):
		return true
	}
	return false
}

// scannerFile reports a path the filename rules class as scanner configuration.
func scannerFile(p string) (hooks.Rule, bool) {
	r, ok := hooks.PathRule(path.Clean(p))
	return r, ok && r.Action == hooks.ActGuard
}

const (
	ownReason = "That file is part of keyguard's own protection (its allowlist, learned keys, config, rules or binary). Changing it is how a finding gets let through or keyguard taken out, and that is the user's call."
)

func scannerReason(p string, r hooks.Rule) string {
	return "Writing " + path.Base(p) + " (" + r.Why + "). Whatever it holds hides a finding from the scanner it is written for, and an agent whose commit was blocked is the one who would write it. The one allowlist is `keyguard allow <id>`, which the user runs themselves."
}

// target judges one file a command is about to write (or, with removal, to delete: taking away
// a scanner's ignore file only adds protection, so only keyguard's own files count then).
func (d *decider) target(p string, removal bool) {
	if p == "" {
		return
	}
	switch {
	case keyguardOwn(p):
		d.deny(KindOwner, ownReason)
	case !removal:
		if r, ok := scannerFile(p); ok {
			d.deny(KindScanner, scannerReason(p, r))
		}
	}
}

// writes finds the files a command writes through its arguments: tee, touch, cp, mv and
// friends, sed -i, dd of=. Redirections are handled where the command is read. It names no
// command that only reads, so `cat .gitleaksignore` and `grep x .betterleaksignore` pass.
func (d *decider) writes(prog string, argv []string) {
	if d.reason != "" || len(argv) < 2 {
		return
	}
	args := argv[1:]
	var pos []string
	for _, a := range args {
		if !strings.HasPrefix(a, "-") || a == "-" {
			pos = append(pos, a)
		}
	}
	switch prog {
	case "tee", "touch", "truncate", "shred":
		for _, a := range pos {
			d.target(a, false)
		}
	case "rm", "unlink":
		for _, a := range pos {
			d.target(a, true)
		}
	case "cp", "install", "ln", "mv":
		if len(pos) < 2 {
			return
		}
		dest := pos[len(pos)-1]
		d.target(dest, false)
		for _, src := range pos[:len(pos)-1] {
			// Into a directory the file keeps its name. Only a destination that says it is one
			// is read that way; `cp .gitleaksignore /tmp/backup` copies it away.
			if dest == "." || dest == ".." || strings.HasSuffix(dest, "/") {
				d.target(path.Join(dest, path.Base(src)), false)
			}
			if prog == "mv" {
				d.target(src, true) // a moved file is gone from where it was
			}
		}
	case "sed", "perl", "ruby":
		if !editsInPlace(args) {
			return
		}
		for _, a := range pos {
			d.target(a, false)
		}
	case "dd":
		for _, a := range args {
			if of, ok := strings.CutPrefix(a, "of="); ok {
				d.target(of, false)
			}
		}
	}
}

// editsInPlace: sed -i, sed -i.bak, sed --in-place, perl -pi -e, perl -i.
func editsInPlace(args []string) bool {
	for _, a := range args {
		if strings.HasPrefix(a, "--in-place") {
			return true
		}
		if len(a) > 1 && a[0] == '-' && a[1] != '-' && strings.ContainsRune(a, 'i') && !strings.ContainsAny(a, "e=") {
			return true
		}
	}
	return false
}

// goRunKeyguard recognises `go run [flags] ./cmd/keyguard args...`, which is keyguard under a
// longer name, and returns the arguments the program gets.
func goRunKeyguard(args []string) ([]string, bool) {
	if len(args) == 0 || args[0] != "run" {
		return nil, false
	}
	valued := set("-C", "-tags", "-ldflags", "-gcflags", "-asmflags", "-gccgoflags", "-mod", "-modfile", "-overlay",
		"-pgo", "-p", "-exec", "-toolexec", "-pkgdir", "-installsuffix", "-buildmode", "-compiler", "-coverpkg", "-covermode")
	for i := 1; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			return nil, false
		case strings.HasPrefix(a, "-"):
			if valued[a] {
				i++
			}
		default:
			pkg := strings.TrimSuffix(path.Clean(a), "/")
			if path.Base(pkg) == "keyguard" || strings.HasSuffix(pkg, "cmd/keyguard") || strings.HasSuffix(pkg, "cmd/keyguard/main.go") {
				return args[i+1:], true
			}
			return nil, false
		}
	}
	return nil, false
}
