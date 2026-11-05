package guard

import (
	"math/rand/v2"
	"reflect"
	"strings"
	"testing"
)

// fakeToken is assembled at run time (prefix plus random alphanumerics), so no
// secret-shaped literal lives in source.
func fakeToken() string {
	const alnum = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := []byte("sk-")
	for range 48 {
		b = append(b, alnum[rand.IntN(len(alnum))])
	}
	return string(b)
}

type row struct {
	name    string
	cmd     string
	block   bool
	kind    Kind
	publish []Target
}

func block(name, cmd string, k Kind) row { return row{name: name, cmd: cmd, block: true, kind: k} }
func allow(name, cmd string) row         { return row{name: name, cmd: cmd} }
func pub(name, cmd string, ts ...Target) row {
	return row{name: name, cmd: cmd, publish: ts}
}

var table = []row{
	// git commit: flags that skip the hooks
	block("long flag", "git commit --no-verify -m x", KindBypass),
	block("short flag", "git commit -n -m x", KindBypass),
	block("short flag in group nm", "git commit -nm x", KindBypass),
	block("short flag in group anm", "git commit -anm x", KindBypass),
	block("short flag last", "git commit -m x -n", KindBypass),
	block("long flag last", "git commit -m x --no-verify", KindBypass),
	block("amend no-edit then -n", "git commit --amend --no-edit -n", KindBypass),
	block("abbrev --no-v", "git commit --no-v -m x", KindBypass),
	block("abbrev --no-verif", "git commit --no-verif -m x", KindBypass),
	block("verbose+n group", "git commit -vn", KindBypass),
	block("git -C path", "git -C /tmp/repo commit -n", KindBypass),
	block("git --git-dir=", "git --git-dir=/x/.git commit --no-verify", KindBypass),
	block("quoted flag", `git commit "-n"`, KindBypass),
	block("ansi-c quoted flag", `git commit $'-n'`, KindBypass),
	block("backslash-escaped flag", `git commit --no\-verify`, KindBypass),
	block("quote concatenation", `git commit --no-ver""ify`, KindBypass),
	block("after cd &&", "cd repo && git commit -a -n -m x", KindBypass),
	block("after git add &&", "git add . && git commit --no-verify -m wip", KindBypass),
	block("subshell", "(cd sub; git commit -n)", KindBypass),
	block("line continuation", "git commit --no-verify \\\n -m x", KindBypass),
	block("apostrophe then -n", `git commit -m "it's fine" -n`, KindBypass),
	block("quote dance then -n", `git commit -m 'don'"'"'t' -n`, KindBypass),
	block("complete first line, broken second", "git commit -n -m x\necho 'broken", KindBypass),

	allow("-F with an attached value that looks like a flag", "git commit -F-n"),
	allow("-F with a separate value that looks like a flag", "git commit -F -n"),
	block("-n first in a group that goes on", "git commit -n-m msg", KindBypass),
	allow("an unknown option that merely starts like --no-verify", "git commit --no-verify-message=x"),
	block("abbreviation with =value", "git commit --no-v=1", KindBypass),
	block("push --no-verify before the remote", "git push --no-verify origin", KindBypass),
	allow("push unknown flag group", "git push -xyz origin"),
	block("hooksPath then an alias", "git -c core.hooksPath=/dev/null -c alias.ci='commit -n' ci", KindConfig),
	allow("a value that names a guarded key", "git config --replace-all user.name core.hooksPath"),
	block("assignment from a substitution", "X=$(git commit -n)", KindBypass),
	block("before another command", "git commit -n; echo done", KindBypass),
	block("in braces", "{ git commit -n; }", KindBypass),
	block("in the background", "git commit -n &", KindBypass),
	block("into a pipe", "git commit -n | cat", KindBypass),
	block("negated", "! git commit -n", KindBypass),
	block("timed", "time git commit -n", KindBypass),
	block("--no-verify=value", "git commit --no-verify=1", KindBypass),
	block("attached message then -n", `git commit -m"x" -n`, KindBypass),
	block("--message form then --no-verify", `git commit --message "x" --no-verify`, KindBypass),
	block("quiet group with n", "git commit -qnm init", KindBypass),
	block("echo -e piped to bash", "echo -e 'git commit -n' | bash", KindBypass),
	block("printf piped to sh", `printf 'git commit -n\n' | sh`, KindBypass),
	block("push flag after a refspec", "git push origin HEAD:refs/heads/x --no-verify", KindBypass),
	allow("a command only a substitution can name", `bash -c "$(echo git commit -n)"`),
	allow("a script file is not on the command line", "cat <<EOF > run.sh\ngit commit -n\nEOF\nbash run.sh"),
	allow("-n belongs to git log", "git log --oneline -n 5"),
	allow("quiet commit", "git commit -qm init"),
	allow("--no-gpg-sign is not --no-verify", "git commit -m init -q --no-gpg-sign"),
	allow("-n in a message after allow-empty", "git commit --allow-empty -m 'chore: -n'"),
	allow("two commits", "git commit -m 'a' && git commit -m 'b'"),
	allow("push with lease and options", "git push --force-with-lease=main:abc -o ci.skip -u origin main"),

	// wrappers and nested shells
	block("bash -c", `bash -c "git commit --no-verify"`, KindBypass),
	block("sh -c single quotes", `sh -c 'git commit -n -m x'`, KindBypass),
	block("bash -lc", `bash -lc 'git commit --no-verify'`, KindBypass),
	block("bash -c nested twice", `bash -c "bash -c \"git commit -n\""`, KindBypass),
	block("env prefix", "env GIT_AUTHOR_NAME=x git commit -n", KindBypass),
	block("assignment prefix", "FOO=1 git commit --no-verify", KindBypass),
	block("sudo", "sudo git commit -n", KindBypass),
	block("sudo -u user", "sudo -u someone git commit -n", KindBypass),
	block("timeout", "timeout 30 git commit -n", KindBypass),
	block("command builtin", "command git commit --no-verify", KindBypass),
	block("absolute path git", "/usr/bin/git commit -n", KindBypass),
	block("xargs", "echo x | xargs git commit -n -m", KindBypass),
	block("eval", `eval "git commit --no-verify"`, KindBypass),
	block("env -S", `env -S 'git commit -n'`, KindBypass),
	block("command substitution as argument", "echo $(git commit --no-verify)", KindBypass),
	block("backticks", "echo `git commit -n`", KindBypass),
	block("substitution inside quotes", `echo "$(git commit -n)"`, KindBypass),
	block("if/then", "if true; then git commit -n; fi", KindBypass),
	block("for/do", "for i in 1 2; do git commit -n -m $i; done", KindBypass),
	block("heredoc to sh", "cat <<EOF | sh\ngit commit -n\nEOF", KindBypass),
	block("heredoc to bash", "bash <<'EOF'\ngit commit --no-verify\nEOF", KindBypass),
	block("here-string to bash", `bash <<< "git commit -n"`, KindBypass),
	block("echo piped to sh", `echo "git commit -n" | sh`, KindBypass),
	block("alias on the command line", "git -c alias.ci=commit ci -n", KindBypass),
	block("shell alias on the command line", "git -c 'alias.ci=!git commit' ci -n", KindBypass),
	block("expanded heredoc runs substitutions", "cat <<EOF\n$(git commit -n)\nEOF", KindBypass),
	block("git -c option before subcommand then -n", "git -c user.name=x -c user.email=y commit -n", KindBypass),

	// git commit: text that only mentions a flag
	allow("flag inside the message", "git commit -m 'use -n flag'"),
	allow("--no-verify inside the message", `git commit -m "feat: add --no-verify docs"`),
	allow("-n as the message", "git commit -m -n"),
	allow("-mn is message n", "git commit -mn"),
	allow("-am", `git commit -am "x"`),
	allow("amend no-edit", "git commit --amend --no-edit"),
	allow("signed", "git commit -S -m x"),
	allow("message file", "git commit -F msg.txt"),
	allow("-F takes -n as file name", "git commit --file -n"),
	allow("--message=-n", "git commit --message=-n"),
	allow("pathspec after --", "git commit -m x -- -n"),
	allow("trailing comment", "git commit -m x # -n"),
	allow("whole-line comment", "# git commit --no-verify"),
	allow("echo mentions it", "echo git commit --no-verify"),
	allow("echo quoted", `echo "git commit -n"`),
	allow("grep for it", `grep -rn "git commit --no-verify" docs/`),
	allow("printf mentions push", `printf '%s\n' 'git push --no-verify'`),
	allow("sed over a script", `sed -i 's/--no-verify//' hooks.sh`),
	allow("heredoc into a file is data", "cat > notes.md <<'EOF'\ngit commit --no-verify\nEOF"),
	allow("heredoc message in substitution", "git commit -m \"$(cat <<'EOF'\nfix: handle -n\n\nnever git commit --no-verify; it's blocked\nEOF\n)\""),
	allow("unquoted heredoc with apostrophe", "git commit -m \"$(cat <<EOF\ndon't use -n\nEOF\n)\""),
	allow("single quoted substitution is text", `echo '$(git commit -n)'`),
	allow("commit-tree is not commit", "git commit-tree HEAD^{tree} -m x"),
	allow("commit-graph is not commit", "git commit-graph write"),
	allow("log with odd flag", "git log --no-verify"),
	allow("plain status", "git status"),
	allow("empty", ""),
	allow("blanks", "   \n  "),
	allow("unterminated quote", `git commit --no-verify -m "unterminated`),
	allow("broken second line keeps the clean first", "git status\ngit commit -m \"x\n"),

	// git push
	block("push --no-verify", "git push --no-verify", KindBypass),
	block("push flag after refs", "git push origin main --no-verify", KindBypass),
	block("push abbreviation", "git push --no-v origin", KindBypass),
	allow("push dry-run -n", "git push -n origin main"),
	allow("push --dry-run", "git push --dry-run"),
	allow("push -u", "git push -u origin feat"),
	allow("push plain", "git push origin main"),
	allow("push push-option value", "git push -o ci.skip origin main"),

	// hooks config
	block("-c core.hooksPath", "git -c core.hooksPath=/dev/null commit -m x", KindConfig),
	block("-c core.hooksPath on status", "git -c core.hooksPath=/dev/null status", KindConfig),
	block("-c lower-case key", "git -c core.hookspath=/x commit", KindConfig),
	block("-c hook keyguard enabled=false", "git -c hook.keyguard-precommit.enabled=false commit", KindConfig),
	block("-c hook keyguard command", "git -c hook.keyguard-reftx.command=true commit", KindConfig),
	block("-c any hook enabled=false", "git -c hook.foo.enabled=false commit -m x", KindConfig),
	block("-c any hook enabled=0", "git -c hook.foo.enabled=0 commit -m x", KindConfig),
	block("--config-env hooksPath", "git --config-env=core.hooksPath=EVIL commit", KindConfig),
	block("-c include.path", "git -c include.path=/tmp/x commit", KindConfig),
	block("-c core.bare hides a repo from the ref hook", "git -c core.bare=true update-ref refs/heads/x HEAD", KindConfig),
	block("config core.bare", "git config core.bare true", KindConfig),
	allow("config read core.bare", "git config --get core.bare"),
	allow("-c hook enabled=true", "git -c hook.foo.enabled=true commit -m x"),
	allow("-c user settings", "git -c user.name=x -c user.email=y commit -m z"),
	block("config set hooksPath", "git config core.hooksPath /dev/null", KindConfig),
	block("config global hooksPath", "git config --global core.hooksPath .husky", KindConfig),
	block("config unset hooksPath", "git config --unset core.hooksPath", KindConfig),
	block("config unset-all keyguard command", "git config --global --unset-all hook.keyguard-reftx.command", KindConfig),
	block("config keyguard enabled", "git config hook.keyguard-prepush.enabled false", KindConfig),
	block("config any hook enabled", "git config --global hook.foo.enabled false", KindConfig),
	block("config typed any hook enabled", "git config --bool hook.foo.enabled false", KindConfig),
	block("config remove-section keyguard", "git config --remove-section hook.keyguard-precommit", KindConfig),
	block("config include.path", "git config --global include.path /tmp/x", KindConfig),
	block("config set subcommand", "git config set core.hooksPath /dev/null", KindConfig),
	block("config -C dir", "git -C /r config core.hooksPath /dev/null", KindConfig),
	allow("config read hooksPath", "git config core.hooksPath"),
	allow("config --get hooksPath", "git config --get core.hooksPath"),
	allow("config get subcommand", "git config get core.hooksPath"),
	allow("config list", "git config --global --list"),
	allow("config get-regexp hooks", `git config --get-regexp '^hook\.'`),
	allow("config user.name", `git config user.name "A B"`),
	allow("config value named set", "git config user.name set"),

	// environment that hides the global config
	block("GIT_CONFIG_GLOBAL prefix", "GIT_CONFIG_GLOBAL=/dev/null git commit -m x", KindConfig),
	block("GIT_CONFIG_COUNT prefix", "GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.hooksPath GIT_CONFIG_VALUE_0=/dev/null git commit", KindConfig),
	block("HOME prefix on push", "HOME=/tmp git push", KindConfig),
	block("env -i HOME", "env -i HOME=/tmp git commit -m x", KindConfig),
	// git without a HOME reads no ~/.gitconfig, so every hook in it is gone.
	block("env -i", "env -i git commit -m x", KindConfig),
	block("env -i PATH", "env -i PATH=/usr/bin git commit -m x", KindConfig),
	block("env - (old -i)", "env - git push", KindConfig),
	block("env --ignore-environment", "env --ignore-environment git commit -m x", KindConfig),
	block("env -u HOME", "env -u HOME git commit -m x", KindConfig),
	block("env -uHOME", "env -uHOME git push", KindConfig),
	block("env --unset HOME", "env --unset HOME git commit -m x", KindConfig),
	block("env --unset=HOME", "env --unset=HOME git commit -m x", KindConfig),
	block("env -iv", "env -iv git commit -m x", KindConfig),
	block("env -u HOME -u FOO", "env -u FOO -u HOME git commit -m x", KindConfig),
	block("sudo env -i", "sudo env -i git commit -m x", KindConfig),
	allow("env -u unrelated", "env -u FOO git commit -m x"),
	allow("env -u HOMEDIR", "env -u HOMEDIR git commit -m x"),
	allow("env -i on status", "env -i git status"),
	allow("env -u HOME on status", "env -u HOME git log"),
	block("export GIT_CONFIG_GLOBAL", "export GIT_CONFIG_GLOBAL=/dev/null", KindConfig),
	allow("HOME prefix on status", "HOME=/tmp git status"),
	allow("author prefix", "GIT_AUTHOR_NAME=x git commit -m y"),

	// publish gate
	pub("repo create public with source", "gh repo create x --public --source .", Target{Path: "."}),
	pub("repo create source= push", "gh repo create x --public --source=./app --push", Target{Path: "./app"}),
	pub("repo create -s", "gh repo create x -s ../app --public", Target{Path: "../app"}),
	pub("repo create template", "gh repo create x --public --template o/tpl", Target{Repo: "o/tpl"}),
	pub("repo create after cd", "cd app && gh repo create x --public --source=. --push", Target{Path: "."}),
	pub("two creates", "gh repo create a --public --source=./a && gh repo create b --public --source=./b", Target{Path: "./a"}, Target{Path: "./b"}),
	pub("repo create visibility flag", "gh repo create x --visibility public --source .", Target{Path: "."}),
	pub("repo edit public", "gh repo edit o/n --visibility public --accept-visibility-change-consequences", Target{Repo: "o/n"}),
	pub("repo edit public url", "gh repo edit https://github.com/o/n.git --visibility=public", Target{Repo: "o/n"}),
	pub("repo edit current", "gh repo edit --visibility=public", Target{Path: "."}),
	pub("api private=false", "gh api repos/o/n -X PATCH -f private=false", Target{Repo: "o/n"}),
	pub("api visibility=public", "gh api repos/o/n --method PATCH --field visibility=public", Target{Repo: "o/n"}),
	pub("api leading slash -F", "gh api /repos/o/n -F private=false -X PATCH", Target{Repo: "o/n"}),
	pub("api placeholders", "gh api repos/{owner}/{repo} -X PATCH -f private=false", Target{Path: "."}),
	pub("api template generate", "gh api repos/o/tpl/generate -X POST -f name=x -f private=false", Target{Repo: "o/tpl"}),
	allow("repo create private", "gh repo create x --private --source ."),
	allow("repo create empty public", "gh repo create x --public"),
	allow("repo create public=false", "gh repo create x --public=false --source ."),
	allow("repo edit private", "gh repo edit o/n --visibility private"),
	allow("repo edit description", "gh repo edit o/n --description x"),
	allow("api edit description", "gh api repos/o/n -X PATCH -f description=x"),
	allow("api create repo is empty", "gh api user/repos -f name=x -f private=false"),
	allow("api read", "gh api repos/o/n/issues"),
	allow("repo view", "gh repo view o/n"),
	allow("pr create", "gh pr create --title x"),
}

func TestDecideTable(t *testing.T) {
	if len(table) < 40 {
		t.Fatalf("table has %d cases, want at least 40", len(table))
	}
	for _, r := range table {
		t.Run(r.name, func(t *testing.T) {
			d := Decide(r.cmd)
			if d.Block != r.block {
				t.Fatalf("Decide(%q): block=%v (%s), want %v", r.cmd, d.Block, d.Reason, r.block)
			}
			if r.block {
				if d.Kind != r.kind {
					t.Errorf("Decide(%q): kind %q, want %q", r.cmd, d.Kind, r.kind)
				}
				if d.Reason == "" {
					t.Errorf("Decide(%q): blocked with no reason", r.cmd)
				}
				return
			}
			if !reflect.DeepEqual(d.Publish, r.publish) {
				t.Errorf("Decide(%q): publish %+v, want %+v", r.cmd, d.Publish, r.publish)
			}
		})
	}
	t.Logf("%d table cases", len(table))
}

func TestTokenize(t *testing.T) {
	cases := []struct {
		in   string
		want [][]string
	}{
		{`git commit -m 'a b' "c d"`, [][]string{{"git", "commit", "-m", "a b", "c d"}}},
		{`a; b && c || d | e & f`, [][]string{{"a"}, {"b"}, {"c"}, {"d"}, {"e"}, {"f"}}},
		{"a\nb\n\nc", [][]string{{"a"}, {"b"}, {"c"}}},
		{`echo "$(git log -1)" x`, [][]string{{"echo", "$(…)", "x"}}},
		{`echo $(a; b) y`, [][]string{{"echo", "$(…)", "y"}}},
		{`echo a\ b`, [][]string{{"echo", "a b"}}},
		{`echo 'a;b' "c|d"`, [][]string{{"echo", "a;b", "c|d"}}},
		{`cmd 2>&1 >out.txt arg`, [][]string{{"cmd", "arg"}}},
		{`cmd &>/dev/null`, [][]string{{"cmd"}}},
		{`cmd >> log 2> err`, [][]string{{"cmd"}}},
		{`echo $'a\tb\x41'`, [][]string{{"echo", "a\tbA"}}},
		{`echo "a\"b" 'c\d'`, [][]string{{"echo", `a"b`, `c\d`}}},
		{`echo ${HOME:-/tmp} $((1+2))`, [][]string{{"echo", "${…}", "$((…))"}}},
		{`echo a # b c`, [][]string{{"echo", "a"}}},
		{`echo a#b`, [][]string{{"echo", "a#b"}}},
		{"cat <<EOF\nline; git commit -n\nEOF\nnext", [][]string{{"cat"}, {"next"}}},
		{"cat <<-EOF\n\tbody\n\tEOF\nnext", [][]string{{"cat"}, {"next"}}},
		{"a |\n b", [][]string{{"a"}, {"b"}}},
		{`diff <(a x) <(b y)`, [][]string{{"diff", "<(…)", "<(…)"}}},
	}
	for _, c := range cases {
		got, err := Tokenize(c.in)
		if err != nil {
			t.Errorf("Tokenize(%q): %v", c.in, err)
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("Tokenize(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestTokenizeErrors(t *testing.T) {
	for _, in := range []string{`echo "open`, `echo 'open`, "echo $(open", "echo `open", "echo ${open", `echo "x\`} {
		if _, err := Tokenize(in); err == nil {
			t.Errorf("Tokenize(%q): want a parse error", in)
		}
	}
}

// Pipes carry stdin to the next command; the parser has to remember it for `echo ... | sh`.
func TestParsePipeFlag(t *testing.T) {
	sc, err := parse("a | b && c")
	if err != nil {
		t.Fatal(err)
	}
	got := []bool{sc.cmds[0].piped, sc.cmds[1].piped, sc.cmds[2].piped}
	if want := []bool{false, true, false}; !reflect.DeepEqual(got, want) {
		t.Errorf("piped = %v, want %v", got, want)
	}
}

// A hostile or merely long command must not hang or blow the stack.
func TestDeepNestingTerminates(t *testing.T) {
	Decide(strings.Repeat("echo $(", 200) + "git commit -n" + strings.Repeat(")", 200))
	Decide(strings.Repeat("eval ", 200) + "git commit -n")
	Decide(strings.Repeat("env ", 200) + "git commit -n")
	Decide(strings.Repeat("(", 500) + "git commit -n" + strings.Repeat(")", 500))
	// Allowed past maxDepth is acceptable; hanging is not. Within the limit the inner
	// command is still found. (Each level of quoting multiplies the text by four, so the
	// loop stays short.)
	nested := "git commit -n"
	for range 5 {
		nested = "bash -c '" + strings.ReplaceAll(nested, "'", `'\''`) + "'"
	}
	if !Decide(nested).Block {
		t.Errorf("five levels of bash -c should still be read")
	}
}

func TestReasonsNameTheRule(t *testing.T) {
	for cmd, want := range map[string]string{
		"git commit -n":                 "pre-commit",
		"git push --no-verify":          "pre-push",
		"git config core.hooksPath x":   "hooksPath",
		"GIT_CONFIG_GLOBAL=/x git push": "GIT_CONFIG",
	} {
		if d := Decide(cmd); !d.Block || !strings.Contains(d.Reason, want) {
			t.Errorf("Decide(%q) reason %q lacks %q", cmd, d.Reason, want)
		}
	}
}
