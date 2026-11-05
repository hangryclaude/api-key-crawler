package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"keyguard/internal/core"
	"keyguard/internal/fp"
	"keyguard/internal/install"
	"keyguard/internal/inventory/ghcli"
	"keyguard/internal/mirror"
	"keyguard/internal/upgrade"
)

// Exit codes. 1 means "the check found something", never "keyguard itself broke": a script
// can tell a dirty repo from a failed run.
const (
	exitOK     = 0
	exitFound  = 1
	exitUsage  = 2
	exitFailed = 3
	exitLocked = 4
)

// version is bumped by hand when behaviour a caller depends on changes.
const version = "0.2.0"

// mirrorAPI is the mirror as the CLI uses it: core.Mirror for the sweep, SyncResult for `sync`.
type mirrorAPI interface {
	core.Mirror
	SyncResult(ctx context.Context, s core.Source) (mirror.Result, error)
}

// seams are the few things a test replaces: the network (GitHub, through the inventory and
// the mirror) and the desktop (notifications, opening the report). All nil in production.
type seams struct {
	inventory func(cfg install.Config, p core.Paths) (core.Inventory, error)
	mirror    func(p core.Paths) (mirrorAPI, error)
	gh        *ghcli.Client // for github-settings; nil is the real gh
	notifier  core.Notifier
	open      func(path string) error
	run       install.Runner // git, launchctl and gh for install and doctor
	exe       string         // the binary `install` copies and the guard calls back; "" is this process
	now       func() time.Time

	// The weekly engine check reads GitHub's releases anonymously and scores what it downloads on the
	// bench; a test points the first at a local server and replaces the second with a stand-in.
	upgradeAPI string
	scorer     upgrade.Scorer
}

type cli struct {
	ctx      context.Context
	in       io.Reader
	out, err io.Writer
	seams    seams
}

func run(ctx context.Context, args []string, in io.Reader, out, errw io.Writer) int {
	c := &cli{ctx: ctx, in: in, out: out, err: errw}
	return c.dispatch(args)
}

type command struct {
	name    string
	summary string
	fn      func(*cli, []string) int
}

// groups orders the help text. A command in none of them is hidden (hook, guard).
func commandTable() (cmds map[string]command, groups []struct {
	title string
	names []string
}) {
	list := []command{
		{"install", "put the git hooks, binary and launchd jobs in place", (*cli).cmdInstall},
		{"uninstall", "take them out again (files are moved aside, never deleted)", (*cli).cmdUninstall},
		{"doctor", "check every layer; each problem names the command that fixes it", (*cli).cmdDoctor},
		{"selftest", "plant fakes through every layer in temp repos and check each one stops", (*cli).cmdSelftest},
		{"learn", "read this Mac's secrets and keep only their hashes", (*cli).cmdLearn},
		{"known", "list | forget: what is learned", (*cli).cmdKnown},
		{"match", "find learned secrets in files or stdin", (*cli).cmdMatch},
		{"allow", "mark a finding a false positive by its id", (*cli).cmdAllow},
		{"inventory", "list the repos, wikis and gists being watched", (*cli).cmdInventory},
		{"sync", "fetch the bare mirrors", (*cli).cmdSync},
		{"scan", "scan the mirrors: --full for everything, --repo for one source", (*cli).cmdScan},
		{"verify", "re-check whether open secrets still work", (*cli).cmdVerify},
		{"poll", "the one-minute job: scan what changed on GitHub", (*cli).cmdPoll},
		{"deep", "the weekly job: relearn, rescan everything, import GitHub's alerts", (*cli).cmdDeep},
		{"github-settings", "survey GitHub secret scanning; --apply turns it on for public repos", (*cli).cmdGitHubSettings},
		{"engines", "list | pin | check-upgrade: the scanners keyguard runs, pinned by hash", (*cli).cmdEngines},
		{"publish-check", "scan a repo's whole history before it goes public", (*cli).cmdPublishCheck},
		{"report", "write the dashboard; --open shows it", (*cli).cmdReport},
		{"export-triage", "write the unreviewed findings, redacted, for a model to judge", (*cli).cmdExportTriage},
		{"import-triage", "read a model's verdicts back in", (*cli).cmdImportTriage},
		{"bench", "score the engines and the pipeline on a synthetic repo of planted fakes", (*cli).cmdBench},
		{"version", "print the version", (*cli).cmdVersion},
		{"hook", "git hook entry point: pre-commit | pre-push | reference-transaction | commit-msg", (*cli).cmdHook},
		{"guard", "Claude Code PreToolUse guard: guard claude", (*cli).cmdGuard},
	}
	cmds = map[string]command{}
	for _, cmd := range list {
		cmds[cmd.name] = cmd
	}
	groups = []struct {
		title string
		names []string
	}{
		{"Put it on this Mac", []string{"install", "uninstall", "doctor", "selftest", "engines"}},
		{"What it knows", []string{"learn", "known", "match", "allow"}},
		{"Watch GitHub", []string{"inventory", "sync", "scan", "verify", "poll", "deep", "github-settings", "publish-check", "report"}},
		{"Judge and measure", []string{"export-triage", "import-triage", "bench", "version"}},
	}
	return cmds, groups
}

func (c *cli) dispatch(args []string) int {
	cmds, groups := commandTable()
	if len(args) == 0 {
		c.usage(cmds, groups)
		return exitUsage
	}
	switch args[0] {
	case "-h", "--help", "help":
		c.usage(cmds, groups)
		return exitOK
	case "-v", "--version":
		return c.cmdVersion(nil)
	}
	cmd, ok := cmds[args[0]]
	if !ok {
		fmt.Fprintf(c.err, "keyguard: unknown command %q\n", args[0])
		c.suggest(args[0], cmds)
		fmt.Fprintln(c.err, "run `keyguard help` for the list")
		return exitUsage
	}
	return cmd.fn(c, args[1:])
}

func (c *cli) usage(cmds map[string]command, groups []struct {
	title string
	names []string
}) {
	fmt.Fprintln(c.err, "keyguard: never leak a key to GitHub")
	for _, g := range groups {
		fmt.Fprintf(c.err, "\n%s\n", g.title)
		for _, n := range g.names {
			fmt.Fprintf(c.err, "  %-16s %s\n", n, cmds[n].summary)
		}
	}
	fmt.Fprintln(c.err, "\nkeyguard <command> -h shows a command's flags.")
}

// suggest names the command a typo was probably meant for.
func (c *cli) suggest(got string, cmds map[string]command) {
	for name := range cmds {
		if strings.HasPrefix(name, got) || strings.HasPrefix(got, name) || editDistance(got, name) <= 2 {
			fmt.Fprintf(c.err, "did you mean `keyguard %s`?\n", name)
			return
		}
	}
}

func editDistance(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	prev := make([]int, len(rb)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ra); i++ {
		cur := make([]int, len(rb)+1)
		cur[0] = i
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev = cur
	}
	return prev[len(rb)]
}

// ----- flags -----

// flagSet makes a flag set that prints its usage to stderr.
func (c *cli) flagSet(name, usage string) *flag.FlagSet {
	f := flag.NewFlagSet(name, flag.ContinueOnError)
	f.SetOutput(c.err)
	f.Usage = func() {
		fmt.Fprintf(c.err, "usage: keyguard %s\n", usage)
		f.PrintDefaults()
	}
	return f
}

// parse reads flags that may come before, between and after the positional arguments
// (`allow kg123abc --reason x`), which the standard library stops doing at the first one.
// ok is false when the caller should return code.
func (c *cli) parse(f *flag.FlagSet, args []string) (pos []string, code int, ok bool) {
	for {
		if err := f.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil, exitOK, false
			}
			return nil, exitUsage, false
		}
		rest := f.Args()
		if len(rest) == 0 {
			return pos, 0, true
		}
		if rest[0] == "--" {
			return append(pos, rest[1:]...), 0, true
		}
		pos = append(pos, rest[0])
		args = rest[1:]
	}
}

// ----- messages -----

func (c *cli) failf(format string, a ...any) int {
	fmt.Fprintf(c.err, "keyguard: "+format+"\n", a...)
	return exitFailed
}

func (c *cli) usageErr(f *flag.FlagSet, format string, a ...any) int {
	fmt.Fprintf(c.err, "keyguard: "+format+"\n", a...)
	f.Usage()
	return exitUsage
}

func (c *cli) warnf(format string, a ...any) {
	fmt.Fprintf(c.err, "keyguard: warning: "+format+"\n", a...)
}

// safeErr is an error as text that is safe to print: control bytes dropped, random-looking
// tokens masked in case an upstream message ever carried one, and short.
func safeErr(err error) string {
	s := fp.Scrub(err.Error())
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	if utf8.RuneCountInString(s) > 300 {
		s = string([]rune(s)[:299]) + "…"
	}
	return s
}

// ----- environment -----

func (c *cli) paths() core.Paths { return core.PathsAt(core.Root()) }

func (c *cli) home() string {
	h, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return h
}

func (c *cli) now() time.Time {
	if c.seams.now != nil {
		return c.seams.now()
	}
	return time.Now()
}

func (c *cli) exe() (string, error) {
	if c.seams.exe != "" {
		return c.seams.exe, nil
	}
	return os.Executable()
}

// config loads state/config.json. A file that does not parse is said out loud and the
// defaults are used: a sweep that stops because of a typo protects nothing.
func (c *cli) config(p core.Paths) install.Config {
	cfg, err := install.LoadConfig(p, c.home())
	if err != nil {
		c.warnf("%s; using the defaults", safeErr(err))
	}
	return cfg
}

// openKeyring loads the salt that keys every fingerprint under p, making one on the very first
// use. It will not mint a new one beside a learned store: a salt created after the fact would
// quietly orphan every hash in it, and the store would stop matching without a word. The
// commands that scan, learn and judge use this; `install` has already made the salt by then.
func openKeyring(p core.Paths) (*fp.Keyring, error) {
	salt := filepath.Join(p.Known, "salt")
	if _, err := os.Stat(salt); errors.Is(err, fs.ErrNotExist) {
		if _, serr := os.Stat(filepath.Join(p.Known, "known.json")); serr == nil {
			return nil, fmt.Errorf("%s is missing but known.json exists; restore the salt, or move known.json aside and run keyguard learn", salt)
		}
	}
	return fp.Load(p.Known)
}

// openKeyringHook is what a git hook uses: it reads the salt and never makes one. A hook runs
// in every repo, under whatever HOME git was started with, and a salt minted there would be a
// second, unrelated keyring that no learned hash matches. A missing salt is said out loud.
func openKeyringHook(p core.Paths) (*fp.Keyring, error) {
	kr, err := fp.Open(p.Known)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s is missing (run keyguard install)", filepath.Join(p.Known, "salt"))
	}
	return kr, err
}

// ----- output -----

// table prints rows with the columns lined up; right[i] right-aligns column i (numbers).
func table(w io.Writer, indent string, rows [][]string, right ...int) {
	if len(rows) == 0 {
		return
	}
	width := make([]int, len(rows[0]))
	for _, r := range rows {
		for i, cell := range r {
			if n := utf8.RuneCountInString(cell); i < len(width) && n > width[i] {
				width[i] = n
			}
		}
	}
	isRight := map[int]bool{}
	for _, i := range right {
		isRight[i] = true
	}
	for _, r := range rows {
		var b strings.Builder
		b.WriteString(indent)
		for i, cell := range r {
			pad := strings.Repeat(" ", max(0, width[i]-utf8.RuneCountInString(cell)))
			switch {
			case i == len(r)-1 && !isRight[i]:
				b.WriteString(cell)
			case isRight[i]:
				b.WriteString(pad + cell)
			default:
				b.WriteString(cell + pad)
			}
			if i < len(r)-1 {
				b.WriteString("  ")
			}
		}
		fmt.Fprintln(w, strings.TrimRight(b.String(), " "))
	}
}

// tilde writes paths under the home directory as ~/..., which is shorter to read.
func (c *cli) tilde(s string) string {
	if h := c.home(); h != "" {
		return strings.ReplaceAll(s, h+"/", "~/")
	}
	return s
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

func secs(f float64) string { return fmt.Sprintf("%.1f s", f) }
