package selftest

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"keyguard/internal/core"
	"keyguard/internal/fp"
	"keyguard/internal/install"
	"keyguard/internal/known"
	"keyguard/rules"
)

// cmdTimeout bounds one child. A hook that hangs must fail a check, not freeze the run.
const cmdTimeout = 90 * time.Second

// decoys pad the learned store to something like a real one, so the speed figures are not
// those of a store with a single secret in it.
const decoys = 100

// suite is one run: the throwaway machine and what the checks share.
type suite struct {
	o   Options
	ctx context.Context

	dir       string // the machine
	home      string // its HOME
	root      string // its data root, <home>/.keyguard: what the hooks read, and $KEYGUARD_HOME too
	gitconfig string // its global git config, where the hooks are wired
	work      string // the repos the checks make
	learnDir  string // where the .env files the store learns from sit; not under home
	bin       string // the binary under test

	env        []string
	realHome   string            // the real home, where the engines are looked for; the machine's own HOME has none
	gitVersion string            // "2.55.0"
	engine     map[string]string // engine name -> binary, as found on the real machine
	regex      string            // the engine the hooks scan with

	// engineSums and hadLock are what the engines were when the run began (STEAL P0-01): the
	// hash of each binary and whether trufflehog's updates lock was already beside it (it is on
	// this Mac, left by an update before keyguard pinned anything).
	engineSums map[string]string
	hadLock    map[string]bool

	k       string // the learned fake; in memory and in repos, never in the store
	secrets int    // learned secrets in the store (the decoys included)
	forms   int    // and the forms they are matched in

	fakes   []string // every fake made, for the leak audits
	roots   []string // the other data roots a check made, for the audits
	latency []Latency
	n       int // numbers the scenes

	captured []capture
}

// capture is everything one command printed, kept for the audits at the end.
type capture struct {
	cmd      string
	text     string
	tolerate bool // a hook warning here is the point of the check
}

func newSuite(ctx context.Context, o Options) (*suite, error) {
	bin, err := resolveBinary(o.Binary)
	if err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp(o.TempDir, "keyguard-gates-")
	if err != nil {
		return nil, err
	}
	s := &suite{o: o, ctx: ctx, bin: bin, dir: dir}
	if err := s.build(); err != nil {
		if !o.Keep {
			os.RemoveAll(dir)
		}
		return nil, fmt.Errorf("selftest: building the throwaway machine: %w", err)
	}
	return s, nil
}

var gitVersionRE = regexp.MustCompile(`\d+(\.\d+)+`)

// build makes the machine. Wiring it to the binary is the machine check's to verify, so a
// binary that does not work shows up as a failed row and not as an error here.
func (s *suite) build() error {
	s.home = filepath.Join(s.dir, "home")
	s.root = filepath.Join(s.home, ".keyguard")
	s.gitconfig = filepath.Join(s.dir, "gitconfig")
	s.work = filepath.Join(s.dir, "work")
	s.learnDir = filepath.Join(s.dir, "learn")
	for _, d := range []string{s.home, s.work} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	// Background gc and maintenance would make the repos move under the checks.
	pristine := "[user]\n\tname = Keyguard Selftest\n\temail = selftest@example.invalid\n" +
		"[init]\n\tdefaultBranch = main\n[commit]\n\tgpgsign = false\n[tag]\n\tgpgsign = false\n" +
		"[gc]\n\tauto = 0\n[maintenance]\n\tauto = false\n[advice]\n\tdetachedHead = false\n"
	if err := os.WriteFile(s.gitconfig, []byte(pristine), 0o600); err != nil {
		return err
	}
	s.env = childEnv(os.Environ(), s.home, s.root, s.gitconfig)

	r := s.run(runOpts{dir: s.dir, quiet: true}, "git", "--version")
	if err := s.ctx.Err(); err != nil {
		return err // stopped before it began
	}
	if r.code != 0 {
		return fmt.Errorf("git does not run: %s", s.line(r.out))
	}
	s.gitVersion = gitVersionRE.FindString(r.out)

	// The engines are found the way install finds them, from the real home: the throwaway
	// home has no ~/.local/bin, and a hook that cannot find betterleaks scans nothing.
	realHome, err := os.UserHomeDir()
	if err != nil {
		realHome = filepath.Join(os.TempDir(), "no-home")
	}
	s.realHome = realHome
	paths := core.PathsAt(s.root)
	cfg := install.DefaultConfig(paths, realHome)
	s.engine = cfg.EnginePaths()
	if err := os.MkdirAll(filepath.Dir(cfg.Rules), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(cfg.Rules, rules.KeyguardTOML, 0o600); err != nil {
		return err
	}
	// The engines are pinned where they are, as an installed machine's are: every hook then
	// checks the binary it is about to start against its hash, which is the path a real commit takes.
	s.engineSums, s.hadLock = map[string]string{}, map[string]bool{}
	for name, path := range s.engine {
		if sum, err := fileSum(path); err == nil {
			s.engineSums[name] = sum
		}
		s.hadLock[name] = exists(filepath.Join(filepath.Dir(path), name+"-updates.lock"))
	}
	cfg.Pins = install.PinEngines(cfg)
	if err := cfg.Save(paths); err != nil {
		return err
	}
	for _, name := range install.DefaultTiers()[install.TierPreCommit] {
		if p := s.engine[name]; p != "" {
			s.regex = name
			break
		}
	}

	// The learned store: one fake that matters and a hundred that make it a realistic size.
	s.k = s.fake("sk-proj-", 48)
	vals := [][2]string{{"SELFTEST_API_KEY", s.k}}
	for i := 0; i < decoys; i++ {
		vals = append(vals, [2]string{fmt.Sprintf("DECOY_KEY_%03d", i), randomBody(40)})
	}
	rep, err := s.learn(s.root, s.learnDir, vals)
	if err != nil {
		return err
	}
	if !slices.ContainsFunc(rep.Learned, func(l known.Learned) bool { return l.Name == "SELFTEST_API_KEY" }) {
		return fmt.Errorf("the learned-secret store did not take the fake (rejected: %v)", rep.Rejected)
	}
	s.secrets, s.forms = len(rep.Learned), rep.Entries

	// Wire the hooks with the installer's own command lines.
	for _, k := range install.HookKeys(s.bin) {
		if r := s.run(runOpts{dir: s.dir, quiet: true}, "git", "config", "--global", k.Key, k.Value); r.code != 0 {
			return fmt.Errorf("git config %s: %s", k.Key, s.line(r.out))
		}
	}
	return nil
}

// learn registers values the way `keyguard learn` does: from .env files, into the store of
// root. The files hold the raw values, so they live outside home and the audits skip them.
func (s *suite) learn(root, dir string, vals [][2]string) (*known.Report, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	var b strings.Builder
	for _, v := range vals {
		fmt.Fprintf(&b, "%s=%s\n", v[0], v[1])
	}
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte(b.String()), 0o600); err != nil {
		return nil, err
	}
	return known.Learn(known.Options{
		Ctx: s.ctx, Root: root, Home: s.home,
		EnvRoots: []string{dir}, SkipDirs: []string{}, GHUsers: []string{},
		Run: func(context.Context, string, ...string) ([]byte, error) {
			return nil, errors.New("the selftest never asks gh for a token")
		},
	})
}

var envKeep = regexp.MustCompile(`^(PATH|TMPDIR|USER|LOGNAME)=`)

// childEnv is the environment every child gets: a short whitelist from the caller's, then the
// machine's own. A drop list would pass along whatever the caller exports next year.
func childEnv(environ []string, home, root, gitconfig string) []string {
	var env []string
	for _, kv := range environ {
		if envKeep.MatchString(kv) {
			env = append(env, kv)
		}
	}
	if !slices.ContainsFunc(env, func(kv string) bool { return strings.HasPrefix(kv, "PATH=") }) {
		env = append(env, "PATH=/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin")
	}
	return append(env,
		"HOME="+home,
		// The data root as an environment variable too, so a hook that reads it lands in the
		// machine, never on the real ~/.keyguard. It is the same directory the hooks always read.
		"KEYGUARD_HOME="+root,
		"GIT_CONFIG_GLOBAL="+gitconfig,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_TERMINAL_PROMPT=0",
		"GIT_EDITOR=true",
		"GIT_ADVICE=0",
		"LC_ALL=C", "LANG=C",
	)
}

// ----- fakes -----

const alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

func randomBody(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // the system has no randomness; nothing here can go on
	}
	for i := range b {
		b[i] = alnum[int(b[i])%len(alnum)]
	}
	return string(b)
}

// fake builds a key-shaped value at run time from a public prefix and random characters,
// re-rolled until the body is random enough that no entropy gate in any engine would take it
// for a placeholder. It is remembered, so the audits can look for it in everything printed.
func (s *suite) fake(prefix string, n int) string {
	for {
		body := randomBody(n)
		if fp.Entropy(body) >= 4.4 {
			v := prefix + body
			s.fakes = append(s.fakes, v)
			return v
		}
	}
}

// forms are the ways a fake could show up in text: as is, and in the base64 spellings the
// learned store also matches.
func forms(v string) []string {
	return []string{
		v,
		base64.StdEncoding.EncodeToString([]byte(v)),
		base64.RawStdEncoding.EncodeToString([]byte(v)),
		base64.URLEncoding.EncodeToString([]byte(v)),
		base64.RawURLEncoding.EncodeToString([]byte(v)),
	}
}

// leaks counts the fakes that appear, in any spelling, in text.
func (s *suite) leaks(text string) int {
	n := 0
	for _, v := range s.fakes {
		if slices.ContainsFunc(forms(v), func(f string) bool { return strings.Contains(text, f) }) {
			n++
		}
	}
	return n
}

// ----- running things -----

type runOpts struct {
	dir      string
	env      []string // NAME=value overrides; the last one wins
	stdin    string
	quiet    bool // do not keep the output for the audits: it holds a fake on purpose
	tolerate bool // a hook warning in the output is expected here
}

type result struct {
	out   string // stdout and stderr together, in the order they were written
	code  int    // -1: could not be started; -2: killed for running too long
	took  time.Duration
	label string
}

// run starts a child on the throwaway machine and keeps what it printed for the audits.
func (s *suite) run(o runOpts, name string, args ...string) result {
	ctx, cancel := context.WithTimeout(s.ctx, cmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = o.dir
	cmd.Env = append(slices.Clone(s.env), o.env...)
	cmd.WaitDelay = 2 * time.Second // a grandchild holding the pipe open must not hold us
	if o.stdin != "" {
		cmd.Stdin = strings.NewReader(o.stdin)
	}
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf // one writer: the two streams keep their order
	started := time.Now()
	err := cmd.Run()
	r := result{out: buf.String(), took: time.Since(started), label: label(name, args)}
	if err != nil {
		var ee *exec.ExitError
		switch {
		case ctx.Err() == context.DeadlineExceeded:
			r.code = -2
			if err := s.ctx.Err(); err != nil {
				r.out += "\n[stopped: " + err.Error() + "]" // the whole run was, not this command
			} else {
				r.out += fmt.Sprintf("\n[killed: still running after %s]", cmdTimeout)
			}
		case errors.As(err, &ee):
			r.code = ee.ExitCode()
		default:
			r.code = -1
			r.out += err.Error()
		}
	}
	if !o.quiet {
		s.captured = append(s.captured, capture{cmd: r.label, text: r.out, tolerate: o.tolerate})
	}
	return r
}

// label names a command for messages: the program and its first words, never the later ones.
func label(name string, args []string) string {
	l := []string{filepath.Base(name)}
	for _, a := range args {
		if strings.HasPrefix(a, "-") && len(l) < 2 {
			continue
		}
		l = append(l, a)
		if len(l) == 3 {
			break
		}
	}
	return strings.Join(l, " ")
}

// hooksOff is what the sweep's mirror work runs git with (PLAN.md invariant 6, every hook keyguard installs) and what stands
// in here for "a commit made somewhere keyguard is not": another machine, a fresh clone.
var hooksOff = []string{
	"-c", "hook.keyguard-precommit.enabled=false",
	"-c", "hook.keyguard-commitmsg.enabled=false",
	"-c", "hook.keyguard-prepush.enabled=false",
	"-c", "hook.keyguard-reftx.enabled=false",
}

// line makes any text one short line that is safe to print: the machine's path shortened,
// random-looking tokens masked in case a hook ever printed one, whitespace collapsed.
func (s *suite) line(text string) string {
	for _, d := range []string{s.dir, realPath(s.dir)} {
		if d != "" {
			text = strings.ReplaceAll(text, d, "<machine>")
		}
	}
	text = strings.Join(strings.Fields(fp.Scrub(text)), " ")
	if r := []rune(text); len(r) > 240 {
		text = string(r[:239]) + "…"
	}
	return text
}

func realPath(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return p
}

// fileSum is the sha256 of the file a path leads to.
func fileSum(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// datastores lists the titus datastore files anywhere in the machine (a hook runs titus with
// --output :memory:, so there should be none): the file keeps every finding in the clear.
func (s *suite) datastores() []string {
	var found []string
	_ = filepath.WalkDir(s.dir, func(p string, d fs.DirEntry, err error) error {
		switch {
		case err != nil:
			return nil
		case d.IsDir() && d.Name() == ".git":
			return fs.SkipDir
		case !d.IsDir() && (d.Name() == "datastore.db" || strings.HasSuffix(d.Name(), ".ds")):
			found = append(found, p)
		}
		return nil
	})
	return found
}

// scratchLeft counts what the engines left in the data root's tmp: each run makes its own
// directory there and removes it on every normal exit.
func (s *suite) scratchLeft() int {
	ents, _ := os.ReadDir(core.PathsAt(s.root).Tmp)
	return len(ents)
}
