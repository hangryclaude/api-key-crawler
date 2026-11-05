package install

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"keyguard/internal/core"
	"keyguard/internal/db"
	"keyguard/internal/engines"
	"keyguard/internal/fp"
	"keyguard/internal/known"
	"keyguard/internal/mirror"
	"keyguard/internal/report"
	"keyguard/internal/sweep"
	"keyguard/internal/triage"
)

// SelftestOptions says what to test and where to record the answer.
type SelftestOptions struct {
	Executable string     // the keyguard binary under test: it is installed into the throwaway machine
	Record     core.Paths // where state/selftest.json goes; the zero value records nothing
	Log        io.Writer  // one line per step (never a value); nil is silent
	Only       []string   // run just these layers (by name); empty runs all
	Keep       bool       // keep the throwaway machine, for looking at after a failure
}

// Selftest plants fake secrets, built at run time from a prefix and random characters, through
// every protection layer on a throwaway machine, and checks that each layer stops what it
// should. The machine is a temp dir with its own HOME, its own global git config and its
// own keyguard root, so nothing of the real one is read or written. The layers run the
// installed binary exactly as git, Claude Code and launchd would; only the sweep, which
// would otherwise need GitHub, runs in this process against a local mirror.
//
// A layer that fails is a result, not an error: the error return is for being unable to build
// the machine at all.
func Selftest(ctx context.Context, o SelftestOptions) (SelftestRecord, error) {
	if o.Executable == "" {
		return SelftestRecord{}, errors.New("install: selftest needs the binary to test")
	}
	dir, err := os.MkdirTemp("", "keyguard-selftest-")
	if err != nil {
		return SelftestRecord{}, err
	}
	if !o.Keep {
		defer os.RemoveAll(dir) // our own temp dir; it holds fakes only
	}
	s := &selftest{o: o, ctx: ctx, dir: dir}
	if err := s.setup(); err != nil {
		return SelftestRecord{}, err
	}
	started := time.Now()
	rec := SelftestRecord{At: started.UTC().Format(time.RFC3339), OK: true}
	for _, l := range s.layers() {
		if len(o.Only) > 0 && !slices.Contains(o.Only, l.name) {
			continue
		}
		if ctx.Err() != nil {
			break
		}
		t0 := time.Now()
		s.logf("%s", l.name)
		detail, lerr := l.run()
		res := SelftestLayer{Name: l.name, OK: lerr == nil, Detail: detail, Seconds: time.Since(t0).Seconds()}
		if lerr != nil {
			res.Detail = scrubLine(lerr.Error())
			rec.OK = false
		}
		rec.Layers = append(rec.Layers, res)
	}
	if err := ctx.Err(); err != nil {
		// A run that was cut short has not shown that anything works.
		rec.OK = false
		rec.Layers = append(rec.Layers, SelftestLayer{Name: "selftest", Detail: "interrupted: " + err.Error()})
	}
	rec.Seconds = time.Since(started).Seconds()
	if o.Record.State != "" {
		b, err := json.MarshalIndent(rec, "", "  ")
		if err == nil {
			err = db.WriteFileAtomic(SelftestPath(o.Record), append(b, '\n'), 0o600)
		}
		if err != nil {
			return rec, fmt.Errorf("install: recording the selftest: %w", err)
		}
	}
	return rec, nil
}

type selftestLayer struct {
	name string
	run  func() (string, error)
}

type selftest struct {
	o   SelftestOptions
	ctx context.Context
	dir string

	home, gitconfig, launch string
	paths                   core.Paths
	bin                     string
	env                     []string

	learned, rx1, rx2 string // the fakes: one the matcher learns, two only a scanner can find
	pullKey, tagKey   string // two more, kept where no branch reaches them
	pristineConfig    []byte // the global git config before install, for the round trip
	idOfRx1           string
	kr                *fp.Keyring
	cfg               Config

	po pollOutcome // the one sweep the poll and report layers both look at

	mu       sync.Mutex
	captured [][]byte // everything every command printed, for the leak audit
}

func (s *selftest) logf(format string, a ...any) {
	if s.o.Log != nil {
		fmt.Fprintf(s.o.Log, "selftest: "+format+"\n", a...)
	}
}

func (s *selftest) layers() []selftestLayer {
	return []selftestLayer{
		{"install", s.layerInstall},
		{LayerKnown, s.layerKnown},
		{LayerCommit, s.layerCommit},
		{LayerRef, s.layerRef},
		{LayerPush, s.layerPush},
		{LayerGuard, s.layerGuard},
		{"publish gate", s.layerPublish},
		{LayerEngines, s.layerEngines},
		{LayerPoll, s.layerPoll},
		{"report", s.layerReport},
		{"no raw secrets on disk", s.layerAudit},
		{"uninstall", s.layerUninstall},
	}
}

const (
	stAlnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	// A GitHub token is the shape every regex engine here has a rule for.
	rxPrefix = "ghp_"
)

func randString(charset string, n int) (string, error) {
	b := make([]byte, n)
	for i := range b {
		x, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", err
		}
		b[i] = charset[x.Int64()]
	}
	return string(b), nil
}

// fake builds a key-shaped value at run time. It is re-rolled until it is random enough that
// no entropy filter in any engine would wave it through as a placeholder.
func fake(prefix string, n int) (string, error) {
	for {
		body, err := randString(stAlnum, n)
		if err != nil {
			return "", err
		}
		if fp.Entropy(body) >= 4.4 {
			return prefix + body, nil
		}
	}
}

func (s *selftest) setup() error {
	s.home = filepath.Join(s.dir, "home")
	s.gitconfig = filepath.Join(s.dir, "gitconfig")
	s.launch = filepath.Join(s.dir, "LaunchAgents")
	s.paths = core.PathsAt(filepath.Join(s.home, ".keyguard"))
	s.bin = s.paths.Bin
	if err := os.MkdirAll(s.home, 0o755); err != nil {
		return err
	}
	var err error
	if s.learned, err = fake("sk-proj-", 48); err != nil {
		return err
	}
	if s.rx1, err = fake(rxPrefix, 36); err != nil {
		return err
	}
	if s.rx2, err = fake(rxPrefix, 36); err != nil {
		return err
	}
	s.pristineConfig = []byte("# selftest\n[user]\n\tname = Selftest\n\temail = selftest@example.invalid\n" +
		"[init]\n\tdefaultBranch = main\n[commit]\n\tgpgsign = false\n[gc]\n\tauto = 0\n[maintenance]\n\tauto = false\n[advice]\n\tdetachedHead = false\n")
	if err := os.WriteFile(s.gitconfig, s.pristineConfig, 0o600); err != nil {
		return err
	}
	// The child environment is built from scratch around the real PATH: nothing of the real
	// HOME, git config, keyguard root or GitHub credentials can reach a layer.
	// A whitelist, not a drop list: `keyguard learn` reads the environment, and the throwaway
	// machine must not learn the real keys exported into the shell that runs the selftest.
	keep := regexp.MustCompile(`^(PATH|TMPDIR|LANG|LC_ALL|USER|LOGNAME|SHELL)=`)
	for _, kv := range os.Environ() {
		if keep.MatchString(kv) {
			s.env = append(s.env, kv)
		}
	}
	s.env = append(s.env, "HOME="+s.home, "GIT_CONFIG_GLOBAL="+s.gitconfig, "GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0")
	return nil
}

// ----- running things -----

type result struct {
	out  string // stdout and stderr together, in the order they were written
	code int
}

func (s *selftest) record(b []byte) {
	s.mu.Lock()
	s.captured = append(s.captured, b)
	s.mu.Unlock()
}

// run starts a command in dir on the throwaway machine. The exit code is -1 if it could
// not be started at all.
func (s *selftest) run(dir, stdin, name string, args ...string) result {
	cmd := exec.CommandContext(s.ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = s.env
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	err := cmd.Run()
	s.record(buf.Bytes())
	code := 0
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		} else {
			code = -1
		}
	}
	return result{out: buf.String(), code: code}
}

// runSplit is run with the two streams kept apart, for a hook whose standard output is a document
// that something else reads (Claude Code reads the guard's decision from it). Both are kept for
// the leak audit.
func (s *selftest) runSplit(dir, stdin, name string, args ...string) (stdout, stderr string, code int) {
	cmd := exec.CommandContext(s.ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = s.env
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	s.record(out.Bytes())
	s.record(errb.Bytes())
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		} else {
			code = -1
		}
	}
	return out.String(), errb.String(), code
}

func (s *selftest) git(dir string, args ...string) result { return s.run(dir, "", "git", args...) }

func (s *selftest) write(path, body string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(body), 0o644)
}

func (s *selftest) repo(name string) (string, error) {
	dir := filepath.Join(s.dir, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	if r := s.git(dir, "init", "-q", "-b", "main"); r.code != 0 {
		return "", fmt.Errorf("git init failed: %s", scrubLine(r.out))
	}
	return dir, nil
}

// leaks says which of the fakes appear in text (the matcher's own encodings count too).
func (s *selftest) leaks(text string) []string {
	var found []string
	for name, v := range map[string]string{"learned": s.learned, "rx1": s.rx1, "rx2": s.rx2, "pull": s.pullKey, "tag": s.tagKey} {
		if v == "" {
			continue
		}
		for _, form := range forms(v) {
			if strings.Contains(text, form) {
				found = append(found, name)
				break
			}
		}
	}
	slices.Sort(found)
	return found
}

func forms(v string) []string {
	return []string{v, base64.StdEncoding.EncodeToString([]byte(v)), base64.RawURLEncoding.EncodeToString([]byte(v))}
}

// scrubLine makes a message one short line that is safe to record.
func scrubLine(s string) string {
	s = strings.Join(strings.Fields(fp.Scrub(s)), " ")
	if r := []rune(s); len(r) > 240 {
		s = string(r[:239]) + "…"
	}
	return s
}

func expectBlocked(what string, r result, s *selftest, mustHave ...string) error {
	if r.code == 0 {
		return fmt.Errorf("%s was not blocked (exit 0)", what)
	}
	if l := s.leaks(r.out); len(l) > 0 {
		return fmt.Errorf("%s printed the secret itself (%s)", what, strings.Join(l, ","))
	}
	for _, m := range mustHave {
		if !strings.Contains(r.out, m) {
			return fmt.Errorf("%s was refused, but the message lacks %q: %s", what, m, scrubLine(r.out))
		}
	}
	return nil
}

func expectOK(what string, r result) error {
	if r.code != 0 {
		return fmt.Errorf("%s failed (exit %d): %s", what, r.code, scrubLine(r.out))
	}
	return nil
}

var allowRE = regexp.MustCompile(`keyguard allow (kg[0-9a-f]{6})`)

// ----- layers -----

func (s *selftest) layerInstall() (string, error) {
	// The real install, engines included: each one is copied into the throwaway machine and
	// pinned, exactly as on the real Mac. Only launchd is not for a test to touch.
	res, err := Install(s.ctx, Options{
		Paths: s.paths, Home: s.home, GitConfig: s.gitconfig, LaunchDir: s.launch, Executable: s.o.Executable,
		NoBootstrap: true,
	})
	if err != nil {
		return "", err
	}
	if !res.Changed() {
		return "", errors.New("install into an empty machine changed nothing")
	}
	if r := s.run(s.dir, "", s.bin, "version"); r.code != 0 {
		return "", fmt.Errorf("the installed binary does not run: %s", scrubLine(r.out))
	}
	for _, h := range HookSpecs {
		out := s.git(s.dir, "config", "--global", "--get", "hook."+h.name+".command")
		if out.code != 0 || !strings.Contains(out.out, s.bin+" hook "+h.event) {
			return "", fmt.Errorf("git does not see the %s hook", h.event)
		}
	}
	for _, j := range jobsFor() {
		if _, err := os.Stat(j.file(s.launch)); err != nil {
			return "", fmt.Errorf("no plist for %s", j.label)
		}
		if p, err := exec.LookPath("plutil"); err == nil {
			if r := s.run(s.dir, "", p, "-lint", j.file(s.launch)); r.code != 0 {
				return "", fmt.Errorf("%s plist is not valid: %s", j.label, scrubLine(r.out))
			}
		}
	}
	cfg, err := LoadConfig(s.paths, s.home)
	if err != nil {
		return "", err
	}
	s.cfg = cfg
	if cfg.EnginePaths()["betterleaks"] == "" {
		return "", errors.New("betterleaks is not installed, so no commit can be scanned")
	}
	// Every engine that was found is a pinned copy in the machine's bin, and what is pinned is
	// what is there: a copy that is not the pin would be refused at its first start.
	pinned := 0
	for name, path := range cfg.EnginePaths() {
		if !inBinDir(s.paths, path) {
			return "", fmt.Errorf("%s was not copied into the data root (%s)", name, path)
		}
		pin, ok := cfg.Pins[name]
		if !ok || pin.SHA256 == "" || pin.Version == "" || filepath.Base(path) != name+"-"+pin.Version {
			return "", fmt.Errorf("%s has no usable pin (%+v)", name, pin)
		}
		e, err := engines.New(name, path, nopFP{}, cfg.EngineOptions(s.paths)...)
		if err != nil {
			return "", err
		}
		if err := engines.CheckPin(e); err != nil {
			return "", fmt.Errorf("%s: %s", name, scrubLine(err.Error()))
		}
		pinned++
	}
	if fi, err := os.Stat(s.paths.Tmp); err != nil || fi.Mode().Perm() != 0o700 {
		return "", errors.New("the engines' scratch directory was not made private")
	}
	if _, err := fp.Open(s.paths.Known); err != nil {
		return "", fmt.Errorf("install made no keyring: %w", err)
	}
	return fmt.Sprintf("%d hooks, %d launchd plists, the binary and rules in place; %d engines copied and pinned", len(HookSpecs), len(jobsFor()), pinned), nil
}

func (s *selftest) layerKnown() (string, error) {
	if err := s.write(filepath.Join(s.home, "dev", "selftest", ".env"), "SELFTEST_API_KEY="+s.learned+"\nGREETING=hello\n"); err != nil {
		return "", err
	}
	r := s.run(s.dir, "", s.bin, "learn", "--no-engine", "--no-gh")
	if err := expectOK("learn", r); err != nil {
		return "", err
	}
	if l := s.leaks(r.out); len(l) > 0 {
		return "", errors.New("learn printed the secret itself")
	}
	if !strings.Contains(r.out, "SELFTEST_API_KEY") {
		return "", fmt.Errorf("learn did not find the planted key: %s", scrubLine(r.out))
	}
	kr, err := openKeyringAt(s.paths)
	if err != nil {
		return "", err
	}
	s.kr = kr

	probe := filepath.Join(s.dir, "probe.txt")
	cases := []struct {
		what, body string
		want       int
	}{
		{"the raw value", "key = " + s.learned + "\n", 1},
		{"its base64", "auth: " + base64.StdEncoding.EncodeToString([]byte(s.learned)) + "\n", 1},
		{"its base64url", "t=" + base64.RawURLEncoding.EncodeToString([]byte(s.learned)) + "\n", 1},
		{"text with no secret", "nothing to see here, " + s.learned[:len(s.learned)-1] + "\n", 0},
	}
	for _, c := range cases {
		if err := s.write(probe, c.body); err != nil {
			return "", err
		}
		r := s.run(s.dir, "", s.bin, "match", probe)
		if r.code != c.want {
			return "", fmt.Errorf("match on %s exited %d, want %d: %s", c.what, r.code, c.want, scrubLine(r.out))
		}
		if l := s.leaks(r.out); len(l) > 0 {
			return "", errors.New("match printed the secret itself")
		}
	}
	return "learned 1 secret; found in raw, base64 and base64url; nothing else matched", nil
}

// openKeyringAt reads the salt learn made; the selftest never makes one, as no hook may.
func openKeyringAt(p core.Paths) (*fp.Keyring, error) { return fp.Open(p.Known) }

func (s *selftest) layerCommit() (string, error) {
	dir, err := s.repo("commit-gate")
	if err != nil {
		return "", err
	}
	if err := s.write(filepath.Join(dir, "README.md"), "hello\n"); err != nil {
		return "", err
	}
	s.git(dir, "add", "-A")
	if err := expectOK("a clean commit", s.git(dir, "commit", "-q", "-m", "clean")); err != nil {
		return "", err
	}

	if err := s.write(filepath.Join(dir, "config.py"), "TOKEN = \""+s.rx1+"\"\n"); err != nil {
		return "", err
	}
	s.git(dir, "add", "config.py")
	r := s.git(dir, "commit", "-q", "-m", "oops")
	if err := expectBlocked("a commit with a token in it", r, s, "commit blocked", "ghp_…"); err != nil {
		return "", err
	}
	m := allowRE.FindStringSubmatch(r.out)
	if m == nil {
		return "", errors.New("the block message does not say how to allow it")
	}
	s.idOfRx1 = m[1]

	s.git(dir, "reset", "-q")
	if err := s.write(filepath.Join(dir, ".env"), "X=1\n"); err != nil {
		return "", err
	}
	s.git(dir, "add", "-f", ".env")
	if err := expectBlocked("a staged .env", s.git(dir, "commit", "-q", "-m", "env"), s, ".env"); err != nil {
		return "", err
	}

	// `allow` turns a block into a pass, for good, by the id the message printed.
	s.git(dir, "reset", "-q")
	s.git(dir, "add", "config.py")
	if err := expectOK("allow", s.run(s.dir, "", s.bin, "allow", s.idOfRx1, "--reason", "selftest")); err != nil {
		return "", err
	}
	if err := expectOK("the same commit after allow", s.git(dir, "commit", "-q", "-m", "allowed")); err != nil {
		return "", err
	}
	return "blocked a token and a .env with only their shape printed; `allow` let the token through", nil
}

func (s *selftest) layerRef() (string, error) {
	dir, err := s.repo("ref-gate")
	if err != nil {
		return "", err
	}
	if err := s.write(filepath.Join(dir, "README.md"), "hello\n"); err != nil {
		return "", err
	}
	s.git(dir, "add", "-A")
	if err := expectOK("a clean commit", s.git(dir, "commit", "-q", "-m", "clean")); err != nil {
		return "", err
	}
	head := strings.TrimSpace(s.git(dir, "rev-parse", "HEAD").out)

	if err := s.write(filepath.Join(dir, "deploy.sh"), "export KEY="+s.learned+"\n"); err != nil {
		return "", err
	}
	s.git(dir, "add", "deploy.sh")
	// --no-verify skips the pre-commit hook; the reference-transaction hook has no such switch.
	r := s.git(dir, "commit", "-q", "--no-verify", "-m", "sneaky")
	if err := expectBlocked("a --no-verify commit of a learned key", r, s); err != nil {
		return "", err
	}
	if after := strings.TrimSpace(s.git(dir, "rev-parse", "HEAD").out); after != head {
		return "", errors.New("the commit exists although the ref hook refused it")
	}
	s.git(dir, "reset", "-q")
	if err := s.write(filepath.Join(dir, "notes.txt"), "just notes\n"); err != nil {
		return "", err
	}
	s.git(dir, "add", "notes.txt")
	if err := expectOK("a clean --no-verify commit", s.git(dir, "commit", "-q", "--no-verify", "-m", "notes")); err != nil {
		return "", err
	}
	return "a --no-verify commit of a learned key was aborted at the ref level; a clean one passed", nil
}

func (s *selftest) layerPush() (string, error) {
	dir, err := s.repo("push-gate")
	if err != nil {
		return "", err
	}
	remote := filepath.Join(s.dir, "remote.git")
	if r := s.git(s.dir, "init", "-q", "--bare", "-b", "main", remote); r.code != 0 {
		return "", fmt.Errorf("git init --bare: %s", scrubLine(r.out))
	}
	s.git(dir, "remote", "add", "origin", remote)
	if err := s.write(filepath.Join(dir, "README.md"), "hello\n"); err != nil {
		return "", err
	}
	s.git(dir, "add", "-A")
	if err := expectOK("a clean commit", s.git(dir, "commit", "-q", "-m", "clean")); err != nil {
		return "", err
	}
	if err := expectOK("a clean push", s.git(dir, "push", "-q", "origin", "main")); err != nil {
		return "", err
	}
	if err := s.write(filepath.Join(dir, "settings.py"), "API = \""+s.rx2+"\"\n"); err != nil {
		return "", err
	}
	s.git(dir, "add", "settings.py")
	// Only a scanner knows rx2 (it is not learned), so the commit gets through with --no-verify;
	// the push gate is the layer that has to catch it.
	if err := expectOK("a --no-verify commit of a token", s.git(dir, "commit", "-q", "--no-verify", "-m", "oops")); err != nil {
		return "", err
	}
	if err := expectBlocked("a push of a token", s.git(dir, "push", "origin", "main"), s); err != nil {
		return "", err
	}
	refs := strings.Fields(s.git(remote, "rev-list", "--all").out)
	if len(refs) != 1 {
		return "", fmt.Errorf("the remote has %d commits after the refused push, want 1", len(refs))
	}
	return "a clean push went through; a push carrying a token was refused and the remote stayed clean", nil
}

func (s *selftest) layerGuard() (string, error) {
	call := func(command string) result {
		b, _ := json.Marshal(map[string]any{"tool_name": "Bash", "tool_input": map[string]string{"command": command}, "cwd": s.dir})
		return s.run(s.dir, string(b), s.bin, "guard", "claude")
	}
	// The last two are the way an agent would open a gate it cannot get past: let its own
	// finding through, or take keyguard out. Both are the user's to run.
	for _, cmd := range []string{
		"git commit --no-verify -m x", "git -c core.hooksPath=/dev/null commit -m x", "git push --no-verify",
		"keyguard allow kg1a2b3c --reason fixture", "keyguard uninstall",
	} {
		if r := call(cmd); r.code != 2 || strings.TrimSpace(r.out) == "" {
			return "", fmt.Errorf("the guard let %q through (exit %d)", cmd, r.code)
		}
	}
	for _, cmd := range []string{"git status", "git commit -m ok", "ls -la", "keyguard allow --list", "keyguard doctor"} {
		if r := call(cmd); r.code != 0 {
			return "", fmt.Errorf("the guard blocked %q (exit %d): %s", cmd, r.code, scrubLine(r.out))
		}
	}
	if err := s.guardTools(); err != nil {
		return "", err
	}
	return "blocked --no-verify, a hooksPath override, `allow` and `uninstall`; refused a learned key in Write, Edit, MultiEdit and an MCP call, and an allow comment; allowed ordinary git and reading", nil
}

// guardTools is STEAL P0-14 on the installed binary: a tool other than Bash carrying a learned
// key is denied in the shape Claude Code reads (a JSON decision on standard output, exit 2, the
// same reason on standard error), with a reason made of shapes only; and a clean call is left
// alone without a word. The event is the PreToolUse payload Claude Code sends.
func (s *selftest) guardTools() error {
	send := func(tool string, input map[string]any) (stdout, stderr string, code int) {
		b, _ := json.Marshal(map[string]any{
			"session_id": "selftest", "transcript_path": "/dev/null", "cwd": s.dir, "permission_mode": "default",
			"hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": input, "tool_use_id": "toolu_selftest",
		})
		return s.runSplit(s.dir, string(b), s.bin, "guard", "claude")
	}
	denied := func(what, tool string, input map[string]any) error {
		stdout, stderr, code := send(tool, input)
		if code != 2 {
			return fmt.Errorf("%s was not denied (exit %d)", what, code)
		}
		var doc struct {
			Out struct {
				Event    string `json:"hookEventName"`
				Decision string `json:"permissionDecision"`
				Reason   string `json:"permissionDecisionReason"`
			} `json:"hookSpecificOutput"`
		}
		if err := json.Unmarshal([]byte(stdout), &doc); err != nil || doc.Out.Decision != "deny" || doc.Out.Event != "PreToolUse" || doc.Out.Reason == "" {
			return fmt.Errorf("%s: the guard's answer is not the decision Claude Code reads: %s", what, scrubLine(stdout))
		}
		if strings.TrimSpace(stderr) == "" {
			return fmt.Errorf("%s: exit 2 with nothing on standard error", what)
		}
		if l := s.leaks(stdout + stderr); len(l) > 0 {
			return fmt.Errorf("%s: the denial printed the secret itself", what)
		}
		return nil
	}
	key := "API_KEY=" + s.learned + "\n"
	for _, c := range []struct {
		what, tool string
		input      map[string]any
	}{
		{"a Write of a learned key", "Write", map[string]any{"file_path": filepath.Join(s.dir, "notes.env"), "content": key}},
		{"an Edit adding a learned key", "Edit", map[string]any{"file_path": filepath.Join(s.dir, "app.py"), "old_string": "KEY = None", "new_string": "KEY = \"" + s.learned + "\""}},
		{"a MultiEdit adding a learned key", "MultiEdit", map[string]any{"file_path": filepath.Join(s.dir, "app.py"), "edits": []any{
			map[string]any{"old_string": "a", "new_string": "b"}, map[string]any{"old_string": "c", "new_string": "k = " + s.learned}}}},
		{"an MCP call carrying a learned key", "mcp__selftest__create_issue", map[string]any{"title": "x", "body": map[string]any{"text": "token " + s.learned}}},
		{"a Write with an allow comment", "Write", map[string]any{"file_path": filepath.Join(s.dir, "docs.md"), "content": "example # betterleaks:allow\n"}},
		{"a Write of a scanner ignore file", "Write", map[string]any{"file_path": filepath.Join(s.dir, ".betterleaksignore"), "content": "anything\n"}},
	} {
		if err := denied(c.what, c.tool, c.input); err != nil {
			return err
		}
	}
	for _, c := range []struct {
		what, tool string
		input      map[string]any
	}{
		{"a clean Write", "Write", map[string]any{"file_path": filepath.Join(s.dir, "notes.md"), "content": "nothing secret here\n"}},
		{"a clean Edit", "Edit", map[string]any{"file_path": filepath.Join(s.dir, "notes.md"), "old_string": "a", "new_string": "b"}},
		{"a Read", "Read", map[string]any{"file_path": filepath.Join(s.dir, "notes.md")}},
	} {
		stdout, _, code := send(c.tool, c.input)
		if code != 0 || strings.TrimSpace(stdout) != "" {
			return fmt.Errorf("%s was not left alone (exit %d, %s)", c.what, code, scrubLine(stdout))
		}
	}
	return nil
}

var kgIDRE = regexp.MustCompile(`kg[0-9a-f]{6}`)

func (s *selftest) layerPublish() (string, error) {
	dirty := filepath.Join(s.dir, "push-gate")
	r := s.run(s.dir, "", s.bin, "publish-check", "--no-verify", "--json", dirty)
	if r.code != 1 {
		return "", fmt.Errorf("publish-check on a repo with a token exited %d, want 1: %s", r.code, scrubLine(r.out))
	}
	if l := s.leaks(r.out); len(l) > 0 {
		return "", errors.New("publish-check printed the secret itself")
	}
	var doc struct {
		Clean    bool `json:"clean"`
		Blocking []struct {
			ID, Shape string
		} `json:"blocking"`
	}
	if err := json.Unmarshal([]byte(r.out), &doc); err != nil || doc.Clean || len(doc.Blocking) == 0 {
		return "", fmt.Errorf("publish-check's report does not list the token: %s", scrubLine(r.out))
	}
	if !strings.HasPrefix(doc.Blocking[0].Shape, rxPrefix) {
		return "", fmt.Errorf("the listed shape is %q", doc.Blocking[0].Shape)
	}

	clean, err := s.repo("publish-clean")
	if err != nil {
		return "", err
	}
	if err := s.write(filepath.Join(clean, "README.md"), "nothing here\n"); err != nil {
		return "", err
	}
	s.git(clean, "add", "-A")
	if err := expectOK("a clean commit", s.git(clean, "commit", "-q", "-m", "clean")); err != nil {
		return "", err
	}
	if err := expectOK("publish-check on a clean repo", s.run(s.dir, "", s.bin, "publish-check", "--no-verify", clean)); err != nil {
		return "", err
	}
	return "a repo with a token is refused (shape listed); a clean one passes", nil
}

// layerEngines starts every configured engine on a directory holding a fake, and then on a
// bare mirror whose only copies of two other fakes are out of every branch's reach. Only
// betterleaks and trufflehog are held to finding them: the others decide for themselves what is
// a secret. It also proves what the engines must not do on the way: replace themselves, leave a
// titus datastore, leave their scratch directory behind.
func (s *selftest) layerEngines() (detail string, err error) {
	if s.kr == nil {
		return "", errors.New("skipped: the learned store was not set up")
	}
	defer s.inMachine()()
	dir := filepath.Join(s.dir, "engine-dir")
	if err := s.write(filepath.Join(dir, "app.py"), "GITHUB_TOKEN = \""+s.rx1+"\"\n"); err != nil {
		return "", err
	}
	mirror, err := s.hiddenKeys()
	if err != nil {
		return "", err
	}
	before := map[string]string{}
	var parts []string
	for _, name := range engines.Names {
		path := s.cfg.EnginePaths()[name]
		if path == "" || !isExecutable(path) {
			parts = append(parts, name+" absent")
			continue
		}
		before[name], _ = hashFile(path)
		e, err := engines.New(name, path, s.kr, s.cfg.EngineOptions(s.paths)...)
		if err != nil {
			return "", err
		}
		var mu sync.Mutex
		hits, saw := 0, false
		err = e.ScanDir(s.ctx, dir, core.ScanOpts{}, func(h core.Hit) {
			mu.Lock()
			hits++
			saw = saw || h.FP == s.kr.FP(s.rx1)
			mu.Unlock()
		})
		switch {
		case errors.Is(err, core.ErrUnsupported):
			parts = append(parts, name+" n/a")
			continue
		case err != nil:
			return "", fmt.Errorf("%s failed: %s", name, scrubLine(err.Error()))
		case name == "betterleaks" && !saw:
			return "", errors.New("betterleaks did not find the planted token")
		}
		parts = append(parts, fmt.Sprintf("%s %d", name, hits))

		// The mirror: reachable by no branch, only by refs/pull/N/head and a tag (STEAL P0-02).
		if name != "betterleaks" && name != "trufflehog" {
			continue
		}
		found := map[string]bool{}
		err = e.ScanGit(s.ctx, mirror, core.Range{All: true}, core.ScanOpts{}, func(h core.Hit) {
			mu.Lock()
			defer mu.Unlock()
			for _, v := range []string{s.pullKey, s.tagKey} {
				if h.FP == s.kr.FP(v) {
					found[v] = true
				}
			}
		})
		if err != nil {
			return "", fmt.Errorf("%s failed on a bare mirror: %s", name, scrubLine(err.Error()))
		}
		if !found[s.pullKey] || !found[s.tagKey] {
			return "", fmt.Errorf("%s on a bare mirror named %s found the pull-request-only key: %v, the tag-only key: %v", name, filepath.Base(mirror), found[s.pullKey], found[s.tagKey])
		}
	}

	// An engine is the binary that was pinned when it is done, and has changed nothing around it.
	for name, sum := range before {
		path := s.cfg.EnginePaths()[name]
		if after, _ := hashFile(path); after != sum {
			return "", fmt.Errorf("%s is not the same binary after it ran", name)
		}
		for _, lock := range []string{filepath.Join(filepath.Dir(path), name+"-updates.lock")} {
			if _, err := os.Stat(lock); err == nil {
				return "", fmt.Errorf("%s left %s: it tried to update itself", name, filepath.Base(lock))
			}
		}
	}
	if err := s.noDatastore(); err != nil {
		return "", err
	}
	if left, _ := os.ReadDir(s.paths.Tmp); len(left) > 0 {
		return "", fmt.Errorf("%d engine scratch director(ies) left behind in the data root's tmp", len(left))
	}
	return "hits on the planted token: " + strings.Join(parts, ", ") + "; the pull-ref-only and tag-only keys found in a bare mirror; no engine changed, updated or left a datastore", nil
}

// hiddenKeys makes a bare repository, in a directory whose name ends in .git as a mirror's does,
// holding one key that only refs/pull/1/head reaches and one that only a tag reaches. A scanner
// that follows branches finds neither; trufflehog finds them only with the two flags that make it
// read the mirror in place (STEAL P0-02).
func (s *selftest) hiddenKeys() (string, error) {
	var err error
	if s.pullKey, err = fake(rxPrefix, 36); err != nil {
		return "", err
	}
	if s.tagKey, err = fake(rxPrefix, 36); err != nil {
		return "", err
	}
	work, err := s.repo("hidden-keys")
	if err != nil {
		return "", err
	}
	step := func(args ...string) error {
		off := []string{"-c", "hook.keyguard-precommit.enabled=false", "-c", "hook.keyguard-prepush.enabled=false",
			"-c", "hook.keyguard-reftx.enabled=false", "-c", "hook.keyguard-commitmsg.enabled=false"}
		if r := s.git(work, append(off, args...)...); r.code != 0 {
			return fmt.Errorf("building the hidden-keys fixture (git %s): %s", args[0], scrubLine(r.out))
		}
		return nil
	}
	if err := s.write(filepath.Join(work, "README.md"), "a mirror\n"); err != nil {
		return "", err
	}
	if err := errors.Join(step("add", "-A"), step("commit", "-q", "-m", "init")); err != nil {
		return "", err
	}
	for _, c := range []struct{ file, key, ref string }{
		{"pull.py", s.pullKey, "refs/pull/1/head"},
		{"tagged.py", s.tagKey, "refs/tags/v0.0.1"},
	} {
		if err := errors.Join(step("checkout", "-q", "-b", "tmp"), s.write(filepath.Join(work, c.file), "T = \""+c.key+"\"\n")); err != nil {
			return "", err
		}
		if err := errors.Join(step("add", "-A"), step("commit", "-q", "-m", c.file), step("update-ref", c.ref, "HEAD"),
			step("checkout", "-q", "main"), step("branch", "-q", "-D", "tmp")); err != nil {
			return "", err
		}
	}
	mirror := filepath.Join(s.dir, "hidden-mirror.git")
	if r := s.git(s.dir, "clone", "-q", "--mirror", work, mirror); r.code != 0 {
		return "", fmt.Errorf("git clone --mirror: %s", scrubLine(r.out))
	}
	return mirror, nil
}

// noDatastore is STEAL P0-06 checked where it would show: titus keeps every match in a SQLite
// file unless it is told not to, and the file holds the secrets in the clear. None may exist in
// the machine's data root, in the engines' scratch directory or in the directory a scan ran from.
func (s *selftest) noDatastore() error {
	skip := filepath.Join(s.paths.Root, "cache", "mirrors")
	for _, root := range []string{s.paths.Root, s.dir} {
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			switch {
			case err != nil:
				return nil
			case d.IsDir() && (p == skip || d.Name() == ".git" || strings.HasSuffix(d.Name(), ".git")):
				return fs.SkipDir
			case d.IsDir():
				return nil
			}
			if n := d.Name(); n == "datastore.db" || strings.HasSuffix(n, ".ds") {
				return fmt.Errorf("a titus datastore, which keeps findings in the clear, was left at %s", rel(s.dir, p))
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// ----- the sweep, in process -----

type localInventory struct{ src core.Source }

func (l localInventory) List(context.Context) ([]core.Source, error) {
	return []core.Source{l.src}, nil
}
func (l localInventory) Changed(_ context.Context, prev map[string]core.Source) ([]core.Source, []core.Event, error) {
	if p, ok := prev[l.src.ID]; ok && p.PushedAt == l.src.PushedAt && p.Visibility == l.src.Visibility {
		return nil, nil, nil
	}
	return []core.Source{l.src}, nil, nil
}

type captureNotifier struct {
	mu  sync.Mutex
	got []string
	sev []core.Severity
}

func (n *captureNotifier) Notify(title, body string, sev core.Severity) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.got = append(n.got, title+"\n"+body)
	n.sev = append(n.sev, sev)
	return nil
}

// pollOutcome is shared by the poll and report layers: one sweep, looked at twice.
type pollOutcome struct {
	once     sync.Once
	err      error
	stats    core.RunStats
	idle     core.RunStats
	notifier *captureNotifier
	store    *db.Store
	report   string
}

func (s *selftest) sweepOnce(po *pollOutcome) error {
	po.once.Do(func() {
		defer s.inMachine()()
		po.err = s.doSweep(po)
	})
	return po.err
}

// inMachine points this process's own environment at the throwaway machine, for the layers
// that run in process (the engines, the sweep and the git they start). The returned function
// puts it back. The process is a CLI run: nothing else in it reads the environment meanwhile.
func (s *selftest) inMachine() (restore func()) {
	type old struct {
		key, val string
		set      bool
	}
	var saved []old
	setenv := func(k, v string, unset bool) {
		prev, was := os.LookupEnv(k)
		saved = append(saved, old{k, prev, was})
		if unset {
			os.Unsetenv(k)
		} else {
			os.Setenv(k, v)
		}
	}
	setenv("HOME", s.home, false)
	setenv("GIT_CONFIG_GLOBAL", s.gitconfig, false)
	setenv("GIT_CONFIG_NOSYSTEM", "1", false)
	setenv("KEYGUARD_HOME", "", true)
	for _, k := range []string{"GH_TOKEN", "GITHUB_TOKEN", "XDG_CONFIG_HOME"} {
		setenv(k, "", true)
	}
	return func() {
		for i := len(saved) - 1; i >= 0; i-- {
			if o := saved[i]; o.set {
				os.Setenv(o.key, o.val)
			} else {
				os.Unsetenv(o.key)
			}
		}
	}
}

func (s *selftest) doSweep(po *pollOutcome) error {
	origin, err := s.repo("leaky")
	if err != nil {
		return err
	}
	// The repo being "mirrored" holds a learned key and a token on purpose, so the gates that
	// are installed on this machine would refuse to let it be made. They are switched off for
	// building it, which is also what the mirror does when it fetches (PLAN.md invariant 6).
	step := func(args ...string) error {
		off := []string{"-c", "hook.keyguard-precommit.enabled=false", "-c", "hook.keyguard-commitmsg.enabled=false",
			"-c", "hook.keyguard-prepush.enabled=false", "-c", "hook.keyguard-reftx.enabled=false"}
		if r := s.git(origin, append(off, args...)...); r.code != 0 {
			return fmt.Errorf("building the sweep fixture (git %s): %s", args[0], scrubLine(r.out))
		}
		return nil
	}
	if err := s.write(filepath.Join(origin, "README.md"), "a public repo\n"); err != nil {
		return err
	}
	if err := errors.Join(step("add", "-A"), step("commit", "-q", "-m", "init")); err != nil {
		return err
	}
	if err := s.write(filepath.Join(origin, "deploy.env"), "SELFTEST_API_KEY="+s.learned+"\n"); err != nil {
		return err
	}
	if err := errors.Join(step("add", "-A"), step("commit", "-q", "-m", "add env")); err != nil {
		return err
	}
	// A token that only a pull request ref reaches, as GitHub keeps after a branch is deleted.
	if err := step("checkout", "-q", "-b", "pr"); err != nil {
		return err
	}
	if err := s.write(filepath.Join(origin, "pr.py"), "T = \""+s.rx1+"\"\n"); err != nil {
		return err
	}
	if err := errors.Join(step("add", "-A"), step("commit", "-q", "-m", "pr"), step("update-ref", "refs/pull/1/head", "HEAD"),
		step("checkout", "-q", "main"), step("branch", "-q", "-D", "pr")); err != nil {
		return err
	}

	src := core.Source{
		ID: "github.com/selftest/leaky", Kind: "repo", Owner: "selftest", Name: "leaky", Account: "selftest",
		CloneURL: "file://" + origin, Visibility: core.Public, PushedAt: "2026-01-01T00:00:00Z", SizeKB: 1,
	}
	mir, err := mirror.New(mirror.Config{Root: s.paths.Mirrors, AllowLocal: true})
	if err != nil {
		return err
	}
	var engs []core.Engine
	for _, name := range s.cfg.Tier(TierPoll) {
		if path := s.cfg.EnginePaths()[name]; path != "" && isExecutable(path) {
			e, err := engines.New(name, path, s.kr, s.cfg.EngineOptions(s.paths)...)
			if err != nil {
				return err
			}
			engs = append(engs, e)
		}
	}
	m, err := known.LoadMatcher([]string{s.paths.Root})
	if err != nil {
		return fmt.Errorf("loading the learned store: %w", err)
	}
	st, err := db.Open(s.paths)
	if err != nil {
		return err
	}
	po.store = st
	po.notifier = &captureNotifier{}
	rep := report.New(s.paths.Report)
	r, err := sweep.New(sweep.Config{
		Paths: s.paths, Inventory: localInventory{src}, Mirror: mir, Engines: engs, Known: m, Store: st,
		Triage:   triage.New(triage.WithStoreEvidence(st), triage.WithFingerprinter(s.kr)),
		Reporter: rep, Notifier: po.notifier, Jobs: 2, NoVerify: true,
	})
	if err != nil {
		return err
	}
	if po.stats, err = r.Poll(s.ctx); err != nil {
		return fmt.Errorf("poll: %w (%s)", err, strings.Join(po.stats.Notes, "; "))
	}
	if po.idle, err = r.Poll(s.ctx); err != nil {
		return fmt.Errorf("second poll: %w", err)
	}
	po.report = s.paths.Report
	return nil
}

func (s *selftest) layerPoll() (string, error) {
	if s.kr == nil {
		return "", errors.New("the learned store was not set up (see the learned secrets layer)")
	}
	po := &s.po
	if err := s.sweepOnce(po); err != nil {
		return "", err
	}
	if po.stats.Scanned != 1 {
		return "", fmt.Errorf("the first poll scanned %d sources, want 1: %v", po.stats.Scanned, po.stats.Notes)
	}
	if po.idle.Scanned != 0 || po.idle.Sources != 0 {
		return "", fmt.Errorf("an idle second poll scanned %d sources", po.idle.Scanned)
	}
	learned, ok := po.store.Get(s.kr.FP(s.learned))
	if !ok || learned.Known == "" {
		return "", errors.New("the learned key in a public repo was not found by the known-secret pass")
	}
	if learned.Severity != core.Critical || !learned.Exposed() {
		return "", fmt.Errorf("a learned key in a public repo is %s, want critical", learned.Severity)
	}
	pr, ok := po.store.Get(s.kr.FP(s.rx1))
	if !ok {
		return "", errors.New("the token that only refs/pull/1/head reaches was not found")
	}
	_ = pr
	po.notifier.mu.Lock()
	defer po.notifier.mu.Unlock()
	crit := 0
	for i, n := range po.notifier.got {
		if po.notifier.sev[i] == core.Critical {
			crit++
		}
		if l := s.leaks(n); len(l) > 0 {
			return "", errors.New("an alert carried the secret itself")
		}
	}
	if crit == 0 {
		return "", errors.New("no critical alert was sent for a learned key in a public repo")
	}
	return fmt.Sprintf("mirrored a repo, found a learned key and a pull-ref-only token, sent %d critical alert(s); an idle poll did nothing", crit), nil
}

func (s *selftest) layerReport() (string, error) {
	po := &s.po
	if err := s.sweepOnce(po); err != nil {
		return "", err
	}
	b, err := os.ReadFile(s.paths.Report)
	if err != nil {
		return "", fmt.Errorf("no report was written: %w", err)
	}
	if l := s.leaks(string(b)); len(l) > 0 {
		return "", errors.New("the report carries the secret itself")
	}
	learned, _ := po.store.Get(s.kr.FP(s.learned))
	if !strings.Contains(string(b), learned.ID) {
		return "", fmt.Errorf("the report does not list the learned key (%s)", learned.ID)
	}
	if !strings.Contains(string(b), "Content-Security-Policy") {
		return "", errors.New("the report has no Content-Security-Policy")
	}
	return fmt.Sprintf("report written (%d bytes), lists the key by id, no script allowed", len(b)), nil
}

// layerAudit is invariant 1 checked on this run: no byte of any fake, raw or base64, is in
// anything keyguard wrote or printed. The mirrors are excluded because they are git object
// stores of repos that hold the fake by construction.
func (s *selftest) layerAudit() (string, error) {
	var forbidden []string
	for _, v := range []string{s.learned, s.rx1, s.rx2, s.pullKey, s.tagKey} {
		if v != "" {
			forbidden = append(forbidden, forms(v)...)
		}
	}
	check := func(label string, b []byte) error {
		for _, f := range forbidden {
			if bytes.Contains(b, []byte(f)) {
				return fmt.Errorf("%s holds a planted secret", label)
			}
		}
		return nil
	}
	files := 0
	// The mirrors are git stores of repos that hold the fakes by construction, and bin holds the
	// engines' own binaries, which keyguard copied and did not write findings into.
	skip, bins := filepath.Join(s.paths.Root, "cache"), s.paths.BinDir
	for _, root := range []string{s.paths.Root, s.launch} {
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			switch {
			case err != nil:
				return nil
			case d.IsDir() && (p == skip || p == bins):
				return fs.SkipDir
			case d.IsDir():
				return nil
			}
			if n := d.Name(); n == "datastore.db" || strings.HasSuffix(n, ".ds") {
				return fmt.Errorf("an engine left %s behind: it keeps findings in the clear", n)
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return nil
			}
			files++
			return check(rel(s.dir, p), b)
		})
		if err != nil {
			return "", err
		}
	}
	for _, p := range []string{s.gitconfig} {
		b, _ := os.ReadFile(p)
		if err := check("git config", b); err != nil {
			return "", err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, b := range s.captured {
		if err := check(fmt.Sprintf("the output of command %d", i+1), b); err != nil {
			return "", err
		}
	}
	return fmt.Sprintf("%d files and %d command outputs searched in 3 encodings of 5 fakes: none found", files, len(s.captured)), nil
}

func (s *selftest) layerUninstall() (string, error) {
	res, err := Uninstall(s.ctx, Options{
		Paths: s.paths, Home: s.home, GitConfig: s.gitconfig, LaunchDir: s.launch,
	})
	if err != nil {
		return "", err
	}
	if !res.Changed() {
		return "", errors.New("uninstall changed nothing")
	}
	got, err := os.ReadFile(s.gitconfig)
	if err != nil || !bytes.Equal(got, s.pristineConfig) {
		return "", errors.New("the global git config was not put back byte for byte")
	}
	for _, p := range []string{s.bin, ManifestPath(s.paths)} {
		if _, err := os.Stat(p); err == nil {
			return "", fmt.Errorf("%s survived the uninstall", rel(s.dir, p))
		}
	}
	for name, path := range s.cfg.EnginePaths() {
		if _, err := os.Stat(path); err == nil && inBinDir(s.paths, path) {
			return "", fmt.Errorf("the pinned copy of %s survived the uninstall", name)
		}
	}
	return "the git config is back byte for byte; the binary, the pinned engines and the install record moved aside", nil
}
