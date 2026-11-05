package install

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"keyguard/internal/core"
	"keyguard/internal/db"
	"keyguard/internal/fp"
	"keyguard/rules"
)

// Runner runs an external command and returns its standard output. An error carries the
// command's own complaint, so a message can say why launchctl or git refused.
type Runner func(ctx context.Context, name string, args ...string) ([]byte, error)

// ExecRunner is the Runner that really runs things.
func ExecRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return out, fmt.Errorf("%w: %s", err, firstLine(msg))
		}
	}
	return out, err
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return line
}

// Options says where Install and Uninstall work. The zero value of everything but Paths is
// the real machine: ~/.gitconfig (or GIT_CONFIG_GLOBAL), ~/Library/LaunchAgents, this
// executable. Tests and selftest point every one of them at a temp dir.
type Options struct {
	Paths       core.Paths
	Home        string // "" = the user's home
	GitConfig   string // "" = $GIT_CONFIG_GLOBAL, else <Home>/.gitconfig
	LaunchDir   string // "" = <Home>/Library/LaunchAgents
	Executable  string // the binary to install; "" = this process's
	Git         string // "" = git on PATH
	NoLaunchd   bool   // hooks, binary, rules and config only
	NoBootstrap bool   // write the launchd plists but do not load them
	DryRun      bool   // work out and report the changes, write nothing
	UID         int    // 0 = this user
	Run         Runner // nil = ExecRunner
	Now         func() time.Time
	// Pin records the engines' versions and hashes into config.json; nil is PinEngines, which
	// starts every engine once and reads their binaries (about a second). Tests that are not
	// about pins swap in a stub.
	Pin func(Config) map[string]Pin
	// InPlace pins each engine where it is found instead of copying it to <root>/bin. Tests that
	// are not about copies set it: a suite that copied a 170 MB trufflehog for every install
	// would take minutes.
	InPlace bool
	// NoPrewarm leaves the titus rule cache to its first use (2.7 s once). Same reason.
	NoPrewarm bool
}

func (o Options) resolve() (Options, error) {
	if o.Paths.Root == "" || o.Paths.State == "" {
		return o, errors.New("install: Paths is incomplete; build it with core.PathsAt")
	}
	if o.Home == "" {
		h, err := os.UserHomeDir()
		if err != nil {
			return o, err
		}
		o.Home = h
	}
	if o.GitConfig == "" {
		o.GitConfig = os.Getenv("GIT_CONFIG_GLOBAL")
	}
	if o.GitConfig == "" {
		o.GitConfig = filepath.Join(o.Home, ".gitconfig")
	}
	if o.GitConfig == os.DevNull {
		return o, errors.New("install: GIT_CONFIG_GLOBAL is /dev/null, so there is no global git config to put the hooks in")
	}
	if o.LaunchDir == "" {
		o.LaunchDir = filepath.Join(o.Home, "Library", "LaunchAgents")
	}
	if o.Executable == "" {
		exe, err := os.Executable()
		if err != nil {
			return o, err
		}
		o.Executable = exe
	}
	if o.Git == "" {
		o.Git = "git"
	}
	if o.UID == 0 {
		o.UID = os.Getuid()
	}
	if o.Run == nil {
		o.Run = ExecRunner
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return o, nil
}

// Action is one thing Install or Uninstall did, or would do under DryRun.
type Action struct {
	Step   string `json:"step"`   // binary|rules|config|git|launchd|manifest
	Target string `json:"target"` // the file, key or label touched
	Change string `json:"change"` // created|updated|unchanged|removed|restored|moved|skipped
	Detail string `json:"detail,omitempty"`
}

// Result is what Install or Uninstall did.
type Result struct {
	Actions  []Action `json:"actions"`
	Warnings []string `json:"warnings,omitempty"`
	// Claude is the `!` line the user runs to register the agent guard (Install) or to take it
	// out again (Uninstall). Snippet is what that line adds to their settings.json, for them to
	// read first; nothing here writes that file.
	Claude  string `json:"claude"`
	Snippet string `json:"claude_snippet,omitempty"`
}

// Changed reports whether anything was, or under DryRun would be, written.
func (r *Result) Changed() bool {
	for _, a := range r.Actions {
		switch a.Change {
		case "created", "updated", "removed", "restored", "moved":
			return true
		}
	}
	return false
}

// Manifest is state/install.json: what Install did, so Uninstall can undo exactly that.
type Manifest struct {
	Version     int        `json:"version"`
	InstalledAt string     `json:"installed_at"`
	UpdatedAt   string     `json:"updated_at"`
	Git         GitRecord  `json:"git"`
	Binary      FileRecord `json:"binary"`
	Rules       FileRecord `json:"rules"`
	// Engines are the pinned copies Install put in <root>/bin, by engine name.
	Engines map[string]FileRecord `json:"engines,omitempty"`
	Launchd LaunchdRecord         `json:"launchd"`
}

// GitRecord is the global git config file as it was before the first install and as
// Install left it.
type GitRecord struct {
	File         string   `json:"file"`
	Existed      bool     `json:"existed"`                 // the file was there before the first install
	OriginalSHA  string   `json:"original_sha256"`         // of its bytes then
	OriginalCopy string   `json:"original_copy,omitempty"` // a verbatim copy, kept so Uninstall can put the bytes back
	AfterSHA     string   `json:"after_sha256"`            // of its bytes right after the last install
	Edited       bool     `json:"edited"`                  // something else changed the file between two installs
	Keys         []GitKey `json:"keys"`
}

// GitKey is one config key Install set, and what it held before.
type GitKey struct {
	Key      string   `json:"key"`
	Value    string   `json:"value"`
	Previous []string `json:"previous,omitempty"` // values the key held before Install (usually none)
}

// FileRecord is a file Install wrote.
type FileRecord struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// LaunchdRecord is the agents Install wrote.
type LaunchdRecord struct {
	Dir  string      `json:"dir"`
	Jobs []JobRecord `json:"jobs"`
}

// JobRecord is one launchd agent: its plist and whether Install loaded it.
type JobRecord struct {
	Label        string `json:"label"`
	Plist        string `json:"plist"`
	SHA256       string `json:"sha256"`
	Bootstrapped bool   `json:"bootstrapped"`
}

// ManifestPath is where Install records itself.
func ManifestPath(p core.Paths) string { return filepath.Join(p.State, "install.json") }

// LoadManifest reads state/install.json. A missing file is "never installed" and returns a
// zero Manifest.
func LoadManifest(p core.Paths) (Manifest, error) {
	var m Manifest
	b, err := os.ReadFile(ManifestPath(p))
	if errors.Is(err, fs.ErrNotExist) {
		return m, nil
	}
	if err != nil {
		return m, err
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return Manifest{}, fmt.Errorf("install: %s does not parse", ManifestPath(p))
	}
	return m, nil
}

// hookSpec is one config-based git hook.
type hookSpec struct{ name, event string }

// HookSpecs are the entries PLAN.md layer 1 puts in the global git config. commit-msg is the
// one that sees a key typed into a message (STEAL P0-13): no engine reads a commit message.
var HookSpecs = []hookSpec{
	{"keyguard-precommit", "pre-commit"},
	{"keyguard-prepush", "pre-push"},
	{"keyguard-reftx", "reference-transaction"},
	{"keyguard-commitmsg", "commit-msg"},
}

// HookCommand is the one-liner git runs for an event, with git's hook arguments appended.
// The binary may be missing (an uninstall in progress, a wiped data dir) and then the hook
// must not break git everywhere, hence the test and exit 0.
func HookCommand(bin, event string) string {
	q := shellQuote(bin)
	return "test -x " + q + " || exit 0; exec " + q + " hook " + event
}

// HookKeys lists every git config key Install owns with the value it sets, in a fixed order.
func HookKeys(bin string) []GitKey {
	var keys []GitKey
	for _, h := range HookSpecs {
		keys = append(keys,
			GitKey{Key: "hook." + h.name + ".event", Value: h.event},
			GitKey{Key: "hook." + h.name + ".command", Value: HookCommand(bin, h.event)})
	}
	return keys
}

// installer carries one Install or Uninstall run. Every write goes through its methods, so
// DryRun is honoured in one place and the Result lists everything touched.
type installer struct {
	o       Options
	ctx     context.Context
	m       Manifest
	written []byte // the manifest as last written or loaded, minus its timestamps
	res     Result
}

func (in *installer) act(step, target, change, detail string) {
	in.res.Actions = append(in.res.Actions, Action{step, target, change, detail})
}

func (in *installer) warn(format string, a ...any) {
	in.res.Warnings = append(in.res.Warnings, fmt.Sprintf(format, a...))
}

func (in *installer) stamp() string { return in.o.Now().UTC().Format(time.RFC3339) }

// saveManifest is called after each step that changes the machine, so an install that dies
// half way can still be undone.
func (in *installer) saveManifest() error {
	if in.o.DryRun {
		return nil
	}
	in.m.Version = 1
	// A manifest that says what it said before is not rewritten, so a repeated install
	// changes no byte on disk, its timestamp included.
	stable := in.m
	stable.UpdatedAt, stable.InstalledAt = "", ""
	sb, err := json.Marshal(stable)
	if err != nil {
		return err
	}
	if in.written != nil && bytes.Equal(in.written, sb) {
		return nil
	}
	in.written = sb
	in.m.UpdatedAt = in.stamp()
	if in.m.InstalledAt == "" {
		in.m.InstalledAt = in.m.UpdatedAt
	}
	b, err := json.MarshalIndent(in.m, "", "  ")
	if err != nil {
		return err
	}
	return db.WriteFileAtomic(ManifestPath(in.o.Paths), append(b, '\n'), 0o600)
}

func (in *installer) git(args ...string) ([]byte, error) {
	return in.o.Run(in.ctx, in.o.Git, args...)
}

// Install puts keyguard on this machine, or reports that it already is. It is safe to run
// again: every step compares before it writes.
func Install(ctx context.Context, opts Options) (*Result, error) {
	o, err := opts.resolve()
	if err != nil {
		return nil, err
	}
	in := &installer{o: o, ctx: ctx}
	if in.m, err = LoadManifest(o.Paths); err != nil {
		bad := ManifestPath(o.Paths) + ".bad-" + fmt.Sprint(o.Now().Unix())
		if !o.DryRun {
			if rerr := os.Rename(ManifestPath(o.Paths), bad); rerr != nil {
				return nil, err
			}
		}
		in.warn("the install record could not be read and was moved to %s; undoing the old install by hand may be needed", bad)
		in.m = Manifest{}
	}
	if in.m.Version != 0 {
		stable := in.m
		stable.UpdatedAt, stable.InstalledAt = "", ""
		in.written, _ = json.Marshal(stable)
	}
	in.res.Claude, in.res.Snippet = ClaudeRegistration(o.Paths.Bin), ClaudeSnippet(o.Paths.Bin)
	if real := filepath.Join(o.Home, ".keyguard"); o.Paths.Root != real {
		// The git hooks run the binary at Paths.Bin but read the learned store, the ignore list
		// and the config from ~/.keyguard (PLAN.md invariant 4: the environment cannot move
		// them), so an install anywhere else protects with data it does not have.
		in.warn("the data root is %s, not %s: the git hooks will run the binary there but read their data from %s", o.Paths.Root, real, real)
	}

	steps := []func() error{in.dirs, in.salt, in.binary, in.rulesFile, in.config, in.gitConfig}
	if !o.NoLaunchd {
		steps = append(steps, in.launchd)
	}
	for _, step := range steps {
		if err := step(); err != nil {
			return &in.res, err
		}
	}
	if err := in.saveManifest(); err != nil {
		return &in.res, err
	}
	return &in.res, nil
}

func (in *installer) dirs() error {
	if in.o.DryRun {
		return nil
	}
	p := in.o.Paths
	// tmp is the private TMPDIR engines spool under (P0-04); bin holds the pinned engine copies.
	for _, d := range []string{p.Root, p.BinDir, p.Tmp, p.State, p.Logs, filepath.Dir(RulesPath(p)), filepath.Join(p.State, "install")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
	}
	return nil
}

// salt makes the keyring the first time. Only an install may: a hook or a matcher that finds
// the salt gone must not mint another (fp.Open), because every hash stored under the old one
// would silently stop matching. So the salt exists from the day keyguard is installed, and when
// a learned store is there without one, this says so instead of making a salt that orphans it.
func (in *installer) salt() error {
	known := in.o.Paths.Known
	salt := filepath.Join(known, "salt")
	if _, err := os.Stat(salt); err == nil {
		in.act("keyring", salt, "unchanged", "")
		return nil
	}
	if in.o.DryRun {
		in.act("keyring", salt, "created", "")
		return nil
	}
	if _, err := os.Stat(in.o.Paths.KnownStore); err == nil {
		in.warn("%s is missing but %s exists; no new salt was made, because it would orphan every learned hash. Restore the salt, or move known.json aside and run keyguard learn", salt, in.o.Paths.KnownStore)
		return nil
	}
	if err := os.MkdirAll(known, 0o700); err != nil {
		return err
	}
	if _, err := fp.Load(known); err != nil {
		return fmt.Errorf("install: making the keyring: %w", err)
	}
	in.act("keyring", salt, "created", "")
	return nil
}

// binary copies this executable to <root>/bin/keyguard, the path the hooks run.
func (in *installer) binary() error {
	dst := in.o.Paths.Bin
	src := in.o.Executable
	if sameFile(src, dst) {
		sum, err := hashFile(dst)
		if err != nil {
			return err
		}
		in.m.Binary = FileRecord{Path: dst, SHA256: sum}
		in.act("binary", dst, "unchanged", "this is the installed binary")
		return nil
	}
	want, err := hashFile(src)
	if err != nil {
		return fmt.Errorf("install: reading %s: %w", src, err)
	}
	have, herr := hashFile(dst)
	if herr == nil && have == want {
		in.m.Binary = FileRecord{Path: dst, SHA256: want}
		in.act("binary", dst, "unchanged", "")
		return in.saveManifest()
	}
	change := "created"
	if herr == nil {
		change = "updated"
	}
	if in.o.DryRun {
		in.act("binary", dst, change, "from "+src)
		return nil
	}
	if err := copyFileAtomic(src, dst, 0o755); err != nil {
		return fmt.Errorf("install: copying the binary to %s: %w", dst, err)
	}
	in.m.Binary = FileRecord{Path: dst, SHA256: want}
	in.act("binary", dst, change, "from "+src)
	return in.saveManifest()
}

// rulesFile writes the embedded rules where the engines are pointed at them.
func (in *installer) rulesFile() error {
	path := RulesPath(in.o.Paths)
	sum := hashBytes(rules.KeyguardTOML)
	cur, err := os.ReadFile(path)
	if err == nil && string(cur) == string(rules.KeyguardTOML) {
		in.m.Rules = FileRecord{Path: path, SHA256: sum}
		in.act("rules", path, "unchanged", "")
		return nil
	}
	change := "created"
	if err == nil {
		change = "updated"
	}
	if in.o.DryRun {
		in.act("rules", path, change, "")
		return nil
	}
	if err := writeAtomic(path, rules.KeyguardTOML, 0o600); err != nil {
		return err
	}
	in.m.Rules = FileRecord{Path: path, SHA256: sum}
	in.act("rules", path, change, "")
	return in.saveManifest()
}

// config creates state/config.json when it is missing and otherwise keeps what the user set. It
// is also the engine step: each engine becomes a pinned copy in <root>/bin and its pin is
// recorded here (engineCopies), then the titus rule cache is built. Running install again
// changes none of that unless a binary is new.
func (in *installer) config() error {
	p := in.o.Paths
	cfg, err := LoadConfig(p, in.o.Home)
	if err != nil {
		return fmt.Errorf("install: %w; fix or move %s and run install again", err, p.Config)
	}
	if _, err := os.Stat(p.Config); errors.Is(err, fs.ErrNotExist) {
		in.discoverAccounts(&cfg)
	}
	old := cfg.Pins
	drifted := in.engineCopies(&cfg)
	if !in.o.DryRun {
		if err := in.saveManifest(); err != nil {
			return err
		}
	}
	pin := in.o.Pin
	if pin == nil {
		pin = PinEngines
	}
	cfg.Pins = pin(cfg)
	for name := range drifted {
		if was, ok := old[name]; ok {
			cfg.Pins[name] = was
		}
	}
	want, err := cfg.marshal()
	if err != nil {
		return err
	}
	cur, rerr := os.ReadFile(p.Config)
	switch {
	case rerr == nil && bytes.Equal(cur, want):
		in.act("config", p.Config, "unchanged", "")
	case in.o.DryRun:
		in.act("config", p.Config, map[bool]string{true: "updated", false: "created"}[rerr == nil], "")
		return nil
	default:
		if err := db.WriteFileAtomic(p.Config, want, 0o600); err != nil {
			return err
		}
		in.act("config", p.Config, map[bool]string{true: "updated", false: "created"}[rerr == nil], "")
	}
	in.prewarm(cfg)
	return nil
}

// gitValues returns every value of a key in the file ("" slice when unset).
func (in *installer) gitValues(file, key string) ([]string, error) {
	out, err := in.git("config", "--file", file, "--get-all", key)
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && ee.ExitCode() == 1 {
			return nil, nil // git exits 1 for a key that is not set
		}
		return nil, err
	}
	s := strings.TrimRight(string(out), "\n")
	if s == "" {
		return nil, nil
	}
	return strings.Split(s, "\n"), nil
}

func (in *installer) gitConfig() error {
	file := in.o.GitConfig
	rec := &in.m.Git
	if rec.File != "" && rec.File != file {
		in.warn("a previous install put hooks in %s; that file is not touched. Uninstall with GIT_CONFIG_GLOBAL=%s to remove them", rec.File, rec.File)
		*rec = GitRecord{}
	}
	cur, rerr := os.ReadFile(file)
	existed := rerr == nil
	if rerr != nil && !errors.Is(rerr, fs.ErrNotExist) {
		return rerr
	}
	if rec.File == "" {
		// First install on this file: keep its bytes exactly as they are, so Uninstall can put
		// them back byte for byte (git rewrites a file it edits: a missing final newline is
		// the usual casualty).
		*rec = GitRecord{File: file, Existed: existed}
		if existed {
			rec.OriginalSHA = hashBytes(cur)
			rec.OriginalCopy = filepath.Join(in.o.Paths.State, "install", "gitconfig.orig")
			if !in.o.DryRun {
				if err := writeAtomic(rec.OriginalCopy, cur, 0o600); err != nil {
					return err
				}
			}
		}
	}

	if rec.AfterSHA != "" && existed && hashBytes(cur) != rec.AfterSHA && !rec.Edited {
		// Someone edited the file since the last install. From here on its bytes are no longer
		// "the original plus our keys", so Uninstall must cut our keys out instead of putting
		// the original back over their edit.
		rec.Edited = true
		in.warn("%s was edited since the last install; uninstall will remove only keyguard's keys from it", file)
	}

	byKey := map[string]GitKey{}
	for _, k := range rec.Keys {
		byKey[k.Key] = k
	}
	var keys []GitKey
	for _, want := range HookKeys(in.o.Paths.Bin) {
		have, err := in.gitValues(file, want.Key)
		if err != nil {
			return fmt.Errorf("install: reading %s from %s: %w", want.Key, file, err)
		}
		k := want
		if old, ok := byKey[want.Key]; ok {
			k.Previous = old.Previous // what the key held before the very first install stays what it was
		} else if len(have) > 0 && !(len(have) == 1 && have[0] == want.Value) {
			k.Previous = have
		}
		keys = append(keys, k)
		if len(have) == 1 && have[0] == want.Value {
			in.act("git", want.Key, "unchanged", "")
			continue
		}
		change := "created"
		if len(have) > 0 {
			change = "updated"
		}
		if !in.o.DryRun {
			if _, err := in.git("config", "--file", file, "--replace-all", want.Key, want.Value); err != nil {
				return fmt.Errorf("install: setting %s in %s: %w", want.Key, file, err)
			}
		}
		in.act("git", want.Key, change, file)
	}
	rec.Keys = keys
	if in.o.DryRun {
		return nil
	}
	if after, err := os.ReadFile(file); err == nil {
		rec.AfterSHA = hashBytes(after)
	}
	return in.saveManifest()
}

// launchd writes the two agents and loads them.
func (in *installer) launchd() error {
	o := in.o
	rec := &in.m.Launchd
	if rec.Dir != "" && rec.Dir != o.LaunchDir {
		in.warn("a previous install put launchd agents in %s; they are not touched", rec.Dir)
		*rec = LaunchdRecord{}
	}
	rec.Dir = o.LaunchDir
	have := map[string]JobRecord{}
	for _, j := range rec.Jobs {
		have[j.Label] = j
	}
	var jobsOut []JobRecord
	for _, j := range jobsFor() {
		path := j.file(o.LaunchDir)
		body := j.plist(o.Paths.Bin, o.Home, o.Paths)
		changed, err := false, error(nil)
		if o.DryRun {
			cur, rerr := os.ReadFile(path)
			changed = rerr != nil || !bytes.Equal(cur, body)
		} else {
			if err := os.MkdirAll(o.LaunchDir, 0o755); err != nil {
				return err
			}
			if changed, err = writeIfChanged(path, body, 0o644); err != nil {
				return err
			}
		}
		jr := JobRecord{Label: j.label, Plist: path, SHA256: hashBytes(body), Bootstrapped: have[j.label].Bootstrapped}
		change := "unchanged"
		if changed {
			change = "updated"
			if _, ok := have[j.label]; !ok {
				change = "created"
			}
		}
		in.act("launchd", path, change, "")
		if !o.NoBootstrap {
			loaded := in.loaded(j.label)
			if changed || !loaded {
				if o.DryRun {
					in.act("launchd", j.label, "updated", "would load")
				} else {
					if err := in.bootstrap(j, path); err != nil {
						jobsOut = append(jobsOut, jr)
						rec.Jobs = jobsOut
						_ = in.saveManifest()
						return err
					}
					jr.Bootstrapped = true
					in.act("launchd", j.label, "created", "loaded in "+in.domain())
				}
			} else {
				jr.Bootstrapped = true
				in.act("launchd", j.label, "unchanged", "already loaded")
			}
		}
		jobsOut = append(jobsOut, jr)
	}
	rec.Jobs = jobsOut
	return in.saveManifest()
}

func (in *installer) domain() string { return fmt.Sprintf("gui/%d", in.o.UID) }

func (in *installer) loaded(label string) bool {
	_, err := in.o.Run(in.ctx, "launchctl", "print", in.domain()+"/"+label)
	return err == nil
}

// bootstrap replaces whatever is loaded under the job's label with the file on disk.
// launchctl tears an agent down asynchronously, so the first bootstrap right after a
// bootout can be refused; it is retried briefly.
func (in *installer) bootstrap(j job, plist string) error {
	target := in.domain() + "/" + j.label
	_, _ = in.o.Run(in.ctx, "launchctl", "bootout", target) // "not loaded" is the usual answer
	_, _ = in.o.Run(in.ctx, "launchctl", "enable", target)
	var err error
	for i := 0; i < 5; i++ {
		if _, err = in.o.Run(in.ctx, "launchctl", "bootstrap", in.domain(), plist); err == nil {
			break
		}
		select {
		case <-in.ctx.Done():
			return in.ctx.Err()
		case <-time.After(300 * time.Millisecond):
		}
	}
	if err != nil {
		return fmt.Errorf("install: launchctl bootstrap %s: %w", j.label, err)
	}
	if !in.loaded(j.label) {
		return fmt.Errorf("install: launchctl bootstrapped %s but it is not loaded", j.label)
	}
	return nil
}

// Uninstall takes out what Install put in, as the install record lists it. Nothing is
// deleted: files are moved to <root>/.uninstalled/<time>/. Data (findings, the learned
// store, mirrors, config.json) is not part of an install and stays.
func Uninstall(ctx context.Context, opts Options) (*Result, error) {
	o, err := opts.resolve()
	if err != nil {
		return nil, err
	}
	in := &installer{o: o, ctx: ctx}
	if in.m, err = LoadManifest(o.Paths); err != nil {
		return nil, err
	}
	in.res.Claude = ClaudeUnregistration(o.Paths.Bin)
	if in.m.Version == 0 {
		in.warn("there is no install record at %s; nothing is known to undo", ManifestPath(o.Paths))
		return &in.res, nil
	}
	aside := filepath.Join(o.Paths.Root, ".uninstalled", o.Now().UTC().Format("20060102T150405Z"))

	// Launchd first: a job that fires while the binary is half removed would only fail, but
	// failing every minute into a log is exactly the noise this avoids.
	for _, j := range in.m.Launchd.Jobs {
		target := fmt.Sprintf("gui/%d/%s", o.UID, j.Label)
		if j.Bootstrapped && !o.DryRun {
			if _, err := o.Run(ctx, "launchctl", "bootout", target); err != nil {
				in.warn("launchctl bootout %s: %v (it may not have been loaded)", j.Label, err)
			} else {
				in.act("launchd", j.Label, "removed", "unloaded from "+fmt.Sprintf("gui/%d", o.UID))
			}
		} else if j.Bootstrapped {
			in.act("launchd", j.Label, "removed", "would unload")
		}
		in.moveOut("launchd", j.Plist, aside, j.SHA256)
	}
	in.gitRestore(aside)
	in.moveOut("binary", in.m.Binary.Path, aside, in.m.Binary.SHA256)
	in.moveOut("rules", in.m.Rules.Path, aside, in.m.Rules.SHA256)
	names := make([]string, 0, len(in.m.Engines))
	for name := range in.m.Engines {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		in.moveOut("engine", in.m.Engines[name].Path, aside, in.m.Engines[name].SHA256)
	}
	if !o.DryRun {
		if dst, err := moveAside(ManifestPath(o.Paths), aside); err == nil {
			in.act("manifest", ManifestPath(o.Paths), "moved", dst)
		}
		if in.m.Git.OriginalCopy != "" {
			_, _ = moveAside(in.m.Git.OriginalCopy, aside) // kept beside the rest: it is the one verbatim copy
		}
	}
	return &in.res, nil
}

// moveOut moves a file Install wrote aside, noting if someone changed it since.
func (in *installer) moveOut(step, path, aside, wantSHA string) {
	if path == "" {
		return
	}
	sum, err := hashFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			in.act(step, path, "skipped", "already gone")
		}
		return
	}
	detail := "to " + aside
	if wantSHA != "" && sum != wantSHA {
		detail += " (it had been changed since install)"
	}
	if in.o.DryRun {
		in.act(step, path, "moved", detail)
		return
	}
	if _, err := moveAside(path, aside); err != nil {
		in.warn("could not move %s aside: %v", path, err)
		return
	}
	in.act(step, path, "moved", detail)
}

// gitRestore undoes the git config changes. A file nobody has touched since install gets
// its original bytes back (or goes aside if install created it); one that has been edited
// since loses only keyguard's keys.
func (in *installer) gitRestore(aside string) {
	rec := in.m.Git
	if rec.File == "" {
		return
	}
	cur, err := os.ReadFile(rec.File)
	if errors.Is(err, fs.ErrNotExist) {
		in.act("git", rec.File, "skipped", "already gone")
		return
	}
	if err != nil {
		in.warn("reading %s: %v", rec.File, err)
		return
	}
	if !rec.Edited && rec.AfterSHA != "" && hashBytes(cur) == rec.AfterSHA {
		switch {
		case rec.Existed && rec.OriginalCopy != "":
			orig, err := os.ReadFile(rec.OriginalCopy)
			if err == nil && hashBytes(orig) == rec.OriginalSHA {
				if !in.o.DryRun {
					// Through the link, as git writes: a dotfile manager's symlink must stay one.
					dst := rec.File
					if resolved, err := filepath.EvalSymlinks(rec.File); err == nil {
						dst = resolved
					}
					mode := os.FileMode(0o644)
					if fi, err := os.Stat(dst); err == nil {
						mode = fi.Mode().Perm()
					}
					if err := writeAtomic(dst, orig, mode); err != nil {
						in.warn("restoring %s: %v", rec.File, err)
						return
					}
				}
				in.act("git", rec.File, "restored", "its bytes from before the install")
				return
			}
			in.warn("the saved original of %s is missing or changed; removing keyguard's keys instead", rec.File)
		case !rec.Existed:
			// Install created this file and nothing else is in it.
			in.moveOut("git", rec.File, aside, "")
			return
		}
	}
	in.surgery(rec, aside)
}

// surgery removes the keys Install set, one by one, from a file that holds other things.
func (in *installer) surgery(rec GitRecord, aside string) {
	for _, k := range rec.Keys {
		have, err := in.gitValues(rec.File, k.Key)
		if err != nil {
			in.warn("reading %s: %v", k.Key, err)
			continue
		}
		switch {
		case len(have) == 0:
			in.act("git", k.Key, "skipped", "not set")
			continue
		case len(have) != 1 || have[0] != k.Value:
			in.warn("%s was changed after install; left alone", k.Key)
			in.act("git", k.Key, "skipped", "changed since install")
			continue
		}
		if in.o.DryRun {
			in.act("git", k.Key, "removed", "")
			continue
		}
		var err2 error
		if len(k.Previous) == 0 {
			_, err2 = in.git("config", "--file", rec.File, "--unset-all", k.Key)
		} else {
			_, err2 = in.git("config", "--file", rec.File, "--replace-all", k.Key, k.Previous[0])
			for _, v := range k.Previous[1:] {
				if err2 == nil {
					_, err2 = in.git("config", "--file", rec.File, "--add", k.Key, v)
				}
			}
		}
		if err2 != nil {
			in.warn("removing %s: %v", k.Key, err2)
			continue
		}
		in.act("git", k.Key, "removed", "")
	}
	if !rec.Existed && !in.o.DryRun {
		if left, err := os.ReadFile(rec.File); err == nil && len(bytes.TrimSpace(left)) == 0 {
			in.moveOut("git", rec.File, aside, "")
		}
	}
}
