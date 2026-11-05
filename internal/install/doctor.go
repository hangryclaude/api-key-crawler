package install

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"keyguard/internal/core"
	"keyguard/internal/engines"
	"keyguard/internal/inventory"
	"keyguard/internal/inventory/ghcli"
	"keyguard/internal/known"
	"keyguard/internal/notify"
	"keyguard/rules"
)

// DoctorSchemaVersion is the contract of `keyguard doctor --json`. It changes only when a
// field a caller reads changes meaning.
const DoctorSchemaVersion = 1

// Status is how one check came out.
type Status string

const (
	OK   Status = "ok"
	Warn Status = "warn" // works, but something is off or stale
	Fail Status = "fail" // a protection layer is not doing its job
)

// Check is one thing the doctor looked at. Every finding names the command that fixes it:
// the doctor itself never writes, because a repair is `keyguard install`, which backs up
// what it changes and is undone by `keyguard uninstall`.
type Check struct {
	ID      string   `json:"id"`
	Layers  []string `json:"layers,omitempty"` // the protection layers that depend on it
	Status  Status   `json:"status"`
	Summary string   `json:"summary"`
	Detail  string   `json:"detail,omitempty"`
	Fix     string   `json:"fix,omitempty"`
}

// Report is the doctor's answer.
type Report struct {
	SchemaVersion int     `json:"schema_version"`
	At            string  `json:"at"`
	Root          string  `json:"root"`
	Quick         bool    `json:"quick"`
	Healthy       bool    `json:"healthy"` // no warnings and no failures
	Ok            int     `json:"ok"`
	Warnings      int     `json:"warnings"`
	Failures      int     `json:"failures"`
	Checks        []Check `json:"checks"`
}

// DoctorOptions says what to inspect. The embedded Options names the same things Install
// did; Executable is not used.
type DoctorOptions struct {
	Options
	ClaudeSettings string // "" = <Home>/.claude/settings.json
	// Quick skips what costs real time: starting engines, hashing binaries and the gh token
	// check. The report every sweep writes uses it; the daily doctor and the command do not.
	Quick bool
	// Probe asks an engine binary its version and, when it is pinned, checks the binary against
	// the pin: err is then an *engines.PinError. nil is RealProbe. Tests that are not about engines
	// stub it, since starting trufflehog and hashing its 170 MB takes half a second.
	Probe func(name, path string, pin *Pin) (version string, err error)
	// Skew asks GitHub how far this Mac's clock is ahead of it (negative: behind), with the one
	// request that costs no quota (inventory.Skew). Nil skips the check: a doctor with no
	// inventory to ask has no GitHub to compare with. The quick doctor never asks.
	Skew func(ctx context.Context) (time.Duration, error)
}

// RealProbe starts the engine for its version, checking its binary against the pin first: an
// engine that is not the pinned binary is not started (engines.CheckPin).
func RealProbe(name, path string, pin *Pin) (version string, err error) {
	var opts []engines.Option
	if pin != nil {
		opts = append(opts, engines.WithPins(map[string]engines.Pin{name: engines.Pin(*pin)}))
	}
	e, err := engines.New(name, path, nopFP{}, opts...)
	if err != nil {
		return "", err
	}
	if err := engines.CheckPin(e); err != nil {
		return "", err
	}
	return e.Version(), nil
}

// Layer names, as the report shows them.
const (
	LayerCommit   = "commit gate"
	LayerPush     = "push gate"
	LayerRef      = "ref gate"
	LayerGuard    = "agent guard"
	LayerPoll     = "one-minute poll"
	LayerDeep     = "weekly deep scan"
	LayerUpgrade  = "engine upgrade check"
	LayerEngines  = "scan engines"
	LayerKnown    = "learned secrets"
	LayerGitHub   = "GitHub's own protection"
	LayerSelftest = "self-test"
)

// Stale limits for the poll: it runs every minute, so ten missed is a warning and half an
// hour is a failure. A scan that holds the run lock for longer counts as running, not as late.
const (
	pollWarnAfter   = 10 * time.Minute
	pollFailAfter   = 30 * time.Minute
	selftestEvery   = 26 * time.Hour      // daily, with a little room for a Mac that was asleep
	upgradeEvery    = 15 * 24 * time.Hour // weekly, with a week of room
	protectionEvery = 3 * 24 * time.Hour  // the daily poll surveys GitHub; three days missed is a warning
)

type doctor struct {
	DoctorOptions
	ctx context.Context
	cfg Config
	m   Manifest
	now time.Time
	out []Check
}

func (d *doctor) add(c Check) { d.out = append(d.out, c) }

// Doctor inspects the install and the data without changing a byte of either. The one
// error it returns is for options it cannot use; everything wrong with the machine is a
// Check.
func Doctor(ctx context.Context, opts DoctorOptions) (Report, error) {
	// resolve wants an executable only to copy it; the doctor never does.
	if opts.Executable == "" {
		opts.Executable = "-"
	}
	explicitLaunchDir := opts.LaunchDir != ""
	o, err := opts.Options.resolve()
	if err != nil {
		return Report{}, err
	}
	opts.Options = o
	if opts.ClaudeSettings == "" {
		opts.ClaudeSettings = filepath.Join(o.Home, ".claude", "settings.json")
	}
	d := &doctor{DoctorOptions: opts, ctx: ctx, now: o.Now()}
	cfg, cerr := LoadConfig(o.Paths, o.Home)
	d.cfg = cfg
	d.m, _ = LoadManifest(o.Paths)
	if !explicitLaunchDir && d.m.Launchd.Dir != "" {
		d.LaunchDir = d.m.Launchd.Dir // install was told to write the plists elsewhere (--launchd-dir)
	}

	d.configCheck(cerr)
	d.gitVersion()
	d.hooks()
	d.guard()
	d.launchd()
	d.sweepAge()
	d.enginesCheck()
	d.scratchCheck()
	d.titusCheck()
	d.upgradeCheck()
	d.rulesCheck()
	d.knownCheck()
	d.stateCheck()
	d.mirrors()
	d.selftest()
	d.notifyCheck()
	d.protectionCheck()
	if !opts.Quick {
		d.ghAuth()
		d.clockCheck()
	}

	r := Report{
		SchemaVersion: DoctorSchemaVersion, At: d.now.UTC().Format(time.RFC3339), Root: o.Paths.Root,
		Quick: opts.Quick, Checks: d.out,
	}
	for _, c := range d.out {
		switch c.Status {
		case OK:
			r.Ok++
		case Warn:
			r.Warnings++
		default:
			r.Failures++
		}
	}
	r.Healthy = r.Warnings == 0 && r.Failures == 0
	return r, nil
}

// ExitCode is 0 for a healthy install and 1 when there is anything to look at.
func (r Report) ExitCode() int {
	if r.Healthy {
		return 0
	}
	return 1
}

// Layers folds the checks into the per-layer health the report page shows. A layer is down
// when a check that serves it failed; a warning keeps it up and shows in the detail.
func (r Report) Layers() []core.LayerStatus {
	order := []string{LayerCommit, LayerPush, LayerRef, LayerGuard, LayerPoll, LayerDeep, LayerUpgrade, LayerEngines, LayerKnown, LayerGitHub, LayerSelftest}
	type agg struct {
		fail         bool
		note         []string
		failFix, fix string // the fix of the first failing check, and of the first that is not ok
	}
	by := map[string]*agg{}
	for _, c := range r.Checks {
		for _, l := range c.Layers {
			a := by[l]
			if a == nil {
				a = &agg{}
				by[l] = a
			}
			switch c.Status {
			case Fail:
				a.fail = true
				a.note = append(a.note, c.Summary)
			case Warn:
				a.note = append(a.note, c.Summary)
			}
			if c.Status != OK && a.fix == "" {
				a.fix = layerFix(c.Fix)
			}
			if c.Status == Fail && a.failFix == "" {
				a.failFix = layerFix(c.Fix)
			}
		}
	}
	var out []core.LayerStatus
	for _, name := range order {
		a := by[name]
		if a == nil {
			continue
		}
		detail := "ok"
		if len(a.note) > 0 {
			detail = strings.Join(a.note, "; ")
		}
		out = append(out, core.LayerStatus{Name: name, OK: !a.fail, Detail: detail, Fix: cmp.Or(a.failFix, a.fix), CheckedAt: r.At})
	}
	return out
}

// layerFix is a check's fix as the report's layer table shows it. The agent guard's fix is a
// long shell line the user runs in Claude Code, which does not belong in a table cell: the table
// points at where to find it.
func layerFix(fix string) string {
	if strings.HasPrefix(fix, "! ") {
		return "keyguard doctor (it prints the line to run in Claude Code)"
	}
	return fix
}

// ----- checks -----

func (d *doctor) configCheck(err error) {
	switch {
	case err != nil:
		d.add(Check{ID: "config", Layers: []string{LayerEngines}, Status: Fail,
			Summary: "state/config.json does not parse; defaults are in use",
			Detail:  err.Error(), Fix: "fix or move " + d.Paths.Config + ", then run: keyguard install"})
	default:
		if p := d.cfg.Problems(); len(p) > 0 {
			d.add(Check{ID: "config", Layers: []string{LayerEngines}, Status: Warn,
				Summary: "config.json has " + strconv.Itoa(len(p)) + " problem(s)", Detail: strings.Join(p, "; "),
				Fix: "edit " + d.Paths.Config})
		} else if _, serr := os.Stat(d.Paths.Config); serr != nil {
			d.add(Check{ID: "config", Layers: []string{LayerEngines}, Status: Warn,
				Summary: "no state/config.json yet; defaults are in use", Fix: "keyguard install"})
		} else {
			d.add(Check{ID: "config", Status: OK, Summary: "config.json is valid"})
		}
	}
}

var gitVersionRE = regexp.MustCompile(`(\d+)\.(\d+)`)

// gitVersion: config-based hooks arrived in git 2.54. Older git ignores the keys without
// a word, which is the worst kind of broken.
func (d *doctor) gitVersion() {
	out, err := d.Run(d.ctx, d.Git, "--version")
	if err != nil {
		d.add(Check{ID: "git.version", Layers: []string{LayerCommit, LayerPush, LayerRef}, Status: Fail,
			Summary: "git did not run", Detail: err.Error(), Fix: "install git 2.54 or newer (brew install git)"})
		return
	}
	m := gitVersionRE.FindStringSubmatch(string(out))
	if m == nil {
		d.add(Check{ID: "git.version", Status: Warn, Summary: "could not read git's version", Detail: strings.TrimSpace(string(out))})
		return
	}
	maj, _ := strconv.Atoi(m[1])
	min, _ := strconv.Atoi(m[2])
	v := m[1] + "." + m[2]
	if maj < 2 || maj == 2 && min < 54 {
		d.add(Check{ID: "git.version", Layers: []string{LayerCommit, LayerPush, LayerRef}, Status: Fail,
			Summary: "git " + v + " ignores config-based hooks, so the gates do not run",
			Fix:     "install git 2.54 or newer (brew install git) and put it first on PATH"})
		return
	}
	d.add(Check{ID: "git.version", Status: OK, Summary: "git " + v + " runs config-based hooks"})
}

// hooks checks the three hook entries and the binary they run. The one-liner exits 0 when
// the binary is gone, so a missing binary silently turns every gate off.
func (d *doctor) hooks() {
	layerOf := map[string]string{"keyguard-precommit": LayerCommit, "keyguard-prepush": LayerPush, "keyguard-reftx": LayerRef, "keyguard-commitmsg": LayerCommit}
	idOf := map[string]string{"keyguard-precommit": "hooks.precommit", "keyguard-prepush": "hooks.prepush", "keyguard-reftx": "hooks.reftx", "keyguard-commitmsg": "hooks.commitmsg"}
	entries := map[string][]string{}
	out, err := d.Run(d.ctx, d.Git, "config", "--file", d.GitConfig, "--get-regexp", `^hook\.keyguard-`)
	if err != nil && !isExit(err, 1) {
		for _, h := range HookSpecs {
			d.add(Check{ID: idOf[h.name], Layers: []string{layerOf[h.name]}, Status: Fail,
				Summary: "could not read " + d.GitConfig, Detail: err.Error(), Fix: "keyguard install"})
		}
		return
	}
	for _, ln := range strings.Split(strings.TrimRight(string(out), "\n"), "\n") {
		if key, val, ok := strings.Cut(ln, " "); ok {
			entries[key] = append(entries[key], val)
		}
	}
	for _, h := range HookSpecs {
		prefix := "hook." + h.name + "."
		events, cmds := entries[prefix+"event"], entries[prefix+"command"]
		want := HookCommand(d.Paths.Bin, h.event)
		c := Check{ID: idOf[h.name], Layers: []string{layerOf[h.name]}, Fix: "keyguard install"}
		switch {
		case len(events) == 0 && len(cmds) == 0:
			c.Status, c.Summary = Fail, h.event+" gate is not in "+d.GitConfig
		case !slices.Equal(events, []string{h.event}):
			c.Status, c.Summary = Fail, h.event+" gate listens for "+strings.Join(events, ",")+" instead"
		case len(cmds) != 1 || cmds[0] != want:
			c.Status, c.Summary = Fail, h.event+" gate runs a different command"
			if len(cmds) == 1 {
				c.Detail = "found: " + cmds[0]
			}
		case len(entries[prefix+"enabled"]) > 0 && entries[prefix+"enabled"][len(entries[prefix+"enabled"])-1] != "true":
			c.Status, c.Summary = Fail, h.event+" gate is switched off ("+prefix+"enabled)"
			c.Fix = "git config --file " + shellQuote(d.GitConfig) + " --unset-all " + prefix + "enabled"
		default:
			c.Status, c.Summary = OK, h.event+" gate is installed"
		}
		if c.Status == Fail && d.m.Git.File != "" && d.m.Git.File != d.GitConfig {
			// The usual cause: install ran with a different GIT_CONFIG_GLOBAL than git reads now.
			c.Detail += strings.TrimPrefix("; install.json says the hooks went into "+d.m.Git.File+", but git reads "+d.GitConfig, "; ")
		}
		d.add(c)
	}

	all := []string{LayerCommit, LayerPush, LayerRef}
	bin := d.Paths.Bin
	fi, err := os.Stat(bin)
	switch {
	case err != nil:
		d.add(Check{ID: "hooks.binary", Layers: all, Status: Fail,
			Summary: "the hooks' binary is missing, so every gate is silently off",
			Detail:  bin, Fix: "keyguard install"})
		return
	case !fi.Mode().IsRegular() || fi.Mode().Perm()&0o111 == 0:
		d.add(Check{ID: "hooks.binary", Layers: all, Status: Fail, Summary: "the hooks' binary is not executable", Detail: bin, Fix: "keyguard install"})
		return
	}
	if d.Quick {
		d.add(Check{ID: "hooks.binary", Layers: all, Status: OK, Summary: "the hooks' binary is in place"})
		return
	}
	ctx, cancel := context.WithTimeout(d.ctx, 10*time.Second)
	defer cancel()
	if _, err := d.Run(ctx, bin, "version"); err != nil {
		d.add(Check{ID: "hooks.binary", Layers: all, Status: Fail, Summary: "the hooks' binary does not run",
			Detail: err.Error(), Fix: "keyguard install"})
		return
	}
	sum, _ := hashFile(bin)
	if d.m.Binary.SHA256 != "" && sum != d.m.Binary.SHA256 {
		d.add(Check{ID: "hooks.binary", Layers: all, Status: Warn,
			Summary: "the installed binary is not the one that was installed",
			Detail:  "its hash differs from state/install.json", Fix: "keyguard install"})
		return
	}
	d.add(Check{ID: "hooks.binary", Layers: all, Status: OK, Summary: "the hooks' binary runs"})
}

func isExit(err error, code int) bool {
	var ee interface{ ExitCode() int }
	return errors.As(err, &ee) && ee.ExitCode() == code
}

func (d *doctor) guard() {
	uncovered, registered, err := ClaudeUncovered(d.ClaudeSettings, d.Paths.Bin)
	switch {
	case err != nil:
		d.add(Check{ID: "guard.claude", Layers: []string{LayerGuard}, Status: Warn,
			Summary: "could not read Claude Code's settings", Detail: err.Error()})
		return
	case !registered:
		d.add(Check{ID: "guard.claude", Layers: []string{LayerGuard}, Status: Warn,
			Summary: "the agent guard is not registered in Claude Code", Fix: ClaudeRegistration(d.Paths.Bin),
			Detail: "install prints the line to run, and the settings fragment it adds; nothing here edits that file"})
		return
	}
	d.add(Check{ID: "guard.claude", Layers: []string{LayerGuard}, Status: OK, Summary: "the agent guard is registered"})
	// Claude Code calls a PreToolUse hook only for the tools its matcher names. A Bash-only
	// registration, which is what v1 wrote, leaves Write, Edit and every MCP server unwatched.
	if len(uncovered) > 0 {
		d.add(Check{ID: "guard.matcher", Layers: []string{LayerGuard}, Status: Warn,
			Summary: "the guard is not called for " + strings.Join(uncovered, ", "),
			Detail:  "its matcher is narrower than " + GuardMatcher + ", so a key written by those tools is not looked for",
			Fix:     ClaudeRegistration(d.Paths.Bin)})
		return
	}
	d.add(Check{ID: "guard.matcher", Layers: []string{LayerGuard}, Status: OK,
		Summary: "the guard is called for Bash, Write, Edit, MultiEdit, NotebookEdit and MCP tools"})
}

func (d *doctor) launchd() {
	for _, j := range jobsFor() {
		layer, id := LayerPoll, "launchd.poll"
		switch j.label {
		case LabelDeep:
			layer, id = LayerDeep, "launchd.deep"
		case LabelUpgrade:
			layer, id = LayerUpgrade, "launchd.upgrade"
		}
		c := Check{ID: id, Layers: []string{layer}, Fix: "keyguard install"}
		path := j.file(d.LaunchDir)
		want := j.plist(d.Paths.Bin, d.Home, d.Paths)
		got, err := os.ReadFile(path)
		switch {
		case err != nil:
			c.Status, c.Summary, c.Detail = Fail, j.label+" has no plist", path
		case !bytes.Equal(got, want):
			c.Status, c.Summary, c.Detail = Warn, j.label+" plist differs from what install writes", path
		default:
			c.Status = OK
		}
		if c.Status != Fail {
			_, perr := d.Run(d.ctx, "launchctl", "print", fmt.Sprintf("gui/%d/%s", d.UID, j.label))
			if perr != nil {
				c.Status, c.Summary, c.Detail = Fail, j.label+" is not loaded in launchd", "launchctl print: "+perr.Error()
			} else if c.Status == OK {
				c.Summary = j.label + " is loaded"
			}
		}
		d.add(c)
	}
}

// sweepAge says how long ago a poll, full or deep run finished. A long run in progress
// holds the lock and writes its record at the end, so a live lock counts as healthy.
func (d *doctor) sweepAge() {
	layers := []string{LayerPoll}
	st, name, ok := LastSweep(d.Paths)
	holder := lockHolder(d.Paths.Lock)
	if holder.alive {
		d.add(Check{ID: "sweep.age", Layers: layers, Status: OK,
			Summary: "a run is in progress (pid " + strconv.Itoa(holder.pid) + " since " + holder.started + ")"})
		return
	}
	if !ok {
		d.add(Check{ID: "sweep.age", Layers: layers, Status: Fail, Summary: "no poll has run yet",
			Fix: "keyguard poll"})
		return
	}
	fin, err := time.Parse(time.RFC3339, st.Finished)
	if err != nil {
		d.add(Check{ID: "sweep.age", Layers: layers, Status: Warn, Summary: "the last run record has no finish time", Detail: name})
		return
	}
	age := d.now.Sub(fin)
	c := Check{ID: "sweep.age", Layers: layers, Detail: fmt.Sprintf("last %s run finished %s ago (%s)", st.Kind, age.Round(time.Second), name), Fix: "keyguard poll"}
	switch {
	case age > pollFailAfter:
		c.Status, c.Summary = Fail, "the last scan was "+humanAge(age)+" ago"
	case age > pollWarnAfter:
		c.Status, c.Summary = Warn, "the last scan was "+humanAge(age)+" ago"
	default:
		c.Status, c.Summary, c.Fix = OK, "the last scan was "+humanAge(age)+" ago", ""
	}
	d.add(c)
}

func humanAge(a time.Duration) string {
	switch {
	case a < 0:
		return "in the future (the clock moved)"
	case a < 90*time.Second:
		return fmt.Sprintf("%d s", int(a.Seconds()))
	case a < 90*time.Minute:
		return fmt.Sprintf("%d min", int(a.Minutes()))
	case a < 48*time.Hour:
		return fmt.Sprintf("%.1f h", a.Hours())
	}
	return fmt.Sprintf("%d days", int(a.Hours()/24))
}

// LastSweep returns the newest poll, full or deep run record. Run files are named by start
// time, so the last name is the latest run; publish checks and selftests are skipped.
func LastSweep(p core.Paths) (st core.RunStats, name string, ok bool) {
	ents, err := os.ReadDir(p.Runs)
	if err != nil {
		return st, "", false
	}
	for i, tries := len(ents)-1, 0; i >= 0 && tries < 100; i-- {
		e := ents[i]
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		tries++
		b, err := os.ReadFile(filepath.Join(p.Runs, e.Name()))
		if err != nil {
			continue
		}
		var s core.RunStats
		if json.Unmarshal(b, &s) != nil {
			continue
		}
		switch s.Kind {
		case "poll", "full", "deep":
			return s, e.Name(), true
		}
	}
	return st, "", false
}

type lockInfo struct {
	pid     int
	started string
	alive   bool
}

// lockHolder reads state/lock without taking it: who holds it and whether they are alive.
func lockHolder(path string) lockInfo {
	b, err := os.ReadFile(path)
	if err != nil {
		return lockInfo{}
	}
	var li lockInfo
	for _, ln := range strings.Split(string(b), "\n") {
		k, v, _ := strings.Cut(ln, "=")
		switch k {
		case "pid":
			li.pid, _ = strconv.Atoi(v)
		case "started":
			li.started = v
		}
	}
	if li.pid > 0 {
		li.alive = syscall.Kill(li.pid, 0) == nil
	}
	return li
}

func (d *doctor) enginesCheck() {
	required := map[string]bool{"betterleaks": true}
	for _, name := range engines.Names {
		path := d.cfg.EnginePaths()[name]
		id := "engine." + name
		layers := []string{LayerEngines}
		if name == "betterleaks" {
			layers = append(layers, LayerCommit, LayerPush)
		}
		c := Check{ID: id, Layers: layers}
		missing := Warn
		if required[name] {
			missing = Fail
		}
		if path == "" || !isExecutable(path) {
			if !d.cfg.UsesEngine(name) {
				c.Status, c.Summary = OK, name+" is not installed, and no tier uses it"
				d.add(c)
				continue
			}
			c.Status, c.Summary = missing, name+" is not installed"
			c.Detail = path
			c.Fix = map[string]string{
				"betterleaks": "brew install betterleaks, then keyguard install", "gitleaks": "install gitleaks and set engines.gitleaks in " + d.Paths.Config,
				"trufflehog": "install trufflehog into ~/.local/bin, then keyguard install", "titus": "install titus into ~/.local/bin, then keyguard install"}[name]
			d.add(c)
			continue
		}
		pin, pinned := d.cfg.Pins[name]
		if d.Quick {
			c.Status, c.Summary = OK, name+" is installed"
			if pinned {
				c.Summary = name + " " + pin.Version + " is installed"
			}
			d.add(c)
			continue
		}
		probe := d.Probe
		if probe == nil {
			probe = RealProbe
		}
		var pp *Pin
		if pinned && pin.SHA256 != "" {
			pp = &pin
		}
		ver, perr := probe(name, path, pp)
		c.Detail = path
		var pe *engines.PinError
		switch {
		case errors.As(perr, &pe):
			// The engine refuses to start (engines.WithPins), so a hook skips it and takes the next
			// of its tier, and a sweep or a publish check fails rather than call itself clean.
			c.Status = Fail
			c.Summary = fmt.Sprintf("%s is not the binary that was pinned (pinned %.12s, found %.12s)", name, pe.Want, pe.Got)
			c.Detail += "; it will not run until it is pinned again on purpose"
			c.Fix = "keyguard engines pin " + name + " <path of the binary you checked>"
		case perr != nil:
			c.Status, c.Summary = Fail, name+" could not be checked: "+scrubLine(perr.Error())
			c.Fix = "reinstall " + name
		case ver == "" || ver == "unknown":
			c.Status, c.Summary = Fail, name+" runs but does not say its version"
			c.Fix = "reinstall " + name
		case !pinned:
			c.Status, c.Summary = Warn, name+" "+ver+" is not pinned"
			c.Fix = "keyguard install"
		case pin.Version != ver:
			c.Status, c.Summary = Warn, fmt.Sprintf("%s changed from %s to %s since install", name, pin.Version, ver)
			c.Detail += "; a new engine can drop a flag a hook relies on, and hooks fail open"
			c.Fix = "keyguard engines check-upgrade, then keyguard engines pin " + name + " <path>"
		case !inBinDir(d.Paths, path):
			// Pinned by hash, so a package upgrade stops it rather than replacing it unseen; but
			// the pinned copy in the data root is what keeps it running through that upgrade.
			c.Status, c.Summary = Warn, fmt.Sprintf("%s %s is pinned where a package manager can replace it", name, ver)
			c.Fix = "keyguard install"
		default:
			c.Status, c.Summary = OK, name+" "+ver+" matches its pin"
		}
		d.add(c)
		if name == "trufflehog" {
			d.trufflehogLock(path)
		}
	}
}

// trufflehogLock: trufflehog swaps its own binary on start unless told not to (STEAL P0-01; it
// went from 3.97.5 to 3.99.8 in the middle of a session) and leaves this lock behind. keyguard
// always starts it with --no-update, so the lock's presence means another tool did, or that an
// old update is still on record. Either way the next one is not what was pinned, so it fails
// until the lock is moved aside (never deleted).
func (d *doctor) trufflehogLock(path string) {
	// Beside the binary that runs, and in ~/.local/bin where the copy it was made from lived on this Mac.
	dirs := []string{filepath.Dir(path), filepath.Join(d.Home, ".local", "bin")}
	var seen []string
	for _, dir := range dirs {
		lock := filepath.Join(dir, "trufflehog-updates.lock")
		if slices.Contains(seen, lock) {
			continue
		}
		seen = append(seen, lock)
		if _, err := os.Stat(lock); err != nil {
			continue
		}
		d.add(Check{ID: "engine.trufflehog.updates", Layers: []string{LayerEngines}, Status: Fail,
			Summary: "trufflehog has updated itself before (" + filepath.Base(lock) + " exists)",
			Detail:  lock + "; keyguard always starts it with --no-update, and the pin refuses a different binary. Move the lock aside so a new one stands out",
			Fix:     "mkdir -p " + shellQuote(filepath.Join(d.Paths.Root, ".superseded")) + " && mv " + shellQuote(lock) + " " + shellQuote(filepath.Join(d.Paths.Root, ".superseded", "trufflehog-updates.lock"))})
		return
	}
}

// scratchCheck: engines spool under <root>/tmp, which has to be private (a scanner's spool files
// can hold raw diff text), and nothing should be left in it between runs. A directory that is
// still there means an engine run died (a hard kill skips its cleanup); a live run lock means
// one is in progress and its directories are in use.
func (d *doctor) scratchCheck() {
	layers := []string{LayerEngines}
	fi, err := os.Lstat(d.Paths.Tmp)
	switch {
	case err != nil:
		d.add(Check{ID: "engines.tmp", Layers: layers, Status: Warn,
			Summary: "the engines' private scratch directory does not exist yet (they fall back to the system temp dir)",
			Detail:  d.Paths.Tmp, Fix: "keyguard install"})
		return
	case fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir():
		d.add(Check{ID: "engines.tmp", Layers: layers, Status: Fail, Summary: "the engines' scratch directory is not a plain directory", Detail: d.Paths.Tmp,
			Fix: "mv " + shellQuote(d.Paths.Tmp) + " " + shellQuote(d.Paths.Tmp+".aside") + " && keyguard install"})
		return
	case fi.Mode().Perm() != 0o700:
		d.add(Check{ID: "engines.tmp", Layers: layers, Status: Warn,
			Summary: fmt.Sprintf("the engines' scratch directory is %04o, want 0700", fi.Mode().Perm()),
			Detail:  "a scanner spools diff text there", Fix: "chmod 700 " + shellQuote(d.Paths.Tmp)})
		return
	}
	left, _ := os.ReadDir(d.Paths.Tmp)
	if len(left) > 0 && !lockHolder(d.Paths.Lock).alive {
		d.add(Check{ID: "engines.tmp", Layers: layers, Status: Warn,
			Summary: plural(len(left), "engine scratch directory was", "engine scratch directories were") + " left behind: a run died",
			Detail:  "they may hold spool files with raw diff text; move them aside and look",
			Fix:     "mkdir -p " + shellQuote(filepath.Join(d.Paths.Root, ".superseded")) + " && mv " + shellQuote(filepath.Join(d.Paths.Tmp, left[0].Name())) + " " + shellQuote(filepath.Join(d.Paths.Root, ".superseded"))})
		return
	}
	d.add(Check{ID: "engines.tmp", Status: OK, Summary: "the engines' scratch directory is private and empty"})
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

// titusCheck: titus keeps every match it finds in a SQLite datastore, raw (20 of 20 planted
// keys were in it, STEAL P0-06), unless it is run with --output :memory:, which the engine
// always does. So a datastore anywhere under the data root means something ran it another way.
// The same check looks that its rule cache is built: compiling the rules takes 2.7 s the first
// time and 30 ms after, and a hook should not be the first to pay.
func (d *doctor) titusCheck() {
	path := d.cfg.EnginePaths()["titus"]
	if path == "" || !isExecutable(path) || !d.cfg.UsesEngine("titus") {
		return
	}
	layers := []string{LayerEngines}
	var stores []string
	skip := d.cfg.MirrorRoot(d.Paths)
	for _, root := range []string{d.Paths.State, d.Paths.Tmp, d.Paths.TitusCache, filepath.Dir(d.Paths.Report), d.Paths.Logs} {
		_ = filepath.WalkDir(root, func(p string, e fs.DirEntry, err error) error {
			switch {
			case err != nil:
				return nil
			case e.IsDir() && p == skip:
				return fs.SkipDir
			case !e.IsDir() && (e.Name() == "datastore.db" || strings.HasSuffix(e.Name(), ".ds")):
				stores = append(stores, p)
			}
			return nil
		})
	}
	if len(stores) > 0 {
		d.add(Check{ID: "engine.titus.cache", Layers: layers, Status: Fail,
			Summary: "titus left a datastore behind, and it keeps every finding in the clear",
			Detail:  stores[0] + "; keyguard runs titus with --output :memory:, so something else ran it",
			Fix:     "mkdir -p " + shellQuote(filepath.Join(d.Paths.Root, ".superseded")) + " && mv " + shellQuote(stores[0]) + " " + shellQuote(filepath.Join(d.Paths.Root, ".superseded")) + "  # it holds raw secrets: delete it yourself once you have looked"})
		return
	}
	if ents, err := os.ReadDir(d.Paths.TitusCache); err != nil || len(ents) == 0 {
		d.add(Check{ID: "engine.titus.cache", Layers: layers, Status: Warn,
			Summary: "titus has no rule cache yet, so its first scan spends about 3 s compiling rules",
			Detail:  d.Paths.TitusCache, Fix: "keyguard install"})
		return
	}
	d.add(Check{ID: "engine.titus.cache", Status: OK, Summary: "titus has its rule cache and no datastore anywhere"})
}

// upgradeCheck reads what the weekly check last decided. It appears only once the check has run.
func (d *doctor) upgradeCheck() {
	rec, ok := LoadUpgrade(d.Paths)
	if !ok {
		return
	}
	layers := []string{LayerUpgrade}
	var ready, failed []string
	for _, e := range rec.Engines {
		if e.Switch && !e.Applied {
			ready = append(ready, e.Engine+" "+e.Latest)
		}
		if e.Error != "" {
			failed = append(failed, e.Engine)
		}
	}
	age := time.Duration(-1)
	if at, err := time.Parse(time.RFC3339, rec.At); err == nil {
		age = d.now.Sub(at)
	}
	switch {
	case len(ready) > 0:
		d.add(Check{ID: "engines.upgrade", Layers: layers, Status: Warn,
			Summary: "a newer engine passes the bench gate: " + strings.Join(ready, ", "),
			Detail:  "recall and precision no worse than the pinned one, no more than 1.10x slower", Fix: "keyguard engines check-upgrade --apply"})
	case age < 0 || age > upgradeEvery:
		d.add(Check{ID: "engines.upgrade", Layers: layers, Status: Warn,
			Summary: "the weekly engine check last ran " + humanAge(age) + " ago", Fix: "keyguard engines check-upgrade"})
	case len(failed) > 0:
		d.add(Check{ID: "engines.upgrade", Layers: layers, Status: Warn,
			Summary: "the weekly engine check could not look at " + strings.Join(failed, ", "), Fix: "keyguard engines check-upgrade"})
	default:
		d.add(Check{ID: "engines.upgrade", Status: OK, Summary: "the weekly engine check ran " + humanAge(age) + " ago; the pinned engines are the best on offer"})
	}
}

// protectionCheck reads the survey of GitHub's own protection that `keyguard github-settings`
// and the daily poll write: reading a file is all the doctor does, since it never writes and a
// survey does. A feature that was on at the last survey and is off now is a failure (STEAL
// P0-19): someone, or something, switched protection off.
func (d *doctor) protectionCheck() {
	layers := []string{LayerGitHub}
	pr, ok := LoadProtection(d.Paths)
	if !ok {
		d.add(Check{ID: "github.protection", Layers: layers, Status: Warn,
			Summary: "GitHub's own secret scanning has not been looked at yet", Fix: "keyguard github-settings"})
		return
	}
	age := time.Duration(-1)
	if at, err := time.Parse(time.RFC3339, pr.At); err == nil {
		age = d.now.Sub(at)
	}
	switch {
	case len(pr.Drift) > 0:
		var what []string
		for _, x := range pr.Drift {
			what = append(what, strings.TrimPrefix(x.Source, "github.com/")+" "+FeatureWord(x.Feature))
		}
		d.add(Check{ID: "github.protection", Layers: layers, Status: Fail,
			Summary: "GitHub protection went off on " + strings.Join(what[:min(3, len(what))], ", ") + moreTail(len(what), 3),
			Detail:  "it was on at the survey before this one; someone switched it off, or the repo left a plan that had it", Fix: "keyguard github-settings --apply"})
	case len(pr.Gaps) > 0:
		d.add(Check{ID: "github.protection", Layers: layers, Status: Warn,
			Summary: plural(len(pr.Gaps), "public repo lacks", "public repos lack") + " secret scanning or push protection",
			Detail:  pr.Headline, Fix: "keyguard github-settings --apply"})
	case age < 0 || age > protectionEvery:
		d.add(Check{ID: "github.protection", Layers: layers, Status: Warn,
			Summary: "GitHub's protection was last surveyed " + humanAge(age) + " ago", Fix: "keyguard github-settings"})
	default:
		d.add(Check{ID: "github.protection", Status: OK, Summary: pr.Headline})
	}
}

func moreTail(n, shown int) string {
	if n > shown {
		return fmt.Sprintf(" and %d more", n-shown)
	}
	return ""
}

// clockCheck compares this Mac's clock with GitHub's (STEAL P0-16). Every cursor and backoff in
// the sweep is GitHub's, so the sweep itself is not hurt; but a Mac two hours off, as this one
// has been, is wrong for the launchd schedule, the notification stamps and the commit dates too.
func (d *doctor) clockCheck() {
	if d.Skew == nil {
		return
	}
	ctx, cancel := context.WithTimeout(d.ctx, 30*time.Second)
	defer cancel()
	skew, err := d.Skew(ctx)
	if err != nil {
		d.add(Check{ID: "clock", Layers: []string{LayerPoll}, Status: Warn,
			Summary: "could not ask GitHub what time it is", Detail: scrubLine(err.Error()), Fix: "gh auth status"})
		return
	}
	if !ghcli.SkewOK(skew) {
		dir := "ahead of"
		if skew < 0 {
			dir, skew = "behind", -skew
		}
		d.add(Check{ID: "clock", Layers: []string{LayerPoll}, Status: Fail,
			Summary: fmt.Sprintf("this Mac's clock is %s %s GitHub's", skew.Round(time.Second), dir),
			Detail:  "keyguard's cursors use GitHub's clock, but launchd's schedule, notification stamps and commit dates use this one",
			Fix:     "System Settings > General > Date & Time: turn on Set time and date automatically"})
		return
	}
	d.add(Check{ID: "clock", Status: OK, Summary: "this Mac's clock is within a minute of GitHub's"})
}

func (d *doctor) rulesCheck() {
	path := d.cfg.Rules
	b, err := os.ReadFile(path)
	switch {
	case err != nil:
		d.add(Check{ID: "rules", Layers: []string{LayerEngines}, Status: Warn,
			Summary: "the extra rules file is missing; engines run on their defaults", Detail: path, Fix: "keyguard install"})
		return
	case !bytes.Equal(b, rules.KeyguardTOML):
		d.add(Check{ID: "rules", Layers: []string{LayerEngines}, Status: Warn,
			Summary: "the rules file differs from this build's", Detail: path, Fix: "keyguard install"})
		return
	default:
		d.add(Check{ID: "rules", Status: OK, Summary: "the rules file is this build's"})
	}
	d.rulesLoad(path, bytes.Count(b, []byte("[[rules]]")))
}

var rulesCountRE = regexp.MustCompile(`OK: (\d+) rules`)

// rulesLoad asks betterleaks itself whether it accepts the file and what it adds (STEAL P0-11): a
// file it cannot load makes every pre-commit scan an engine error, and a hook fails open on one.
// The count has to be the defaults' plus the file's own rules; fewer means a rule id collided with
// a default and replaced it.
func (d *doctor) rulesLoad(rules string, own int) {
	path := d.cfg.EnginePaths()["betterleaks"]
	if d.Quick || path == "" || !isExecutable(path) {
		return
	}
	layers := []string{LayerEngines, LayerCommit, LayerPush}
	count := func(args ...string) (int, error) {
		ctx, cancel := context.WithTimeout(d.ctx, 20*time.Second)
		defer cancel()
		out, err := d.Run(ctx, path, append([]string{"config", "check"}, args...)...)
		if err != nil {
			return 0, err
		}
		m := rulesCountRE.FindSubmatch(out)
		if m == nil {
			return 0, errors.New("no rule count in its answer")
		}
		return strconv.Atoi(string(m[1]))
	}
	with, err := count("-c", rules)
	if err != nil {
		d.add(Check{ID: "rules.betterleaks", Layers: layers, Status: Fail,
			Summary: "betterleaks does not accept the rules file, so staged files are not scanned", Detail: scrubLine(err.Error()), Fix: "keyguard install"})
		return
	}
	base, err := count()
	if err != nil {
		d.add(Check{ID: "rules.betterleaks", Layers: layers, Status: Warn,
			Summary: "betterleaks accepts the rules file, but its default rule count could not be read", Detail: scrubLine(err.Error())})
		return
	}
	if with != base+own {
		d.add(Check{ID: "rules.betterleaks", Layers: layers, Status: Fail,
			Summary: fmt.Sprintf("betterleaks loads %d rules with the file and %d without; the file adds %d, not %d", with, base, with-base, own),
			Detail:  "a rule id in the file is probably the same as a default's and replaced it", Fix: "keyguard install"})
		return
	}
	d.add(Check{ID: "rules.betterleaks", Status: OK, Summary: fmt.Sprintf("betterleaks loads the rules file: %d rules, the %d defaults and %d of keyguard's", with, base, own)})
}

// permWant is the mode a path must have. The store and the salt decide what every git hook
// on this Mac blocks; anyone who can read both can test guesses against them offline.
type permWant struct {
	path   string
	mode   os.FileMode
	dir    bool
	strict bool // key material: a loose mode here is a failure, not a warning
}

func (d *doctor) knownCheck() {
	p := d.Paths
	// The key material (the known dir, the salt, known.json) must be private: anyone who can
	// read the salt and the store can test guesses against them offline. The data root and the
	// state dir only list names, so loose modes there are a warning: the bootstrap script made
	// state/ 0755 on this Mac.
	wants := []permWant{
		{p.Root, 0o700, true, false}, {p.State, 0o700, true, false}, {p.Known, 0o700, true, true},
		{filepath.Join(p.Known, "salt"), 0o600, false, true}, {filepath.Join(p.Known, "known.json"), 0o600, false, true},
	}
	var bad, loose, fix []string
	for _, w := range wants {
		fi, err := os.Lstat(w.path)
		if err != nil {
			continue // a file that is not there is knownStore's business
		}
		var problems []string
		if fi.Mode()&os.ModeSymlink != 0 {
			problems = append(problems, rel(p.Root, w.path)+" is a symlink")
		} else if fi.Mode().Perm() != w.mode {
			problems = append(problems, fmt.Sprintf("%s is %04o, want %04o", rel(p.Root, w.path), fi.Mode().Perm(), w.mode))
			fix = append(fix, fmt.Sprintf("chmod %o %s", w.mode, shellQuote(w.path)))
		}
		if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Getuid() {
			problems = append(problems, rel(p.Root, w.path)+" belongs to another user")
		}
		if w.strict {
			bad = append(bad, problems...)
		} else {
			loose = append(loose, problems...)
		}
	}
	switch {
	case len(bad) > 0:
		d.add(Check{ID: "known.perms", Layers: []string{LayerKnown}, Status: Fail,
			Summary: "the learned-secret store is readable by others", Detail: strings.Join(append(bad, loose...), "; "), Fix: strings.Join(fix, " && ")})
	case len(loose) > 0:
		d.add(Check{ID: "known.perms", Layers: []string{LayerKnown}, Status: Warn,
			Summary: "the data directory is open to other users (the key files inside are private)", Detail: strings.Join(loose, "; "), Fix: strings.Join(fix, " && ")})
	default:
		d.add(Check{ID: "known.perms", Status: OK, Summary: "salt and learned store are private (0600 in 0700)"})
	}

	st, err := known.ReadStore(p.Root)
	switch {
	case err != nil:
		d.add(Check{ID: "known.store", Layers: []string{LayerKnown, LayerRef}, Status: Fail,
			Summary: "known.json cannot be read, so learned keys are not matched", Detail: err.Error(), Fix: "keyguard learn"})
	case st == nil || len(st.Entries) == 0:
		d.add(Check{ID: "known.store", Layers: []string{LayerKnown, LayerRef}, Status: Warn,
			Summary: "no secrets are learned yet, so the zero-false-positive gate has nothing to match", Fix: "keyguard learn"})
	default:
		learned := len(st.Secrets())
		c := Check{ID: "known.store", Layers: []string{LayerKnown}, Status: OK,
			Summary: fmt.Sprintf("%d secrets learned (%d forms)", learned, len(st.Entries)), Detail: "updated " + st.Updated}
		if _, merr := known.LoadMatcher([]string{p.Root}); merr != nil {
			c.Status, c.Layers = Fail, []string{LayerKnown, LayerRef}
			c.Summary, c.Detail, c.Fix = "the learned store does not load: "+merr.Error(), "", "keyguard learn"
		}
		d.add(c)
	}
}

func rel(root, path string) string {
	if r, err := filepath.Rel(root, path); err == nil {
		return r
	}
	return path
}

// stateCheck makes sure the files other commands depend on parse.
func (d *doctor) stateCheck() {
	var bad []string
	for _, f := range []string{d.Paths.Findings, d.Paths.Ignore, d.Paths.Inventory} {
		b, err := os.ReadFile(f)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil || !json.Valid(b) {
			bad = append(bad, rel(d.Paths.Root, f))
		}
	}
	if len(bad) > 0 {
		d.add(Check{ID: "state.files", Layers: []string{LayerPoll}, Status: Fail,
			Summary: "state files that do not parse: " + strings.Join(bad, ", "),
			Detail:  "keyguard leaves a file it cannot read untouched; move it aside to start fresh",
			Fix:     "mv " + shellQuote(filepath.Join(d.Paths.Root, bad[0])) + " " + shellQuote(filepath.Join(d.Paths.Root, bad[0]+".bad"))})
		return
	}
	d.add(Check{ID: "state.files", Status: OK, Summary: "findings, ignore list and inventory parse"})
}

// mirrors counts the bare clones against the inventory. A wiki that was never created has
// no mirror by design, so only repos and gists count as missing.
func (d *doctor) mirrors() {
	srcs, err := inventory.LoadSnapshot(d.Paths.Inventory)
	root := d.cfg.MirrorRoot(d.Paths)
	have, _ := filepath.Glob(filepath.Join(root, "*", "*", "*.git"))
	if err != nil || len(srcs) == 0 {
		d.add(Check{ID: "mirrors", Layers: []string{LayerPoll}, Status: Warn,
			Summary: fmt.Sprintf("%d mirrors, and no inventory to compare them with yet", len(have)), Fix: "keyguard poll"})
		return
	}
	// PLAN.md "Sweep scope": only what a stranger can read is mirrored, so a private repo having
	// no mirror is the design, not a gap. A wiki that was never created has none either.
	watched, private, missing := 0, 0, 0
	for _, s := range srcs {
		if !s.Visibility.Exposed() {
			private++
			continue
		}
		watched++
		if s.Kind == "wiki" {
			continue
		}
		if p := mirrorPath(root, s.ID); p != "" {
			if _, err := os.Stat(p); err != nil {
				missing++
			}
		}
	}
	if missing > 0 {
		d.add(Check{ID: "mirrors", Layers: []string{LayerPoll}, Status: Warn,
			Summary: fmt.Sprintf("%d mirrors; %d of %d watched sources have none yet", len(have), missing, watched),
			Detail:  "the next poll clones them", Fix: "keyguard sync"})
		return
	}
	d.add(Check{ID: "mirrors", Status: OK,
		Summary: fmt.Sprintf("%d mirrors for %d watched sources (%d private left alone)", len(have), watched, private)})
}

// mirrorPath is where the mirror of a source id lives: <root>/<host>/<owner>/<name>.git, the
// layout the bootstrap script made. It is worked out here and not by asking the mirror
// package, whose constructor makes the directory: the doctor must not write.
func mirrorPath(root, id string) string {
	parts := strings.Split(id, "/")
	if len(parts) != 3 {
		return ""
	}
	for _, p := range parts {
		if p == "" || p == "." || p == ".." || strings.ContainsAny(p, `\:`) {
			return ""
		}
	}
	return filepath.Join(root, parts[0], parts[1], parts[2]+".git")
}

// SelftestRecord is state/selftest.json: the last time every layer was proved to work.
type SelftestRecord struct {
	At      string          `json:"at"`
	OK      bool            `json:"ok"`
	Seconds float64         `json:"seconds"`
	Layers  []SelftestLayer `json:"layers"`
}

// SelftestLayer is one layer's result in a selftest.
type SelftestLayer struct {
	Name    string  `json:"name"`
	OK      bool    `json:"ok"`
	Detail  string  `json:"detail"`
	Seconds float64 `json:"seconds"`
}

// SelftestPath is where the last selftest is recorded.
func SelftestPath(p core.Paths) string { return filepath.Join(p.State, "selftest.json") }

// LoadSelftest reads the last selftest record; ok is false when there is none.
func LoadSelftest(p core.Paths) (rec SelftestRecord, ok bool) {
	b, err := os.ReadFile(SelftestPath(p))
	if err != nil || json.Unmarshal(b, &rec) != nil {
		return SelftestRecord{}, false
	}
	return rec, true
}

func (d *doctor) selftest() {
	layers := []string{LayerSelftest}
	rec, ok := LoadSelftest(d.Paths)
	if !ok {
		d.add(Check{ID: "selftest.last", Layers: layers, Status: Warn, Summary: "the selftest has never run", Fix: "keyguard selftest"})
		return
	}
	at, err := time.Parse(time.RFC3339, rec.At)
	if err != nil {
		d.add(Check{ID: "selftest.last", Layers: layers, Status: Warn, Summary: "the selftest record has no time", Fix: "keyguard selftest"})
		return
	}
	age := d.now.Sub(at)
	var failed []string
	for _, l := range rec.Layers {
		if !l.OK {
			failed = append(failed, l.Name)
		}
	}
	switch {
	case !rec.OK:
		d.add(Check{ID: "selftest.last", Layers: layers, Status: Fail,
			Summary: "the last selftest failed: " + strings.Join(failed, ", "), Detail: humanAge(age) + " ago", Fix: "keyguard selftest"})
	case age > selftestEvery:
		d.add(Check{ID: "selftest.last", Layers: layers, Status: Warn,
			Summary: "the last selftest was " + humanAge(age) + " ago", Fix: "keyguard selftest"})
	default:
		d.add(Check{ID: "selftest.last", Layers: layers, Status: OK,
			Summary: fmt.Sprintf("selftest passed %s ago (%d layers)", humanAge(age), len(rec.Layers))})
	}
}

func (d *doctor) notifyCheck() {
	if _, err := os.Stat("/usr/bin/osascript"); err != nil {
		d.add(Check{ID: "notify", Status: Warn, Summary: "osascript is missing, so macOS banners cannot be shown"})
		return
	}
	if d.cfg.Notify.IMessageTo == "" {
		d.add(Check{ID: "notify", Status: OK, Summary: "banners on; iMessage for critical is off (no notify.imessage_to)"})
		return
	}
	// notify.New refuses a target that is not a phone number or an email, at poll time; say so
	// here, where it can be fixed, instead of in a launchd log nobody reads.
	if _, err := notify.New(notify.Config{IMessageTo: d.cfg.Notify.IMessageTo}); err != nil {
		d.add(Check{ID: "notify", Status: Warn, Summary: "notify.imessage_to is not a phone number or an email, so iMessage is off",
			Detail: scrubLine(err.Error()), Fix: "edit notify.imessage_to in " + d.Paths.Config})
		return
	}
	// notify.New only keeps a target from turning into a flag, and a bare number or a few words
	// pass it. iMessage needs an address Messages can resolve: a phone number with its country
	// code, or an email. The doctor is stricter than the notifier on purpose, because a target
	// that sends nothing is an alert nobody gets.
	if why := unreachableTarget(d.cfg.Notify.IMessageTo); why != "" {
		d.add(Check{ID: "notify", Status: Warn, Summary: "notify.imessage_to " + why + ", so iMessage alerts may never arrive",
			Detail: "use +<country code><number>, such as +1 followed by ten digits, or an email address",
			Fix:    "edit notify.imessage_to in " + d.Paths.Config})
		return
	}
	d.add(Check{ID: "notify", Status: OK, Summary: "banners and iMessage for critical are on"})
}

var emailTarget = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)

// unreachableTarget says why an iMessage target would not reach anyone, or "" if it looks
// reachable. It never repeats the target.
func unreachableTarget(t string) string {
	if emailTarget.MatchString(t) {
		return ""
	}
	if strings.HasPrefix(t, "+") {
		digits := 0
		for _, r := range t[1:] {
			switch {
			case r >= '0' && r <= '9':
				digits++
			case r == ' ' || r == '-' || r == '(' || r == ')' || r == '.':
			default:
				return "is not a phone number or an email address"
			}
		}
		if digits < 8 || digits > 15 {
			return "has too few or too many digits for a phone number"
		}
		return ""
	}
	if strings.Trim(t, "0123456789 ()-.") == "" {
		return "has no country code (+1 for the US)"
	}
	return "is not a phone number or an email address"
}

// ghAuth asks gh for each account's token and throws it away: only whether it can be had
// matters, and the token never leaves this function.
func (d *doctor) ghAuth() {
	var missing []string
	for _, acct := range d.cfg.Accounts {
		out, err := d.Run(d.ctx, "gh", "auth", "token", "--user", acct)
		clear(out)
		if err != nil {
			missing = append(missing, acct)
		}
	}
	if len(missing) > 0 {
		d.add(Check{ID: "gh.auth", Layers: []string{LayerPoll}, Status: Fail,
			Summary: "no gh login for " + strings.Join(missing, ", "),
			Fix:     "gh auth login (then gh auth switch back; keyguard never changes the active account)"})
		return
	}
	d.add(Check{ID: "gh.auth", Status: OK, Summary: fmt.Sprintf("gh has a login for each of %d account(s)", len(d.cfg.Accounts))})
}

// CheckInfo describes one check without running it. `doctor capabilities` prints the catalog,
// and a test compares it with what a real run produces, so the list an agent reads cannot say
// something the doctor does not do.
type CheckInfo struct {
	ID       string   `json:"id"`
	Layers   []string `json:"layers,omitempty"`
	Looks    string   `json:"looks_at"`
	Fix      string   `json:"fix,omitempty"`      // the command that repairs it, when one command does
	Quick    bool     `json:"quick"`              // still runs under --quick
	Optional bool     `json:"optional,omitempty"` // appears only when its condition holds
}

// Catalog lists every check, in the order a report shows them.
func Catalog() []CheckInfo {
	all := []string{LayerCommit, LayerPush, LayerRef}
	pin := "installed, its version, and its binary against the pin in config.json: an engine that is not the pinned binary does not run"
	return []CheckInfo{
		{ID: "config", Layers: []string{LayerEngines}, Looks: "state/config.json parses and has no unusable entries", Quick: true},
		{ID: "git.version", Layers: all, Looks: "git is 2.54 or newer, the first to run config-based hooks (and well past 2.40, which GIT_ATTR_SOURCE needs)", Quick: true},
		{ID: "hooks.precommit", Layers: []string{LayerCommit}, Looks: "the pre-commit entry is in the global git config and is the one install writes", Fix: "keyguard install", Quick: true},
		{ID: "hooks.prepush", Layers: []string{LayerPush}, Looks: "the pre-push entry is in the global git config and is the one install writes", Fix: "keyguard install", Quick: true},
		{ID: "hooks.reftx", Layers: []string{LayerRef}, Looks: "the reference-transaction entry is in the global git config and is the one install writes", Fix: "keyguard install", Quick: true},
		{ID: "hooks.commitmsg", Layers: []string{LayerCommit}, Looks: "the commit-msg entry is in the global git config and is the one install writes (a key typed into a message)", Fix: "keyguard install", Quick: true},
		{ID: "hooks.binary", Layers: all, Looks: "the binary the hooks run exists, is executable, runs and is the one installed (the hooks exit 0 without it)", Fix: "keyguard install", Quick: true},
		{ID: "guard.claude", Layers: []string{LayerGuard}, Looks: "the agent guard is registered in Claude Code's settings (install prints the line and the settings fragment; nothing here edits that file)", Quick: true},
		{ID: "guard.matcher", Layers: []string{LayerGuard}, Looks: "the registered matcher names Bash, Write, Edit, MultiEdit, NotebookEdit and MCP tools, so Claude Code calls the guard for them", Quick: true, Optional: true},
		{ID: "launchd.poll", Layers: []string{LayerPoll}, Looks: "the one-minute poll agent's plist is what install writes and launchd has it loaded", Fix: "keyguard install", Quick: true},
		{ID: "launchd.deep", Layers: []string{LayerDeep}, Looks: "the weekly deep agent's plist is what install writes and launchd has it loaded", Fix: "keyguard install", Quick: true},
		{ID: "launchd.upgrade", Layers: []string{LayerUpgrade}, Looks: "the weekly engine-check agent's plist is what install writes and launchd has it loaded", Fix: "keyguard install", Quick: true},
		{ID: "sweep.age", Layers: []string{LayerPoll}, Looks: "how long ago the last poll, full or deep run finished (a live run lock counts as running)", Fix: "keyguard poll", Quick: true},
		{ID: "engine.betterleaks", Layers: append([]string{LayerEngines}, LayerCommit, LayerPush), Looks: pin, Fix: "keyguard install", Quick: true},
		{ID: "engine.gitleaks", Layers: []string{LayerEngines}, Looks: pin, Fix: "keyguard install", Quick: true},
		{ID: "engine.trufflehog", Layers: []string{LayerEngines}, Looks: pin, Fix: "keyguard install", Quick: true},
		{ID: "engine.trufflehog.updates", Layers: []string{LayerEngines}, Looks: "trufflehog has not replaced its own binary (its updates lock sits beside it)", Quick: false, Optional: true},
		{ID: "engine.titus", Layers: []string{LayerEngines}, Looks: pin, Fix: "keyguard install", Quick: true},
		{ID: "engine.titus.cache", Layers: []string{LayerEngines}, Looks: "titus has built its rule cache under the data root, and no datastore.db or *.ds exists anywhere in it (titus keeps findings in the clear there)", Fix: "keyguard install", Quick: true, Optional: true},
		{ID: "engines.tmp", Layers: []string{LayerEngines}, Looks: "the engines' scratch directory exists, is mode 0700 and holds nothing left by a run that died", Fix: "keyguard install", Quick: true},
		{ID: "engines.upgrade", Layers: []string{LayerUpgrade}, Looks: "what the weekly engine check last decided: whether a newer engine passes the bench gate, and how long ago it ran", Fix: "keyguard engines check-upgrade", Quick: true, Optional: true},
		{ID: "rules", Layers: []string{LayerEngines}, Looks: "the installed rules file is this build's", Fix: "keyguard install", Quick: true},
		{ID: "rules.betterleaks", Layers: []string{LayerEngines, LayerCommit, LayerPush}, Looks: "betterleaks loads the rules file and counts its default rules plus keyguard's own", Fix: "keyguard install", Quick: false, Optional: true},
		{ID: "known.perms", Layers: []string{LayerKnown}, Looks: "the learned store's directory is 0700 and its salt and known.json 0600, none a symlink or another user's (root and state being 0700 is a warning, not a failure)", Quick: true},
		{ID: "known.store", Layers: []string{LayerKnown, LayerRef}, Looks: "the learned store parses, loads with its salt, and holds secrets", Fix: "keyguard learn", Quick: true},
		{ID: "state.files", Layers: []string{LayerPoll}, Looks: "findings, ignore list and inventory parse", Quick: true},
		{ID: "mirrors", Layers: []string{LayerPoll}, Looks: "every public repo and gist in the inventory has a mirror on disk (private repos have none, by design)", Fix: "keyguard sync", Quick: true},
		{ID: "selftest.last", Layers: []string{LayerSelftest}, Looks: "the last selftest passed and is less than a day old", Fix: "keyguard selftest", Quick: true},
		{ID: "notify", Looks: "macOS banners are possible and the iMessage target, if set, is a phone number or an email", Quick: true},
		{ID: "github.protection", Layers: []string{LayerGitHub}, Looks: "the last survey of GitHub's own secret scanning: no feature that was on has gone off, and no public repo lacks one", Fix: "keyguard github-settings", Quick: true},
		{ID: "gh.auth", Layers: []string{LayerPoll}, Looks: "gh has a login for every configured account (the token is never read into the report)", Quick: false},
		{ID: "clock", Layers: []string{LayerPoll}, Looks: "this Mac's clock is within a minute of GitHub's (one free request); every cursor in the sweep is GitHub's, but launchd's schedule and the commit dates are this Mac's", Quick: false, Optional: true},
	}
}

// Fixers lists the distinct commands the catalog names as repairs.
func Fixers() []string {
	var out []string
	for _, c := range Catalog() {
		if c.Fix != "" && !slices.Contains(out, c.Fix) {
			out = append(out, c.Fix)
		}
	}
	return out
}

// userOnly says a fix is not for an agent to run. Registering the guard edits Claude Code's
// settings, and pinning an engine says which binary every gate will trust: both are their call.
func userOnly(fix string) bool {
	return strings.HasPrefix(fix, "! ") || strings.Contains(fix, "keyguard engines pin") || strings.Contains(fix, "engines check-upgrade --apply")
}

// Triage is the whole answer in one call, for a caller that will act on it: what is wrong,
// the commands that fix it, and which of them only the user may run.
type Triage struct {
	SchemaVersion int      `json:"schema_version"`
	Summary       string   `json:"summary"`
	Healthy       bool     `json:"healthy"`
	Findings      []Check  `json:"findings"`        // not-ok checks, failures first
	Actions       []string `json:"actions_planned"` // distinct fixes an agent may run, most urgent first
	NeedsUser     []string `json:"needs_user"`      // fixes only the user runs (they edit their Claude Code settings, or say which scanner binary to trust)
	Recommended   string   `json:"recommended_command"`
	Capabilities  string   `json:"capabilities_command"`
}

// Triage folds a report into the one-call answer.
func (r Report) Triage() Triage {
	t := Triage{SchemaVersion: DoctorSchemaVersion, Healthy: r.Healthy, Findings: []Check{}, Actions: []string{}, NeedsUser: []string{},
		Capabilities: "keyguard doctor capabilities"}
	for _, want := range []Status{Fail, Warn} {
		for _, c := range r.Checks {
			if c.Status != want {
				continue
			}
			t.Findings = append(t.Findings, c)
			switch {
			case c.Fix == "":
			case userOnly(c.Fix):
				if !slices.Contains(t.NeedsUser, c.Fix) {
					t.NeedsUser = append(t.NeedsUser, c.Fix)
				}
			case !slices.Contains(t.Actions, c.Fix):
				t.Actions = append(t.Actions, c.Fix)
			}
		}
	}
	switch {
	case r.Healthy:
		t.Summary = "healthy: every check passed"
	default:
		t.Summary = fmt.Sprintf("%d failing, %d warning, %d ok", r.Failures, r.Warnings, r.Ok)
	}
	if len(t.Actions) > 0 {
		t.Recommended = t.Actions[0]
	}
	return t
}
