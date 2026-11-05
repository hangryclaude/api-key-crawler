package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"keyguard/internal/core"
	"keyguard/internal/engines"
	"keyguard/internal/install"
	"keyguard/internal/upgrade"
)

// cmdEngines is the scanners keyguard runs. Each is a copy in <root>/bin whose sha256 is
// recorded, and a binary that is not the recorded one does not start (STEAL P0-01): an engine
// that updates itself, or that a package manager upgrades, can change what is found or drop a
// flag a hook depends on, and hooks fail open. Changing which binary is trusted is therefore a
// deliberate act, and these are the two ways to do it.
func (c *cli) cmdEngines(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(c.err, "usage: keyguard engines list | pin <engine> [<path>] | check-upgrade [--apply]")
		return exitUsage
	}
	switch args[0] {
	case "list":
		return c.enginesList(args[1:])
	case "pin":
		return c.enginesPin(args[1:])
	case "check-upgrade":
		return c.enginesCheckUpgrade(args[1:])
	}
	fmt.Fprintf(c.err, "keyguard: engines has no %q; it has list, pin and check-upgrade\n", args[0])
	return exitUsage
}

// ----- list -----

func (c *cli) enginesList(args []string) int {
	f := c.flagSet("engines list", "engines list [--json]\n\nEach engine, its version, whether its binary is the one that was pinned, and where it is.")
	asJSON := f.Bool("json", false, "machine-readable output")
	if _, code, ok := c.parse(f, args); !ok {
		return code
	}
	p := c.paths()
	cfg := c.config(p)
	type row struct {
		Engine  string `json:"engine"`
		Version string `json:"version,omitempty"`
		State   string `json:"state"`
		Path    string `json:"path,omitempty"`
		SHA256  string `json:"sha256,omitempty"`
	}
	var rows []row
	exit := exitOK
	for _, name := range engines.Names {
		r := row{Engine: name, Path: cfg.EnginePaths()[name]}
		pin, pinned := cfg.Pins[name]
		r.SHA256 = pin.SHA256
		switch {
		case r.Path == "":
			r.State = "not installed"
		default:
			e, err := engines.New(name, r.Path, nopFingerprinter{}, cfg.EngineOptions(p)...)
			switch {
			case err != nil || !e.Available():
				r.State = "not installed"
			case engines.CheckPin(e) != nil:
				r.State, exit = "CHANGED since it was pinned: it will not run", exitFound
			case !pinned:
				r.Version, r.State = e.Version(), "not pinned"
			default:
				r.Version, r.State = e.Version(), "pinned"
			}
		}
		rows = append(rows, r)
	}
	if *asJSON {
		c.printJSON(rows)
		return exit
	}
	out := [][]string{{"ENGINE", "VERSION", "STATE", "PATH"}}
	for _, r := range rows {
		out = append(out, []string{r.Engine, r.Version, r.State, c.tilde(r.Path)})
	}
	table(c.out, "", out)
	return exit
}

// nopFingerprinter is for tools that only ask an engine its version or whether it may run.
type nopFingerprinter struct{}

func (nopFingerprinter) FP(string) string { return "" }

// ----- pin -----

func (c *cli) enginesPin(args []string) int {
	f := c.flagSet("engines pin", "engines pin <engine> [<path>]\n\nCopies the engine binary to <root>/bin/<engine>-<version>, checks the copy by hash, records its sha256 in\nconfig.json and points the engine at the copy. Without a path it takes the one on this Mac (PATH, then\nHomebrew, ~/.local/bin). Pinning says: this is the binary I trust. Do it for one you have looked at.")
	pos, code, ok := c.parse(f, args)
	if !ok {
		return code
	}
	if len(pos) < 1 || len(pos) > 2 {
		return c.usageErr(f, "pin takes an engine name and, optionally, the path of its binary")
	}
	name := pos[0]
	if !contains(engines.Names, name) {
		return c.failf("%q is not an engine keyguard has (%s)", name, strings.Join(engines.Names, ", "))
	}
	p := c.paths()
	src := ""
	if len(pos) == 2 {
		abs, err := filepath.Abs(pos[1])
		if err != nil {
			return c.failf("%s", safeErr(err))
		}
		src = abs
	} else if src = install.DiscoverEngines(c.home())[name]; src == "" {
		return c.failf("no %s binary was found on this Mac; name its path", name)
	}
	dst, pin, created, err := install.PinEngine(p, name, src, c.now())
	if err != nil {
		return c.failf("%s", safeErr(err))
	}
	if err := install.SavePin(p, c.home(), name, dst, pin); err != nil {
		return c.failf("%s", safeErr(err))
	}
	verb := "pinned"
	if !created {
		verb = "already pinned"
	}
	fmt.Fprintf(c.out, "%s %s %s at %s (sha256 %.16s…)\n", verb, name, pin.Version, c.tilde(dst), pin.SHA256)
	if cfg := c.config(p); name == "titus" && cfg.UsesEngine(name) {
		if err := install.PrewarmEngine(c.ctx, cfg, p, name); err != nil {
			c.warnf("titus did not build its rule cache (%s); its first scan will", safeErr(err))
		}
	}
	return exitOK
}

// ----- check-upgrade -----

// upgradeRoot is where the check stages what it downloads and the corpus it scores on: under the
// data root, which is in no git work tree (the bench refuses one) and is private.
func upgradeRoot(p core.Paths) string { return filepath.Join(p.Root, "cache", "upgrade") }

func (c *cli) enginesCheckUpgrade(args []string) int {
	f := c.flagSet("engines check-upgrade", "engines check-upgrade [--apply] [--engines a,b] [--runs N] [--json]\n\nThe weekly job. For each pinned engine it asks GitHub for the newest stable release, downloads the macOS\nbuild, checks it against the project's published checksums, scores it and the pinned one on the bench\ncorpus, and decides: recall and precision no worse than the pinned engine's, one scan no more than\n1.10 times as slow. Release candidates are skipped. It writes the decision to state/upgrade/ and changes\nnothing else; the doctor shows a warning while a better engine waits.\n\n--apply  also pin the candidates that passed: copy each to <root>/bin, record its hash, point config.json\n         at it. The pinned copy it replaces stays in <root>/bin, so going back is `engines pin`.")
	apply := f.Bool("apply", false, "pin the candidates that passed")
	only := f.String("engines", "", "comma-separated engines to check (default: every pinned engine)")
	runs := f.Int("runs", 5, "times each binary is scored; the fastest run is its speed")
	asJSON := f.Bool("json", false, "machine-readable output")
	if _, code, ok := c.parse(f, args); !ok {
		return code
	}
	if *runs < 1 {
		return c.usageErr(f, "--runs must be at least 1")
	}
	p := c.paths()
	cfg := c.config(p)
	names := splitList(*only)
	pins := map[string]upgrade.Pinned{}
	for _, name := range engines.Names {
		if len(names) > 0 && !contains(names, name) {
			continue
		}
		path := cfg.EnginePaths()[name]
		if path == "" {
			continue
		}
		e, err := engines.New(name, path, nopFingerprinter{}, cfg.EngineOptions(p)...)
		if err != nil || !e.Available() {
			continue
		}
		if perr := engines.CheckPin(e); perr != nil {
			// The engine in use is not the one that was pinned: scoring it would score a stranger.
			c.warnf("%s is not the binary that was pinned; it was not checked (see `keyguard doctor`)", name)
			continue
		}
		ver := cfg.Pins[name].Version
		if ver == "" {
			ver = e.Version()
		}
		pins[name] = upgrade.Pinned{Path: path, Version: ver}
	}
	if len(pins) == 0 {
		return c.failf("no pinned engine to check; run `keyguard install`")
	}

	root := upgradeRoot(p)
	if err := os.MkdirAll(root, 0o700); err != nil {
		return c.failf("%s", safeErr(err))
	}
	rules := ""
	if cfg.Rules != "" {
		if _, err := os.Stat(cfg.Rules); err == nil {
			rules = cfg.Rules
		}
	}
	benchDir, err := os.MkdirTemp(root, "bench-")
	if err != nil {
		return c.failf("%s", safeErr(err))
	}
	defer os.RemoveAll(benchDir) // our own scratch, made a moment ago: a corpus of fakes
	var scorer upgrade.Scorer = &upgrade.BenchScorer{
		NewEngine: func(name, bin string, f core.Fingerprinter) (core.Engine, error) { return engines.New(name, bin, f) },
		Dir:       benchDir, Rules: rules,
	}
	if c.seams.scorer != nil {
		scorer = c.seams.scorer
	}
	opts := upgrade.Options{API: c.seams.upgradeAPI, Dir: root, Runs: *runs, Scorer: scorer}
	decisions := opts.CheckAll(c.ctx, pins)
	if c.ctx.Err() != nil {
		return c.failf("check-upgrade: %s", safeErr(c.ctx.Err()))
	}

	rec := install.UpgradeRecord{At: c.now().UTC().Format(time.RFC3339)}
	failed := false
	for _, d := range decisions {
		e := install.UpgradeEngine{Engine: d.Engine, Pinned: d.Pinned.Version, Latest: d.Latest, Switch: d.Switch, Why: d.Reasons, Error: d.Err}
		if d.Err != "" {
			failed = true
		}
		if *apply && d.Switch && d.Candidate != nil {
			if err := c.applyUpgrade(p, d); err != nil {
				e.Error, failed = safeErr(err), true
			} else {
				e.Applied = true
			}
		}
		rec.Engines = append(rec.Engines, e)
		c.cleanStaging(root, d.Dir)
	}
	if err := install.SaveUpgrade(p, rec, c.now().UTC().Format("20060102T150405Z")); err != nil {
		c.warnf("the decision could not be recorded: %s", safeErr(err))
	}

	if *asJSON {
		c.printJSON(decisions)
	} else {
		c.printUpgrade(decisions, rec, *apply)
	}
	if failed {
		return exitFailed
	}
	return exitOK
}

// applyUpgrade pins the candidate that passed. The copy is checked against the hash the check
// computed from the download, which in turn matched the project's published checksums, so what
// is pinned is the release and not whatever happens to be at a path.
func (c *cli) applyUpgrade(p core.Paths, d upgrade.Decision) error {
	dst, pin, _, err := install.PinEngine(p, d.Engine, d.Candidate.Path, c.now())
	if err != nil {
		return err
	}
	if pin.SHA256 != d.Candidate.SHA256 {
		return fmt.Errorf("the copy of %s is not the release that was checked", d.Engine)
	}
	if err := install.SavePin(p, c.home(), d.Engine, dst, pin); err != nil {
		return err
	}
	if cfg := c.config(p); d.Engine == "titus" && cfg.UsesEngine("titus") {
		if err := install.PrewarmEngine(c.ctx, cfg, p, "titus"); err != nil {
			c.warnf("titus did not build its rule cache (%s); its first scan will", safeErr(err))
		}
	}
	return nil
}

// cleanStaging removes the directory a check staged a download in. It is ours, made a moment
// ago under the upgrade root, and only a path under that root is touched.
func (c *cli) cleanStaging(root, dir string) {
	if dir == "" {
		return
	}
	rel, err := filepath.Rel(root, dir)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
		return
	}
	_ = os.RemoveAll(dir)
}

func (c *cli) printUpgrade(decisions []upgrade.Decision, rec install.UpgradeRecord, apply bool) {
	rows := [][]string{{"ENGINE", "PINNED", "LATEST", "VERDICT"}}
	for i, d := range decisions {
		verdict := "current"
		switch {
		case d.Err != "":
			verdict = "could not check: " + d.Err
		case d.Candidate == nil:
		case rec.Engines[i].Applied:
			verdict = "SWITCHED to " + d.Candidate.Version
		case d.Switch:
			verdict = "BETTER: passes the gate (run with --apply to pin it)"
		default:
			verdict = "kept: the candidate fails the gate"
		}
		rows = append(rows, []string{d.Engine, d.Pinned.Version, d.Latest, verdict})
	}
	table(c.out, "", rows)
	var why []string
	for _, d := range decisions {
		if d.Candidate != nil {
			for _, r := range d.Reasons {
				why = append(why, d.Engine+" "+d.Candidate.Version+": "+r)
			}
		}
		for _, s := range d.Skipped {
			why = append(why, fmt.Sprintf("%s: %s skipped (%s)", d.Engine, s.Tag, s.Why))
		}
	}
	sort.Strings(why)
	if len(why) > 0 {
		fmt.Fprintln(c.out)
		for _, w := range why {
			fmt.Fprintf(c.out, "  %s\n", w)
		}
	}
	if !apply {
		for _, e := range rec.Engines {
			if e.Switch {
				fmt.Fprintln(c.out, "\nA better engine is waiting. `keyguard engines check-upgrade --apply` pins it; nothing was changed.")
				break
			}
		}
	}
}
