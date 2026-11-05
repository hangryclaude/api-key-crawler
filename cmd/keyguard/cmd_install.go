package main

import (
	"encoding/json"
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"

	"keyguard/internal/install"
)

func (c *cli) installOptions(f installFlags) (install.Options, error) {
	exe, err := c.exe()
	if err != nil {
		return install.Options{}, err
	}
	return install.Options{
		Paths: c.paths(), Executable: exe, NoLaunchd: f.noLaunchd, NoBootstrap: f.noBootstrap,
		LaunchDir: f.launchDir, DryRun: f.dry, InPlace: f.inPlace, Run: c.seams.run, Now: c.seams.now,
	}, nil
}

type installFlags struct {
	noLaunchd, noBootstrap, dry, asJSON, verbose, inPlace bool
	launchDir                                             string
}

func (c *cli) installFlags(name, usage string, args []string) (installFlags, int, bool) {
	var v installFlags
	f := c.flagSet(name, usage)
	f.BoolVar(&v.dry, "dry-run", false, "say what would change and change nothing")
	f.BoolVar(&v.noLaunchd, "no-launchd", false, "hooks, binary, rules and config only; no launchd agents")
	f.BoolVar(&v.noBootstrap, "no-bootstrap", false, "write the launchd plists but do not load them")
	f.BoolVar(&v.inPlace, "in-place", false, "pin the engines where they are instead of copying them into <root>/bin (a package upgrade then stops them)")
	f.StringVar(&v.launchDir, "launchd-dir", "", "where the plists go (default ~/Library/LaunchAgents)")
	f.BoolVar(&v.asJSON, "json", false, "machine-readable result")
	f.BoolVar(&v.verbose, "v", false, "also list what was already right")
	_, code, ok := c.parse(f, args)
	return v, code, ok
}

func (c *cli) cmdInstall(args []string) int {
	v, code, ok := c.installFlags("install", "install [--dry-run] [--no-launchd] [--no-bootstrap] [--launchd-dir DIR] [--in-place] [--json] [-v]\n\nPuts keyguard on this Mac: copies this binary and each scanner to <root>/bin (the scanners pinned by hash,\nso a binary that changes does not run), makes the keyring, writes the rules and config.json, adds four hooks\nto the global git config (GIT_CONFIG_GLOBAL if set, else ~/.gitconfig: pre-commit, commit-msg, pre-push,\nreference-transaction), and loads three launchd agents (poll every minute, deep scan Sunday 03:30,\nengine check Saturday 04:00). Safe to run again; undone by `keyguard uninstall`.\n\nIt prints the line that registers the agent guard in Claude Code, and the settings it adds; it never edits\nthat file itself.", args)
	if !ok {
		return code
	}
	o, err := c.installOptions(v)
	if err != nil {
		return c.failf("%s", safeErr(err))
	}
	res, err := install.Install(c.ctx, o)
	if v.asJSON {
		c.printJSON(res)
	} else if res != nil {
		c.printActions(res, v.verbose, v.dry, "installed", "already installed: nothing needed changing")
	}
	if err != nil {
		return c.failf("install: %s", safeErr(err))
	}
	if v.asJSON || v.dry {
		return exitOK
	}
	fmt.Fprintln(c.out, "\nNext:")
	fmt.Fprintln(c.out, "  1. Register the agent guard. It adds this to ~/.claude/settings.json (a dated backup is kept):")
	for _, ln := range strings.Split(res.Snippet, "\n") {
		fmt.Fprintf(c.out, "       %s\n", ln)
	}
	fmt.Fprintln(c.out, "     Run this line in Claude Code to add it (keyguard never edits that file):")
	fmt.Fprintf(c.out, "       %s\n", res.Claude)
	fmt.Fprintln(c.out, "  2. keyguard learn      reads this Mac's secrets once and stores only hashes")
	fmt.Fprintln(c.out, "  3. keyguard selftest   proves each layer stops a planted fake")
	fmt.Fprintln(c.out, "  4. keyguard doctor     anything still wrong, with the command that fixes it")
	return exitOK
}

func (c *cli) cmdUninstall(args []string) int {
	v, code, ok := c.installFlags("uninstall", "uninstall [--dry-run] [--json] [-v]\n\nTakes out exactly what `install` put in, as state/install.json records it: the git hooks (the config file\nis put back byte for byte if nobody has touched it since), the launchd agents, the binary and the rules.\nFiles are moved to <root>/.uninstalled/, never deleted. Findings, the learned store, mirrors and config.json stay.", args)
	if !ok {
		return code
	}
	o, err := c.installOptions(v)
	if err != nil {
		return c.failf("%s", safeErr(err))
	}
	res, err := install.Uninstall(c.ctx, o)
	if v.asJSON {
		c.printJSON(res)
	} else if res != nil {
		c.printActions(res, v.verbose, v.dry, "uninstalled", "nothing to uninstall")
	}
	if err != nil {
		return c.failf("uninstall: %s", safeErr(err))
	}
	if !v.asJSON && res.Changed() {
		fmt.Fprintln(c.out, "\nThe agent guard stays registered in Claude Code until you take it out. Run this line there:")
		fmt.Fprintf(c.out, "  %s\n", res.Claude)
	}
	return exitOK
}

func (c *cli) printJSON(v any) {
	enc := json.NewEncoder(c.out)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func (c *cli) printActions(res *install.Result, verbose, dry bool, done, none string) {
	head := done
	if dry {
		head = "dry run: would have " + done
	}
	if !res.Changed() {
		head = none
	}
	fmt.Fprintln(c.out, head)
	var rows [][]string
	gitRow := map[string]int{} // change -> its row, so six config keys read as one line
	gitKeys := map[string]int{}
	for _, a := range res.Actions {
		if a.Change == "unchanged" && !verbose {
			continue
		}
		if a.Step == "git" && !verbose && strings.HasPrefix(a.Target, "hook.") {
			i, ok := gitRow[a.Change]
			if !ok {
				i = len(rows)
				gitRow[a.Change] = i
				rows = append(rows, []string{"git", a.Change, "", c.tilde(a.Detail)})
			}
			gitKeys[a.Change]++
			rows[i][2] = plural(gitKeys[a.Change], "hook key", "hook keys") + " in"
			continue
		}
		rows = append(rows, []string{a.Step, a.Change, c.tilde(a.Target), c.tilde(a.Detail)})
	}
	table(c.out, "  ", rows)
	for _, w := range res.Warnings {
		fmt.Fprintf(c.out, "  warning: %s\n", w)
	}
}

// ----- doctor -----

func (c *cli) cmdDoctor(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "capabilities":
			return c.doctorCapabilities()
		case "robot-docs":
			fmt.Fprint(c.out, doctorHandbook)
			return exitOK
		case "health":
			return c.doctorHealth(args[1:])
		}
	}
	f := c.flagSet("doctor", "doctor [--json | --robot] [--robot-triage] [--quick] [--explain ID]\n       doctor health | capabilities | robot-docs\n\nChecks every layer without changing anything. Each finding names the command that fixes it.\nExit 0: healthy. Exit 1: something to look at.")
	asJSON := f.Bool("json", false, "machine-readable output (schema_version 1)")
	robot := f.Bool("robot", false, "same as --json: data only on stdout, the same stable schema")
	triage := f.Bool("robot-triage", false, "one call for an agent: the summary, the findings, the commands that fix them and the one to run first")
	quick := f.Bool("quick", false, "skip starting engines, hashing binaries and asking gh")
	explain := f.String("explain", "", "show one check in full")
	if _, code, ok := c.parse(f, args); !ok {
		return code
	}
	rep, err := install.Doctor(c.ctx, c.doctorOptions(c.paths(), *quick))
	if err != nil {
		return c.failf("%s", safeErr(err))
	}
	if *explain != "" {
		for _, ch := range rep.Checks {
			if ch.ID == *explain {
				c.printJSON(ch)
				return exitOK
			}
		}
		var ids []string
		for _, ch := range rep.Checks {
			ids = append(ids, ch.ID)
		}
		return c.failf("no check %q; the checks are: %s", *explain, strings.Join(ids, ", "))
	}
	if *triage {
		c.printJSON(rep.Triage())
		return rep.ExitCode()
	}
	if *asJSON || *robot {
		c.printJSON(rep)
		return rep.ExitCode()
	}
	c.printDoctor(rep)
	return rep.ExitCode()
}

func (c *cli) printDoctor(rep install.Report) {
	fmt.Fprintf(c.out, "keyguard doctor   root %s\n\n", rep.Root)
	rows := [][]string{}
	for _, ch := range rep.Checks {
		mark := map[install.Status]string{install.OK: "ok", install.Warn: "WARN", install.Fail: "FAIL"}[ch.Status]
		rows = append(rows, []string{mark, ch.ID, ch.Summary})
	}
	table(c.out, "  ", rows)
	// One line per distinct fix, with the checks it answers. The guard registration is a long
	// line the user runs in Claude Code, so it is set apart.
	var order []string
	by := map[string][]string{}
	for _, ch := range rep.Checks {
		if ch.Status == install.OK || ch.Fix == "" {
			continue
		}
		if _, seen := by[ch.Fix]; !seen {
			order = append(order, ch.Fix)
		}
		by[ch.Fix] = append(by[ch.Fix], ch.ID)
	}
	var guardLine string
	var fixRows [][]string
	for _, fx := range order {
		if strings.HasPrefix(fx, "! ") {
			guardLine = fx
			continue
		}
		fixRows = append(fixRows, []string{fx, strings.Join(by[fx], " ")})
	}
	if len(fixRows) > 0 {
		fmt.Fprintln(c.out, "\nTo fix:")
		table(c.out, "  ", fixRows)
	}
	if guardLine != "" {
		fmt.Fprintln(c.out, "\nTo register the agent guard, run this line in Claude Code:")
		fmt.Fprintf(c.out, "  %s\n", guardLine)
	}
	if len(order) > 0 {
		fmt.Fprintln(c.out, "\n`keyguard doctor --explain <id>` shows the detail behind one line.")
	}
	fmt.Fprintf(c.out, "\n%d ok, %s, %s\n", rep.Ok, plural(rep.Warnings, "warning", "warnings"), plural(rep.Failures, "failure", "failures"))
}

func (c *cli) doctorHealth(args []string) int {
	f := c.flagSet("doctor health", "doctor health\n\nOne line and an exit code (0 healthy, 1 not), from the quick checks.")
	if _, code, ok := c.parse(f, args); !ok {
		return code
	}
	rep, err := install.Doctor(c.ctx, c.doctorOptions(c.paths(), true))
	if err != nil {
		return c.failf("%s", safeErr(err))
	}
	if rep.Healthy {
		fmt.Fprintln(c.out, "healthy")
		return exitOK
	}
	var bad []string
	for _, ch := range rep.Checks {
		if ch.Status != install.OK {
			bad = append(bad, ch.ID)
		}
	}
	fmt.Fprintf(c.out, "%d failing, %d warning: %s\n", rep.Failures, rep.Warnings, strings.Join(bad, " "))
	return exitFound
}

func (c *cli) doctorCapabilities() int {
	caps := map[string]any{
		"tool":               "keyguard",
		"version":            version,
		"schema_version":     install.DoctorSchemaVersion,
		"read_only":          true,
		"writes":             []string{},
		"network":            "none with --quick; otherwise `gh auth token` is asked for each account and GitHub is asked the time once (a request that costs no quota)",
		"commands":           []string{"doctor", "doctor --json", "doctor --robot", "doctor --robot-triage", "doctor --quick", "doctor --explain <id>", "doctor health", "doctor capabilities", "doctor robot-docs"},
		"exit_codes":         map[string]string{"0": "healthy: no warnings, no failures", "1": "something to look at (warnings or failures)", "2": "usage error", "3": "the doctor itself could not run"},
		"statuses":           []string{string(install.OK), string(install.Warn), string(install.Fail)},
		"detectors":          install.Catalog(),
		"fixers":             install.Fixers(),
		"fixes":              "every non-ok check names the command that repairs it. The doctor has no --fix of its own: install problems are repaired by `keyguard install`, which backs nothing up because it deletes nothing, changes only what differs, and is undone exactly by `keyguard uninstall` from state/install.json",
		"needs_user":         "registering the agent guard edits Claude Code's settings, which is theirs to run: the fix is a `! ...` line. keyguard allow, known forget, uninstall and import-triage are refused to agents by the guard.",
		"layers":             []string{install.LayerCommit, install.LayerPush, install.LayerRef, install.LayerGuard, install.LayerPoll, install.LayerDeep, install.LayerUpgrade, install.LayerEngines, install.LayerKnown, install.LayerGitHub, install.LayerSelftest},
		"check_fields":       []string{"id", "layers", "status", "summary", "detail", "fix"},
		"never_contains":     "a secret value: shapes, ids, paths, versions and counts only",
		"stdout":             "data only; warnings go to stderr",
		"environment_in_use": []string{"KEYGUARD_HOME", "GIT_CONFIG_GLOBAL", "HOME"},
	}
	c.printJSON(caps)
	return exitOK
}

const doctorHandbook = `keyguard doctor: handbook for an agent

  keyguard doctor --robot-triage  one call: summary, findings, actions_planned, recommended_command
  keyguard doctor --json          every check, stable schema (schema_version 1); --robot is the same
  keyguard doctor health          one line, exit code 0 healthy / 1 not
  keyguard doctor --explain ID  one check in full
  keyguard doctor capabilities  what the doctor reads, its exit codes, its fields

The doctor never writes. Each check has a status (ok, warn, fail) and, when it is not ok, a fix:
the exact command that repairs it. Run it, then run the doctor again.

Most fixes are one command:  keyguard install   (idempotent; it deletes nothing and is undone
exactly by keyguard uninstall). Run the commands in actions_planned yourself. The ones in
needs_user edit their Claude Code settings (registering the agent guard) or say which scanner binary
every gate will trust (keyguard engines pin, check-upgrade --apply): give them the line.
keyguard allow, known forget, uninstall and import-triage are refused to you by the guard.

A "fail" means a protection layer is not doing its job. The quietest one to miss is
hooks.binary: the git hooks exit 0 when the binary is gone, so every gate is off and
nothing complains.
`

// ----- version -----

func (c *cli) cmdVersion(args []string) int {
	f := c.flagSet("version", "version [--json]")
	asJSON := f.Bool("json", false, "machine-readable output")
	if _, code, ok := c.parse(f, args); !ok {
		return code
	}
	rev, dirty := "", false
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				rev = s.Value
			case "vcs.modified":
				dirty = s.Value == "true"
			}
		}
	}
	if len(rev) > 7 {
		rev = rev[:7]
	}
	if *asJSON {
		c.printJSON(map[string]any{"version": version, "go": runtime.Version(), "os": runtime.GOOS, "arch": runtime.GOARCH, "revision": rev, "modified": dirty})
		return exitOK
	}
	line := fmt.Sprintf("keyguard %s (%s %s/%s", version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
	if rev != "" {
		line += ", " + rev
		if dirty {
			line += "+dirty"
		}
	}
	fmt.Fprintln(c.out, line+")")
	return exitOK
}
