package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"keyguard/internal/core"
	"keyguard/internal/db"
	"keyguard/internal/engines"
	"keyguard/internal/ghsettings"
	"keyguard/internal/install"
	"keyguard/internal/known"
)

// learnOptions builds the options for a learn run: this machine's environment, and the
// engines of the learn tier as a second opinion on values whose names do not look secret.
func (c *cli) learnOptions(p core.Paths, cfg install.Config, noEngine bool) (known.Options, error) {
	opts := known.Options{Ctx: c.ctx, Root: p.Root, Env: os.Environ(), GHUsers: slices.Clone(cfg.Accounts)}
	if noEngine {
		return opts, nil
	}
	// The engines must fingerprint with this root's salt: Learn compares their hits with its own.
	kr, err := openKeyring(p)
	if err != nil {
		return opts, err
	}
	for _, name := range cfg.Tier(install.TierLearn) {
		if e, err := engines.New(name, cfg.EnginePaths()[name], kr, cfg.EngineOptions(p)...); err == nil && e.Available() {
			opts.Engines = append(opts.Engines, e)
		}
	}
	if len(opts.Engines) == 0 {
		c.warnf("no engine of the %q tier is installed; learning by name alone", install.TierLearn)
	}
	return opts, nil
}

// ----- poll -----

func (c *cli) cmdPoll(args []string) int {
	f := c.flagSet("poll", "poll [-j N] [--no-verify] [--daily | --no-daily]\n\nThe one-minute job: ask GitHub what changed with conditional requests (an idle minute is a few 304s that\ncost no quota), scan only that, alert on new findings, rewrite the report. Once a day it also runs the\nselftest and the doctor, surveys GitHub's own protection, and alerts if a layer broke or protection went off.")
	jobs := f.Int("j", 0, "sources scanned at once (default from config.json, 8)")
	noVerify := f.Bool("no-verify", false, "do not ask providers whether found keys still work")
	daily := f.Bool("daily", false, "run the selftest and doctor now, whatever the last one's age")
	noDaily := f.Bool("no-daily", false, "never run the selftest and doctor from this poll")
	if _, code, ok := c.parse(f, args); !ok {
		return code
	}
	s, err := c.buildStack(stackOpts{tier: install.TierPoll})
	if err != nil {
		return c.failf("%s", safeErr(err))
	}
	r, err := s.runner(runnerOpts{jobs: *jobs, noVerify: *noVerify})
	if err != nil {
		return c.failf("%s", safeErr(err))
	}
	st, err := r.Poll(c.ctx)
	if err != nil {
		if msg, locked := lockedMessage(err); locked {
			// A deep scan can hold the lock for an hour; the poll is not broken, it is early.
			fmt.Fprintf(c.out, "%s poll skipped: %s\n", c.now().UTC().Format(time.RFC3339), msg)
			return exitOK
		}
		printRun(c.out, st)
		return c.failf("poll: %s", safeErr(err))
	}
	// One line for the launchd log, then whatever the run had to say.
	fmt.Fprintf(c.out, "%s poll: sources %d scanned %d skipped %d new %d\n", st.Finished, st.Sources, st.Scanned, st.Skipped, st.NewFPs)
	for _, n := range st.Notes {
		fmt.Fprintf(c.out, "  note: %s\n", n)
	}
	if !*noDaily {
		c.daily(s, *daily)
	}
	return exitOK
}

const keepRunDays = 30

// daily runs the selftest and the full doctor when the last selftest is more than a day old,
// surveys what GitHub's own scanning covers, alerts if a layer is down or protection went off,
// and files away old run records. It never fails the poll: the poll's job is done, and a broken
// selftest is an alert, not a crash.
func (c *cli) daily(s *stack, force bool) {
	p := s.paths
	defer archiveRuns(p, c.now())
	if !force {
		if rec, ok := install.LoadSelftest(p); ok {
			if at, err := time.Parse(time.RFC3339, rec.At); err == nil && c.now().Sub(at) < 24*time.Hour {
				return
			}
		}
	}
	var broken []string
	// The daily run leaves out the speed checks: a busy Mac is no reason to say a layer is broken.
	rec, err := c.runSelftest(selftestRun{gates: true, layers: true, noLatency: true})
	if err != nil {
		broken = append(broken, "the selftest could not run: "+safeErr(err))
	}
	for _, l := range rec.Layers {
		if !l.OK {
			broken = append(broken, l.Name+": "+l.Detail)
		}
	}
	// The survey comes before the doctor, which reads what it wrote.
	if msg := c.surveyDaily(s); msg != "" {
		broken = append(broken, msg)
	}
	rep, derr := install.Doctor(c.ctx, c.doctorOptions(p, false))
	if derr != nil {
		broken = append(broken, "the doctor could not run: "+safeErr(derr))
	}
	for _, ch := range rep.Checks {
		if ch.Status == install.Fail && ch.ID != "github.protection" { // the survey already said it
			broken = append(broken, ch.Summary)
		}
	}
	fmt.Fprintf(c.out, "daily check: selftest %s, doctor %d ok %d warnings %d failures\n",
		map[bool]string{true: "passed", false: "FAILED"}[rec.OK], rep.Ok, rep.Warnings, rep.Failures)
	if len(broken) > 0 && s.notif != nil {
		body := strings.Join(broken, "\n") + "\nRun: keyguard doctor"
		if err := s.notif.Notify("keyguard: a protection layer is broken", body, core.High); err != nil {
			fmt.Fprintf(c.out, "  could not send the alert: %s\n", safeErr(err))
		}
	}
}

// surveyDaily reads where GitHub's own secret scanning stands (7 to 15 GETs for 461 repos, no
// write, no alert polled) and leaves the summary where the doctor reads it. It returns a line
// for the alert when protection that was on has gone off (STEAL P0-19); a survey that could not
// be made is a note in the log, not a broken layer.
func (c *cli) surveyDaily(s *stack) string {
	srcs, err := s.sources(false)
	if err != nil || len(srcs) == 0 {
		return ""
	}
	gs, err := ghsettings.New(ghsettings.Config{Client: c.seams.gh, FP: s.kr, StatePath: s.paths.GHSettings})
	if err != nil {
		return ""
	}
	sv, err := c.survey(s, gs, srcs)
	if err != nil {
		fmt.Fprintf(c.out, "  GitHub's protection could not be surveyed: %s\n", safeErr(err))
		return ""
	}
	fmt.Fprintf(c.out, "  %s\n", sv.Headline())
	if len(sv.Drift) == 0 {
		return ""
	}
	return fmt.Sprintf("GitHub protection went off: %s", driftWords(sv.Drift))
}

// driftWords names the repos and features of a drift, without repeating a long list.
func driftWords(d []ghsettings.Drift) string {
	var parts []string
	for i, x := range d {
		if i == 3 {
			parts = append(parts, fmt.Sprintf("and %d more", len(d)-3))
			break
		}
		parts = append(parts, strings.TrimPrefix(x.Source, "github.com/")+" "+install.FeatureWord(string(x.Feature)))
	}
	return strings.Join(parts, ", ")
}

// survey reads GitHub's settings for every repo and writes the doctor's summary of them.
func (c *cli) survey(s *stack, gs *ghsettings.Settings, srcs []core.Source) (ghsettings.Survey, error) {
	var repos []core.Source
	for _, x := range srcs {
		if x.Kind == "repo" {
			repos = append(repos, x)
		}
	}
	sv, err := gs.Survey(c.ctx, repos)
	if len(sv.Results) == 0 && err != nil {
		return sv, err
	}
	// A state file that could not be written is reported beside a survey that is complete.
	if serr := install.SaveProtection(s.paths, protectionOf(sv, c.ghClient().Clock().Now())); serr != nil {
		err = errors.Join(err, serr)
	}
	return sv, err
}

// protectionOf is the survey as the doctor keeps it: counts, and names of repos, nothing else.
func protectionOf(sv ghsettings.Survey, at time.Time) install.Protection {
	pr := install.Protection{
		At: at.UTC().Format(time.RFC3339), Headline: sv.Headline(), Repos: sv.Counts.Repos, Public: sv.Counts.Public,
		Protected: sv.Counts.Protected, GapCount: sv.Counts.Gap, Unreadable: sv.Counts.Unreadable, Unavailable: sv.Counts.Unavailable,
	}
	for _, a := range sv.Results {
		if a.Source.Visibility != core.Public || ghsettings.ClassOf(a) != ghsettings.Gap {
			continue
		}
		var off []string
		for _, ft := range []ghsettings.Feature{ghsettings.SecretScanning, ghsettings.PushProtection} {
			if a.State[ft] != ghsettings.Enabled {
				off = append(off, install.FeatureWord(string(ft)))
			}
		}
		pr.Gaps = append(pr.Gaps, install.ProtectionGap{Source: a.Source.ID, Off: off})
	}
	for _, d := range sv.Drift {
		pr.Drift = append(pr.Drift, install.ProtectionDrift{Source: d.Source, Feature: string(d.Feature), Was: string(d.Was), Now: string(d.Now)})
	}
	return pr
}

// idleAfter is how long a poll that did nothing stays in state/runs: a poll every minute
// writes one a time, 1,440 a day, and nobody reads yesterday's quiet minutes.
const idleAfter = 24 * time.Hour

// archiveRuns files run records away. Nothing is deleted. The sweep moves what is older than
// keepRunDays; this also moves, after a day, the polls that found and did nothing, into
// runs/archive/<yyyymm>/<yyyymmdd>/, so the directory the doctor reads stays a few thousand files
// long. A cursor remembers how far the records have been looked at, so a minute's housekeeping
// reads the few new ones and not all of them.
func archiveRuns(p core.Paths, now time.Time) {
	ents, err := os.ReadDir(p.Runs)
	if err != nil {
		return
	}
	cutoff := now.UTC().AddDate(0, 0, -keepRunDays).Format("20060102")
	idleCut := now.UTC().Add(-idleAfter).Format("20060102T150405")
	cursorFile := filepath.Join(p.Runs, ".compacted")
	cursor := ""
	if b, err := os.ReadFile(cursorFile); err == nil {
		cursor = strings.TrimSpace(string(b))
	}
	moved, last := 0, cursor
	for _, e := range ents {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".json") || len(name) < 8 {
			continue
		}
		switch {
		case name[:8] < cutoff:
			if moveRun(p, name, name[:6]) != nil {
				return
			}
			moved++
		case name > cursor && name[:15] < idleCut:
			if idleRun(filepath.Join(p.Runs, name)) {
				if moveRun(p, name, name[:6], name[:8]) != nil {
					return
				}
				moved++
			}
			last = name
		}
		if moved >= 5000 {
			break // the rest next time; a poll should not spend long on housekeeping
		}
	}
	if last != cursor {
		_ = os.WriteFile(cursorFile, []byte(last+"\n"), 0o600)
	}
}

func moveRun(p core.Paths, name string, sub ...string) error {
	dir := filepath.Join(append([]string{p.Runs, "archive"}, sub...)...)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.Rename(filepath.Join(p.Runs, name), filepath.Join(dir, name))
}

// idleRun reports whether a run record is a poll that scanned nothing, found nothing, failed
// at nothing and hit no engine error: the record of a quiet minute.
func idleRun(path string) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var st core.RunStats
	if json.Unmarshal(b, &st) != nil || st.Kind != "poll" || st.Scanned != 0 || st.NewFPs != 0 || st.Failed != 0 || st.Alerts != 0 {
		return false
	}
	for _, e := range st.Engines {
		if e.Errors != 0 {
			return false
		}
	}
	return true
}

// ----- deep -----

func (c *cli) cmdDeep(args []string) int {
	f := c.flagSet("deep", "deep [-j N] [--no-verify] [--no-learn] [--no-alerts]\n\nThe weekly job: relearn this Mac's secrets, import GitHub's own secret-scanning alerts,\nrescan every mirror in full with every engine (verifying what is found), and rewrite the report.")
	jobs := f.Int("j", 0, "sources scanned at once (default from config.json, 8)")
	noVerify := f.Bool("no-verify", false, "do not ask providers whether found keys still work")
	noLearn := f.Bool("no-learn", false, "skip relearning")
	noAlerts := f.Bool("no-alerts", false, "skip importing GitHub's alerts")
	if _, code, ok := c.parse(f, args); !ok {
		return code
	}
	p := c.paths()
	cfg := c.config(p)
	if !*noLearn {
		opts, err := c.learnOptions(p, cfg, false)
		if err != nil {
			return c.failf("%s", safeErr(err))
		}
		rep, err := known.Learn(opts)
		if err != nil {
			// The scan below still runs: stale hashes protect better than no scan.
			c.warnf("relearn failed: %s", safeErr(err))
		} else {
			fmt.Fprintf(c.out, "relearned: %d new, %d refreshed, %d kept (%d forms)\n", rep.Added, rep.Refreshed, rep.Retained, rep.Entries)
		}
	}
	s, err := c.buildStack(stackOpts{tier: install.TierDeep})
	if err != nil {
		return c.failf("%s", safeErr(err))
	}
	if !*noAlerts {
		// Imported first, so the sweep's own alerting at the end of the run covers them too.
		n, err := c.importAlerts(s)
		switch {
		case err != nil:
			if msg, locked := lockedMessage(err); locked {
				c.warnf("GitHub's alerts were not imported: %s", msg)
			} else {
				c.warnf("GitHub's alerts were not imported: %s", safeErr(err))
			}
		default:
			fmt.Fprintf(c.out, "GitHub alerts imported: %s\n", plural(n, "alert", "alerts"))
		}
	}
	r, err := s.runner(runnerOpts{jobs: *jobs, noVerify: *noVerify})
	if err != nil {
		return c.failf("%s", safeErr(err))
	}
	st, err := r.Deep(c.ctx)
	return c.finishRun(s, "deep", st, err)
}

// importAlerts reads every repo's open secret-scanning alerts and merges them into the
// findings under the run lock. It returns how many alerts it merged.
func (c *cli) importAlerts(s *stack) (int, error) {
	gs, err := ghsettings.New(ghsettings.Config{Client: c.seams.gh, FP: s.kr, StatePath: s.paths.GHSettings})
	if err != nil {
		return 0, err
	}
	srcs, err := s.sources(false)
	if err != nil {
		return 0, err
	}
	var repos []core.Source
	for _, x := range srcs {
		if x.Kind == "repo" && x.Visibility.Exposed() {
			repos = append(repos, x)
		}
	}
	var hits []core.Hit
	disabled, failed := 0, 0
	var firstErr error
	for _, r := range gs.AlertsAll(c.ctx, repos) {
		switch {
		case errors.Is(r.Err, ghsettings.ErrDisabled):
			disabled++
		case r.Err != nil:
			failed++
			if firstErr == nil {
				firstErr = r.Err
			}
		default:
			hits = append(hits, r.Hits...)
		}
	}
	if failed > 0 {
		c.warnf("%s: alerts could not be read (%s)", plural(failed, "repo", "repos"), safeErr(firstErr))
	}
	if disabled > 0 {
		fmt.Fprintf(c.out, "secret scanning is off or unavailable on %s\n", plural(disabled, "repo", "repos"))
	}
	if len(hits) == 0 {
		return 0, nil
	}
	now := c.now().UTC().Format(time.RFC3339)
	err = c.withStore(s.paths, func(st *db.Store) error {
		_, merr := st.Merge(hits, now)
		return merr
	})
	return len(hits), err
}

// ----- github-settings -----

func (c *cli) cmdGitHubSettings(args []string) int {
	f := c.flagSet("github-settings", "github-settings [--apply] [--no-alerts]\n\nSurveys whether GitHub's own secret scanning and push protection are on, and imports its open alerts.\nA free account gets both on public repos only, so a private repo is classified from the GET that reads it\n(one sample per owner), never written to: 461 repos cost about 15 reads, not 461. With --apply it switches\nthe two on for every public repo that lacks them, one write at a time, and reads each repo again to check\nGitHub did it. That is the only thing here that changes GitHub.")
	apply := f.Bool("apply", false, "turn the features on for public repos")
	noAlerts := f.Bool("no-alerts", false, "do not import GitHub's open alerts")
	if _, code, ok := c.parse(f, args); !ok {
		return code
	}
	s, err := c.buildStack(stackOpts{tier: install.TierPoll})
	if err != nil {
		return c.failf("%s", safeErr(err))
	}
	gs, err := ghsettings.New(ghsettings.Config{Client: c.seams.gh, FP: s.kr, StatePath: s.paths.GHSettings})
	if err != nil {
		return c.failf("%s", safeErr(err))
	}
	srcs, err := s.sources(false)
	if err != nil {
		return c.failf("%s", safeErr(err))
	}
	var repos, public []core.Source
	for _, x := range srcs {
		if x.Kind != "repo" {
			continue
		}
		repos = append(repos, x)
		if x.Visibility == core.Public && !x.Archived {
			public = append(public, x)
		}
	}
	if len(repos) == 0 {
		return c.failf("the inventory has no repos")
	}

	sv, err := c.survey(s, gs, srcs)
	if err != nil && len(sv.Results) == 0 {
		return c.failf("%s", safeErr(err))
	} else if err != nil {
		c.warnf("%s", safeErr(err))
	}
	c.printSurvey(sv, repos, len(public), *apply)

	if *apply {
		if len(public) == 0 {
			fmt.Fprintln(c.out, "\nno public repos to change.")
		} else {
			c.printApply(gs.Apply(c.ctx, public))
			c.printPlan(gs, sv)
			// What the survey just recorded is out of date the moment something was switched on.
			if sv2, err := c.survey(s, gs, srcs); err == nil {
				fmt.Fprintf(c.out, "\n%s\n", sv2.Headline())
			}
		}
	}
	fmt.Fprintln(c.out, "\n\"Push protection for yourself\" has no API. Check it by hand: https://github.com/settings/security_analysis")

	if !*noAlerts {
		n, err := c.importAlerts(s)
		if err != nil {
			if msg, locked := lockedMessage(err); locked {
				c.warnf("GitHub's alerts were not imported: %s", msg)
			} else {
				c.warnf("GitHub's alerts were not imported: %s", safeErr(err))
			}
		} else {
			fmt.Fprintf(c.out, "GitHub alerts imported: %s\n", plural(n, "alert", "alerts"))
		}
	}
	return exitOK
}

// printSurvey is the headline, a table of the four features across the public repos, the repos
// that lack one, and what GitHub cannot do for the private ones.
func (c *cli) printSurvey(sv ghsettings.Survey, repos []core.Source, public int, apply bool) {
	fmt.Fprintf(c.out, "%s\n", sv.Headline())
	fmt.Fprintf(c.out, "public repos: %d   private: %d\n\n", public, len(repos)-public)
	type count struct{ on, off, unknown int }
	tally := map[ghsettings.Feature]*count{}
	for _, ft := range ghsettings.Features {
		tally[ft] = &count{}
	}
	var gaps [][]string
	for _, a := range sv.Results {
		if a.Err != nil || a.Source.Visibility != core.Public {
			continue
		}
		var off []string
		for _, ft := range ghsettings.Features {
			switch a.State[ft] {
			case ghsettings.Enabled:
				tally[ft].on++
			case ghsettings.Disabled:
				tally[ft].off++
				off = append(off, strings.TrimPrefix(string(ft), "secret_scanning_"))
			default:
				tally[ft].unknown++
			}
		}
		if len(off) > 0 {
			gaps = append(gaps, []string{a.Source.ID, strings.Join(off, ", ")})
		}
	}
	rows := [][]string{{"FEATURE (PUBLIC REPOS)", "ON", "OFF", "UNKNOWN"}}
	for _, ft := range ghsettings.Features {
		t := tally[ft]
		rows = append(rows, []string{string(ft), fmt.Sprint(t.on), fmt.Sprint(t.off), fmt.Sprint(t.unknown)})
	}
	table(c.out, "", rows, 1, 2, 3)
	if n := sv.Counts.Unreadable; n > 0 {
		fmt.Fprintf(c.out, "\n%s could not be read (the token lacks admin rights there, or GitHub refused)\n", plural(n, "repo", "repos"))
	}
	if n := sv.Counts.Unavailable; n > 0 {
		fmt.Fprintf(c.out, "\n%s cannot be scanned by GitHub on this plan; the hooks and keyguard's own scans are all the protection they have\n", plural(n, "private repo", "private repos"))
	}
	if len(sv.Drift) > 0 {
		fmt.Fprintf(c.out, "\nPROTECTION WENT OFF since the last survey: %s\n", driftWords(sv.Drift))
	}
	if len(gaps) > 0 && !apply {
		fmt.Fprintln(c.out, "\nwithout a feature:")
		table(c.out, "  ", gaps)
		fmt.Fprintln(c.out, "\nRun `keyguard github-settings --apply` to switch them on.")
	}
}

// printPlan asks the two optional features once per owner, on a public repo that lacks one of
// them (they are not in the free tier as far as GitHub's documentation says, but its wording is
// loose), and says what each owner's plan answered. A repo that already has both says it
// already: nothing is written to learn what is plainly there. The answer is kept for a month, so
// a second run asks nothing.
func (c *cli) printPlan(gs *ghsettings.Settings, sv ghsettings.Survey) {
	seen := map[string]bool{}
	var rows [][]string
	for _, a := range sv.Results {
		src := a.Source
		if src.Visibility != core.Public || a.Err != nil || !a.Reported || seen[strings.ToLower(src.Owner)] {
			continue
		}
		if a.State[ghsettings.NonProviderPatterns] == ghsettings.Enabled && a.State[ghsettings.ValidityChecks] == ghsettings.Enabled {
			continue
		}
		seen[strings.ToLower(src.Owner)] = true
		plan, err := gs.ProbePlan(c.ctx, src, false)
		if err != nil {
			rows = append(rows, []string{src.Owner, "-", "could not ask: " + safeErr(err)})
			continue
		}
		for _, ft := range []ghsettings.Feature{ghsettings.NonProviderPatterns, ghsettings.ValidityChecks} {
			switch p, known := plan[ft]; {
			case !known:
				rows = append(rows, []string{src.Owner, string(ft), "no answer"})
			case p.Unavailable:
				rows = append(rows, []string{src.Owner, string(ft), "unavailable on this plan: " + p.Message})
			default:
				rows = append(rows, []string{src.Owner, string(ft), "available"})
			}
		}
	}
	if len(rows) > 0 {
		fmt.Fprintln(c.out, "\noptional features (asked once per owner, remembered for a month):")
		table(c.out, "  ", rows)
	}
}

func (c *cli) printApply(results []ghsettings.ApplyResult) {
	changed, already, failed := 0, 0, 0
	refused := map[string]int{}
	var errs [][]string
	for _, r := range results {
		if r.Err != nil {
			failed++
			errs = append(errs, []string{r.Source.ID, safeErr(r.Err)})
			continue
		}
		did := false
		for _, fld := range r.Fields {
			switch {
			case fld.Sent && fld.Done():
				did = true
			case fld.Sent:
				refused[string(fld.Feature)+": "+fld.Message]++
			}
		}
		if did {
			changed++
		} else {
			already++
		}
	}
	fmt.Fprintf(c.out, "\napplied: %d changed, %d already as wanted, %d could not be written\n", changed, already, failed)
	keys := make([]string, 0, len(refused))
	for k := range refused {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(c.out, "  refused %dx  %s\n", refused[k], k)
	}
	table(c.out, "  ", errs)
}
