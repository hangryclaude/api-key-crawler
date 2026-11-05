package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"keyguard/internal/core"
	"keyguard/internal/db"
	"keyguard/internal/install"
	"keyguard/internal/inventory"
)

// sources returns what keyguard watches: the saved inventory, or a fresh listing when there
// is none (or refresh is set). Listing costs one GraphQL page per hundred repos.
func (s *stack) sources(refresh bool) ([]core.Source, error) {
	if !refresh {
		if srcs, err := inventory.LoadSnapshot(s.paths.Inventory); err == nil && len(srcs) > 0 {
			return srcs, nil
		}
	}
	if s.inv == nil {
		return nil, errors.New("there is no saved inventory yet; run `keyguard poll` or `keyguard inventory`")
	}
	return s.inv.List(s.c.ctx)
}

// ----- inventory -----

func (c *cli) cmdInventory(args []string) int {
	f := c.flagSet("inventory", "inventory [--cached] [--all] [--json]\n\nLists the repos, wikis and gists keyguard watches. Asks GitHub unless --cached.")
	cached := f.Bool("cached", false, "show the saved inventory; do not ask GitHub")
	all := f.Bool("all", false, "list every source, not only the public ones")
	asJSON := f.Bool("json", false, "machine-readable output")
	if _, code, ok := c.parse(f, args); !ok {
		return code
	}
	var srcs []core.Source
	if *cached {
		var err error
		if srcs, err = inventory.LoadSnapshot(c.paths().Inventory); err != nil {
			return c.failf("%s", safeErr(err))
		}
		if len(srcs) == 0 {
			return c.failf("there is no saved inventory yet; run `keyguard inventory` without --cached, or `keyguard poll`")
		}
	} else {
		s, err := c.buildStack(stackOpts{tier: install.TierPoll})
		if err != nil {
			return c.failf("%s", safeErr(err))
		}
		started := time.Now()
		if srcs, err = s.inv.List(c.ctx); err != nil {
			return c.failf("listing GitHub: %s", safeErr(err))
		}
		fmt.Fprintf(c.err, "listed %d sources in %s\n", len(srcs), secs(time.Since(started).Seconds()))
	}
	slices.SortFunc(srcs, func(a, b core.Source) int { return strings.Compare(a.ID, b.ID) })
	if *asJSON {
		enc := json.NewEncoder(c.out)
		enc.SetIndent("", "  ")
		_ = enc.Encode(srcs)
		return exitOK
	}

	type tally struct{ repos, public, private, wikis, gists int }
	by := map[string]*tally{}
	var owners []string
	for _, s := range srcs {
		t := by[s.Owner]
		if t == nil {
			t = &tally{}
			by[s.Owner] = t
			owners = append(owners, s.Owner)
		}
		switch s.Kind {
		case "wiki":
			t.wikis++
		case "gist":
			t.gists++
		default:
			t.repos++
			if s.Visibility == core.Public {
				t.public++
			} else {
				t.private++
			}
		}
	}
	sort.Strings(owners)
	rows := [][]string{{"OWNER", "REPOS", "PUBLIC", "PRIVATE", "WIKIS", "GISTS"}}
	var sum tally
	for _, o := range owners {
		t := by[o]
		rows = append(rows, []string{o, fmt.Sprint(t.repos), fmt.Sprint(t.public), fmt.Sprint(t.private), fmt.Sprint(t.wikis), fmt.Sprint(t.gists)})
		sum.repos, sum.public, sum.private, sum.wikis, sum.gists = sum.repos+t.repos, sum.public+t.public, sum.private+t.private, sum.wikis+t.wikis, sum.gists+t.gists
	}
	rows = append(rows, []string{"total", fmt.Sprint(sum.repos), fmt.Sprint(sum.public), fmt.Sprint(sum.private), fmt.Sprint(sum.wikis), fmt.Sprint(sum.gists)})
	table(c.out, "", rows, 1, 2, 3, 4, 5)

	var listed [][]string
	for _, s := range srcs {
		if *all || s.Visibility == core.Public || s.Visibility == core.SecretGist {
			listed = append(listed, []string{string(s.Visibility), s.ID, s.PushedAt})
		}
	}
	if len(listed) > 0 {
		title := "\npublic and unlisted sources"
		if *all {
			title = "\nall sources"
		}
		fmt.Fprintln(c.out, title)
		table(c.out, "  ", append([][]string{{"VISIBILITY", "SOURCE", "PUSHED"}}, listed...))
	}
	return exitOK
}

// ----- sync -----

func (c *cli) cmdSync(args []string) int {
	f := c.flagSet("sync", "sync [--repo ID] [--refresh] [-j N]\n\nFetches the bare mirrors (cloning the ones that are missing). Scans nothing.")
	repo := f.String("repo", "", "only this source id, e.g. github.com/owner/name")
	refresh := f.Bool("refresh", false, "ask GitHub for the inventory first")
	jobs := f.Int("j", 0, "mirrors fetched at once (default from config.json, 8)")
	if _, code, ok := c.parse(f, args); !ok {
		return code
	}
	s, err := c.buildStack(stackOpts{tier: install.TierPoll})
	if err != nil {
		return c.failf("%s", safeErr(err))
	}
	srcs, err := s.sources(*refresh)
	if err != nil {
		return c.failf("%s", safeErr(err))
	}
	if *repo != "" {
		var keep []core.Source
		for _, x := range srcs {
			if strings.EqualFold(x.ID, *repo) {
				keep = append(keep, x)
			}
		}
		if len(keep) == 0 {
			return c.failf("%s is not in the inventory", *repo)
		}
		srcs = keep
	}
	srcs, private := exposedOnly(srcs)
	if private > 0 {
		fmt.Fprintf(c.err, "leaving %s alone: the sweep fetches only what a stranger can read\n", plural(private, "private source", "private sources"))
	}
	if len(srcs) == 0 {
		fmt.Fprintln(c.out, "nothing to fetch.")
		return exitOK
	}
	n := *jobs
	if n <= 0 {
		n = s.cfg.Jobs
	}
	type outcome struct {
		src core.Source
		res interface{ Moved() []string }
		err error
		new bool
		abs bool
	}
	results := make([]outcome, len(srcs))
	var wg sync.WaitGroup
	sem := make(chan struct{}, n)
	for i, src := range srcs {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			r, err := s.mir.SyncResult(c.ctx, src)
			results[i] = outcome{src: src, res: r, err: err, new: r.Cloned, abs: r.Absent}
		}()
	}
	wg.Wait()
	cloned, absent, moved, failed := 0, 0, 0, 0
	var lines [][]string
	for _, r := range results {
		switch {
		case r.err != nil:
			failed++
			lines = append(lines, []string{"failed", r.src.ID, safeErr(r.err)})
		case r.abs:
			absent++
		default:
			if r.new {
				cloned++
			}
			if m := len(r.res.Moved()); m > 0 {
				moved++
				if !r.new {
					lines = append(lines, []string{"updated", r.src.ID, plural(m, "ref moved", "refs moved")})
				}
			}
		}
	}
	table(c.out, "", lines)
	fmt.Fprintf(c.out, "%s: %d cloned, %d with new commits, %d without a wiki yet, %d failed\n", plural(len(srcs), "source", "sources"), cloned, moved, absent, failed)
	if failed > 0 {
		return exitFailed
	}
	return exitOK
}

// ----- scan -----

func (c *cli) cmdScan(args []string) int {
	f := c.flagSet("scan", "scan [--full | --incremental] [--repo ID] [-j N] [--no-verify] [--no-fetch] [--fresh | --no-ledger] [--engines a,b]\n\nScans the mirrors with every engine and the learned-secret matcher.\n--incremental (the default) looks only at what changed since the last scan; --full looks at everything again,\nbut a blob that every current scanner has already read is not read twice (the blob ledger in state/ledger).\n--fresh reads every blob again anyway and feeds the ledger: the way to rebuild the findings from history.\n--no-ledger reads every blob again and keeps no ledger.\n--no-fetch scans the mirrors as they are on disk: nothing is cloned or fetched, and nothing in them changes.\nThe \"mirrors\" key of config.json points the scan at another data root's mirrors.")
	full := f.Bool("full", false, "rescan everything, ignoring what was scanned before")
	incr := f.Bool("incremental", false, "scan only what changed (the default)")
	repo := f.String("repo", "", "only this source id, e.g. github.com/owner/name")
	jobs := f.Int("j", 0, "sources scanned at once (default from config.json, 8)")
	noVerify := f.Bool("no-verify", false, "do not ask providers whether found keys still work")
	noFetch := f.Bool("no-fetch", false, "scan the mirrors as they are; never clone or fetch")
	fresh := f.Bool("fresh", false, "read every blob again, even those the ledger has, and record them")
	noLedger := f.Bool("no-ledger", false, "read every blob again and keep no ledger")
	engs := f.String("engines", "", "comma-separated engines to use instead of the poll tier")
	if _, code, ok := c.parse(f, args); !ok {
		return code
	}
	if *full && *incr {
		return c.usageErr(f, "--full and --incremental contradict each other")
	}
	if *fresh && *noLedger {
		return c.usageErr(f, "--fresh and --no-ledger contradict each other")
	}
	tier := install.TierPoll
	if *full {
		tier = install.TierDeep
	}
	s, err := c.buildStack(stackOpts{tier: tier, engines: splitList(*engs), noFetch: *noFetch})
	if err != nil {
		return c.failf("%s", safeErr(err))
	}
	r, err := s.runner(runnerOpts{jobs: *jobs, noVerify: *noVerify, fresh: *fresh, noLedger: *noLedger})
	if err != nil {
		return c.failf("%s", safeErr(err))
	}
	var st core.RunStats
	switch {
	case *repo != "":
		st, err = r.One(c.ctx, *repo, *full)
	case *full:
		st, err = r.Full(c.ctx)
	default:
		st, err = r.Poll(c.ctx)
	}
	return c.finishRun(s, "scan", st, err)
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// finishRun prints what a run did and turns its error into an exit code.
func (c *cli) finishRun(s *stack, what string, st core.RunStats, err error) int {
	printRun(c.out, st)
	if err != nil {
		if msg, locked := lockedMessage(err); locked {
			fmt.Fprintf(c.err, "keyguard: %s\n", msg)
			return exitLocked
		}
		return c.failf("%s: %s", what, safeErr(err))
	}
	printOpen(c.out, s.store.Secrets())
	return exitOK
}

// printRun is the summary of a run, in short lines with the numbers lined up.
func printRun(w io.Writer, st core.RunStats) {
	took := ""
	if a, e1 := time.Parse(time.RFC3339, st.Started); e1 == nil {
		if b, e2 := time.Parse(time.RFC3339, st.Finished); e2 == nil {
			took = " in " + secs(b.Sub(a).Seconds())
		}
	}
	fmt.Fprintf(w, "%s finished%s\n", st.Kind, took)
	fmt.Fprintf(w, "  sources %d   scanned %d   skipped %d   new secrets %d\n", st.Sources, st.Scanned, st.Skipped, st.NewFPs)
	if st.Failed > 0 {
		fmt.Fprintf(w, "  FAILED %d: a sync or an engine did not finish, so they were not scanned; see the notes\n", st.Failed)
	}
	if len(st.Engines) > 0 {
		names := make([]string, 0, len(st.Engines))
		for n := range st.Engines {
			names = append(names, n)
		}
		sort.Strings(names)
		rows := [][]string{{"ENGINE", "TIME", "HITS", "ERRORS"}}
		for _, n := range names {
			e := st.Engines[n]
			rows = append(rows, []string{n, secs(e.Seconds), fmt.Sprint(e.Hits), fmt.Sprint(e.Errors)})
		}
		table(w, "  ", rows, 1, 2, 3)
	}
	const showNotes = 12
	for i, n := range st.Notes {
		if i == showNotes {
			fmt.Fprintf(w, "  ... and %d more notes (they are in the run record)\n", len(st.Notes)-showNotes)
			break
		}
		fmt.Fprintf(w, "  note: %s\n", n)
	}
}

// printOpen counts the open secrets by severity.
func printOpen(w io.Writer, secrets []core.Secret) {
	count := map[core.Severity]int{}
	open := 0
	for _, s := range secrets {
		if s.Status == db.StatusOpen {
			open++
			count[s.Severity]++
		}
	}
	if open == 0 {
		fmt.Fprintln(w, "open findings: none")
		return
	}
	var parts []string
	for sev := core.Critical; sev >= core.Info; sev-- {
		if n := count[sev]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, sev))
		}
	}
	fmt.Fprintf(w, "open findings: %d (%s)\n", open, strings.Join(parts, ", "))
}

// ----- verify -----

func (c *cli) cmdVerify(args []string) int {
	f := c.flagSet("verify", "verify [--all] [id...]\n\nRe-checks whether secrets still work. A key is never stored, so this rescans the repos that hold it,\nin full, asking each provider again. A key you rotated turns dead and resolves.\nExit 1 if a secret is still live afterwards.")
	all := f.Bool("all", false, "every open finding that is not dead")
	jobs := f.Int("j", 0, "engine processes at once (default from config.json, 8)")
	pos, code, ok := c.parse(f, args)
	if !ok {
		return code
	}
	if len(pos) == 0 && !*all {
		return c.usageErr(f, "name the ids to verify, or pass --all")
	}
	p := c.paths()
	st, err := db.Open(p)
	if err != nil {
		return c.failf("%s", safeErr(err))
	}
	var chosen []core.Secret
	if *all {
		for _, sec := range st.Secrets() {
			if sec.Status == db.StatusOpen && sec.Verified != core.Dead {
				chosen = append(chosen, sec)
			}
		}
	}
	for _, id := range pos {
		sec, found := st.Find(id)
		if !found {
			return c.failf("no finding has id %q", id)
		}
		chosen = append(chosen, sec)
	}
	where := map[string]bool{}
	var skippedLocal int
	for _, sec := range chosen {
		for _, l := range sec.Locations {
			if strings.HasPrefix(l.Source, "local:") || !l.Visibility.Exposed() {
				skippedLocal++ // not on GitHub, or not readable by anyone but the user: nothing the sweep rescans
				continue
			}
			where[l.Source] = true
		}
	}
	if len(where) == 0 {
		fmt.Fprintln(c.out, "nothing to verify: none of those findings sits in a repo keyguard can rescan.")
		return exitOK
	}
	s, err := c.buildStack(stackOpts{tier: install.TierDeep})
	if err != nil {
		return c.failf("%s", safeErr(err))
	}
	r, err := s.runner(runnerOpts{jobs: *jobs})
	if err != nil {
		return c.failf("%s", safeErr(err))
	}
	ids := make([]string, 0, len(where))
	for id := range where {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	fmt.Fprintf(c.out, "rescanning %s in full, with verification\n", plural(len(ids), "source", "sources"))
	if skippedLocal > 0 {
		fmt.Fprintf(c.out, "(%s a person alone can read, or that are only on this Mac, cannot be rescanned: the sweep reads only what a stranger can)\n", plural(skippedLocal, "place", "places"))
	}
	var exit int
	for _, id := range ids {
		stats, err := r.One(c.ctx, id, true)
		if err != nil {
			fmt.Fprintf(c.out, "  %s  did not finish\n", id)
			if code := c.finishRun(s, "verify", stats, err); code != exitOK {
				exit = code
			}
			continue
		}
		fmt.Fprintf(c.out, "  %s  done\n", id)
	}
	if exit != exitOK {
		return exit
	}

	rows := [][]string{{"ID", "TYPE", "BEFORE", "NOW", "SEVERITY"}}
	live := 0
	for _, before := range chosen {
		now, _ := s.store.Get(before.FP)
		if now.Verified == core.Live {
			live++
		}
		rows = append(rows, []string{before.ID, orGeneric(before.Type), string(before.Verified), string(now.Verified) + statusTail(now), now.Severity.String()})
	}
	fmt.Fprintln(c.out)
	table(c.out, "", rows)
	if live > 0 {
		fmt.Fprintf(c.out, "\n%s still work. Rotate them.\n", plural(live, "secret", "secrets"))
		return exitFound
	}
	return exitOK
}

func statusTail(s core.Secret) string {
	if s.Status != db.StatusOpen && s.Status != "" {
		return " (" + s.Status + ")"
	}
	return ""
}

// ----- publish-check -----

func (c *cli) cmdPublishCheck(args []string) int {
	f := c.flagSet("publish-check", "publish-check [--json] [--no-verify] <owner/name | path>\n\nScans a repo's whole history, every ref, as if it were already public.\nExit 0: clean. Exit 1: findings (listed, never shown). Anything else: the check could not finish.")
	asJSON := f.Bool("json", false, "machine-readable output")
	noVerify := f.Bool("no-verify", false, "do not ask providers whether found keys still work")
	jobs := f.Int("j", 0, "engine processes at once")
	pos, code, ok := c.parse(f, args)
	if !ok {
		return code
	}
	if len(pos) != 1 {
		return c.usageErr(f, "publish-check takes one target: owner/name or a directory")
	}
	s, err := c.buildStack(stackOpts{tier: install.TierDeep})
	if err != nil {
		return c.failf("%s", safeErr(err))
	}
	r, err := s.runner(runnerOpts{jobs: *jobs, noVerify: *noVerify})
	if err != nil {
		return c.failf("%s", safeErr(err))
	}
	res, err := r.PublishCheck(c.ctx, pos[0])
	if err != nil {
		if msg, locked := lockedMessage(err); locked {
			fmt.Fprintf(c.err, "keyguard: %s\n", msg)
			return exitLocked
		}
		for _, n := range res.Stats.Notes {
			fmt.Fprintf(c.err, "note: %s\n", n)
		}
		return c.failf("publish-check %s: %s", pos[0], safeErr(err))
	}
	if len(res.Blocking) > 0 {
		if err := journalSecrets(s.paths, "publish-check", res.Blocking, c.now()); err != nil {
			c.warnf("could not record the findings (%s); `keyguard allow` will need the full fingerprint", safeErr(err))
		}
	}
	if *asJSON {
		type item struct {
			ID       string   `json:"id"`
			Severity string   `json:"severity"`
			Type     string   `json:"type"`
			Shape    string   `json:"shape"`
			Where    []string `json:"where"`
		}
		doc := struct {
			Target   string   `json:"target"`
			Clean    bool     `json:"clean"`
			Blocking []item   `json:"blocking"`
			Notes    []string `json:"notes,omitempty"`
		}{Target: res.Target, Clean: len(res.Blocking) == 0, Blocking: []item{}, Notes: res.Stats.Notes}
		for _, sec := range res.Blocking {
			doc.Blocking = append(doc.Blocking, item{sec.ID, sec.Severity.String(), orGeneric(sec.Type), sec.Shape, placesOf(sec)})
		}
		enc := json.NewEncoder(c.out)
		enc.SetIndent("", "  ")
		_ = enc.Encode(doc)
	} else if len(res.Blocking) == 0 {
		fmt.Fprintf(c.out, "clean: %s has nothing keyguard would block (%s scanned)\n", pos[0], plural(res.Stats.Scanned, "source", "sources"))
		for _, n := range res.Stats.Notes {
			fmt.Fprintf(c.out, "  note: %s\n", n)
		}
	} else {
		fmt.Fprintf(c.out, "NOT clean: %s has %s that would be public.\n\n", pos[0], plural(len(res.Blocking), "secret", "secrets"))
		rows := [][]string{{"SEVERITY", "ID", "TYPE", "SHAPE", "WHERE"}}
		for _, sec := range res.Blocking {
			where := placesOf(sec)
			rows = append(rows, []string{sec.Severity.String(), sec.ID, orGeneric(sec.Type), sec.Shape, strings.Join(where[:min(1, len(where))], "") + moreTail(len(where))})
		}
		table(c.out, "", rows)
		fmt.Fprintln(c.out, "\nRemove the keys from history (or rotate them and `keyguard allow <id>` what is not a secret), then check again.")
	}
	if len(res.Blocking) > 0 {
		return exitFound
	}
	return exitOK
}

func moreTail(n int) string {
	if n > 1 {
		return fmt.Sprintf("  +%d more", n-1)
	}
	return ""
}

func placesOf(s core.Secret) []string {
	var out []string
	for _, l := range s.Locations {
		w := l.Path
		if l.Line > 0 {
			w += fmt.Sprintf(":%d", l.Line)
		}
		if l.Commit != "" {
			w += " @" + l.Commit[:min(7, len(l.Commit))]
		}
		out = append(out, strings.TrimSpace(w))
	}
	return out
}

// ----- report -----

func (c *cli) cmdReport(args []string) int {
	f := c.flagSet("report", "report [--open]\n\nWrites the dashboard (one self-contained HTML file) from the findings and the last run.")
	open := f.Bool("open", false, "open it in the browser")
	if _, code, ok := c.parse(f, args); !ok {
		return code
	}
	p := c.paths()
	st, err := db.Open(p)
	if err != nil {
		return c.failf("%s", safeErr(err))
	}
	run, _, found := install.LastSweep(p)
	if !found {
		run = core.RunStats{Kind: "none"}
	}
	rep, err := install.Doctor(c.ctx, c.doctorOptions(p, true))
	var layers []core.LayerStatus
	if err == nil {
		layers = rep.Layers()
	}
	path, err := coverageReporter{p}.Write(st.Secrets(), run, layers)
	if err != nil {
		return c.failf("%s", safeErr(err))
	}
	fmt.Fprintln(c.out, path)
	if *open {
		if err := c.openFile(path); err != nil {
			return c.failf("opening the report: %s", safeErr(err))
		}
	}
	return exitOK
}

func (c *cli) openFile(path string) error {
	if c.seams.open != nil {
		return c.seams.open(path)
	}
	return exec.CommandContext(c.ctx, "open", path).Run()
}

// exposedOnly keeps the sources a stranger can read, and says how many it left out. The
// sweep never fetches the rest (PLAN.md "Sweep scope"); `publish-check` is for a repo that is
// about to stop being private.
func exposedOnly(srcs []core.Source) (keep []core.Source, private int) {
	for _, s := range srcs {
		if s.Visibility.Exposed() {
			keep = append(keep, s)
		} else {
			private++
		}
	}
	return keep, private
}
