package main

import (
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"keyguard/internal/db"
	"keyguard/internal/install"
	"keyguard/internal/selftest"
)

// selftestRun says which parts of the selftest to run.
type selftestRun struct {
	gates, layers bool     // the git gates (internal/selftest) and the layers around them (internal/install)
	only          []string // gate checks or groups to run on their own; empty runs all of them
	noLatency     bool
	keep          bool
	runs          int
	log           io.Writer
}

// selftestResult is the record the doctor reads, with the gates' own report beside it for the
// screen and for --json.
type selftestResult struct {
	install.SelftestRecord
	Gates *selftest.Report `json:"gates,omitempty"`
}

// full reports whether this run proves everything, which is the only kind the doctor is told about.
func (o selftestRun) full() bool { return o.gates && o.layers && len(o.only) == 0 }

// runSelftest runs the git gates and then the layers around them, in that order and one after
// the other: the gates time their hooks, and a second suite running beside them would be
// measured too.
func (c *cli) runSelftest(o selftestRun) (selftestResult, error) {
	exe, err := c.exe()
	if err != nil {
		return selftestResult{}, err
	}
	started := time.Now()
	res := selftestResult{SelftestRecord: install.SelftestRecord{At: started.UTC().Format(time.RFC3339), OK: true}}
	if o.gates {
		rep, err := selftest.Run(c.ctx, selftest.Options{Binary: exe, Log: o.log, Keep: o.keep, Only: o.only, Runs: o.runs, NoLatency: o.noLatency})
		if err != nil {
			return res, err
		}
		res.Gates = rep
		res.OK = res.OK && rep.OK
		for _, g := range rep.Groups() {
			res.Layers = append(res.Layers, install.SelftestLayer{Name: "git gates: " + g.Title, OK: g.OK, Detail: g.Detail, Seconds: g.Seconds})
		}
	}
	if o.layers {
		rec, err := install.Selftest(c.ctx, install.SelftestOptions{Executable: exe, Log: o.log, Keep: o.keep})
		if err != nil {
			return res, err
		}
		res.OK = res.OK && rec.OK
		res.Layers = append(res.Layers, rec.Layers...)
	}
	res.Seconds = time.Since(started).Seconds()
	if o.full() {
		b, err := json.MarshalIndent(res.SelftestRecord, "", "  ")
		if err == nil {
			err = db.WriteFileAtomic(install.SelftestPath(c.paths()), append(b, '\n'), 0o600)
		}
		if err != nil {
			return res, fmt.Errorf("recording the selftest: %w", err)
		}
	}
	return res, nil
}

// splitOnly reads --only: "layers" is the install package's suite, anything else names gate
// checks or groups. No names at all runs both.
func splitOnly(names []string) (gates []string, wantGates, wantLayers bool) {
	if len(names) == 0 {
		return nil, true, true
	}
	for _, n := range names {
		if n == "layers" {
			wantLayers = true
			continue
		}
		gates = append(gates, n)
		wantGates = true
	}
	return gates, wantGates, wantLayers
}

func (c *cli) cmdSelftest(args []string) int {
	f := c.flagSet("selftest", "selftest [--json] [-v] [--keep] [--no-latency] [--runs N] [--only NAMES | --list]\n\n"+
		"Plants fake secrets, built at run time, in a throwaway Mac of its own and checks that every\n"+
		"protection stops what it should and lets everything else be.\n\n"+
		"First the git gates, with real git: pre-commit, reference-transaction and pre-push; what they must\n"+
		"stop (a learned key under --no-verify, a token, a .env, a push) and what they must not (clone, fetch,\n"+
		"pull, rebase, stash, branch delete, a bare mirror); and how fast they are (p50 of 10 runs against\n"+
		"150 ms and 40 ms). Then the layers around them: the learned-secret matcher, the agent guard, the\n"+
		"scanners, the publish gate, the one-minute poll and the report.\n\n"+
		"Touches nothing of yours. A full run is recorded for the doctor; a partial one is not.")
	asJSON := f.Bool("json", false, "machine-readable output")
	verbose := f.Bool("v", false, "log each step as it runs")
	keep := f.Bool("keep", false, "keep the throwaway machines, for looking at after a failure")
	noLat := f.Bool("no-latency", false, "leave out the speed checks (a busy Mac is not a broken gate)")
	runs := f.Int("runs", selftest.DefaultRuns, "timed runs behind each speed figure")
	only := f.String("only", "", "run just these, comma separated: gates, layers, a gate group or a check id")
	list := f.Bool("list", false, "list the gate checks and their ids")
	if _, code, ok := c.parse(f, args); !ok {
		return code
	}
	if *list {
		return c.listSelftest()
	}
	if *runs < 1 {
		return c.usageErr(f, "--runs must be at least 1")
	}
	names := splitList(*only)
	gateNames, wantGates, wantLayers := splitOnly(names)
	o := selftestRun{gates: wantGates, layers: wantLayers, only: gateNames, noLatency: *noLat, keep: *keep, runs: *runs}
	if len(names) > 0 && wantLayers && !wantGates {
		o.only = nil
	}
	if *verbose {
		o.log = c.err
	}
	res, err := c.runSelftest(o)
	if err != nil {
		return c.failf("selftest: %s", safeErr(err))
	}
	if *asJSON {
		c.printJSON(res)
	} else {
		c.printSelftest(res, o)
	}
	if !res.OK {
		return exitFound
	}
	return exitOK
}

func (c *cli) printSelftest(res selftestResult, o selftestRun) {
	skip := 0
	if res.Gates != nil {
		res.Gates.Table(c.out)
		skip = len(res.Gates.Groups())
	}
	if o.layers {
		if res.Gates != nil {
			fmt.Fprintln(c.out, "\nthe layers around the gates")
		}
		rows := [][]string{}
		for _, l := range res.Layers[skip:] {
			mark := "ok"
			if !l.OK {
				mark = "FAIL"
			}
			rows = append(rows, []string{mark, l.Name, secs(l.Seconds), l.Detail})
		}
		table(c.out, "  ", rows)
	}
	switch {
	case !res.OK:
		fmt.Fprintf(c.out, "\nA gate or a layer failed. `keyguard doctor` says what to do.\n")
	case o.layers:
		fmt.Fprintf(c.out, "\nevery gate and every layer stopped what it should (%s)\n", secs(res.Seconds))
	}
	if !o.full() && res.OK {
		fmt.Fprintln(c.out, "partial run: the doctor is not told")
	}
}

func (c *cli) listSelftest() int {
	checks, groupIDs := selftest.Catalog()
	rows := [][]string{{"GROUP", "CHECK", "PROVES"}}
	for _, ck := range checks {
		rows = append(rows, []string{ck.Group, ck.ID, ck.Name})
	}
	table(c.out, "", rows)
	fmt.Fprintf(c.out, "\n--only takes a check id, a group (%s), gates or layers.\n", strings.Join(slices.Clone(groupIDs), ", "))
	return exitOK
}
