// Package selftest proves the git gates work, end to end, the way git itself runs them.
//
// It builds a throwaway Mac in a temp dir: its own HOME, its own global git config and its
// own data root, with the three hooks wired to the binary under test by the very command
// lines `keyguard install` writes. Fake secrets, made at run time from a public prefix and
// random characters, are registered in the learned-secret store through the code `keyguard
// learn` uses. Then it does what must be stopped (a learned key committed with --no-verify,
// an unknown token pushed, a .env staged) and what must not be (a clone, a fetch, a pull, a
// rebase, a stash, a branch delete, a bare mirror fed a leaked key), with real git and the
// real engines, and times the hooks against PLAN.md's budgets.
//
// A check that fails is a result, not an error: Run returns an error only when it cannot
// build the machine at all. The children get a short whitelist for an environment, never the
// caller's, so nothing of the real HOME, git config, data root or GitHub login can reach a
// check, and a check can never learn the real keys exported into the caller's shell.
package selftest

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"time"
)

// Budgets are PLAN.md's: these hooks run on every commit, push and ref update.
const (
	BudgetPreCommit = 150 * time.Millisecond
	BudgetRefTx     = 40 * time.Millisecond
	BudgetPrePush   = time.Second // to a local remote, which counts as private
)

// DefaultRuns is how many timed runs sit behind each latency figure.
const DefaultRuns = 10

// Options says what to test.
type Options struct {
	Binary    string    // the keyguard binary under test; the hooks run exactly this file
	Log       io.Writer // one line per check as it starts; never a value. nil is silent
	Keep      bool      // leave the throwaway machine behind, for looking at after a failure
	Only      []string  // run just these checks or groups (see Catalog); empty runs everything
	Runs      int       // timed runs behind each latency figure; 0 means DefaultRuns
	NoLatency bool      // leave out the speed checks: a busy machine is not a broken gate
	TempDir   string    // where the machine is built; "" is os.TempDir()
}

// Check is one thing proved, or not.
type Check struct {
	ID      string  `json:"id"`
	Group   string  `json:"group"`
	Name    string  `json:"name"`
	OK      bool    `json:"ok"`
	Detail  string  `json:"detail"`
	Seconds float64 `json:"seconds"`
}

// Latency is one hook's measured speed, run through sh -c exactly as git runs it.
type Latency struct {
	Hook     string  `json:"hook"`
	Runs     int     `json:"runs"`
	Warmups  int     `json:"warmups"`
	P50ms    float64 `json:"p50_ms"`
	P95ms    float64 `json:"p95_ms"`
	MaxMs    float64 `json:"max_ms"`
	BudgetMs float64 `json:"budget_ms"`
	OK       bool    `json:"ok"`
	Retried  bool    `json:"retried,omitempty"` // the first set of runs was over budget and was measured again
	Load1    float64 `json:"load1,omitempty"`   // 1-minute load average while measuring; 0 = unknown
	Cores    int     `json:"cores"`
}

// Report is everything a run found out.
type Report struct {
	At      string    `json:"at"`
	Binary  string    `json:"binary"`
	Git     string    `json:"git"`
	Machine string    `json:"machine,omitempty"` // where the throwaway machine was left, when Keep asked for it
	OK      bool      `json:"ok"`
	Seconds float64   `json:"seconds"`
	Checks  []Check   `json:"checks"`
	Latency []Latency `json:"latency,omitempty"`
}

// Failed lists the checks that did not pass.
func (r *Report) Failed() []Check {
	var out []Check
	for _, c := range r.Checks {
		if !c.OK {
			out = append(out, c)
		}
	}
	return out
}

// Run builds the machine, runs the checks and takes the machine apart again.
func Run(ctx context.Context, o Options) (*Report, error) {
	rep, _, err := run(ctx, o)
	return rep, err
}

// run is Run with the suite handed back, which this package's tests use to look for the
// fakes in everything the report says.
func run(ctx context.Context, o Options) (*Report, *suite, error) {
	sel, err := selection(o.Only)
	if err != nil {
		return nil, nil, err
	}
	s, err := newSuite(ctx, o)
	if err != nil {
		return nil, nil, err
	}
	if !o.Keep {
		defer os.RemoveAll(s.dir) // our own temp dir; it holds fakes only
	}
	started := time.Now()
	rep := &Report{At: started.UTC().Format(time.RFC3339), Binary: s.bin, OK: true}

	// The machine is not optional: nothing else means anything without it. A machine that
	// cannot be wired ends the run with one failing row that says why.
	first := s.exec(machineCheck())
	rep.Checks = append(rep.Checks, first)
	rep.Git = s.gitVersion
	if !first.OK {
		rep.OK = false
	} else {
		for _, ck := range checks() {
			if ck.group == "machine" || !sel(ck) || (o.NoLatency && ck.group == "speed") {
				continue
			}
			if ctx.Err() != nil {
				break
			}
			c := s.exec(ck)
			rep.OK = rep.OK && c.OK
			rep.Checks = append(rep.Checks, c)
		}
	}
	if err := ctx.Err(); err != nil {
		// A run that was cut short has not shown that anything works.
		rep.OK = false
		rep.Checks = append(rep.Checks, Check{ID: "interrupted", Group: "machine", Name: "run to the end", Detail: "interrupted: " + err.Error()})
	}
	rep.Latency = s.latency
	if o.Keep {
		rep.Machine = s.dir
	}
	rep.Seconds = time.Since(started).Seconds()
	return rep, s, nil
}

// CheckInfo describes one check for listings.
type CheckInfo struct {
	ID    string `json:"id"`
	Group string `json:"group"`
	Name  string `json:"name"`
}

// Catalog lists every check in the order they run, and the group ids that select several.
func Catalog() (all []CheckInfo, groupIDs []string) {
	for _, g := range groups {
		groupIDs = append(groupIDs, g.id)
	}
	for _, ck := range checks() {
		all = append(all, CheckInfo{ck.id, ck.group, ck.name})
	}
	return all, groupIDs
}

// selection turns Options.Only into a filter. Names are check ids or group ids; an empty
// list selects everything, and a name that is neither is an error, since a typo that quietly
// selects nothing would read as a pass.
func selection(only []string) (func(check) bool, error) {
	if len(only) == 0 {
		return func(check) bool { return true }, nil
	}
	known := map[string]bool{"gates": true}
	for _, g := range groups {
		known[g.id] = true
	}
	for _, ck := range checks() {
		known[ck.id] = true
	}
	for _, name := range only {
		if !known[name] {
			var ids []string
			for n := range known {
				ids = append(ids, n)
			}
			slices.Sort(ids)
			// A list of forty ids is no help to someone who mistyped one; the nearest is.
			if near := nearest(name, ids); near != "" {
				return nil, fmt.Errorf("selftest: %q is not a check or a group; did you mean %q? (keyguard selftest --list shows them all)", name, near)
			}
			return nil, fmt.Errorf("selftest: %q is not a check or a group (keyguard selftest --list shows them all)", name)
		}
	}
	return func(ck check) bool {
		return slices.Contains(only, "gates") || slices.Contains(only, ck.id) || slices.Contains(only, ck.group)
	}, nil
}

// exec runs one check, timing it and turning a panic into a failure of that check alone.
func (s *suite) exec(ck check) (c Check) {
	c = Check{ID: ck.id, Group: ck.group, Name: ck.name}
	started := time.Now()
	defer func() {
		if p := recover(); p != nil {
			c.OK, c.Detail = false, "internal error: "+s.line(fmt.Sprint(p))
		}
		c.Seconds = time.Since(started).Seconds()
	}()
	s.logf("%s", ck.id)
	detail, err := ck.run(s)
	if err != nil {
		c.Detail = s.line(err.Error())
		return c
	}
	c.OK, c.Detail = true, detail
	return c
}

func (s *suite) logf(format string, a ...any) {
	if s.o.Log != nil {
		fmt.Fprintf(s.o.Log, "selftest: "+format+"\n", a...)
	}
}

// errNoBinary is returned when the binary under test cannot be run at all, which is not the
// same as a binary that runs and gets things wrong.
var errNoBinary = errors.New("selftest: the binary under test is missing or not executable")

func resolveBinary(path string) (string, error) {
	if path == "" {
		return "", errNoBinary
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	fi, err := os.Stat(abs)
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm()&0o111 == 0 {
		return "", fmt.Errorf("%w: %s", errNoBinary, abs)
	}
	return abs, nil
}

// nearest is the id closest to name by edit distance, or "" when nothing is within three edits.
func nearest(name string, ids []string) string {
	best, bestD := "", 4
	for _, id := range ids {
		if d := editDistance(name, id); d < bestD {
			best, bestD = id, d
		}
	}
	return best
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
