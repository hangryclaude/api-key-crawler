package main

import (
	"context"
	"fmt"
	"slices"

	"keyguard/internal/core"
)

// nativeEngine is the in-process engine of the native-engine plan (docs/NATIVE-BASELINE.md).
// Until its milestone M2 builds it, bench accepts the name so the gate commands of the plan are
// written in the form they will keep, and reports the engine as not built. It is not in
// engines.Names, so "all", the tiers and every other engine behave exactly as before. When the
// engine registers, delete this file and its three call sites in cmdBench.
const nativeEngine = "native"

// nativeNotBuilt is what bench says in place of a score.
const nativeNotBuilt = "native: not built yet (the in-process engine arrives with milestone M2 of the native-engine plan); nothing was scored for it"

// notBuilt stands in for the native engine in a run that also names real engines. It is never
// available, so the bench lists it as skipped, with "not built yet" as its version, and scans
// nothing with it.
type notBuilt struct{}

func (notBuilt) Name() string    { return nativeEngine }
func (notBuilt) Version() string { return "not built yet" }
func (notBuilt) Available() bool { return false }

func (notBuilt) ScanGit(context.Context, string, core.Range, core.ScanOpts, core.Emit) error {
	return core.ErrUnsupported
}

func (notBuilt) ScanStaged(context.Context, string, core.ScanOpts, core.Emit) error {
	return core.ErrUnsupported
}

func (notBuilt) ScanDir(context.Context, string, core.ScanOpts, core.Emit) error {
	return core.ErrUnsupported
}

// withoutNative splits the engine names bench was asked for into the ones that exist and whether
// the unbuilt native engine was among them.
func withoutNative(names []string) (rest []string, asked bool) {
	if !slices.Contains(names, nativeEngine) {
		return names, false
	}
	return slices.DeleteFunc(slices.Clone(names), func(n string) bool { return n == nativeEngine }), true
}

// nativeOnly answers `bench --engines native`: no corpus is built and nothing is scored, and the
// exit status is a failure, because a gate command that scored nothing must not read as a pass.
func (c *cli) nativeOnly(asJSON bool) int {
	if asJSON {
		c.printJSON(map[string]any{"engines": []map[string]any{{"name": nativeEngine, "built": false, "note": nativeNotBuilt}}})
	} else {
		fmt.Fprintln(c.out, nativeNotBuilt)
	}
	return exitFailed
}
