package main

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"keyguard/internal/bench"
	"keyguard/internal/engines"
	"keyguard/internal/testkit"
)

// The native engine is not built until milestone M2 of the native-engine plan. Until then bench
// takes its name, says it is not built, and changes nothing about the engines that exist.

func TestBenchNativeAloneReportsNotBuiltAndScoresNothing(t *testing.T) {
	w := newWorld(t)
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)

	out, errs, code := w.cli("bench", "--engines", "native")
	if code != exitFailed {
		t.Errorf("exit %d, want %d: a gate that scored nothing must not read as a pass\n%s%s", code, exitFailed, out, errs)
	}
	if !strings.Contains(out, "native: not built yet") {
		t.Errorf("stdout does not say the engine is not built:\n%s", out)
	}
	if left, _ := filepath.Glob(filepath.Join(tmp, "keyguard-bench-*")); len(left) != 0 {
		t.Errorf("a corpus was built for an engine that does not exist: %v", left)
	}

	out, _, code = w.cli("bench", "--engines", "native", "--json")
	var res struct {
		Engines []struct {
			Name  string `json:"name"`
			Built bool   `json:"built"`
		} `json:"engines"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("--json is not JSON: %v\n%s", err, out)
	}
	if code != exitFailed || len(res.Engines) != 1 || res.Engines[0].Name != "native" || res.Engines[0].Built {
		t.Errorf("--json: exit %d, %+v", code, res)
	}
}

// engines.Names is what "all", the tiers and the contract tests range over; a stub in it would
// put an engine that cannot scan into all of them.
func TestNativeIsNotRegisteredYet(t *testing.T) {
	for _, n := range engines.Names {
		if n == nativeEngine {
			t.Fatalf("%q is in engines.Names; the stub must go when the engine registers", n)
		}
	}
	if _, err := engines.New(nativeEngine, "", bench.KeyringFor(1)); err == nil {
		t.Errorf("engines.New(%q) succeeded before the engine exists", nativeEngine)
	}
}

func TestBenchNativeBesideARealEngineChangesNothingForIt(t *testing.T) {
	testkit.EnginePath(t, "betterleaks") // skips here, but fails under KEYGUARD_TEST_REQUIRE_ENGINES=1
	w := newWorld(t)
	t.Setenv("TMPDIR", t.TempDir())

	score := func(list string) (string, string) {
		out, errs, code := w.cli("bench", "--engines", list, "--json", "--out", filepath.Join(w.m.dir, "bench-"+strings.ReplaceAll(list, ",", "-")))
		if code != exitOK {
			t.Fatalf("bench --engines %s: exit %d\n%s\n%s", list, code, out, errs)
		}
		return out, errs
	}
	alone, aloneErrs := score("betterleaks")
	beside, besideErrs := score("betterleaks,native")

	if strings.Contains(aloneErrs, "native") {
		t.Errorf("a run without native mentions it:\n%s", aloneErrs)
	}
	if !strings.Contains(besideErrs, "native: not built yet") {
		t.Errorf("a run that asked for native does not say so:\n%s", besideErrs)
	}
	rowsAlone, nativeAlone := scored(t, alone)
	rowsBeside, nativeBeside := scored(t, beside)
	if nativeAlone != "" {
		t.Errorf("a run that did not ask for native lists it: %s", nativeAlone)
	}
	if version, skipped, _ := strings.Cut(nativeBeside, "|"); version != "not built yet" || skipped == "" {
		t.Errorf("the native row does not say it was skipped as not built yet: version %q, skipped %q", version, skipped)
	}
	// Same seed, same corpus, same engine: the rows and the pipeline are the same numbers. Only
	// the seconds differ from run to run, so they are not part of what is compared.
	if rowsAlone != rowsBeside {
		t.Errorf("asking for native changed what the real engines scored:\nalone:  %s\nbeside: %s", rowsAlone, rowsBeside)
	}
}

// scored splits bench --json into the part that does not depend on how fast the run was (each
// real engine's recall, precision and count, and the pipeline's) and the native row, if any.
func scored(t *testing.T, js string) (rows, native string) {
	t.Helper()
	var res struct {
		Engines []struct {
			Name      string  `json:"name"`
			Version   string  `json:"version"`
			Skipped   string  `json:"skipped"`
			Recall    float64 `json:"recall"`
			Precision float64 `json:"precision"`
			Reported  int     `json:"reported"`
		} `json:"engines"`
		Pipeline struct {
			Recall    float64 `json:"recall"`
			Precision float64 `json:"precision"`
			Reported  int     `json:"reported"`
		} `json:"pipeline"`
	}
	if err := json.Unmarshal([]byte(js), &res); err != nil {
		t.Fatalf("bench --json: %v", err)
	}
	kept := res.Engines[:0:0]
	for _, e := range res.Engines {
		if e.Name == nativeEngine {
			native = e.Version + "|" + e.Skipped
			continue
		}
		kept = append(kept, e)
	}
	res.Engines = kept
	b, _ := json.Marshal(res)
	return string(b), native
}
