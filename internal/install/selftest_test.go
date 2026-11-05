package install

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"keyguard/internal/core"
)

func TestSelftestOfABrokenBinaryFailsLoudlyAndNeverPanics(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp) // where the throwaway machine is made
	exe := filepath.Join(tmp, "broken-keyguard")
	if err := os.WriteFile(exe, []byte("#!/bin/sh\nexit 3\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	record := core.PathsAt(filepath.Join(tmp, "real-root"))

	rec, err := Selftest(context.Background(), SelftestOptions{Executable: exe, Record: record})
	if err != nil {
		t.Fatalf("a binary that does not work is a failed layer, not an error: %v", err)
	}
	if rec.OK {
		t.Fatal("a binary that exits 3 for everything passed the selftest")
	}
	if len(rec.Layers) < 10 {
		t.Fatalf("only %d layers ran: a failure in one must not stop the rest from being reported", len(rec.Layers))
	}
	failed := 0
	for _, l := range rec.Layers {
		if !l.OK {
			failed++
			if strings.TrimSpace(l.Detail) == "" {
				t.Errorf("layer %q failed without saying why", l.Name)
			}
		}
	}
	if first := rec.Layers[0]; first.Name != "install" || first.OK || !strings.Contains(first.Detail, "does not run") {
		t.Errorf("the first layer should be the install, failing because the binary does not run: %+v", first)
	}
	if failed < 8 {
		t.Errorf("a machine with no working binary should fail most layers, failed only %d", failed)
	}

	// The record is where the doctor looks, and it says the same.
	got, ok := LoadSelftest(record)
	if !ok || got.OK || len(got.Layers) != len(rec.Layers) {
		t.Errorf("recorded selftest: %+v ok=%v", got, ok)
	}
	if fi, err := os.Stat(SelftestPath(record)); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("record mode: %v %v", fi, err)
	}
	// The throwaway machine is gone.
	if left, _ := filepath.Glob(filepath.Join(tmp, "keyguard-selftest-*")); len(left) != 0 {
		t.Errorf("the throwaway machine was left behind: %v", left)
	}
}

func TestSelftestKeepAndOnly(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	exe := filepath.Join(tmp, "broken-keyguard")
	if err := os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	rec, err := Selftest(context.Background(), SelftestOptions{Executable: exe, Only: []string{"install", "uninstall"}, Keep: true})
	if err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for _, l := range rec.Layers {
		names = append(names, l.Name)
	}
	if strings.Join(names, ",") != "install,uninstall" {
		t.Errorf("Only asked for two layers, got %v", names)
	}
	if left, _ := filepath.Glob(filepath.Join(tmp, "keyguard-selftest-*")); len(left) != 1 {
		t.Errorf("Keep should leave the machine for inspection, found %v", left)
	}
}

func TestSelftestCutShortIsNotAPass(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rec, err := Selftest(ctx, SelftestOptions{Executable: "/bin/true"})
	if err != nil {
		t.Fatal(err)
	}
	if rec.OK || len(rec.Layers) != 1 || !strings.Contains(rec.Layers[0].Detail, "interrupted") {
		t.Errorf("a selftest that never ran a layer must not read as passed: %+v", rec)
	}
}

func TestSelftestNeedsABinary(t *testing.T) {
	if _, err := Selftest(context.Background(), SelftestOptions{}); err == nil {
		t.Fatal("no binary, no test")
	}
}

func TestFakeSecretsAreRandomAndShapedLikeKeys(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		v, err := fake(rxPrefix, 36)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(v, "ghp_") || len(v) != 40 || seen[v] {
			t.Fatalf("fake %q", v)
		}
		seen[v] = true
	}
}
