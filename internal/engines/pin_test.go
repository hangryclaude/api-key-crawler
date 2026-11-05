package engines

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"keyguard/internal/core"
)

// ----- P0-01: an engine that is not the pinned binary does not run -----

// stubBinary writes an executable into the test's own temp dir that leaves a marker file when
// it runs, and returns its path, its sha256 and a func that says whether it ran. It stands in
// for an engine whose binary changed; the real binaries are never touched.
func stubBinary(t *testing.T, name, body string) (path, sum string, ran func() bool) {
	t.Helper()
	dir := t.TempDir()
	marker := filepath.Join(dir, "ran")
	path = filepath.Join(dir, name)
	script := "#!/bin/sh\n# " + body + "\n: > '" + marker + "'\nprintf '[]'\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256([]byte(script))
	return path, hex.EncodeToString(h[:]), func() bool { _, err := os.Stat(marker); return err == nil }
}

func resetPinMemo() {
	memoMu.Lock()
	clear(memo)
	memoMu.Unlock()
}

func TestAnEngineWithTheWrongHashIsRefused(t *testing.T) {
	f := getFixture(t)
	bin, sum, ran := stubBinary(t, "betterleaks", "the pinned build")
	wrong := strings.Repeat("0", 64)
	root := t.TempDir()
	writeLines(t, root, "a.txt", "nothing")

	e, err := New("betterleaks", bin, f.kr, WithPins(map[string]Pin{"betterleaks": {Version: "1.9.0", SHA256: wrong}}))
	if err != nil {
		t.Fatal(err)
	}
	err = e.ScanDir(context.Background(), root, testOpts(), func(core.Hit) {})
	var pe *PinError
	if !errors.As(err, &pe) {
		t.Fatalf("a binary that is not the pinned one was run: %v", err)
	}
	if pe.Engine != "betterleaks" || pe.Want != wrong || pe.Got != sum {
		t.Errorf("pin error %+v", pe)
	}
	if msg := err.Error(); strings.Contains(msg, sum) || strings.Contains(msg, wrong) {
		t.Errorf("the error prints whole hashes: %s", msg)
	}
	if ran() {
		t.Error("the engine was started although it failed its pin")
	}
	if v := e.Version(); v != "" {
		t.Errorf("an engine that fails its pin answered Version() with %q (it was started to ask)", v)
	}
	if ran() {
		t.Error("Version() started a binary that fails its pin")
	}
	if !errors.As(CheckPin(e), &pe) {
		t.Error("CheckPin does not report the mismatch")
	}
	if !e.Available() {
		t.Error("Available() is about installation, not the pin")
	}

	// The right hash, in either case: it runs.
	for _, pin := range []string{sum, strings.ToUpper(sum)} {
		e, _ := New("betterleaks", bin, f.kr, WithPins(map[string]Pin{"betterleaks": {SHA256: pin}}))
		if err := e.ScanDir(context.Background(), root, testOpts(), func(core.Hit) {}); err != nil {
			t.Fatalf("the pinned binary was refused: %v", err)
		}
		if !ran() {
			t.Fatal("the pinned binary did not run")
		}
		os.Remove(filepath.Join(filepath.Dir(bin), "ran"))
	}
	// An engine the pins do not name, or name without a hash, is not checked.
	for _, pins := range []map[string]Pin{nil, {"gitleaks": {SHA256: wrong}}, {"betterleaks": {Version: "1.9.0"}}} {
		e, _ := New("betterleaks", bin, f.kr, WithPins(pins))
		if err := e.ScanDir(context.Background(), root, testOpts(), func(core.Hit) {}); err != nil {
			t.Errorf("pins %v: %v", pins, err)
		}
		if CheckPin(e) != nil {
			t.Errorf("pins %v: CheckPin failed", pins)
		}
	}
}

// Titus is a symlink that is repointed on upgrade; the pin is of what the path resolves to.
func TestARepointedSymlinkFailsItsPin(t *testing.T) {
	f := getFixture(t)
	a, sumA, _ := stubBinary(t, "titus", "version one")
	b, _, ranB := stubBinary(t, "titus", "version two")
	link := filepath.Join(t.TempDir(), "titus")
	if err := os.Symlink(a, link); err != nil {
		t.Fatal(err)
	}
	e, _ := New("titus", link, f.kr, WithPins(map[string]Pin{"titus": {SHA256: sumA}}))
	if err := CheckPin(e); err != nil {
		t.Fatalf("the pinned target was refused through its link: %v", err)
	}
	if err := os.Remove(link); err != nil { // our own link, in our own temp dir
		t.Fatal(err)
	}
	if err := os.Symlink(b, link); err != nil {
		t.Fatal(err)
	}
	e2, _ := New("titus", link, f.kr, WithPins(map[string]Pin{"titus": {SHA256: sumA}}))
	var pe *PinError
	if err := e2.ScanDir(context.Background(), t.TempDir(), testOpts(), func(core.Hit) {}); !errors.As(err, &pe) {
		t.Fatalf("a repointed link ran the new binary: %v", err)
	}
	if ranB() {
		t.Error("the new binary was started")
	}
}

// A pre-commit hook has 150 ms and is a new process every time. The hash of a 170 MB binary is
// read once per size, mtime, ctime and inode, remembered in a file, and read again the moment
// any of them changes.
func TestPinHashIsReadOncePerFileState(t *testing.T) {
	f := getFixture(t)
	bin, sum, _ := stubBinary(t, "betterleaks", "cached")
	cache := filepath.Join(t.TempDir(), "state", "engine-hashes.json")
	pin := WithPins(map[string]Pin{"betterleaks": {SHA256: sum}})
	root := t.TempDir()
	writeLines(t, root, "a.txt", "nothing")
	scan := func(opts ...Option) error {
		e, err := New("betterleaks", bin, f.kr, append([]Option{pin}, opts...)...)
		if err != nil {
			t.Fatal(err)
		}
		return e.ScanDir(context.Background(), root, testOpts(), func(core.Hit) {})
	}

	resetPinMemo()
	start := hashReads.Load()
	for i := 0; i < 5; i++ {
		if err := scan(WithHashCache(cache)); err != nil {
			t.Fatal(err)
		}
	}
	if n := hashReads.Load() - start; n != 1 {
		t.Errorf("the binary was read %d times for 5 scans, want 1", n)
	}
	if _, err := os.Stat(cache); err != nil {
		t.Fatalf("no cache file: %v", err)
	}

	// A new process: nothing in memory, the file answers.
	resetPinMemo()
	start = hashReads.Load()
	if err := scan(WithHashCache(cache)); err != nil {
		t.Fatal(err)
	}
	if n := hashReads.Load() - start; n != 0 {
		t.Errorf("a second process read the binary %d times although the cache file knew it", n)
	}
	// Without a cache file the second process reads it (and only once).
	resetPinMemo()
	start = hashReads.Load()
	for i := 0; i < 3; i++ {
		if err := scan(); err != nil {
			t.Fatal(err)
		}
	}
	if n := hashReads.Load() - start; n != 1 {
		t.Errorf("without a cache file: %d reads, want 1", n)
	}

	// The binary is rewritten with other bytes of the same length and its mtime put back. Only the
	// change time moves, and it is enough: the cache is not believed and the new hash is refused.
	fi, err := os.Stat(bin)
	if err != nil {
		t.Fatal(err)
	}
	old, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	evil := []byte(strings.Replace(string(old), "cached", "CACHED", 1))
	time.Sleep(20 * time.Millisecond) // ctime has the file system's resolution
	if err := os.WriteFile(bin, evil, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(bin, fi.ModTime(), fi.ModTime()); err != nil {
		t.Fatal(err)
	}
	resetPinMemo()
	var pe *PinError
	if err := scan(WithHashCache(cache)); !errors.As(err, &pe) {
		t.Fatalf("a binary rewritten to the same size and mtime passed its pin: %v", err)
	}
}

func TestACorruptHashCacheCostsARehash(t *testing.T) {
	f := getFixture(t)
	bin, sum, _ := stubBinary(t, "betterleaks", "x")
	cache := filepath.Join(t.TempDir(), "engine-hashes.json")
	for _, content := range []string{"", "not json", `{"version":9,"entries":null}`, `{"version":1,"entries":{"x":`} {
		if err := os.WriteFile(cache, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		resetPinMemo()
		e, _ := New("betterleaks", bin, f.kr, WithPins(map[string]Pin{"betterleaks": {SHA256: sum}}), WithHashCache(cache))
		if err := CheckPin(e); err != nil {
			t.Errorf("cache %q: %v", content, err)
		}
	}
	// A cache that lies about the hash is not believed for another file state.
	resetPinMemo()
	e, _ := New("betterleaks", bin, f.kr, WithPins(map[string]Pin{"betterleaks": {SHA256: strings.Repeat("1", 64)}}), WithHashCache(cache))
	if CheckPin(e) == nil {
		t.Error("the wrong pin passed through a cache")
	}
}
