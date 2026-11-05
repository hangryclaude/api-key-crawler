package db

import (
	"crypto/rand"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"keyguard/internal/core"
	"keyguard/internal/fp"
)

const alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

func randStr(t testing.TB, charset string, n int) string {
	t.Helper()
	b := make([]byte, n)
	for i := range b {
		x, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			t.Fatal(err)
		}
		b[i] = charset[x.Int64()]
	}
	return string(b)
}

// isolate points every environment knob at a temp dir, so a test can neither read nor
// write the real keyguard state or git config.
func isolate(t testing.TB) string {
	t.Helper()
	root := t.TempDir()
	t.Setenv("KEYGUARD_HOME", filepath.Join(root, "kg"))
	t.Setenv("HOME", filepath.Join(root, "home"))
	cfg := filepath.Join(root, "gitconfig")
	if err := os.WriteFile(cfg, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_CONFIG_GLOBAL", cfg)
	return filepath.Join(root, "kg")
}

func testPaths(t testing.TB) core.Paths { return core.PathsAt(isolate(t)) }

// fixture builds hits whose fingerprints come from a throwaway keyring. The raw values are
// random at run time, so this file holds nothing a scanner could flag.
type fixture struct{ kr *fp.Keyring }

func newFixture() fixture { return fixture{kr: fp.NewEphemeral()} }

func (f fixture) raw(t testing.TB) string { return "sk-" + randStr(t, alnum, 48) }

func (f fixture) hit(raw, engine string, mods ...func(*core.Hit)) core.Hit {
	h := core.Hit{
		Engine: engine, Rule: engine + "-rule", Type: "openai",
		FP: f.kr.FP(raw), Shape: fp.Shape(raw), Len: len(raw), Entropy: fp.Entropy(raw),
		Verified: core.Unverified, Context: fp.Context("API_KEY = \""+raw+"\"", raw),
		Loc: core.Location{Source: "github.com/o/a", Kind: "repo", Visibility: core.Private,
			Commit: "c1", Path: ".env", Line: 3},
	}
	for _, m := range mods {
		m(&h)
	}
	return h
}

func at(src string, vis core.Visibility, commit, path string, line int) func(*core.Hit) {
	return func(h *core.Hit) {
		h.Loc = core.Location{Source: src, Kind: "repo", Visibility: vis, Commit: commit, Path: path, Line: line}
	}
}

func verified(v core.Verified) func(*core.Hit) { return func(h *core.Hit) { h.Verified = v } }

func mustMerge(t testing.TB, st *Store, now string, hits ...core.Hit) []string {
	t.Helper()
	fresh, err := st.Merge(hits, now)
	if err != nil {
		t.Fatal(err)
	}
	return fresh
}

func mustGet(t testing.TB, st *Store, f string) core.Secret {
	t.Helper()
	s, ok := st.Get(f)
	if !ok {
		t.Fatalf("secret %s not stored", fp.ID(f))
	}
	return s
}

// readAll returns every file under dir joined, for "no raw value anywhere" checks.
func readAll(t testing.TB, dir string) string {
	t.Helper()
	var sb strings.Builder
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		sb.Write(b)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return sb.String()
}
