package known

import (
	crand "crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

const (
	alnum    = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	b64chars = alnum + "+/"
	urlchars = alnum + "-_"
	hexchars = "0123456789abcdef"
	punct    = alnum + "!@#$%^&*()-_=+[]{};:,.<>?/~ "
)

// newRNG is a fast deterministic generator seeded from the OS; the seed is logged if the
// test fails so a failure can be replayed.
func newRNG(t testing.TB) *rand.Rand {
	t.Helper()
	var seed [32]byte
	if h := os.Getenv("KNOWN_TEST_SEED"); h != "" {
		b, err := hex.DecodeString(h)
		if err != nil || len(b) != len(seed) {
			t.Fatal("KNOWN_TEST_SEED must be 64 hex chars")
		}
		copy(seed[:], b)
	} else if _, err := crand.Read(seed[:]); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("rng seed: %x", seed)
		}
	})
	return rand.New(rand.NewChaCha8(seed))
}

func randFrom(r *rand.Rand, charset string, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = charset[r.IntN(len(charset))]
	}
	return string(b)
}

// fakeSecret assembles a secret-shaped value at runtime from a prefix and a random body,
// so no full secret-shaped literal exists in this source (PLAN.md invariant 2).
func fakeSecret(r *rand.Rand) string {
	kinds := []struct {
		prefix, charset string
		min, max        int
	}{
		{"sk-proj-", urlchars, 40, 100},
		{"ghp_", alnum, 36, 36},
		{"AKIA", "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 16, 16},
		{"", b64chars, 40, 40},
		{"", hexchars, 32, 64},
		{"xoxb-", alnum + "-", 30, 60},
		{"", punct, 12, 40},
		{"", alnum, 12, 120},
		{"eyJ", urlchars + ".", 80, 200},
		{"sk_live_", alnum, 24, 99},
	}
	k := kinds[r.IntN(len(kinds))]
	n := k.min
	if k.max > k.min {
		n += r.IntN(k.max - k.min + 1)
	}
	return k.prefix + randFrom(r, k.charset, n)
}

// noise fills n bytes with text-like (printable, lines, words) or binary (uniform) content.
func noise(r *rand.Rand, n int, text bool) []byte {
	b := make([]byte, n)
	if !text {
		var seed [32]byte
		binary.LittleEndian.PutUint64(seed[:], r.Uint64())
		binary.LittleEndian.PutUint64(seed[8:], r.Uint64())
		c := rand.NewChaCha8(seed)
		c.Read(b)
		return b
	}
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-./=:\"'{}[]()"
	for i := 0; i < n; {
		w := 1 + r.IntN(12)
		for j := 0; j < w && i < n; j++ {
			b[i] = letters[r.IntN(len(letters))]
			i++
		}
		if i < n {
			if r.IntN(8) == 0 {
				b[i] = '\n'
			} else {
				b[i] = ' '
			}
			i++
		}
	}
	return b
}

// testEnv isolates a test from real state: a private KEYGUARD_HOME, a private global git
// config, and a HOME that is not the user's.
func testEnv(t *testing.T) (root string) {
	t.Helper()
	root = filepath.Join(t.TempDir(), "kg")
	home := t.TempDir()
	cfg := filepath.Join(t.TempDir(), "gitconfig")
	if err := os.WriteFile(cfg, []byte("[user]\n\tname = t\n\temail = t@example.invalid\n[init]\n\tdefaultBranch = main\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KEYGUARD_HOME", root)
	t.Setenv("HOME", home)
	t.Setenv("GIT_CONFIG_GLOBAL", cfg)
	t.Setenv("GIT_CONFIG_SYSTEM", "/dev/null")
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_TERMINAL_PROMPT", "0")
	return root
}

func git(t testing.TB, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		// Arguments can hold fake secrets (commit messages); only the subcommand is logged.
		t.Fatalf("git %s: %v", args[0], err)
	}
	return string(out)
}
