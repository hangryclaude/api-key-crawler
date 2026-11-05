package pattern

import (
	"math/rand/v2"
	"os"
	"path/filepath"
	"testing"
)

// No secret-shaped literal may sit in this package's source (internal/testkit's selfscan looks), so
// every fake is built at run time: a prefix split in two, a seeded generator for the rest.

const (
	alnum     = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	lowerHex  = "0123456789abcdef"
	upperBase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
)

// fakes is a seeded source of made-up credentials.
type fakes struct{ r *rand.Rand }

func newFakes(seed uint64) *fakes {
	return &fakes{rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))}
}

// run is n characters of alphabet.
func (f *fakes) run(alphabet string, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[f.r.IntN(len(alphabet))]
	}
	return string(b)
}

// githubPAT is the shape of a classic personal access token: a four character prefix and 36 of base 62.
func (f *fakes) githubPAT() string { return "gh" + "p_" + f.run(alnum, 36) }

// awsKeyID is the shape of an access key id.
func (f *fakes) awsKeyID() string { return "AK" + "IA" + f.run(upperBase, 16) }

// awsSecret is 40 characters of base 64.
func (f *fakes) awsSecret() string { return f.run(alnum+"+/", 40) }

// writeTree writes files (path -> content) under a fresh temp dir and returns it.
func writeTree(t testing.TB, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}
