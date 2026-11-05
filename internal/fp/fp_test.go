package fp

import (
	"crypto/rand"
	"errors"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

func randStr(t *testing.T, charset string, n int) string {
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

func TestLoadCreatesPrivateSaltOnce(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "known")
	var wg sync.WaitGroup
	fps := make([]string, 16)
	for i := range fps {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			k, err := Load(dir)
			if err != nil {
				t.Error(err)
				return
			}
			fps[i] = k.FP("same-value")
		}(i)
	}
	wg.Wait()
	for _, f := range fps {
		if f != fps[0] {
			t.Fatalf("racing loads produced different salts: %s vs %s", f, fps[0])
		}
	}
	st, err := os.Stat(filepath.Join(dir, "salt"))
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("salt mode %v, want 0600", st.Mode().Perm())
	}
	dst, _ := os.Stat(dir)
	if dst.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %v, want 0700", dst.Mode().Perm())
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("temp files left behind: %d entries", len(entries))
	}
}

func TestFPStableAndSalted(t *testing.T) {
	a, b := NewEphemeral(), NewEphemeral()
	v := randStr(t, alnum, 40)
	if a.FP(v) != a.FP(v) {
		t.Fatal("FP not deterministic")
	}
	if a.FP(v) == b.FP(v) {
		t.Fatal("different salts gave the same FP")
	}
	if len(a.FP(v)) != 32 || strings.Contains(a.FP(v), v[:8]) {
		t.Fatal("FP has wrong length or echoes the value")
	}
	if a.Base()%2 != 1 {
		t.Fatal("rolling base must be odd")
	}
}

func TestShapeNeverShowsMoreThanFourRandomChars(t *testing.T) {
	for _, pre := range []string{"", "sk-proj-", "ghp_", "AKIA", "sk-ant-api03-", "xoxb-"} {
		for n := 1; n <= 160; n += 7 {
			raw := pre + randStr(t, alnum, n)
			s := Shape(raw)
			body := strings.TrimPrefix(strings.SplitN(s, "…", 2)[0], "")
			if body != "" && !strings.HasPrefix(raw, body) {
				t.Fatalf("shape prefix %q is not a prefix of the value", body)
			}
			tail := strings.SplitN(s, "…", 2)[1]
			if len(tail) > 4 {
				t.Fatalf("tail %q longer than 4", tail)
			}
			if body != "" && body != pre && !strings.HasPrefix(pre, body) && len(body) > 4 {
				t.Fatalf("shape %q shows more than the constant prefix of %q…", s, pre)
			}
		}
	}
	if got := Shape("-----BEGIN OPENSSH PRIVATE KEY-----\nabc"); got != "-----BEGIN…KEY-----" {
		t.Fatalf("pem shape = %q", got)
	}
}

func TestRedactAndContextDropTheValue(t *testing.T) {
	for i := 0; i < 200; i++ {
		raw := "sk-proj-" + randStr(t, alnum+"-_", 20+i%60)
		line := `client = OpenAI(api_key="` + raw + `")  # ` + randStr(t, "abc ", 30)
		for _, out := range []string{Redact(line, raw), Context(line, raw)} {
			if strings.Contains(out, raw) || strings.Contains(out, raw[8:20]) {
				t.Fatalf("raw value survived: %q", out)
			}
		}
	}
	// A secret the engine reported in a different form is still masked by Scrub.
	other := randStr(t, alnum, 40)
	if got := Context("token="+other, "not-on-the-line"); strings.Contains(got, other) {
		t.Fatalf("Scrub missed a high-entropy token: %q", got)
	}
	if got := Context("const maximumRetryCountForUploads = 5", ""); !strings.Contains(got, "maximumRetryCountForUploads") {
		t.Fatalf("Scrub masked an identifier: %q", got)
	}
	if got := Context(strings.Repeat("a ", 300), ""); len([]rune(got)) > 200 {
		t.Fatalf("context not capped: %d runes", len([]rune(got)))
	}
}

func TestEntropy(t *testing.T) {
	if Entropy("aaaaaaaa") != 0 {
		t.Fatal("constant string has entropy")
	}
	if e := Entropy(randStr(t, alnum, 64)); e < 4.5 {
		t.Fatalf("random alnum entropy %.2f too low", e)
	}
}

func TestOpenNeverCreatesASalt(t *testing.T) {
	root := t.TempDir()

	// No directory at all: not created, and the error is the one callers test for.
	missing := filepath.Join(root, "no", "such", "dir")
	if _, err := Open(missing); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Open on a missing dir = %v, want fs.ErrNotExist", err)
	}
	if _, err := os.Stat(filepath.Join(root, "no")); !os.IsNotExist(err) {
		t.Fatal("Open created a directory")
	}

	// A directory that exists but holds no salt (the dangerous case: Load would mint one).
	empty := filepath.Join(root, "known")
	if err := os.Mkdir(empty, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(empty); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Open without a salt = %v, want fs.ErrNotExist", err)
	}
	if left, _ := os.ReadDir(empty); len(left) != 0 {
		t.Fatalf("Open left %d file(s) behind", len(left))
	}

	// Once Load made the salt, Open reads the same one.
	made, err := Load(empty)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := Open(empty)
	if err != nil {
		t.Fatal(err)
	}
	if v := randStr(t, alnum, 30); made.FP(v) != opened.FP(v) || made.Base() != opened.Base() {
		t.Fatal("Open read a different salt than Load made")
	}

	// A damaged salt is an error, never a silent replacement.
	if err := os.WriteFile(filepath.Join(empty, "salt"), []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, f := range map[string]func(string) (*Keyring, error){"Open": Open, "Load": Load} {
		if _, err := f(empty); err == nil || !strings.Contains(err.Error(), "5 bytes") {
			t.Errorf("%s on a damaged salt = %v", name, err)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(empty, "salt")); string(b) != "short" {
		t.Fatal("a damaged salt was overwritten")
	}
}

// Triage tells shippable keys from secret ones by the prefix Shape keeps, so the providers
// whose public and secret keys differ only there must show it.
func TestShapeKeepsTheMapboxAndSentryPrefixes(t *testing.T) {
	for _, pre := range []string{"pk.", "sk.", "sntrys_", "sntryu_"} {
		raw := pre + randStr(t, alnum, 60)
		s := Shape(raw)
		if !strings.HasPrefix(s, pre+"…") {
			t.Errorf("Shape(%s…) = %q, want it to keep the prefix", pre, s)
		}
		if tail := strings.SplitN(s, "…", 2)[1]; tail != raw[len(raw)-4:] {
			t.Errorf("%s: tail %q", pre, tail)
		}
	}
	// Too short to hide anything behind a prefix: nothing is kept.
	if s := Shape("pk.abc"); strings.HasPrefix(s, "pk.") {
		t.Errorf("a value this short is shown whole prefix-wise: %q", s)
	}
}
