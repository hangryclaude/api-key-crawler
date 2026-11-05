package selftest

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
)

// goSource is n small functions of ordinary code, numbered from `from`: the body of a
// realistic commit, with nothing in it that looks like a key.
func goSource(pkg string, from, n int) string {
	var b strings.Builder
	if from == 0 {
		fmt.Fprintf(&b, "package %s\n\n", pkg)
	}
	for i := from; i < from+n; i++ {
		fmt.Fprintf(&b, "// Compute%d returns the distance between a and b, shifted by %d.\n", i, i)
		fmt.Fprintf(&b, "func Compute%d(a, b int) int {\n\tif a > b {\n\t\treturn a - b + %d\n\t}\n\treturn b - a + %d\n}\n\n", i, i, i*7)
	}
	return b.String()
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // the system has no randomness; nothing here can go on
	}
	return b
}

// randomUUID is a version 4 UUID: random, key-length, and not a secret.
func randomUUID() string {
	b := randomBytes(16)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// randomChecksum is a sha256 as `sha256sum` prints it: 64 random-looking hex characters that
// are not a secret.
func randomChecksum() string {
	sum := sha256.Sum256(randomBytes(32))
	return hex.EncodeToString(sum[:])
}

// fakePEM is a private key block with a random body. The header is assembled from parts so
// no key-shaped literal sits in this source; the body lines are remembered, so a hook that
// printed one would be caught.
func (s *suite) fakePEM() string {
	var lines []string
	for i := 0; i < 3; i++ {
		l := base64.StdEncoding.EncodeToString(randomBytes(48))
		lines = append(lines, l)
		s.fakes = append(s.fakes, l)
	}
	return "-----BEGIN " + "PRIVATE KEY" + "-----\n" + strings.Join(lines, "\n") + "\n-----END " + "PRIVATE KEY" + "-----\n"
}

// readSmall reads a file the audits look inside, skipping anything too big to be a key store.
func readSmall(p string) ([]byte, error) {
	fi, err := os.Stat(p)
	if err != nil {
		return nil, err
	}
	if fi.Size() > 32<<20 {
		return nil, errors.New("too big")
	}
	return os.ReadFile(p)
}
