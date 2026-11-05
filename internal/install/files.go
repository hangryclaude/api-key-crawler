package install

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// hashFile is the hex SHA-256 of a file's bytes.
func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func hashBytes(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// writeIfChanged writes data to path atomically (temp file beside it, then rename) unless
// the file already holds exactly that. changed says whether it wrote.
func writeIfChanged(path string, data []byte, perm os.FileMode) (changed bool, err error) {
	if cur, err := os.ReadFile(path); err == nil && string(cur) == string(data) {
		if fi, err := os.Stat(path); err == nil && fi.Mode().Perm() == perm {
			return false, nil
		}
	}
	return true, writeAtomic(path, data, perm)
}

func writeAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".kg-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // a no-op once renamed
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// copyFileAtomic copies src over dst with the given mode, never leaving a half-written dst:
// the hooks on this Mac execute it, so they must see the old binary or the new one.
func copyFileAtomic(src, dst string, perm os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	dir := filepath.Dir(dst)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".kg-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := io.Copy(tmp, in); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), dst)
}

// moveAside takes path out of the way without deleting it: it lands in dir under its own
// name (with a counter if that name is taken). Crossing a filesystem falls back to copy,
// then removal of the original, which is the only way a file can leave its place there.
func moveAside(path, dir string) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	dst := filepath.Join(dir, filepath.Base(path))
	for i := 2; ; i++ {
		if _, err := os.Lstat(dst); errors.Is(err, fs.ErrNotExist) {
			break
		}
		dst = filepath.Join(dir, fmt.Sprintf("%s.%d", filepath.Base(path), i))
	}
	err := os.Rename(path, dst)
	var le *os.LinkError
	if errors.As(err, &le) && errors.Is(le.Err, syscall.EXDEV) {
		fi, serr := os.Stat(path)
		if serr != nil {
			return "", serr
		}
		if err = copyFileAtomic(path, dst, fi.Mode().Perm()); err == nil {
			err = os.Remove(path)
		}
	}
	if err != nil {
		return "", err
	}
	return dst, nil
}

// shellQuote makes s one word for sh: plain paths stay as they are, anything else gets
// single quotes.
func shellQuote(s string) string {
	if s != "" && strings.IndexFunc(s, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("_-./+@%:,=", r))
	}) < 0 {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// sameFile reports whether two paths are one file on disk.
func sameFile(a, b string) bool {
	fa, err := os.Stat(a)
	if err != nil {
		return false
	}
	fb, err := os.Stat(b)
	return err == nil && os.SameFile(fa, fb)
}
