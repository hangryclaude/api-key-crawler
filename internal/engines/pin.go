package engines

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"keyguard/internal/core"
)

// Pin is an engine binary as the installer recorded it (config.json "pins"). The fields and
// their order are install.Pin's, so the wire code converts one to the other directly.
//
// The hash is what is enforced. Version is for people: a binary with the pinned hash has the
// pinned version, and one without it is refused whatever it says.
type Pin struct {
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}

// PinError is returned by a scan, and by Version's silence, for a binary that is not the one
// that was pinned. TruffleHog replaced itself mid-session (3.97.5 to 3.99.8, STEAL P0-01),
// betterleaks 2.0 drops flags the hooks use, and a hook that fails open on an engine that
// changed its flags protects nothing: the scan stops until someone re-pins on purpose.
type PinError struct {
	Engine, Path string
	Want, Got    string // sha256, hex
}

func (e *PinError) Error() string {
	return fmt.Sprintf("engines: %s: %s is not the pinned binary (pinned sha256 %.16s…, found %.16s…); the scan was not run. Check what changed, then pin it again deliberately",
		e.Engine, e.Path, e.Want, e.Got)
}

// WithPins makes an engine refuse to run unless its binary has the sha256 pinned under its
// name. An engine with no entry, or an entry with no hash, is not checked. The hash is of the
// file the path resolves to, so a repointed symlink (titus is one) is caught.
func WithPins(pins map[string]Pin) Option {
	return func(b *base) {
		if p, ok := pins[b.name]; ok && p.SHA256 != "" {
			b.pin = &Pin{Version: p.Version, SHA256: strings.ToLower(p.SHA256)}
		}
	}
}

// WithHashCache keeps what was learned about a binary's hash in a file, so the next process
// does not read 170 MB (trufflehog) to learn it again. A pre-commit hook is a new process
// every time and has 150 ms. The file is advisory: a missing, unreadable or stale one costs
// a rehash and never a wrong answer.
func WithHashCache(path string) Option { return func(b *base) { b.hashCache = path } }

// CheckPin reports whether e is the binary it was pinned to. It is nil for an engine built
// without a pin. A doctor asks this without starting a scan.
func CheckPin(e core.Engine) error {
	if c, ok := e.(interface{ checkPin() error }); ok {
		return c.checkPin()
	}
	return nil
}

func (b *base) checkPin() error {
	if b.pin == nil {
		return nil
	}
	sum, err := b.sumOf(b.bin)
	if err != nil {
		return fmt.Errorf("engines: %s: cannot read the binary to check its pin: %w", b.name, err)
	}
	if sum != b.pin.SHA256 {
		return &PinError{Engine: b.name, Path: b.bin, Want: b.pin.SHA256, Got: sum}
	}
	return nil
}

// fileKey is what makes a file the same file for the purpose of its hash: where it really is
// and the stat fields git's index trusts. ctime is the one that cannot be set back, so a
// binary rewritten to the same size and mtime is still noticed.
type fileKey struct {
	path         string
	size         int64
	mtime, ctime int64
	dev, ino     uint64
}

type hashEntry struct {
	Size   int64  `json:"size"`
	MTime  int64  `json:"mtime"`
	CTime  int64  `json:"ctime"`
	Dev    uint64 `json:"dev"`
	Ino    uint64 `json:"ino"`
	SHA256 string `json:"sha256"`
}

type hashDoc struct {
	Version int                  `json:"version"`
	Entries map[string]hashEntry `json:"entries"`
}

var (
	memoMu sync.Mutex
	memo   = map[fileKey]string{}

	// hashReads counts files read in full to be hashed; the tests watch it.
	hashReads atomic.Int64
)

func keyOf(path string) (fileKey, error) {
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return fileKey{}, err
	}
	fi, err := os.Stat(real)
	if err != nil {
		return fileKey{}, err
	}
	k := fileKey{path: real, size: fi.Size(), mtime: fi.ModTime().UnixNano()}
	k.ctime, k.dev, k.ino = statExtra(fi)
	return k, nil
}

func (k fileKey) entry(sum string) hashEntry {
	return hashEntry{Size: k.size, MTime: k.mtime, CTime: k.ctime, Dev: k.dev, Ino: k.ino, SHA256: sum}
}

func (k fileKey) matches(e hashEntry) bool {
	return e.SHA256 != "" && e.Size == k.size && e.MTime == k.mtime && e.CTime == k.ctime && e.Dev == k.dev && e.Ino == k.ino
}

// sumOf is the sha256 of the file at path, read once per size, mtime, ctime and inode.
func (b *base) sumOf(path string) (string, error) {
	k, err := keyOf(path)
	if err != nil {
		return "", err
	}
	memoMu.Lock()
	sum, ok := memo[k]
	memoMu.Unlock()
	if ok {
		return sum, nil
	}
	doc := b.loadHashes()
	if e, ok := doc.Entries[k.path]; ok && k.matches(e) {
		memoMu.Lock()
		memo[k] = e.SHA256
		memoMu.Unlock()
		return e.SHA256, nil
	}
	if sum, err = hashFile(k.path); err != nil {
		return "", err
	}
	// The file may have been replaced while it was read; the entry then describes a file it
	// does not match and the next stat finds the difference.
	memoMu.Lock()
	memo[k] = sum
	memoMu.Unlock()
	if b.hashCache != "" {
		doc.Entries[k.path] = k.entry(sum)
		if err := saveHashes(b.hashCache, doc); err != nil {
			b.note("the engine hash cache could not be written; binaries are rehashed on every start")
		}
	}
	return sum, nil
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	hashReads.Add(1)
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (b *base) loadHashes() hashDoc {
	doc := hashDoc{Version: 1, Entries: map[string]hashEntry{}}
	if b.hashCache == "" {
		return doc
	}
	raw, err := os.ReadFile(b.hashCache)
	if err != nil {
		return doc
	}
	var got hashDoc
	if json.Unmarshal(raw, &got) != nil || got.Version != 1 || got.Entries == nil {
		return doc
	}
	return got
}

// saveHashes replaces the cache file atomically; two hooks racing leave one of their entries,
// and the other is rehashed next time.
func saveHashes(path string, doc hashDoc) error {
	raw, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".engine-hashes-*")
	if err != nil {
		return err
	}
	_, werr := tmp.Write(raw)
	cerr := tmp.Close()
	if err := errors.Join(werr, cerr); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return nil
}
