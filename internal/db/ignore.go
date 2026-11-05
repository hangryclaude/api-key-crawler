package db

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"syscall"
)

// IgnoreEntry is one fingerprint a human marked as a false positive. It holds no secret:
// the key is the salted fingerprint and the id is its first six hex digits.
type IgnoreEntry struct {
	ID     string `json:"id"`
	Reason string `json:"reason,omitempty"`
	At     string `json:"at"`
}

// ignoreDoc is the on-disk form of state/ignore.json. A map keyed by fingerprint cannot
// hold a duplicate and answers "is this ignored" without a scan, which a pre-commit hook
// asks on its hot path.
type ignoreDoc struct {
	Version int                    `json:"version"`
	Ignored map[string]IgnoreEntry `json:"ignored"`
}

// IgnoreList is a read-only view of ignore.json for callers that only need to ask, such as
// the hooks. A Store keeps its own mutable copy.
type IgnoreList struct{ m map[string]IgnoreEntry }

// LoadIgnore reads the list at path. A missing file is the normal empty state.
func LoadIgnore(path string) (*IgnoreList, error) {
	m, err := readIgnore(path)
	if err != nil {
		return nil, err
	}
	return &IgnoreList{m: m}, nil
}

func readIgnore(path string) (map[string]IgnoreEntry, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]IgnoreEntry{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("db: read ignore list: %w", err)
	}
	var doc ignoreDoc
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("db: %s is not a valid ignore list: %w", path, err)
	}
	if doc.Version > fileVersion {
		return nil, fmt.Errorf("db: %s is version %d, this build reads up to %d", path, doc.Version, fileVersion)
	}
	if doc.Ignored == nil {
		doc.Ignored = map[string]IgnoreEntry{}
	}
	return doc.Ignored, nil
}

// Has reports whether fp is ignored.
func (l *IgnoreList) Has(fp string) bool { _, ok := l.m[fp]; return ok }

// Entry returns the stored entry for fp.
func (l *IgnoreList) Entry(fp string) (IgnoreEntry, bool) { e, ok := l.m[fp]; return e, ok }

// Len is the number of ignored fingerprints.
func (l *IgnoreList) Len() int { return len(l.m) }

// IgnoredFunc returns the lookup the hooks take as Deps.Ignored. It reads the file once, on
// first use, so a hook that exits before it needs the list never pays for it. An unreadable
// list counts as empty: failing closed here means a finding blocks, which is the safe way
// for an ignore check to be wrong.
func IgnoredFunc(path string) func(fp string) bool {
	var (
		once sync.Once
		list *IgnoreList
	)
	return func(fp string) bool {
		once.Do(func() {
			var err error
			if list, err = LoadIgnore(path); err != nil {
				list = &IgnoreList{m: map[string]IgnoreEntry{}}
			}
		})
		return list.Has(fp)
	}
}

func marshalIgnore(m map[string]IgnoreEntry) ([]byte, error) {
	b, err := json.MarshalIndent(ignoreDoc{Version: fileVersion, Ignored: m}, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// lockIgnore takes an exclusive advisory lock beside ignore.json for the length of one
// read-modify-write. "keyguard allow" is one process and a sweep or a second "allow" is another;
// each reads the list, adds an entry and writes the whole file back, and without this the
// second write would lose the first one's entry. The lock is on a file of its own because the
// list is replaced by rename, which would take a lock on the list itself away. The kernel drops
// it when the process dies.
func lockIgnore(listPath string) (unlock func(), err error) {
	if err := os.MkdirAll(filepath.Dir(listPath), 0o700); err != nil {
		return nil, fmt.Errorf("db: lock ignore list: %w", err)
	}
	f, err := os.OpenFile(listPath+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("db: lock ignore list: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, fmt.Errorf("db: lock ignore list: %w", err)
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}
