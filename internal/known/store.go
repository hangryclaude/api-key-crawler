package known

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"keyguard/internal/core"
)

// Store is <Paths.Known>/known.json: every registered form of every learned value, hashes
// only. SaltCheck ties it to the salt that keyed it.
type Store struct {
	Version   int     `json:"version"`
	SaltCheck string  `json:"salt_check"`
	Updated   string  `json:"updated"`
	Entries   []Entry `json:"entries"`
}

// The file names are core.PathsAt's, so install, doctor and the code that writes the files
// cannot disagree about them.
var (
	storeFile = filepath.Base(core.PathsAt("").KnownStore)
	lockFile  = filepath.Base(core.PathsAt("").KnownLock)
)

// errNotJSON marks a store that exists but does not parse, as opposed to one this binary
// is too old to read.
var errNotJSON = errors.New("known.json is not valid JSON")

// readStore returns (nil, nil) when dir has no store yet: nothing learned is a state, not
// an error.
func readStore(dir string) (*Store, error) {
	b, err := os.ReadFile(filepath.Join(dir, storeFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	s, ok := parseStoreFast(b)
	if !ok {
		s = new(Store)
		if err := json.Unmarshal(b, s); err != nil {
			// json's own message can quote a byte of the input; the store holds no values, but
			// the habit is cheaper than the audit.
			return nil, fmt.Errorf("%s: %w", filepath.Join(dir, storeFile), errNotJSON)
		}
	}
	if s.Version != storeVersion {
		return nil, fmt.Errorf("%s is version %d, want %d", filepath.Join(dir, storeFile), s.Version, storeVersion)
	}
	return s, nil
}

// writeStore replaces known.json atomically: readers (every git hook on this Mac) see the
// old store or the new one, never half of one. One entry per line keeps it greppable.
func writeStore(dir string, s *Store) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	var buf bytes.Buffer
	head, _ := json.Marshal(struct {
		Version   int    `json:"version"`
		SaltCheck string `json:"salt_check"`
		Updated   string `json:"updated"`
	}{s.Version, s.SaltCheck, s.Updated})
	buf.Write(head[:len(head)-1]) // reopen the object to append the entries
	buf.WriteString(`,"entries":[`)
	for i, e := range s.Entries {
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.WriteByte('\n')
		b, err := json.Marshal(e)
		if err != nil {
			return err
		}
		buf.Write(b)
	}
	buf.WriteString("\n]}\n")

	tmp, err := os.CreateTemp(dir, ".known-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // a no-op once renamed
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(buf.Bytes()); err != nil {
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
	return os.Rename(tmp.Name(), filepath.Join(dir, storeFile))
}

// lockStore takes an exclusive advisory lock on the store directory for the read-merge-write
// of one Learn run. Readers never take it: they see whole files because writeStore renames.
// The lock dies with the process, so a crashed run cannot wedge the next.
func lockStore(dir string) (unlock func(), err error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, lockFile), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() { f.Close() }, nil // closing releases the lock
}

func now() string { return time.Now().UTC().Format(time.RFC3339) }

// ReadStore loads the store under a data root for display and diagnosis: doctor, a listing
// of what is learned, resolving an id a human typed. It returns (nil, nil) when nothing has
// been learned there. Matching goes through LoadMatcher, which also checks the salt.
func ReadStore(root string) (*Store, error) {
	return readStore(core.PathsAt(root).Known)
}

// Secrets groups the entries by the value they stand for, in store order: one row per
// learned secret, display fields only.
func (s *Store) Secrets() []Learned {
	var out []Learned
	at := map[string]int{}
	for _, e := range s.Entries {
		i, ok := at[e.FP]
		if !ok {
			i = len(out)
			at[e.FP] = i
			out = append(out, Learned{ID: e.ID, Name: e.Name, Source: e.Source, Shape: e.Shape})
		}
		out[i].Forms++
		if e.Variant == "raw" {
			out[i].Len = e.Len
		}
	}
	return out
}
