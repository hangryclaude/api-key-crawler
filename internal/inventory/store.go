package inventory

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"time"

	"keyguard/internal/core"
)

// eventsFile is the one name state/events.json has in core.Paths. It is taken from there and not
// spelled out a second time, so install, doctor and this writer cannot disagree about it
// (a test pins that Join(StateDir, eventsFile) is Paths.Events).
var eventsFile = filepath.Base(core.PathsAt("x").Events)

// tri is a fact that is true, false or not known yet. It is a number so that a state holding
// one can be compared with ==, and it reads and writes as a JSON bool (null while unknown).
type tri int8

const (
	triUnknown tri = iota
	triYes
	triNo
)

func (t tri) MarshalJSON() ([]byte, error) {
	switch t {
	case triYes:
		return []byte("true"), nil
	case triNo:
		return []byte("false"), nil
	}
	return []byte("null"), nil
}

func (t *tri) UnmarshalJSON(b []byte) error {
	switch string(bytes.TrimSpace(b)) {
	case "true":
		*t = triYes
	case "false":
		*t = triNo
	default:
		*t = triUnknown
	}
	return nil
}

// watchEntry is what one conditional request left behind: the ETag GitHub gave a list, and what
// was in it, so that a 304 can be answered from here instead of from the network. It holds the
// whitelisted fields of core.Source and never the response body: a repo's description is text a
// person wrote, and it stays out of the state directory.
type watchEntry struct {
	ETag    string        `json:"etag"`
	Sources []core.Source `json:"sources"`
	More    bool          `json:"more,omitempty"` // the page was full, so a next page exists
}

// stateFile is state/events.json: per-account event ETags and high-water marks, as it has
// always been, and beside them under two reserved keys (no GitHub login starts with an
// underscore) what the cheap poll remembers between runs. The old shape, accounts only, still
// reads, so an upgrade costs nothing.
type stateFile struct {
	accounts  map[string]eventState
	watch     map[string]watchEntry
	refreshed map[string]string // account -> GitHub's clock when its last full GraphQL poll finished
	// delivered is the pages the activity fallback has handed out lately, each with the time
	// GitHub gave it. The fallback lists since a cursor that sits ten minutes behind the newest
	// thing seen, so without this a page would be handed out on every poll for ten minutes, and
	// scanned each time.
	delivered map[string]string
}

const (
	keyWatch     = "_watch"
	keyRefreshed = "_refreshed"
	keyDelivered = "_delivered"
)

func newStateFile() stateFile {
	return stateFile{accounts: map[string]eventState{}, watch: map[string]watchEntry{}, refreshed: map[string]string{}, delivered: map[string]string{}}
}

func (f stateFile) clone() stateFile {
	return stateFile{accounts: maps.Clone(f.accounts), watch: maps.Clone(f.watch), refreshed: maps.Clone(f.refreshed), delivered: maps.Clone(f.delivered)}
}

func (f stateFile) MarshalJSON() ([]byte, error) {
	m := make(map[string]any, len(f.accounts)+2)
	for k, v := range f.accounts {
		m[k] = v
	}
	if len(f.watch) > 0 {
		m[keyWatch] = f.watch
	}
	if len(f.refreshed) > 0 {
		m[keyRefreshed] = f.refreshed
	}
	if len(f.delivered) > 0 {
		m[keyDelivered] = f.delivered
	}
	return json.Marshal(m)
}

func (f *stateFile) UnmarshalJSON(b []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	*f = newStateFile()
	for k, v := range raw {
		var err error
		switch k {
		case keyWatch:
			err = json.Unmarshal(v, &f.watch)
		case keyRefreshed:
			err = json.Unmarshal(v, &f.refreshed)
		case keyDelivered:
			err = json.Unmarshal(v, &f.delivered)
		default:
			var es eventState
			if err = json.Unmarshal(v, &es); err == nil {
				f.accounts[k] = es
			}
		}
		if err != nil {
			return fmt.Errorf("%q: %w", k, err)
		}
	}
	return nil
}

// loadState returns a copy of the persisted poll state, read from StateDir once per Inventory.
// State that cannot be read is reported and replaced by an empty one: the cost is a single
// baseline poll, not a stuck sweep.
func (inv *Inventory) loadState() (stateFile, error) {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	if inv.loaded {
		return inv.state.clone(), nil
	}
	inv.loaded = true
	inv.state = newStateFile()
	if inv.cfg.StateDir == "" {
		return newStateFile(), nil
	}
	path := filepath.Join(inv.cfg.StateDir, eventsFile)
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return newStateFile(), nil
	}
	if err == nil {
		err = json.Unmarshal(b, &inv.state)
	}
	if err != nil {
		inv.state = newStateFile()
		return newStateFile(), fmt.Errorf("inventory: %s is unreadable, polling events from a fresh baseline: %w", path, err)
	}
	return inv.state.clone(), nil
}

// stateDelta is what one poll learned. Entries of accounts whose poll failed are simply absent,
// so they keep their old state.
type stateDelta struct {
	accounts  map[string]eventState
	watch     map[string]watchEntry // the full set of entries to keep; the rest are dropped
	refreshed map[string]string
	delivered map[string]string // the full set of pages to remember; nil leaves it as it was
}

func newDelta() stateDelta {
	return stateDelta{accounts: map[string]eventState{}, refreshed: map[string]string{}}
}

// saveState folds a poll into the persisted state and writes it only when something moved.
func (inv *Inventory) saveState(old stateFile, d stateDelta) error {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	moved := false
	for login, ns := range d.accounts {
		if ns != old.accounts[login] {
			inv.state.accounts[login] = ns
			moved = true
		}
	}
	for acct, at := range d.refreshed {
		if at != old.refreshed[acct] {
			inv.state.refreshed[acct] = at
			moved = true
		}
	}
	if d.watch != nil && !sameWatch(d.watch, inv.state.watch) {
		inv.state.watch = d.watch
		moved = true
	}
	if d.delivered != nil && !maps.Equal(d.delivered, inv.state.delivered) {
		inv.state.delivered = d.delivered
		moved = true
	}
	if !moved || inv.cfg.StateDir == "" {
		return nil
	}
	b, err := json.MarshalIndent(inv.state, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(inv.cfg.StateDir, eventsFile), append(b, '\n'))
}

func sameWatch(a, b map[string]watchEntry) bool {
	if len(a) != len(b) {
		return false
	}
	for k, x := range a {
		y, ok := b[k]
		if !ok || x.ETag != y.ETag || x.More != y.More {
			return false
		}
	}
	return true
}

// snapshot is the on-disk form of state/inventory.json.
type snapshot struct {
	Version int           `json:"version"`
	Updated string        `json:"updated"`
	Sources []core.Source `json:"sources"`
}

// LoadSnapshot reads the last saved inventory. A file that does not exist yet is the normal
// first-run state and yields no sources and no error.
func LoadSnapshot(path string) ([]core.Source, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var s snapshot
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("inventory: %s is not a snapshot: %w", path, err)
	}
	return s.Sources, nil
}

// SaveSnapshot replaces state/inventory.json atomically. It refuses an empty list: that is
// what a failed List looks like, and saving it would turn every repo into "new" next poll.
func SaveSnapshot(path string, sources []core.Source, now time.Time) error {
	if len(sources) == 0 {
		return errors.New("inventory: refusing to save an empty inventory")
	}
	b, err := json.MarshalIndent(snapshot{Version: 1, Updated: now.UTC().Format(time.RFC3339), Sources: sources}, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, append(b, '\n'))
}

// writeFileAtomic writes beside the target and renames over it, so a reader (a hook, a
// poll that overlaps a deep scan) sees the old file or the new one, never half of one.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
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
