package sweep

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"keyguard/internal/core"
	"keyguard/internal/db"
)

// sourceState is state/sources/<id with "/" as "__">.json: how far each engine has scanned
// one source. Tips is where the source stood at the last scan; ScannedWith records, per
// engine, the version that scanned it; Lag holds an engine's own tips when it fell behind
// (it failed, or was unavailable, while the others moved on).
type sourceState struct {
	Source      string                       `json:"source"`
	Visibility  core.Visibility              `json:"visibility,omitempty"`
	Tips        map[string]string            `json:"tips"`
	ScannedWith map[string]string            `json:"scanned_with"`
	Lag         map[string]map[string]string `json:"lag,omitempty"`
	Unsupported map[string]string            `json:"unsupported,omitempty"` // engine -> version found unable to scan git, so it is not asked again
	LastScan    string                       `json:"last_scan"`
	// LastAPI is when, on GitHub's clock, an API resource of this source was last scanned. It is
	// for the person reading the file: no scan takes a cursor from it (STEAL P0-22).
	LastAPI string `json:"last_api,omitempty"`
	// APIPending are the resource URLs an event named whose scan failed. Events are delivered
	// once, so this list is how a failed scan gets another try.
	APIPending []apiTry `json:"api_pending,omitempty"`
}

// apiTry is a resource waiting for another try, and how many it has had.
type apiTry struct {
	URL   string `json:"url"`
	Tries int    `json:"tries"`
}

// progress is how far one engine has got in one source.
type progress struct {
	version string
	tips    map[string]string
}

func (s *sourceState) progressOf(engine string) (progress, bool) {
	if s == nil {
		return progress{}, false
	}
	v, ok := s.ScannedWith[engine]
	if !ok {
		return progress{}, false
	}
	tips := s.Tips
	if lag, behind := s.Lag[engine]; behind {
		tips = lag
	}
	return progress{version: v, tips: tips}, true
}

// set records that engine has scanned up to tips with version. It is stored as a lag only
// when it differs from the source's overall tips, which keeps the common file small.
func (s *sourceState) set(engine, version string, tips map[string]string) {
	s.ScannedWith[engine] = version
	if maps.Equal(tips, s.Tips) {
		delete(s.Lag, engine)
		return
	}
	s.Lag[engine] = maps.Clone(tips)
}

func (s *sourceState) forget(engine string) {
	delete(s.ScannedWith, engine)
	delete(s.Lag, engine)
}

// cannot reports that engine, at this version, is known not to scan git. Without the memory a
// source would be "due" for it on every poll, and a quiet poll would sync every mirror.
func (s *sourceState) cannot(engine, version string) bool {
	return s != nil && s.Unsupported[engine] == version
}

// sameProgress reports whether two states say the same about what has been scanned. When a
// source is looked at and nothing is due, the record would differ only in its timestamp, and
// rewriting 469 files to move a timestamp is the whole cost of a quiet poll.
func (s *sourceState) sameProgress(o *sourceState) bool {
	return s != nil && o != nil && s.Source == o.Source && s.Visibility == o.Visibility &&
		maps.Equal(s.Tips, o.Tips) && maps.Equal(s.ScannedWith, o.ScannedWith) && maps.EqualFunc(s.Lag, o.Lag, maps.Equal) &&
		maps.Equal(s.Unsupported, o.Unsupported) && slices.Equal(s.APIPending, o.APIPending)
}

func (s *sourceState) clone() *sourceState {
	c := *s
	c.Tips = maps.Clone(s.Tips)
	c.ScannedWith = maps.Clone(s.ScannedWith)
	c.Unsupported = maps.Clone(s.Unsupported)
	c.APIPending = slices.Clone(s.APIPending)
	c.Lag = make(map[string]map[string]string, len(s.Lag))
	for k, v := range s.Lag {
		c.Lag[k] = maps.Clone(v)
	}
	return &c
}

func newState(id string) *sourceState {
	return &sourceState{Source: id, Tips: map[string]string{}, ScannedWith: map[string]string{}, Lag: map[string]map[string]string{}}
}

// stateFile maps a source id onto its state file. Slashes are the only characters that
// could climb out of the directory; ids come from GitHub or from a local path, so nothing
// else needs care. The id is stored inside the file too, so two ids that flatten to one name
// are noticed instead of trusted.
func stateFile(dir, id string) string {
	return filepath.Join(dir, strings.ReplaceAll(id, "/", "__")+".json")
}

// loadState returns nil for a source never scanned. An unreadable or foreign file counts as
// never scanned too, which errs towards scanning more, and says so in the second result.
func loadState(dir, id string) (*sourceState, string) {
	b, err := os.ReadFile(stateFile(dir, id))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ""
	}
	if err != nil {
		return nil, fmt.Sprintf("%s: state file unreadable (%v); rescanning from scratch", id, err)
	}
	var st sourceState
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, id + ": state file is not valid JSON; rescanning from scratch"
	}
	if st.Source != id {
		return nil, id + ": state file belongs to another source; rescanning from scratch"
	}
	if st.Tips == nil {
		st.Tips = map[string]string{}
	}
	if st.ScannedWith == nil {
		st.ScannedWith = map[string]string{}
	}
	if st.Lag == nil {
		st.Lag = map[string]map[string]string{}
	}
	return &st, ""
}

func saveState(dir string, st *sourceState) error {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return db.WriteFileAtomicLazy(stateFile(dir, st.Source), append(b, '\n'), 0o600)
}

// snapshot is state/inventory.json. The layout matches inventory.SaveSnapshot, which owns
// the format: version, updated, sources. The sweep reads and writes it because only the
// sweep knows which sources it finished scanning.
type snapshot struct {
	Version int           `json:"version"`
	Updated string        `json:"updated"`
	Sources []core.Source `json:"sources"`
}

// loadSnapshot returns the last saved inventory by source id, empty on first run.
func loadSnapshot(path string) (map[string]core.Source, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]core.Source{}, nil
	}
	if err != nil {
		return nil, err
	}
	var s snapshot
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("sweep: %s is not an inventory snapshot: %w", path, err)
	}
	m := make(map[string]core.Source, len(s.Sources))
	for _, src := range s.Sources {
		m[src.ID] = src
	}
	return m, nil
}

// saveSnapshot refuses an empty inventory for the reason inventory.SaveSnapshot does: it is
// what a failed listing looks like, and saving it would make every repo new next poll.
func saveSnapshot(path string, m map[string]core.Source, now time.Time) error {
	if len(m) == 0 {
		return errors.New("sweep: refusing to save an empty inventory")
	}
	list := make([]core.Source, 0, len(m))
	for _, id := range slices.Sorted(maps.Keys(m)) {
		list = append(list, m[id])
	}
	b, err := json.MarshalIndent(snapshot{Version: 1, Updated: stamp(now), Sources: list}, "", "  ")
	if err != nil {
		return err
	}
	return db.WriteFileAtomicLazy(path, append(b, '\n'), 0o600)
}
