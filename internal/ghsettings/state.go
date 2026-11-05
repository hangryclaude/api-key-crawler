package ghsettings

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// Saved is state/ghsettings.json: per repo and feature, what GitHub last reported, and what
// the plan is known to lack (STEAL P0-17, P0-18). It holds display facts only, GitHub's own
// words included: no alert, no value, no token.
type Saved struct {
	Version int    `json:"version"`
	Updated string `json:"updated,omitempty"` // GitHub's clock, as of the last write
	// Repos is keyed by source id ("github.com/o/r") and holds the repos that were read.
	Repos map[string]RepoState `json:"repos"`
	// Samples is the one private repo read per owner. A free plan answers the same for all of an
	// owner's private repos, so the rest are classified from it without a request each.
	Samples map[string]SampleState `json:"samples,omitempty"`
	// Plan is what each owner's plan is known to lack, keyed by owner (lower case) and then by
	// feature name. A plan belongs to an account or an org, not to a repo, and an org can be on
	// a different one from the account that reads it.
	Plan map[string]map[string]PlanState `json:"plan,omitempty"`
}

// RepoState is one repo as GitHub last reported it.
type RepoState struct {
	Visibility string            `json:"visibility"`
	Class      Class             `json:"class"`
	Reported   bool              `json:"reported"`
	Checked    string            `json:"checked"`
	Features   map[string]string `json:"features,omitempty"` // feature -> status as reported
}

// SampleState is the private repo that stands for an owner's private repos.
type SampleState struct {
	Repo    string `json:"repo"`
	Class   Class  `json:"class"`
	Checked string `json:"checked"`
}

// PlanState is what is known about one feature's availability on this plan.
type PlanState struct {
	Unavailable bool   `json:"unavailable_on_plan"`
	Probed      string `json:"probed"` // GitHub's clock
	Message     string `json:"message,omitempty"`
}

const stateVersion = 1

func newSaved() Saved {
	return Saved{Version: stateVersion, Repos: map[string]RepoState{}, Samples: map[string]SampleState{}, Plan: map[string]map[string]PlanState{}}
}

// loadSaved reads the state file. A file that is not there is the first run; one that cannot be
// read is reported and replaced by an empty state, because the cost of losing it is one run
// without drift detection, and a stuck audit costs more.
func (s *Settings) loadSaved() (Saved, error) {
	st := newSaved()
	if s.statePath == "" {
		return st, nil
	}
	b, err := os.ReadFile(s.statePath)
	if errors.Is(err, fs.ErrNotExist) {
		return st, nil
	}
	if err == nil {
		err = json.Unmarshal(b, &st)
	}
	if err != nil {
		return newSaved(), fmt.Errorf("ghsettings: %s is unreadable, starting from an empty state: %w", s.statePath, err)
	}
	if st.Repos == nil {
		st.Repos = map[string]RepoState{}
	}
	if st.Samples == nil {
		st.Samples = map[string]SampleState{}
	}
	if st.Plan == nil {
		st.Plan = map[string]map[string]PlanState{}
	}
	return st, nil
}

// saveSaved replaces the state file atomically. It stamps GitHub's clock.
func (s *Settings) saveSaved(st Saved) error {
	if s.statePath == "" {
		return nil
	}
	st.Version = stateVersion
	st.Updated = s.githubStamp()
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(s.statePath, append(b, '\n'))
}

// update runs fn over the state under the lock and saves what it left. The load error, when
// there was one, is returned beside the save error: the run goes on with an empty state.
func (s *Settings) update(fn func(*Saved)) error {
	s.stMu.Lock()
	defer s.stMu.Unlock()
	st, loadErr := s.loadSaved()
	fn(&st)
	return errors.Join(loadErr, s.saveSaved(st))
}

// Saved returns what the state file holds now.
func (s *Settings) Saved() (Saved, error) {
	s.stMu.Lock()
	defer s.stMu.Unlock()
	return s.loadSaved()
}

func stamp(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// githubStamp is GitHub's time now as a stamp, or "" when no response has been heard in this
// process: the Mac's clock is not an acceptable stand-in in a file that later runs compare
// against (STEAL P0-16), and a missing stamp is plainly missing.
func (s *Settings) githubStamp() string {
	if !s.cl.Clock().Known() {
		return ""
	}
	return stamp(s.githubNow())
}

// repoState is what the state file keeps of one audit.
func (s *Settings) repoState(a AuditResult, checked string) RepoState {
	rs := RepoState{Visibility: string(a.Source.Visibility), Class: ClassOf(a), Reported: a.Reported, Checked: checked}
	if a.Err != nil {
		return rs
	}
	rs.Features = map[string]string{}
	for _, f := range Features {
		if st := a.State[f]; st != Unreported {
			rs.Features[string(f)] = string(st)
		}
	}
	return rs
}

// writeFileAtomic writes beside the target and renames over it, so a reader sees the old file
// or the new one and never half of one. The directory is 0700 and the file 0600, like the rest
// of ~/.keyguard.
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
