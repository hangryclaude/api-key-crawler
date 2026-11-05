package install

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"keyguard/internal/core"
	"keyguard/internal/db"
)

// Two small records that something writes and the doctor reads. The doctor never writes, and the
// survey of GitHub's settings and the weekly engine check both do, so what they found is left
// where the doctor can read it without asking anyone anything.

// Protection is state/ghprotection.json: where GitHub's own secret scanning stood at the last
// survey (`keyguard github-settings`, and the daily poll). It holds counts and repo names, which
// are not secret, and nothing GitHub returned about an alert.
type Protection struct {
	At          string `json:"at"` // GitHub's clock
	Headline    string `json:"headline"`
	Repos       int    `json:"repos"`
	Public      int    `json:"public"`
	Protected   int    `json:"protected"`
	GapCount    int    `json:"gap"`
	Unreadable  int    `json:"unreadable"`
	Unavailable int    `json:"unavailable"`
	// Gaps are the public repos with a required feature off. Drift is every feature that was on at
	// the survey before and is off in this one; it is reported by the survey that saw it, and the
	// next survey no longer calls it drift, because by then it is just off.
	Gaps  []ProtectionGap   `json:"gaps,omitempty"`
	Drift []ProtectionDrift `json:"drift,omitempty"`
}

// ProtectionGap is a public repo with at least one required feature off.
type ProtectionGap struct {
	Source string   `json:"source"`
	Off    []string `json:"off"`
}

// ProtectionDrift is one feature of one repo that went from enabled to something else.
type ProtectionDrift struct {
	Source  string `json:"source"`
	Feature string `json:"feature"`
	Was     string `json:"was"`
	Now     string `json:"now"`
}

// ProtectionPath is where the survey's summary is kept.
func ProtectionPath(p core.Paths) string { return filepath.Join(p.State, "ghprotection.json") }

// LoadProtection reads the last summary; ok is false when there is none or it does not parse.
func LoadProtection(p core.Paths) (v Protection, ok bool) {
	b, err := os.ReadFile(ProtectionPath(p))
	if err != nil || json.Unmarshal(b, &v) != nil {
		return Protection{}, false
	}
	return v, true
}

// SaveProtection writes the summary atomically at 0600.
func SaveProtection(p core.Paths, v Protection) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return db.WriteFileAtomic(ProtectionPath(p), append(b, '\n'), 0o600)
}

// UpgradeRecord is state/upgrade/last.json: what the weekly engine check found, one entry per
// engine. The full decision (every test passed or failed) is in the dated file beside it.
type UpgradeRecord struct {
	At      string          `json:"at"`
	Engines []UpgradeEngine `json:"engines"`
}

// UpgradeEngine is the outcome for one engine.
type UpgradeEngine struct {
	Engine  string   `json:"engine"`
	Pinned  string   `json:"pinned"`
	Latest  string   `json:"latest,omitempty"`
	Switch  bool     `json:"switch"`            // the candidate passed every test of the bench gate
	Applied bool     `json:"applied,omitempty"` // and was pinned by --apply
	Why     []string `json:"why,omitempty"`
	Error   string   `json:"error,omitempty"`
}

// UpgradeDir holds the weekly check's records.
func UpgradeDir(p core.Paths) string { return filepath.Join(p.State, "upgrade") }

// UpgradePath is the latest record.
func UpgradePath(p core.Paths) string { return filepath.Join(UpgradeDir(p), "last.json") }

// LoadUpgrade reads the latest record; ok is false when the check has never run.
func LoadUpgrade(p core.Paths) (v UpgradeRecord, ok bool) {
	b, err := os.ReadFile(UpgradePath(p))
	if err != nil || json.Unmarshal(b, &v) != nil {
		return UpgradeRecord{}, false
	}
	return v, true
}

// SaveUpgrade writes the record as last.json and, beside it, a dated copy that is kept.
func SaveUpgrade(p core.Paths, v UpgradeRecord, stamp string) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if err := os.MkdirAll(UpgradeDir(p), 0o700); err != nil {
		return err
	}
	if stamp != "" {
		if err := db.WriteFileAtomic(filepath.Join(UpgradeDir(p), stamp+".json"), b, 0o600); err != nil {
			return err
		}
	}
	return db.WriteFileAtomic(UpgradePath(p), b, 0o600)
}

// FeatureWord is a GitHub feature name as a person says it: secret_scanning is "secret scanning"
// and secret_scanning_push_protection is "push protection".
func FeatureWord(f string) string {
	if f == "secret_scanning" {
		return "secret scanning"
	}
	return strings.ReplaceAll(strings.TrimPrefix(f, "secret_scanning_"), "_", " ")
}
