package bench

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const truthSchema = 1

// Plant is one record of truth.json: a value placed in the corpus and what a scanner should
// do with it. Fingerprints use the bench keyring, so the file holds no raw secret.
type Plant struct {
	ID         string   `json:"id"`
	Type       string   `json:"type"` // provider type for positives; the lookalike's type for negatives
	Variant    string   `json:"variant"`
	Location   Location `json:"location"`
	Positive   bool     `json:"positive"`
	FP         string   `json:"fp"`
	AltFPs     []string `json:"alt_fps,omitempty"` // fingerprints of other extents/encodings present in the file
	Detectable bool     `json:"detectable_by_design"`
	// DetectableBy names the engines whose rules cover the plant as planted; Detectable
	// is true when any engine does.
	DetectableBy []string `json:"detectable_by,omitempty"`
	Known        bool     `json:"known_by_design"` // a matcher holding the raw value (and its encodings) finds it
	Rules        []string `json:"rules,omitempty"` // engine rules that should cover it
	RemovedIn    string   `json:"removed_in,omitempty"`
	Kind         string   `json:"kind,omitempty"` // negatives: placeholder, uuid, integrity-hash...
	Note         string   `json:"note,omitempty"`

	// Format is the provider format a plant, its twins and its placements all belong to. It is
	// the unit of the frozen split (STEAL P0-23): Half says which half that makes the plant.
	Format string `json:"format,omitempty"`
	Half   string `json:"half,omitempty"`
	// Len is the length of the planted secret. A fingerprint cannot say how long a value was, and
	// scoring a hit by the span it covers (STEAL P0-24) needs to know how much of the secret
	// that is: at least min(Len, 12) characters.
	Len int `json:"len,omitempty"`
	// Twin marks the two halves of a near-miss pair (STEAL P0-26): "valid" for the real-format
	// plant, "invalid" for the value beside it that has the look of the format and one thing
	// wrong with it. An invalid twin names the valid plant in TwinOf and is a negative.
	Twin   string `json:"twin,omitempty"`
	TwinOf string `json:"twin_of,omitempty"`
	// Tags are facts about how the plant was made: "floor-rejected" is a value built to fall
	// under its rule's entropy floor, so an engine is expected to drop it.
	Tags []string `json:"tags,omitempty"`
}

type Location struct {
	Ref     string `json:"ref"`
	Commit  string `json:"commit,omitempty"`
	Path    string `json:"path"`
	Line    int    `json:"line"`
	EndLine int    `json:"end_line,omitempty"` // last line of a multi-line value (a PEM, a service-account file)
	// Where is set when the value is not in a file: "message" for a commit message, "tag" for a
	// tag annotation, "ref" for a branch name. Path is empty then, and for a branch name Ref
	// carries the value's display shape, not the value.
	Where string `json:"where,omitempty"`
}

// Stats describes the generated corpus.
type Stats struct {
	Commits          int     `json:"commits"`
	Files            int     `json:"files"` // tracked at main's tip
	Blobs            int     `json:"blobs"`
	Bytes            int64   `json:"bytes"` // uncompressed size of every object
	Refs             int     `json:"refs"`
	Positives        int     `json:"positives"`
	Negatives        int     `json:"negatives"`
	Detectable       int     `json:"detectable"`
	GenerateSeconds  float64 `json:"-"` // wall time of Generate; kept out of truth.json so the file is repeatable
	ProviderFormats  int     `json:"provider_formats"`
	PositiveVariants int     `json:"positive_variants"`
	// Lines is the number of lines in every blob of the repo: the denominator that turns false
	// alerts into a rate per line, and plants into a prevalence.
	Lines    int `json:"lines,omitempty"`
	Twins    int `json:"twins,omitempty"`      // invalid twins: negatives made to sit beside a valid plant
	HeldOut  int `json:"held_out,omitempty"`   // positive plants in the held-out half
	Tunable  int `json:"tunable,omitempty"`    // positive plants in the tune half
	Placings int `json:"placements,omitempty"` // distinct placements (variants) of positive plants
}

// Truth is truth.json.
type Truth struct {
	Schema int     `json:"schema"`
	Seed   uint64  `json:"seed"`
	Scale  int     `json:"scale"`
	Repo   string  `json:"repo"` // relative to the corpus dir
	Stats  Stats   `json:"stats"`
	Plants []Plant `json:"plants"`
}

// LoadTruth reads <dir>/truth.json.
func LoadTruth(dir string) (*Truth, error) {
	b, err := os.ReadFile(filepath.Join(dir, "truth.json"))
	if err != nil {
		return nil, err
	}
	var t Truth
	if err := json.Unmarshal(b, &t); err != nil {
		return nil, fmt.Errorf("bench: truth.json: %w", err)
	}
	if t.Schema != truthSchema {
		return nil, fmt.Errorf("bench: truth.json schema %d, want %d", t.Schema, truthSchema)
	}
	return &t, nil
}

func (t *Truth) save(dir string) error {
	b, err := json.MarshalIndent(t, "", " ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "truth.json"), append(b, '\n'), 0o644)
}

// Positives returns the plants a scanner must find.
func (t *Truth) Positives() []Plant {
	var out []Plant
	for _, p := range t.Plants {
		if p.Positive {
			out = append(out, p)
		}
	}
	return out
}
