package bench

import (
	"crypto/sha256"
	"sort"
)

// The two halves of every corpus (STEAL P0-23). Rules, triage and thresholds are tuned by
// reading the misses of the tune half; the held-out half is only ever read as a score, so the
// gap between the two is a measure of overfitting (the research saw 98.8% precision on a tuning
// half and 91.5% on repos it had never seen).
const (
	HalfTune    = "tune"
	HalfHeldOut = "held-out"
)

// splitSalt is part of the definition of the split and never changes. A name's half is a
// function of the name and this string only, so it does not move when the seed changes, when
// plants are added, or when another corpus is split: a held-out plant stays held out. A new
// version of the split would need a new salt and would make every earlier score incomparable,
// which TestTheSplitIsFrozen exists to prevent by accident.
const splitSalt = "keyguard-bench-split/v1/"

// Half says which half a unit belongs to. The unit is the thing that must not leak between
// halves: a provider format in the planted corpus (all its placements, twins and variants go
// together, so a rule written for the format cannot help its held-out copies), a repository
// in the oracle and natural corpora, a file path for a lookalike.
func Half(unit string) string {
	h := sha256.Sum256([]byte(splitSalt + unit))
	if h[0]&1 == 1 {
		return HalfHeldOut
	}
	return HalfTune
}

// HeldOut returns the names of units that fall in the held-out half, sorted.
func HeldOut(units []string) []string {
	var out []string
	for _, u := range units {
		if Half(u) == HalfHeldOut {
			out = append(out, u)
		}
	}
	sort.Strings(out)
	return out
}

// unitOf is the unit a plant is split on: its format, or for a lookalike the file it sits in.
func unitOf(p Plant) string {
	if p.Format != "" {
		return p.Format
	}
	return p.Location.Path
}

// HalfOf is the half of a plant.
func HalfOf(p Plant) string { return Half(unitOf(p)) }
