package pattern

import (
	"math"
	"regexp"
	"strings"
	"testing"
)

func TestShannon(t *testing.T) {
	for _, c := range []struct {
		in   string
		want float64
	}{
		{"", 0},
		{"aaaaaaaa", 0},
		{"abab", 1},
		{"abcdefgh", 3},
		{"0123456789abcdef", 4},
		{"aabb", 1},
		{"aaab", 0.8112781244591328},
	} {
		if got := shannon([]byte(c.in)); math.Abs(got-c.want) > 1e-9 {
			t.Errorf("shannon(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// The reference counts characters but divides by bytes, and the floors were tuned on its number, so for
// text that is not ASCII this is the number to match, odd as it is: two characters of two bytes each
// are 0.5 bits, not 0.
func TestShannonOnOtherTextIsTheReferencesNumber(t *testing.T) {
	if got := shannon([]byte("éé")); math.Abs(got-0.5) > 1e-9 {
		t.Errorf("shannon(éé) = %v, want 0.5", got)
	}
	// An invalid byte counts as one replacement character, however many there are.
	if a, b := shannon([]byte{0xff, 0xfe, 'a'}), shannon([]byte{0xff, 0xff, 'a'}); math.Abs(a-b) > 1e-9 {
		t.Errorf("two different invalid bytes differ: %v and %v", a, b)
	}
}

// K8 of the plan: a flat floor of 3.5 rejects about 18% of random 32-character hex strings, which is what
// many vendors issue. The measurement is seeded and the claim has a tolerance, not a decimal.
func TestAFlatFloorRejectsRandomHexKeys(t *testing.T) {
	const lowerHex = "0123456789abcdef"
	rate := RejectRate(lowerHex, 32, 3.5, 40000, 1)
	t.Logf("a floor of 3.5 rejects %.1f%% of random hex32", 100*rate)
	if rate < 0.14 || rate > 0.23 {
		t.Errorf("rejects %.1f%%, the plan measured 18.4%%", 100*rate)
	}
	// The quantile floor is lower than the flat one, and rejects what it says.
	f := RandomFloor(lowerHex, 32, 0.002, 40000, 1)
	if f >= 3.5 || f < 2.5 {
		t.Errorf("the 0.2%% floor for hex32 is %v", f)
	}
	if got := RejectRate(lowerHex, 32, f, 40000, 2); got > 0.006 {
		t.Errorf("a floor at the 0.2%% quantile rejects %.2f%% on another draw", 100*got)
	}
	// Same arguments, same number.
	if a, b := RandomFloor(lowerHex, 32, 0.002, 5000, 7), RandomFloor(lowerHex, 32, 0.002, 5000, 7); a != b {
		t.Errorf("not deterministic: %v and %v", a, b)
	}
	if RandomFloor("", 8, 0.1, 10, 1) != 0 || RandomFloor("ab", 0, 0.1, 10, 1) != 0 {
		t.Error("degenerate arguments should give 0")
	}
}

var versionRe = regexp.MustCompile(`^native/\d+\.\d+\.\d+\+[0-9a-f]{12}$`)

func TestVersionNamesTheScannerAndItsRules(t *testing.T) {
	v := Version()
	if !versionRe.MatchString(v) {
		t.Errorf("version %q", v)
	}
	if v != Version() || !strings.HasSuffix(v, RulesHash()) {
		t.Errorf("version is not stable: %q", v)
	}
}
