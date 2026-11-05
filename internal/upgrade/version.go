package upgrade

import (
	"regexp"
	"strconv"
	"strings"
)

// Version is a release number. A tag with a pre-release part (2.0.0-rc.6, 1.0.0-beta) parses
// with Pre set and is never offered as an upgrade: betterleaks 2.0 candidates drop the flags
// keyguard needs (docs/STEAL.md P0-01), and a hook that fails open on an unknown flag would
// stop protecting anything.
type Version struct {
	Major, Minor, Patch int
	Pre                 string
}

var versionRE = regexp.MustCompile(`(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?`)

// ParseVersion finds the first version in s: a bare "1.9.0", a tag "v3.99.8", or the sentence an
// engine prints, such as "trufflehog 3.99.8" or "titus version 1.2.10". Build metadata (+abc)
// is ignored.
func ParseVersion(s string) (Version, bool) {
	m := versionRE.FindStringSubmatch(s)
	if m == nil {
		return Version{}, false
	}
	n := func(x string) int { v, _ := strconv.Atoi(x); return v }
	return Version{n(m[1]), n(m[2]), n(m[3]), m[4]}, true
}

func (v Version) String() string {
	s := strconv.Itoa(v.Major) + "." + strconv.Itoa(v.Minor) + "." + strconv.Itoa(v.Patch)
	if v.Pre != "" {
		s += "-" + v.Pre
	}
	return s
}

// Stable reports whether v has no pre-release part.
func (v Version) Stable() bool { return v.Pre == "" }

// Compare orders versions: -1, 0 or 1. A pre-release sorts below the release it precedes.
func (v Version) Compare(o Version) int {
	for _, d := range [][2]int{{v.Major, o.Major}, {v.Minor, o.Minor}, {v.Patch, o.Patch}} {
		if d[0] != d[1] {
			if d[0] < d[1] {
				return -1
			}
			return 1
		}
	}
	switch {
	case v.Pre == o.Pre:
		return 0
	case v.Pre == "":
		return 1
	case o.Pre == "":
		return -1
	}
	return comparePre(v.Pre, o.Pre)
}

// comparePre orders pre-release parts the way semver does: dot-separated fields, numbers below
// words, numbers by value.
func comparePre(a, b string) int {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) && i < len(bs); i++ {
		x, ex := strconv.Atoi(as[i])
		y, ey := strconv.Atoi(bs[i])
		switch {
		case ex == nil && ey == nil:
			if x != y {
				if x < y {
					return -1
				}
				return 1
			}
		case ex == nil:
			return -1
		case ey == nil:
			return 1
		case as[i] != bs[i]:
			if as[i] < bs[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(as) < len(bs):
		return -1
	case len(as) > len(bs):
		return 1
	}
	return 0
}
