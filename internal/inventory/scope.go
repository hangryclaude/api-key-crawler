package inventory

import (
	"slices"
	"strings"

	"keyguard/internal/core"
)

// The sweep's scope (PLAN.md "Sweep scope"): the public sources, not every repo. The inventory
// lists every repo, wiki and gist as metadata, and marks
// the ones a stranger can read as the ones to scan: public repos, their wikis, and gists, which
// are secret only in that nobody lists them, so anyone holding the link reads them. A private
// repo is never fetched or scanned, and the day one turns public the inventory reports it as a
// flip, so that its whole history is scanned before anything else.

// Exposed reports whether a stranger can read the source now, which is whether the sweep scans
// it. A source of unknown visibility counts: the cautious answer is the one that gets a key
// rotated.
func Exposed(s core.Source) bool { return s.Visibility.Exposed() }

// ScanSet is the part of a listing that the sweep scans, in the order given.
func ScanSet(all []core.Source) []core.Source {
	var out []core.Source
	for _, s := range all {
		if Exposed(s) {
			out = append(out, s)
		}
	}
	return out
}

// Summary counts a listing the way the report states it. It holds counts and owners' logins and
// no names of repositories.
type Summary struct {
	Repos         int            // every repo, whatever its visibility
	PublicRepos   int            // of them, the ones a stranger can read
	PrivateRepos  int            // metadata only
	UnknownRepos  int            // visibility GitHub did not say; scanned, like a public one
	ReposByOwner  map[string]int // lower-case owner login -> repos
	PublicByOwner map[string]int // lower-case owner login -> public repos
	Wikis         int            // wikis of exposed repos
	SecretGists   int
	PublicGists   int
	Scan          int // sources the sweep scans: exposed repos, their wikis and the gists
}

// Summarize counts a listing.
func Summarize(all []core.Source) Summary {
	sum := Summary{ReposByOwner: map[string]int{}, PublicByOwner: map[string]int{}}
	for _, s := range all {
		owner := strings.ToLower(s.Owner)
		switch s.Kind {
		case "repo":
			sum.Repos++
			sum.ReposByOwner[owner]++
			switch s.Visibility {
			case core.Public:
				sum.PublicRepos++
				sum.PublicByOwner[owner]++
			case core.Private:
				sum.PrivateRepos++
			case core.Unknown:
				sum.UnknownRepos++
			}
		case "wiki":
			if Exposed(s) {
				sum.Wikis++
			}
		case "gist":
			switch s.Visibility {
			case core.SecretGist:
				sum.SecretGists++
			case core.Public:
				sum.PublicGists++
			}
		}
		if Exposed(s) {
			sum.Scan++
		}
	}
	return sum
}

// Flip is a source whose visibility is not what the last inventory said.
type Flip struct {
	Source core.Source
	Was    core.Visibility
	Now    core.Visibility
}

// Opened reports whether the source became readable by strangers. That is the flip that matters:
// its whole history was never scanned, because the sweep never read it while it was private, and
// everything in it is public from now on.
func (f Flip) Opened() bool { return !f.Was.Exposed() && f.Now.Exposed() }

// Flips are the sources in cur whose visibility differs from what prev recorded for them. A
// source prev has never seen is new, not flipped. Opened flips come first, then the rest, each
// by ID, so the order a caller scans in puts the flipped repos before anything else.
func Flips(prev map[string]core.Source, cur []core.Source) []Flip {
	var out []Flip
	seen := map[string]bool{}
	for _, s := range cur {
		p, ok := prev[s.ID]
		if !ok || p.Visibility == s.Visibility || seen[s.ID] {
			continue
		}
		seen[s.ID] = true
		out = append(out, Flip{Source: s, Was: p.Visibility, Now: s.Visibility})
	}
	slices.SortFunc(out, func(a, b Flip) int {
		if a.Opened() != b.Opened() {
			if a.Opened() {
				return -1
			}
			return 1
		}
		return strings.Compare(a.Source.ID, b.Source.ID)
	})
	return out
}
