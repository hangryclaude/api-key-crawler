package known

import (
	"errors"
	"fmt"
	"strings"

	"keyguard/internal/core"
)

// ErrNotLearned is what Forget wraps when no learned secret has the id it was given.
var ErrNotLearned = errors.New("no learned secret has that id")

// Forget drops one learned secret, every encoded form of it, from the store under root.
// id is the kg id `known list` prints or the full fingerprint. Six hex digits are not
// unique, so an id shared by two learned values is refused with both named (name and shape,
// never a value) and the caller must pass the fingerprint.
//
// The store is rewritten under the same lock Learn takes, so a Forget cannot lose what a
// concurrent Learn just added or the other way round.
func Forget(root, id string) ([]Learned, error) {
	paths := core.PathsAt(root)
	unlock, err := lockStore(paths.Known)
	if err != nil {
		return nil, err
	}
	defer unlock()

	st, err := readStore(paths.Known)
	if err != nil {
		return nil, err
	}
	if st == nil {
		return nil, fmt.Errorf("known: nothing is learned under %s: %w", root, ErrNotLearned)
	}
	want := strings.ToLower(strings.TrimSpace(id))
	hit := map[string]bool{} // fingerprints of the values that match
	for _, e := range st.Entries {
		if e.ID == want || e.FP == want {
			hit[e.FP] = true
		}
	}
	switch len(hit) {
	case 0:
		return nil, fmt.Errorf("known: %q: %w", id, ErrNotLearned)
	case 1:
	default:
		var names []string
		for _, l := range (&Store{Entries: st.Entries}).Secrets() {
			if l.ID == want {
				names = append(names, l.Name+" "+l.Shape)
			}
		}
		return nil, fmt.Errorf("known: id %s is shared by %d learned secrets (%s); pass the full fingerprint", want, len(hit), strings.Join(names, ", "))
	}

	var gone, keep []Entry
	for _, e := range st.Entries {
		if hit[e.FP] {
			gone = append(gone, e)
		} else {
			keep = append(keep, e)
		}
	}
	st.Entries = keep
	st.Updated = now()
	if err := writeStore(paths.Known, st); err != nil {
		return nil, err
	}
	return (&Store{Entries: gone}).Secrets(), nil
}
