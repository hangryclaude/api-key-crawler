package known

import (
	"strings"
	"testing"

	"keyguard/internal/core"
	"keyguard/internal/fp"
)

// The sweep rescans all of history when the learned set changes, and it can only tell it changed
// by the matcher's Version. A count would miss a key swapped for another.
func TestMatcherVersionNamesTheLearnedSetExactly(t *testing.T) {
	kr := fp.NewEphemeral()
	rng := newRNG(t)
	value := func() string { return "sk-proj-" + randFrom(rng, urlchars, 48) }
	a, b, c := value(), value(), value()
	build := func(raws ...string) *Matcher {
		t.Helper()
		var entries []Entry
		for i, raw := range raws {
			entries = append(entries, EntriesFor(kr, "KEY_"+string(rune('A'+i)), "test", []byte(raw))...)
		}
		m, err := NewMatcher(kr, entries)
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	var _ core.VersionedMatcher = build(a)

	base := build(a, b).Version()
	if base == "" || !strings.HasPrefix(base, "kv") || len(base) != 18 {
		t.Fatalf("version %q is not a short hash", base)
	}
	if got := build(a, b).Version(); got != base {
		t.Errorf("the same set gave %q, then %q", base, got)
	}
	if got := build(b, a).Version(); got != base {
		t.Errorf("the order it was learned in changed the version: %q against %q", got, base)
	}
	if got := build(a, c).Version(); got == base {
		t.Error("a key swapped for another of the same count left the version as it was")
	}
	if got := build(a).Version(); got == base {
		t.Error("a key forgotten left the version as it was")
	}
	if build(a, b).Len() != build(a, c).Len() {
		t.Fatal("setup: the swap should keep the count")
	}
	// A form dropped from a key that is still learned (a store from before an encoding existed)
	// is a different set, though the keys are the same.
	var thin []Entry
	for _, e := range EntriesFor(kr, "KEY_A", "test", []byte(a)) {
		if e.Variant == "raw" {
			thin = append(thin, e)
		}
	}
	m, err := NewMatcher(kr, thin)
	if err != nil {
		t.Fatal(err)
	}
	if m.Version() == build(a).Version() {
		t.Error("a form dropped from a learned key left the version as it was")
	}
	var nilM *Matcher
	if nilM.Version() != "" {
		t.Error("a nil matcher has a version")
	}
	// Nothing in it says anything about a value.
	if strings.Contains(base, a[:12]) {
		t.Error("the version holds part of a key")
	}
}
