package ghsettings

import (
	"context"
	"errors"
	"slices"
	"strings"

	"keyguard/internal/core"
)

// Survey is where GitHub's own protection stands across a set of repos, read without a single
// write and without polling alerts (STEAL P0-18).
type Survey struct {
	// Results holds the audits that were made, in the order they were asked for: every repo that
	// is not private, then one private repo per owner.
	Results []AuditResult
	// Classes names the class of every repo given, the unread ones included.
	Classes map[string]Class
	// Inferred is the repos classified from their owner's sample, with no request of their own.
	Inferred map[string]bool
	Counts   Counts
	// Drift is every feature that was on at the last survey and is off now (STEAL P0-19, the
	// "ON to OFF drift alert"): someone, or something, switched protection off.
	Drift []Drift
	// Plan is what is known about the optional features, per owner (lower case): a plan belongs
	// to an account or an org.
	Plan map[string]map[Feature]PlanState
}

// Drift is one feature that went from enabled to something else between two surveys.
type Drift struct {
	Source  string
	Feature Feature
	Was     State
	Now     State
}

// Headline is the report's lead line.
func (sv Survey) Headline() string { return sv.Counts.Headline() }

// Survey classifies repos from the GET that reads them. Every repo that is not private is read;
// the private ones are read through one sample per owner. A free plan answers the same for every
// private repo an owner has, `security_and_analysis: null`, so asking each of 448 would cost 448
// calls to learn one fact. If a sample says the plan does have the feature, that owner's other
// private repos are read one by one after all, because then they can differ.
//
// The result is written to the state file, and the previous state is what Drift is measured
// against. A state file that cannot be read or written comes back as the error beside a survey
// that is complete without it.
func (s *Settings) Survey(ctx context.Context, repos []core.Source) (Survey, error) {
	sv := Survey{Classes: map[string]Class{}, Inferred: map[string]bool{}}
	var (
		read    []core.Source
		private = map[string][]core.Source{} // lower-case owner -> its private repos
		owners  []string
	)
	for _, src := range repos {
		if src.Kind != "repo" {
			continue
		}
		sv.Counts.Repos++
		switch src.Visibility {
		case core.Private:
			sv.Counts.Private++
			o := strings.ToLower(src.Owner)
			if private[o] == nil {
				owners = append(owners, o)
			}
			private[o] = append(private[o], src)
		case core.Public:
			sv.Counts.Public++
			read = append(read, src)
		default:
			read = append(read, src) // unknown is read like a public one: the cautious way
		}
	}
	slices.Sort(owners)
	samples := make([]core.Source, 0, len(owners))
	for _, o := range owners {
		samples = append(samples, sampleOf(private[o]))
	}
	audits := s.Audit(ctx, append(slices.Clone(read), samples...))
	sv.Results = audits

	for _, a := range audits[:len(read)] {
		sv.Classes[a.Source.ID] = ClassOf(a)
	}
	var more []core.Source
	sampleState := map[string]SampleState{}
	at := s.githubStamp()
	for i, o := range owners {
		a := audits[len(read)+i]
		c := ClassOf(a)
		sv.Classes[a.Source.ID] = c
		sampleState[o] = SampleState{Repo: a.Source.ID, Class: c, Checked: at}
		for _, src := range private[o] {
			if src.ID == a.Source.ID {
				continue
			}
			if c == Protected || c == Gap {
				more = append(more, src) // the plan has it, so these can differ
				continue
			}
			// Unavailable on the sample: so are the rest. A sample that could not be read
			// says nothing, and the rest are as unreadable as it.
			sv.Classes[src.ID], sv.Inferred[src.ID] = c, true
		}
	}
	if len(more) > 0 {
		for _, a := range s.Audit(ctx, more) {
			sv.Classes[a.Source.ID] = ClassOf(a)
			sv.Results = append(sv.Results, a)
		}
	}
	for _, c := range sv.Classes {
		switch c {
		case Protected:
			sv.Counts.Protected++
		case Gap:
			sv.Counts.Gap++
		case Unreadable:
			sv.Counts.Unreadable++
		case Unavailable:
			sv.Counts.Unavailable++
		}
	}

	var errs []error
	errs = append(errs, s.update(func(st *Saved) {
		sv.Drift = driftOf(st.Repos, sv.Results)
		for _, a := range sv.Results {
			st.Repos[a.Source.ID] = s.repoState(a, at)
		}
		for o, ss := range sampleState {
			st.Samples[o] = ss
		}
		sv.Plan = map[string]map[Feature]PlanState{}
		for owner, p := range st.Plan {
			sv.Plan[owner] = planOf(p)
		}
	}))
	return sv, errors.Join(errs...)
}

// sampleOf picks the private repo that stands for an owner's: the first that is not archived,
// since an archived repo is the likeliest to answer differently, else the first.
func sampleOf(repos []core.Source) core.Source {
	for _, r := range repos {
		if !r.Archived {
			return r
		}
	}
	return repos[0]
}

// driftOf compares the audits with what the state file held. Only a feature that was enabled and
// now reads otherwise counts, and only where GitHub answered: a repo that could not be read
// this time has not drifted, it has not been seen.
func driftOf(was map[string]RepoState, audits []AuditResult) []Drift {
	var out []Drift
	for _, a := range audits {
		old, ok := was[a.Source.ID]
		if !ok || a.Err != nil || !a.Reported {
			continue
		}
		for _, f := range Features {
			if State(old.Features[string(f)]) == Enabled && a.State[f] != Enabled {
				out = append(out, Drift{Source: a.Source.ID, Feature: f, Was: Enabled, Now: a.State[f]})
			}
		}
	}
	slices.SortFunc(out, func(a, b Drift) int {
		if c := strings.Compare(a.Source, b.Source); c != 0 {
			return c
		}
		return strings.Compare(string(a.Feature), string(b.Feature))
	})
	return out
}

func planOf(m map[string]PlanState) map[Feature]PlanState {
	out := map[Feature]PlanState{}
	for _, f := range Features {
		if p, ok := m[string(f)]; ok {
			out[f] = p
		}
	}
	return out
}
