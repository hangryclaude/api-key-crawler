package bench

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// frozenHeldOut is the held-out half of the planted corpus's provider formats as it was frozen
// (STEAL P0-23). A format that is here stays here: a rule written for a tune-half format can
// never have been fitted to it, and every score ever recorded stays comparable. If this test
// fails, the split moved; do not update the list, find out why Half changed.
var frozenHeldOut = strings.Fields(`airtable anthropic-admin aws-lone brevo cloudflare-global datadog dockerhub figma
	firebase-web gcp-service-account generic-api-key github-app github-classic github-fine-grained gitlab huggingface
	linear notion openai-project openssh-key planetscale planetscale-lone posthog pypi redis replicate resend sentry
	slack-user slack-webhook stripe-restricted stripe-secret supabase-service-role tavily telegram together twilio xai
	zerobounce zoom`)

func TestTheSplitIsFrozen(t *testing.T) {
	var all []string
	for _, p := range Providers {
		all = append(all, p.ID)
	}
	got := HeldOut(all)
	for _, id := range frozenHeldOut {
		if !slices.Contains(got, id) {
			t.Errorf("%s was held out when the split was frozen and is not now", id)
		}
	}
	// a format added since may fall in either half, but none of the frozen ones left it
	for _, id := range got {
		if !slices.Contains(frozenHeldOut, id) {
			t.Errorf("%s moved into the held-out half", id)
		}
	}
	if len(got) != len(frozenHeldOut) {
		t.Errorf("%d formats are held out, %d were frozen", len(got), len(frozenHeldOut))
	}
	for _, path := range []string{".env.production", "Cargo.lock", "package-lock.json", "yarn.lock"} {
		if Half(path) != HalfHeldOut {
			t.Errorf("lookalike file %s left the held-out half", path)
		}
	}
	for _, path := range []string{".env.example", "README.md", "go.sum", "docs/aws-setup.md"} {
		if Half(path) != HalfTune {
			t.Errorf("lookalike file %s left the tune half", path)
		}
	}
}

func TestSplitIsBalancedAndDependsOnTheNameOnly(t *testing.T) {
	n := len(HeldOut(func() []string {
		var ids []string
		for _, p := range Providers {
			ids = append(ids, p.ID)
		}
		return ids
	}()))
	if frac := float64(n) / float64(len(Providers)); frac < 0.35 || frac > 0.65 {
		t.Errorf("%d of %d formats are held out (%.0f%%): the split is lopsided", n, len(Providers), 100*frac)
	}
	if Half("some/repo") != Half("some/repo") || Half("a") == "" {
		t.Error("a name must always fall in the same half")
	}
	// plenty of repo names land in both halves, so the oracle and natural corpora get both
	seen := map[string]bool{}
	for i := 0; i < 40; i++ {
		seen[Half("hangryclaude/repo-"+string(rune('a'+i%26))+string(rune('a'+i/26)))] = true
	}
	if !seen[HalfTune] || !seen[HalfHeldOut] {
		t.Error("forty repo names fell in one half only")
	}
}

// Everything planted from one format is in one half, whatever the seed, and the half is in truth.json.
func TestEveryPlantIsInTheHalfItsFormatIs(t *testing.T) {
	a := sharedCorpus(t)
	b, err := Generate(filepath.Join(t.TempDir(), "s2"), Options{Seed: 2})
	if err != nil {
		t.Fatal(err)
	}
	half := map[string]string{}
	for _, c := range []*Corpus{a, b} {
		for _, p := range c.Truth.Plants {
			if p.Half == "" || p.Half != HalfOf(p) {
				t.Fatalf("%s: half %q, want %q", p.ID, p.Half, HalfOf(p))
			}
			if p.Format == "" {
				continue // a lookalike file is split by its path
			}
			if h, ok := half[p.Format]; ok && h != p.Half {
				t.Errorf("%s: format %s is in both halves", p.ID, p.Format)
			}
			half[p.Format] = p.Half
		}
	}
	// a twin goes with its valid plant
	byID := map[string]Plant{}
	for _, p := range a.Truth.Plants {
		byID[p.ID] = p
	}
	for _, p := range a.Truth.Plants {
		if p.Twin == "invalid" && byID[p.TwinOf].Half != p.Half {
			t.Errorf("%s is not in the half of %s", p.ID, p.TwinOf)
		}
	}
	st := a.Truth.Stats
	if st.HeldOut == 0 || st.Tunable == 0 || st.HeldOut+st.Tunable != st.Positives {
		t.Errorf("stats: %d held out, %d tunable, %d positives", st.HeldOut, st.Tunable, st.Positives)
	}
}
