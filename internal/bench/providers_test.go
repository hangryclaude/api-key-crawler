package bench

import (
	"fmt"
	"strings"
	"testing"
)

func TestProviderTableIsWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, list := range [][]Provider{Providers, PublicProviders} {
		for _, p := range list {
			if p.ID == "" || p.Type == "" || p.Env == "" || p.Doc == "" || p.Gen == nil {
				t.Errorf("provider %q is incomplete: %+v", p.ID, p)
			}
			if seen[p.ID] {
				t.Errorf("provider id %s is used twice", p.ID)
			}
			seen[p.ID] = true
		}
	}
	for _, p := range Providers {
		// a format is ruled or it says why not, never both and never neither
		if len(p.Rules) > 0 && p.Undetected != "" {
			t.Errorf("%s has rules and an Undetected reason", p.ID)
		}
		if len(p.Rules) == 0 && p.Undetected == "" {
			t.Errorf("%s has neither a rule nor an Undetected reason", p.ID)
		}
		for _, ref := range p.Rules {
			if _, err := lookupRule(ref); err != nil {
				t.Errorf("%s: %v", p.ID, err)
			}
		}
	}
	for _, p := range PublicProviders {
		if len(p.Rules) > 0 {
			t.Errorf("public-by-design %s must not claim to be detectable", p.ID)
		}
	}
}

// Every fake of a ruled provider must satisfy its rule the way the engine applies it: the
// pattern on a line the format would really sit on, the keyword prefilter, the entropy
// gate, and any component a composite rule needs. A dozen draws per format, because the
// gates (entropy, boundaries) fail on some random values and not others.
func TestEveryRuledProviderMatchesItsRule(t *testing.T) {
	for _, p := range Providers {
		if len(p.Rules) == 0 {
			continue
		}
		draws := 12
		if p.Multi {
			draws = 2 // key generation is the slow part
		}
		lone := strings.HasSuffix(p.ID, "-lone")
		for k := 0; k < draws; k++ {
			f := p.Gen(&Gen{r: newRand(99, fmt.Sprintf("rule/%s/%d", p.ID, k))})
			name := f.Name
			if name == "" {
				name = p.Env
			}
			var b strings.Builder
			for _, pr := range f.Pairs {
				b.WriteString(pr.Name + "=" + pr.Value + "\n")
			}
			value := f.Value
			if p.Multi {
				value = dotenvEscape(value)
				b.WriteString(name + `="` + value + `"` + "\n")
			} else {
				b.WriteString(name + "=" + value + "\n")
			}
			content := b.String()
			accept := append([]string{f.Raw, f.Value, value}, f.Alt...)

			// the bare pattern, ignoring the engine's gates
			matched := false
			for _, ref := range p.Rules {
				c, err := lookupRule(ref)
				if err != nil {
					t.Fatal(err)
				}
				for _, m := range c.re.FindAllStringSubmatchIndex(content, -1) {
					s, _ := c.pick(content, m)
					for _, a := range accept {
						matched = matched || s == a
					}
				}
			}
			if !matched {
				t.Errorf("%s draw %d: no rule's pattern extracts the planted secret from a .env line", p.ID, k)
				continue
			}
			by, err := coveredBy(p.Rules, ".env", []string{content}, accept)
			if err != nil {
				t.Fatal(err)
			}
			switch {
			case lone && len(by) != 0:
				t.Errorf("%s draw %d: a composite rule reported a secret with no companion beside it", p.ID, k)
			case !lone && len(by) == 0:
				t.Errorf("%s draw %d: the pattern matches but the engine's keyword, entropy or component gate rejects it", p.ID, k)
			}
		}
	}
}

func TestUnruledProvidersAreNeverDetectableByDesign(t *testing.T) {
	c := sharedCorpus(t)
	unruled := map[string]bool{}
	for _, p := range Providers {
		if len(p.Rules) == 0 {
			unruled[p.Type] = true
		}
	}
	ruledTypes := map[string]bool{}
	for _, p := range Providers {
		if len(p.Rules) > 0 {
			ruledTypes[p.Type] = true
		}
	}
	for _, p := range c.Truth.Plants {
		if p.Positive && unruled[p.Type] && !ruledTypes[p.Type] {
			if p.Detectable || len(p.DetectableBy) != 0 {
				t.Errorf("%s: an unruled format is marked detectable", p.ID)
			}
			if !strings.Contains(p.Note, "undetected by design") {
				t.Errorf("%s: the note does not say why it is undetected", p.ID)
			}
		}
	}
	// the canonical context, a .env file, always works for a ruled format that is not a lone
	// fragment of a composite rule
	for _, p := range c.Truth.Plants {
		if p.Positive && p.Variant == vEnv && len(p.Rules) > 0 && !strings.Contains(p.ID, "-lone-") && !p.Detectable {
			t.Errorf("%s: a ruled format is not detectable in a .env file", p.ID)
		}
	}
}

func TestFakesAreRepeatableAndDistinct(t *testing.T) {
	for _, p := range Providers {
		if p.Multi {
			continue
		}
		a := p.Gen(&Gen{r: newRand(1, "x/"+p.ID)})
		b := p.Gen(&Gen{r: newRand(1, "x/"+p.ID)})
		c := p.Gen(&Gen{r: newRand(2, "x/"+p.ID)})
		if a.Raw != b.Raw {
			t.Errorf("%s: the same stream gave different fakes", p.ID)
		}
		if a.Raw == c.Raw {
			t.Errorf("%s: different seeds gave the same fake", p.ID)
		}
	}
}

// The corpus is a public repo's worth of fakes; none may be a real provider's documented
// example, which scanners rightly ignore and which would make the bench flatter engines.
func TestFakesAreNotDocumentationExamples(t *testing.T) {
	c := sharedCorpus(t)
	for _, r := range c.recs {
		if !r.positive {
			continue
		}
		low := strings.ToLower(r.fake.Raw)
		for _, w := range []string{"example", "placeholder", "xxxxxxxx", "your_", "changeme"} {
			if strings.Contains(low, w) {
				t.Errorf("%s: the fake contains %q", r.id, w)
			}
		}
	}
}
