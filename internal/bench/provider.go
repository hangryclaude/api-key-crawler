package bench

import "strings"

// Fake is one generated secret and how it is written into a file.
type Fake struct {
	Value string   // text assigned to the variable (a whole URL for database plants)
	Raw   string   // the canonical secret inside Value: this is what gets fingerprinted
	Alt   []string // other extents of the same credential an engine may report instead
	Name  string   // variable name, overriding Provider.Env (the AWS secret key)
	Pairs []Pair   // companion assignments written next to it (the AWS key id)
}

// Pair is a companion variable that travels with a secret.
type Pair struct{ Name, Value string }

// Provider is one secret format the corpus plants.
type Provider struct {
	ID    string // stable key in plant ids
	Type  string // normalized provider type: the vocabulary core.Hit.Type uses
	Env   string // conventional variable name; keyword rules need it on the line
	Doc   string // authority for the format
	Multi bool   // Value spans lines (PEM, service-account JSON)

	// Rules lists the engine rules expected to cover the format, as "engine/id". A fake
	// for a ruled provider must satisfy at least one of them (checked at generation time
	// and again in tests); an unruled provider carries Undetected instead.
	Rules      []string
	Undetected string // why no engine has a rule; its plants are not detectable by design

	Gen func(g *Gen) Fake
	// Twins builds the invalid twins planted beside a valid plant of the format (STEAL P0-26).
	// The kinds it returns depend on the format only, never on the draw, so the corpus keeps
	// its structure across seeds.
	Twins func(g *Gen) []Twin
}

func bl(ids ...string) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = "betterleaks/" + id
	}
	return out
}

// flat is a provider whose secret is a literal prefix plus random characters.
func flat(id, typ, env, doc string, rules []string, minEntropy float64, parts ...part) Provider {
	// a fake that sits at its rule's floor is dropped by the engine's own filter 18 times in 100
	// for hex (docs/STEAL.md K8), so the plant would test the filter and not the rule: draw until
	// the entropy is 0.3 bits above it (STEAL P0-26)
	entropy := func() float64 { return max(minEntropy, ruleFloor(rules)+0.3) }
	return Provider{ID: id, Type: typ, Env: env, Doc: doc, Rules: rules, Gen: func(g *Gen) Fake {
		s := g.token(entropy(), parts...)
		return Fake{Value: s, Raw: s}
	}, Twins: func(g *Gen) []Twin { return flatTwins(g, rules, entropy(), parts) }}
}

// unruled is flat for a format no installed engine has a rule for.
func unruled(id, typ, env, doc, why string, minEntropy float64, parts ...part) Provider {
	p := flat(id, typ, env, doc, nil, minEntropy, parts...)
	p.Undetected = why
	return p
}

func envStyle(name string) string { return strings.ToUpper(name) }
