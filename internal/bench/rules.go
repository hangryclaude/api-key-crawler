package bench

import (
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"

	"keyguard/internal/fp"
)

// ruleDef is the part of an engine rule the generator needs to know whether a fake is
// detectable by design: the pattern, the keyword prefilter and the entropy gate.
type ruleDef struct {
	Regex    string
	Keywords []string // lowercased; the engine only runs the rule on content containing one
	Entropy  float64  // the engine drops a secret whose entropy is at or below this
	Group    int      // secretGroup; 0 means the first non-empty capture group, else the whole match

	// Components are the rules a composite rule needs before it reports at all: betterleaks
	// drops a planetscale token with no planetscale id beside it, a supabase secret key with
	// no project url. Optional components are not listed.
	Components []component
}

// component is a required companion finding, at most Within lines away (0 = anywhere in the file).
type component struct {
	ID     string
	Within int
}

// thPrefix is trufflehog's detectors.PrefixRegex: the keyword, then up to 40 characters.
func thPrefix(kw ...string) string {
	return `(?i)(?:` + strings.Join(kw, "|") + `)(?:.|[\n\r]){0,40}?`
}

// trufflehogRules quotes detectors for formats betterleaks has no rule for, from
// pkg/detectors/<name>/<name>.go at trufflehog main (read at 3.99.8):
//
//	zerobounce  keyPat = PrefixRegex({"zerobounce"}) + `\b([a-z0-9]{32})\b`
//
// trufflehog's discordbottoken and discordwebhook detectors are left out on purpose: patterns
//
//	discordbottoken PrefixRegex({"discord"}) + `\b([A-Za-z0-9_-]{24}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27})\b`
//	discordwebhook  `(https:\/\/discord\.com\/api\/webhooks\/[0-9]{18,19}\/[0-9a-zA-Z-]{68})`
//
// but unverified, neither survives trufflehog's false-positive wordlist, so offline they detect
// nothing (see discordWhy). Listing them would claim a detection the engine never makes.
var trufflehogRules = map[string]ruleDef{
	"zerobounce": {
		Regex:    thPrefix("zerobounce") + `\b([a-z0-9]{32})\b`,
		Keywords: []string{"zerobounce"},
	},
}

type compiledRule struct {
	def ruleDef
	re  *regexp.Regexp
}

var (
	ruleMu    sync.Mutex
	ruleCache = map[string]*compiledRule{}
)

// lookupRule resolves "engine/id" and compiles its regex once.
func lookupRule(ref string) (*compiledRule, error) {
	ruleMu.Lock()
	defer ruleMu.Unlock()
	if c, ok := ruleCache[ref]; ok {
		return c, nil
	}
	engine, id, _ := strings.Cut(ref, "/")
	var def ruleDef
	var ok bool
	switch engine {
	case "betterleaks":
		def, ok = betterleaksRules[id]
	case "trufflehog":
		def, ok = trufflehogRules[id]
	}
	if !ok {
		return nil, fmt.Errorf("bench: unknown rule %q", ref)
	}
	re, err := regexp.Compile(def.Regex)
	if err != nil {
		return nil, fmt.Errorf("bench: rule %q: %w", ref, err)
	}
	c := &compiledRule{def: def, re: re}
	ruleCache[ref] = c
	return c, nil
}

// ruleHit is one secret a rule extracts, with the line it starts on.
type ruleHit struct {
	secret string
	line   int
}

// found returns what the rule would report from content: the keyword prefilter, the
// pattern, the secret group and the entropy gate, in the engine's order. Filters written in
// the engines' expression language beyond the entropy gate are not modelled; the live
// engine run measures those.
func (c *compiledRule) found(content string) []ruleHit {
	if len(c.def.Keywords) > 0 {
		low := strings.ToLower(content)
		hit := false
		for _, k := range c.def.Keywords {
			if strings.Contains(low, k) {
				hit = true
				break
			}
		}
		if !hit {
			return nil
		}
	}
	var out []ruleHit
	for _, m := range c.re.FindAllStringSubmatchIndex(content, -1) {
		s, at := c.pick(content, m)
		if s == "" {
			continue
		}
		if c.def.Entropy > 0 && fp.Entropy(s) <= c.def.Entropy {
			continue
		}
		out = append(out, ruleHit{s, 1 + strings.Count(content[:at], "\n")})
	}
	return out
}

func (c *compiledRule) pick(content string, m []int) (string, int) {
	span := func(g int) (string, int) {
		if 2*g+1 < len(m) && m[2*g] >= 0 {
			return content[m[2*g]:m[2*g+1]], m[2*g]
		}
		return "", 0
	}
	if c.def.Group > 0 {
		return span(c.def.Group)
	}
	for g := 1; 2*g < len(m); g++ {
		if s, at := span(g); s != "" {
			return s, at
		}
	}
	return span(0)
}

// componentsMet reports whether every required companion of a finding at line is present.
func (c *compiledRule) componentsMet(view string, line int) (bool, error) {
	for _, comp := range c.def.Components {
		cr, err := lookupRule("betterleaks/" + comp.ID)
		if err != nil {
			return false, err
		}
		ok := false
		for _, h := range cr.found(view) {
			if d := h.line - line; comp.Within == 0 || d <= comp.Within && -d <= comp.Within {
				ok = true
				break
			}
		}
		if !ok {
			return false, nil
		}
	}
	return true, nil
}

// coveredBy returns the engines (the part of each rule ref before "/") with a rule that
// extracts one of the accepted secrets from any view of the file. path is where the engine
// sees the file, for betterleaks' global path prefilter.
func coveredBy(rules []string, path string, views, accept []string) ([]string, error) {
	want := make(map[string]bool, len(accept))
	for _, f := range accept {
		want[f] = true
	}
	var engines []string
	for _, ref := range rules {
		c, err := lookupRule(ref)
		if err != nil {
			return nil, err
		}
		engine, _, _ := strings.Cut(ref, "/")
		if engine == "betterleaks" && betterleaksSkips(path) {
			continue
		}
	views:
		for _, v := range views {
			for _, h := range c.found(v) {
				if !want[h.secret] {
					continue
				}
				ok, err := c.componentsMet(v, h.line)
				if err != nil {
					return nil, err
				}
				if ok {
					engines = append(engines, engine)
					break views
				}
			}
		}
	}
	sort.Strings(engines)
	return slices.Compact(engines), nil
}

var (
	prefilterOnce sync.Once
	prefilterREs  []*regexp.Regexp
)

// betterleaksSkips reports whether betterleaks never scans path (its global prefilter).
func betterleaksSkips(path string) bool {
	prefilterOnce.Do(func() {
		for _, p := range betterleaksPrefilter {
			prefilterREs = append(prefilterREs, regexp.MustCompile(p))
		}
	})
	for _, re := range prefilterREs {
		if re.MatchString(path) {
			return true
		}
	}
	return false
}
