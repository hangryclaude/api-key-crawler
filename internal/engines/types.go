package engines

import (
	_ "embed"
	"strings"
	"sync"
	"unicode"
)

// Generic is the type of a finding no provider claims: high-entropy assignments, passwords,
// curl auth headers. Triage treats it as the least specific label.
const Generic = "generic"

//go:embed providers.txt
var providerData string

var (
	providerOnce sync.Once
	providers    map[string]string // leading words joined without separators -> canonical type
)

func loadProviders() {
	providers = map[string]string{}
	var aliases [][2]string
	for _, l := range strings.Split(providerData, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || l[0] == '#' {
			continue
		}
		if a, c, ok := strings.Cut(l, "="); ok {
			aliases = append(aliases, [2]string{a, c})
			continue
		}
		providers[l] = l
	}
	// Aliases go in last so an alias can never be shadowed by a seeded name of the same spelling.
	for _, ac := range aliases {
		providers[ac[0]] = ac[1]
	}
}

// special covers rule ids whose meaning is not "<provider>-<thing>": the leading words would
// either match nothing or match the wrong provider. Keys are lowercase, engine namespace and
// trailing version number already stripped.
var special = map[string]string{
	"private-key": "private-key", // betterleaks, gitleaks
	"privatekey":  "private-key", // trufflehog PrivateKey
	"pem":         "private-key", // titus np.pem.N
	"privkey":     "private-key", // titus kingfisher.privkey.N
	"pkcs12-file": "private-key",
	"credentials": "uri", // titus kingfisher.credentials.1: user:password@ in a URL
}

// NormalizeType maps an engine's rule id (betterleaks, gitleaks, titus) or detector name
// (trufflehog) to the provider type the rest of keyguard keys on: "github", "aws", "openai".
// Anything no provider claims is Generic, never an error: a new engine release must not be
// able to break a scan.
func NormalizeType(engine, rule string) string {
	providerOnce.Do(loadProviders)
	key := ruleKey(engine, rule)
	if t, ok := special[key]; ok {
		return t
	}
	words := ruleWords(rule)
	for n := len(words); n >= 1; n-- {
		if t, ok := providers[strings.Join(words[:n], "")]; ok {
			return t
		}
	}
	return Generic
}

// ruleKey is the lowercase rule id with the engine's own namespace and version suffix
// removed, so titus's "np.pem.2" and betterleaks's "private-key" meet the same table.
func ruleKey(engine, rule string) string {
	k := strings.ToLower(strings.TrimSpace(rule))
	if engine == "titus" {
		for _, ns := range []string{"np.", "kingfisher.", "titus."} {
			k = strings.TrimPrefix(k, ns)
		}
	}
	if i := strings.LastIndexByte(k, '.'); i > 0 && isDigits(k[i+1:]) {
		k = k[:i]
	}
	return k
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// ruleWords splits "github-fine-grained-pat", "np.github.7" and "GitHubApp" into lowercase
// words. A titus namespace and a trailing version number are dropped: neither is part of a
// provider's name, and a namespace would stop the longest-prefix walk from matching at all.
// Only a whole trailing token goes, so the 42 in "intra42" stays.
func ruleWords(rule string) []string {
	toks := strings.FieldsFunc(rule, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) })
	if len(toks) > 1 && isDigits(toks[len(toks)-1]) {
		toks = toks[:len(toks)-1]
	}
	for len(toks) > 1 && (toks[0] == "np" || toks[0] == "kingfisher" || toks[0] == "titus") {
		toks = toks[1:]
	}
	var words []string
	for _, tok := range toks {
		words = append(words, splitCamel(tok)...)
	}
	return words
}

// splitCamel splits at lower->Upper, letter<->digit and at the end of an acronym
// ("AWSSession" -> aws, session), which is how trufflehog spells its detectors.
func splitCamel(s string) []string {
	rs := []rune(s)
	var out []string
	start := 0
	for i := 1; i < len(rs); i++ {
		prev, cur := rs[i-1], rs[i]
		cut := unicode.IsLower(prev) && unicode.IsUpper(cur) ||
			unicode.IsDigit(prev) != unicode.IsDigit(cur) ||
			unicode.IsUpper(prev) && unicode.IsUpper(cur) && i+1 < len(rs) && unicode.IsLower(rs[i+1])
		if cut {
			out = append(out, strings.ToLower(string(rs[start:i])))
			start = i
		}
	}
	return append(out, strings.ToLower(string(rs[start:])))
}
