// Package fidelity checks that the rule table behaves as the rules it was copied from did, on the
// examples those rules were written against.
//
// Upstream tests every rule with strings that must fire and strings that must not. Those strings
// are made-up secrets inside test lines, and the project keeps no secret-shaped literal in source,
// so they are not in the repository: scripts/rulegen/extract.mjs writes them to a cache, one
// <rule id>.json each. This package reads the cache, runs each rule of the table over its examples
// (the keyword gate, the path gate, the regex, the secret group, the filter, the global filter, as
// betterleaks does) and reduces what happened to a short digest per rule. The digest of each rule
// is committed; a rewrite that changes what a rule does with any example changes its digest.
//
// What it does not judge: TokenRatio, because betterleaks's token-efficiency data is not ours,
// and the Residual parts of a filter, because the table does not carry them. A rule with either is
// held to its true positives only: upstream's false positives may be rejected by exactly what the
// table cannot see.
package fidelity

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"keyguard/internal/pattern/rules"
)

// Example is one test string. Secret, when set, is the value the example was built around.
type Example struct {
	Text   string `json:"text"`
	Path   string `json:"path"`
	Secret string `json:"secret"`
}

// Set is the cache file of one rule.
type Set struct {
	Rule      string    `json:"rule"`
	Source    string    `json:"source"`
	Commit    string    `json:"commit"`
	Positives []Example `json:"positives"`
	Negatives []Example `json:"negatives"`
	Errors    []string  `json:"errors"`
}

// Load reads the examples of a rule from the cache directory. A rule without a file, which is
// every rule upstream gave no examples, returns nil and no error.
func Load(dir, id string) (*Set, error) {
	b, err := os.ReadFile(filepath.Join(dir, id+".json"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var s Set
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("%s: %w", id, err)
	}
	return &s, nil
}

var compiled sync.Map // pattern -> *regexp.Regexp

func rx(pattern string) *regexp.Regexp {
	if v, ok := compiled.Load(pattern); ok {
		return v.(*regexp.Regexp)
	}
	re := regexp.MustCompile(pattern)
	compiled.Store(pattern, re)
	return re
}

func matchesAny(patterns []string, s string) bool {
	for _, p := range patterns {
		if rx(p).MatchString(s) {
			return true
		}
	}
	return false
}

// entropy is the Shannon entropy of s in bits per byte, which is what betterleaks's filters compute.
func entropy(s string) float64 {
	if s == "" {
		return 0
	}
	var freq [256]float64
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	n := float64(len(s))
	h := 0.0
	for _, f := range freq {
		if f > 0 {
			p := f / n
			h -= p * math.Log2(p)
		}
	}
	return h
}

// dropped says whether a filter discards a finding with this secret at this path.
func dropped(f rules.Filter, secret, path string) bool {
	if min := f.Entropy.Min; min != 0 {
		if e := entropy(secret); (f.Entropy.Strict && e <= min) || (!f.Entropy.Strict && e < min) {
			return true
		}
	}
	if matchesAny(f.DropRegex, secret) {
		return true
	}
	for _, w := range f.DropWords {
		if strings.Contains(secret, w) {
			return true
		}
	}
	if len(f.DropSHA256) > 0 {
		sum := sha256.Sum256([]byte(secret))
		h := hex.EncodeToString(sum[:])
		for _, d := range f.DropSHA256 {
			if d == h {
				return true
			}
		}
	}
	if path != "" && matchesAny(f.DropPath, path) {
		return true
	}
	for _, group := range f.Require {
		if !matchesAny(group, secret) {
			return true
		}
	}
	return false
}

// Findings are the secrets the rule reports in text, which sits at path (empty for a bare string).
// They are returned in memory for the caller to hash; nothing here prints or stores one.
func Findings(r *rules.Rule, global rules.Filter, text, path string) []string {
	if path != "" && matchesAny(global.DropPath, path) {
		return nil
	}
	if r.Path != "" {
		if path == "" || !rx(r.Path).MatchString(path) {
			return nil
		}
		if r.Re == "" { // a rule about a file's name: the path is the finding
			return []string{path}
		}
	}
	if len(r.Keywords) > 0 {
		lower := strings.ToLower(text)
		hit := false
		for _, k := range r.Keywords {
			if strings.Contains(lower, k) {
				hit = true
				break
			}
		}
		if !hit {
			return nil
		}
	}
	re := rx(r.Re)
	var out []string
	for _, m := range re.FindAllStringIndex(text, -1) {
		// betterleaks takes the match, trims newlines off it, runs the regex over that, and
		// reports the group (the rule's, or the first that is not empty) or else the match.
		matched := strings.Trim(text[m[0]:m[1]], "\n")
		secret := matched
		if groups := re.FindStringSubmatch(matched); len(groups) >= 2 {
			if r.Group > 0 {
				if len(groups) <= r.Group {
					continue
				}
				secret = groups[r.Group]
			} else {
				for _, g := range groups[1:] {
					if g != "" {
						secret = g
						break
					}
				}
			}
		}
		if dropped(r.Filter, secret, path) || dropped(global, secret, path) {
			continue
		}
		out = append(out, secret)
	}
	return out
}

// Result is what one rule did with its examples.
type Result struct {
	Positives, Negatives int
	Digest               string
	Missed               []string // positives that did not fire
	Fired                []string // negatives that fired, where the table can judge them
	Unjudged             int      // negatives not judged: the rule has filter parts the table does not carry
	HintMisses           int      // positives built around a known secret that the rule reported differently
}

func short(sum [32]byte) string { return hex.EncodeToString(sum[:])[:16] }

// Evaluate runs a rule over its examples.
func Evaluate(r *rules.Rule, global rules.Filter, s *Set) Result {
	res := Result{Positives: len(s.Positives), Negatives: len(s.Negatives)}
	judged := r.Filter.TokenRatio == 0 && r.Filter.Residual == 0
	var lines []string
	one := func(kind string, ex Example) []string {
		got := Findings(r, global, ex.Text, ex.Path)
		id := short(sha256.Sum256([]byte(ex.Path + "\x00" + ex.Text)))
		fired := "0"
		if len(got) > 0 {
			fired = "1"
		}
		lines = append(lines, kind+" "+id+" "+fired+" "+short(sha256.Sum256([]byte(strings.Join(got, "\x00")))))
		return got
	}
	for _, ex := range s.Positives {
		got := one("P", ex)
		if len(got) == 0 {
			res.Missed = append(res.Missed, short(sha256.Sum256([]byte(ex.Path+"\x00"+ex.Text))))
			continue
		}
		if ex.Secret != "" {
			found := false
			for _, g := range got {
				found = found || g == ex.Secret
			}
			if !found {
				res.HintMisses++
			}
		}
	}
	for _, ex := range s.Negatives {
		got := one("N", ex)
		switch {
		case len(got) == 0:
		case judged:
			res.Fired = append(res.Fired, short(sha256.Sum256([]byte(ex.Path+"\x00"+ex.Text))))
		default:
			res.Unjudged++
		}
	}
	sort.Strings(lines) // the digest does not depend on the order the examples were extracted in
	res.Digest = short(sha256.Sum256([]byte(strings.Join(lines, "\n"))))
	return res
}

// Entry is one rule's line of the golden.
type Entry struct {
	Positives int    `json:"positives"`
	Negatives int    `json:"negatives"`
	Digest    string `json:"digest"`
}

// Golden is the committed record of what the table did with the examples: one digest per rule.
// It holds hashes of hashes and counts, never a string that was an example.
type Golden struct {
	Source          string           `json:"source"`
	Examples        int              `json:"examples"`
	Rules           map[string]Entry `json:"rules"`
	WithoutExamples []string         `json:"withoutExamples"`
}

// Build runs the whole table over the cache and returns the golden. It fails, naming the rules,
// if any true positive does not fire or any judged false positive does: a golden is a record of
// a table that passes, not of one that does not.
func Build(corpus string, table []rules.Rule, global rules.Filter, commit string) (*Golden, error) {
	// The golden names the commit by its first 12 characters: a whole 40-hex id is what a scanner calls a key.
	g := &Golden{Source: "betterleaks@" + commit[:min(len(commit), 12)], Rules: map[string]Entry{}}
	var bad []string
	for i := range table {
		r := &table[i]
		s, err := Load(corpus, r.ID)
		if err != nil {
			return nil, err
		}
		if s == nil || (len(s.Positives) == 0 && len(s.Negatives) == 0) {
			g.WithoutExamples = append(g.WithoutExamples, r.ID)
			continue
		}
		if s.Commit != commit && r.Src.Lineage != "own" {
			return nil, fmt.Errorf("%s: the cache was extracted at %s, the table is pinned at %s", r.ID, s.Commit, commit)
		}
		res := Evaluate(r, global, s)
		g.Rules[r.ID] = Entry{Positives: res.Positives, Negatives: res.Negatives, Digest: res.Digest}
		g.Examples += res.Positives + res.Negatives
		if len(res.Missed) > 0 {
			bad = append(bad, fmt.Sprintf("%s: %d of %d true positives did not fire", r.ID, len(res.Missed), res.Positives))
		}
		if len(res.Fired) > 0 {
			bad = append(bad, fmt.Sprintf("%s: %d of %d false positives fired", r.ID, len(res.Fired), res.Negatives))
		}
	}
	sort.Strings(g.WithoutExamples)
	if len(bad) > 0 {
		return nil, fmt.Errorf("the table disagrees with its examples:\n  %s", strings.Join(bad, "\n  "))
	}
	return g, nil
}
