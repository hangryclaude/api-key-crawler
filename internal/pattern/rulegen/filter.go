package main

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"keyguard/internal/pattern/rules"
)

// The filters of rules/keyguard.toml are written for betterleaks, in its expression language.
// The 12 rules of our own use two forms: an entropy gate, and a list of patterns a secret must not
// match. They are read here, and anything else fails the generator, because a filter the table
// cannot carry would silently stop gating. (The 463 upstream rules are read by
// scripts/rulegen/extract.mjs, which tolerates the forms it does not know and counts them.)

var (
	entropyTerm = regexp.MustCompile(`^entropy\(finding\["secret"\]\)\s*(<=|<)\s*(\d+(?:\.\d+)?)$`)
	matchesTerm = regexp.MustCompile("^matchesAny\\(finding\\[\"secret\"\\],\\s*\\[\\s*((?:`[^`]*`\\s*,?\\s*)+)\\]\\)$")
	backticked  = regexp.MustCompile("`([^`]*)`")
	regexMeta   = regexp.MustCompile(`[\\.^$*+?()\[\]{}|]`)
)

func parseOwnFilter(expr string) (rules.Filter, error) {
	var f rules.Filter
	if strings.TrimSpace(expr) == "" {
		return f, nil
	}
	for _, term := range splitTop(expr, "||") {
		term = strings.TrimSpace(term)
		switch {
		case entropyTerm.MatchString(term):
			m := entropyTerm.FindStringSubmatch(term)
			min, _ := strconv.ParseFloat(m[2], 64)
			f.Entropy = rules.Floor{Min: min, Strict: m[1] == "<="}
		case matchesTerm.MatchString(term):
			for _, m := range backticked.FindAllStringSubmatch(matchesTerm.FindStringSubmatch(term)[1], -1) {
				if regexMeta.MatchString(m[1]) {
					f.DropRegex = append(f.DropRegex, m[1])
				} else {
					f.DropWords = append(f.DropWords, m[1])
				}
			}
		default:
			return f, fmt.Errorf("filter term %q is not one the generator reads", term)
		}
	}
	return f, nil
}

// splitTop splits s at sep wherever it is outside backticks, double quotes and brackets.
func splitTop(s, sep string) []string {
	var parts []string
	depth, start := 0, 0
	var q byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case q != 0:
			if c == '\\' && q != '`' {
				i++
			} else if c == q {
				q = 0
			}
		case c == '`' || c == '"':
			q = c
		case c == '(' || c == '[':
			depth++
		case c == ')' || c == ']':
			depth--
		case depth == 0 && strings.HasPrefix(s[i:], sep):
			parts = append(parts, s[start:i])
			start = i + len(sep)
			i += len(sep) - 1
		}
	}
	return append(parts, s[start:])
}
