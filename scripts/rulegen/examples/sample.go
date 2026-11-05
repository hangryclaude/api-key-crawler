package main

import (
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"regexp/syntax"
	"strings"
	"unicode"
)

// sampleRegex draws one string that matches re, walking the parsed expression the way
// betterleaks's own generator does for its examples: a literal is copied, a class gives one
// of its characters, a repeat gives a count between its bounds, an alternation picks a branch.
// The draw comes from rng, so a seed makes the same string. No literal of the result is ever
// written in this repository: it is built here, at run time, from the shape of the regex.
func sampleRegex(re string, rng *rand.Rand) (string, error) {
	p, err := syntax.Parse(re, syntax.Perl)
	if err != nil {
		return "", err
	}
	var sb strings.Builder
	if err := walk(&sb, p.Simplify(), rng); err != nil {
		return "", err
	}
	return sb.String(), nil
}

// extraRepeats bounds an open-ended repeat (+, *, {n,}) the way an unbounded one has to be.
const extraRepeats = 8

func walk(sb *strings.Builder, re *syntax.Regexp, rng *rand.Rand) error {
	switch re.Op {
	case syntax.OpNoMatch:
		return errors.New("a regex that matches nothing")
	case syntax.OpEmptyMatch, syntax.OpBeginLine, syntax.OpEndLine, syntax.OpBeginText, syntax.OpEndText,
		syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return nil
	case syntax.OpLiteral:
		sb.WriteString(string(re.Rune))
	case syntax.OpCharClass:
		r, err := pickRune(re.Rune, rng)
		if err != nil {
			return err
		}
		sb.WriteRune(r)
	case syntax.OpAnyCharNotNL, syntax.OpAnyChar:
		sb.WriteRune(rune('!' + rng.IntN('~'-'!'+1)))
	case syntax.OpCapture:
		return walk(sb, re.Sub[0], rng)
	case syntax.OpConcat:
		for _, s := range re.Sub {
			if err := walk(sb, s, rng); err != nil {
				return err
			}
		}
	case syntax.OpAlternate:
		return walk(sb, re.Sub[rng.IntN(len(re.Sub))], rng)
	case syntax.OpStar:
		return repeat(sb, re.Sub[0], 0, extraRepeats, rng)
	case syntax.OpPlus:
		return repeat(sb, re.Sub[0], 1, 1+extraRepeats, rng)
	case syntax.OpQuest:
		return repeat(sb, re.Sub[0], 0, 1, rng)
	case syntax.OpRepeat:
		hi := re.Max
		if hi < 0 {
			hi = re.Min + extraRepeats
		}
		return repeat(sb, re.Sub[0], re.Min, hi, rng)
	default:
		return fmt.Errorf("regexp op %v is not sampled", re.Op)
	}
	return nil
}

func repeat(sb *strings.Builder, sub *syntax.Regexp, lo, hi int, rng *rand.Rand) error {
	n := lo
	if hi > lo {
		n += rng.IntN(hi - lo + 1)
	}
	for range n {
		if err := walk(sb, sub, rng); err != nil {
			return err
		}
	}
	return nil
}

// pickRune draws uniformly from the class's printable ASCII characters, or from all of it when
// it has none (a class of letters outside ASCII).
func pickRune(ranges []rune, rng *rand.Rand) (rune, error) {
	var ascii, all int
	for i := 0; i+1 < len(ranges); i += 2 {
		all += int(ranges[i+1]-ranges[i]) + 1
		ascii += overlap(ranges[i], ranges[i+1], '!', '~')
	}
	if all == 0 {
		return 0, errors.New("an empty character class")
	}
	lo, hi, n := rune(0), rune(0), all
	if ascii > 0 {
		lo, hi, n = '!', '~', ascii
	}
	k := rng.IntN(n)
	for i := 0; i+1 < len(ranges); i += 2 {
		a, b := ranges[i], ranges[i+1]
		if hi != 0 {
			a, b = max(a, lo), min(b, hi)
		}
		if a > b {
			continue
		}
		size := int(b-a) + 1
		if k < size {
			r := a + rune(k)
			if !unicode.IsPrint(r) {
				return 0, fmt.Errorf("class picked an unprintable rune %U", r)
			}
			return r, nil
		}
		k -= size
	}
	return 0, errors.New("class draw fell off its ranges")
}

func overlap(a, b, lo, hi rune) int {
	a, b = max(a, lo), min(b, hi)
	if a > b {
		return 0
	}
	return int(b-a) + 1
}

// entropy is the Shannon entropy of s in bits per character, over its runes, as betterleaks's
// generator computes it for NewSecretWithEntropy.
func entropy(s string) float64 {
	if s == "" {
		return 0
	}
	counts := map[rune]int{}
	n := 0
	for _, c := range s {
		counts[c]++
		n++
	}
	h := 0.0
	for _, c := range counts {
		f := float64(c) / float64(n)
		h -= f * math.Log2(f)
	}
	return h
}
