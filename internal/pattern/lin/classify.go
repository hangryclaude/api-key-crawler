package lin

import "regexp/syntax"

// isAssign says whether a pattern has the shape the semi-generic rules of the table share: a name, then
// a short stretch of name characters and spaces, up to three spaces or quotes, a separator, and the
// value. Betterleaks writes 207 of its rules that way and the generic rules too. The matcher treats
// them like any other pattern; the name is for the census, which says how many rules are assignments
// and how many are fixed shapes.
func isAssign(re *syntax.Regexp) bool {
	items := flatten(re, nil)
	for i := 0; i+2 < len(items); i++ {
		gap, ws, sep := items[i], items[i+1], items[i+2]
		if repeats(gap, 0, 20, ' ', '\t', '_', '.', '-') && repeats(ws, 0, 3, '\'', '"', '\n') && hasSeparator(sep) {
			return true
		}
	}
	return false
}

// flatten lists the parts a pattern is the concatenation of, looking through groups.
func flatten(re *syntax.Regexp, out []*syntax.Regexp) []*syntax.Regexp {
	switch re.Op {
	case syntax.OpConcat:
		for _, s := range re.Sub {
			out = flatten(s, out)
		}
		return out
	case syntax.OpCapture:
		return flatten(re.Sub[0], out)
	}
	return append(out, re)
}

// repeats says that re is a class holding all of the runes, repeated min to max times.
func repeats(re *syntax.Regexp, min, max int, runes ...rune) bool {
	if re.Op != syntax.OpRepeat || re.Min != min || re.Max != max || re.Sub[0].Op != syntax.OpCharClass {
		return false
	}
	for _, r := range runes {
		if !inClass(re.Sub[0].Rune, r) {
			return false
		}
	}
	return true
}

func inClass(rs []rune, r rune) bool {
	for i := 0; i+1 < len(rs); i += 2 {
		if rs[i] <= r && r <= rs[i+1] {
			return true
		}
	}
	return false
}

// hasSeparator says that re is the alternation of assignment operators: some branch starts with '='
// and some with ':'.
func hasSeparator(re *syntax.Regexp) bool {
	has := func(r rune) bool { return starts(re, r) }
	return has('=') && has(':')
}

// starts says that some way of matching re begins with the rune r.
func starts(re *syntax.Regexp, r rune) bool {
	switch re.Op {
	case syntax.OpLiteral:
		return len(re.Rune) > 0 && re.Rune[0] == r
	case syntax.OpCharClass:
		return inClass(re.Rune, r)
	case syntax.OpCapture:
		return starts(re.Sub[0], r)
	case syntax.OpAlternate:
		for _, s := range re.Sub {
			if starts(s, r) {
				return true
			}
		}
	case syntax.OpConcat:
		return len(re.Sub) > 0 && starts(re.Sub[0], r)
	case syntax.OpRepeat, syntax.OpPlus, syntax.OpStar, syntax.OpQuest:
		return starts(re.Sub[0], r)
	}
	return false
}
