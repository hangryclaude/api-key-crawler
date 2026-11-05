package known

import (
	"encoding/json"
	"strings"
	"unicode/utf8"
)

// parseStoreFast reads known.json in the exact layout writeStore emits. Every git hook on
// this Mac loads the store, and encoding/json spends ~3 ms of a ~4 ms load on it for a few
// hundred secrets; this takes a fraction of that by slicing fields out of one copy of the
// file instead of allocating ten strings per entry. It accepts nothing but its own layout
// (fixed field order, no spare whitespace) and reports false for anything else, in which
// case readStore falls back to encoding/json, so a hand-edited or newer file still loads
// and the fast path can never be the reason a store is misread: tests compare the two on
// random stores and on fuzz input.
func parseStoreFast(b []byte) (*Store, bool) {
	p := fastParser{s: string(b)}
	var st Store
	var ok bool
	if !p.lit(`{"version":`) {
		return nil, false
	}
	if st.Version, ok = p.int(); !ok {
		return nil, false
	}
	if !p.lit(`,"salt_check":`) {
		return nil, false
	}
	if st.SaltCheck, ok = p.str(); !ok {
		return nil, false
	}
	if !p.lit(`,"updated":`) {
		return nil, false
	}
	if st.Updated, ok = p.str(); !ok {
		return nil, false
	}
	if !p.lit(`,"entries":[`) {
		return nil, false
	}
	st.Entries = make([]Entry, 0, strings.Count(p.s[p.i:], "\n{\"id\":"))
	for {
		if p.lit("\n]}") {
			break
		}
		if len(st.Entries) > 0 && !p.lit(",") {
			return nil, false
		}
		var e Entry
		if !p.lit("\n{\"id\":") {
			return nil, false
		}
		if e.ID, ok = p.str(); !ok || !p.lit(`,"name":`) {
			return nil, false
		}
		if e.Name, ok = p.str(); !ok || !p.lit(`,"source":`) {
			return nil, false
		}
		if e.Source, ok = p.str(); !ok || !p.lit(`,"len":`) {
			return nil, false
		}
		if e.Len, ok = p.int(); !ok || !p.lit(`,"tail":`) {
			return nil, false
		}
		if e.Tail, ok = p.str(); !ok || !p.lit(`,"fp":`) {
			return nil, false
		}
		if e.FP, ok = p.str(); !ok || !p.lit(`,"vfp":`) {
			return nil, false
		}
		if e.VFP, ok = p.str(); !ok || !p.lit(`,"variant":`) {
			return nil, false
		}
		if e.Variant, ok = p.str(); !ok || !p.lit(`,"suffix_hash":`) {
			return nil, false
		}
		if e.SuffixHash, ok = p.str(); !ok || !p.lit(`,"shape":`) {
			return nil, false
		}
		if e.Shape, ok = p.str(); !ok || !p.lit("}") {
			return nil, false
		}
		st.Entries = append(st.Entries, e)
	}
	p.lit("\n") // the writer ends the file with one
	if p.i != len(p.s) {
		return nil, false
	}
	return &st, true
}

type fastParser struct {
	s string
	i int
}

func (p *fastParser) lit(lit string) bool {
	if !strings.HasPrefix(p.s[p.i:], lit) {
		return false
	}
	p.i += len(lit)
	return true
}

// int reads a plain non-negative decimal, which is all the writer produces.
func (p *fastParser) int() (int, bool) {
	start, n := p.i, 0
	for p.i < len(p.s) && p.s[p.i] >= '0' && p.s[p.i] <= '9' {
		if n > 1<<40 {
			return 0, false
		}
		n = n*10 + int(p.s[p.i]-'0')
		p.i++
	}
	return n, p.i > start && (p.i-start == 1 || p.s[start] != '0')
}

// str reads a JSON string. Without a backslash it is a substring of the file text; with
// one, encoding/json unescapes it, so escapes mean exactly what they mean there. Raw
// control characters and anything else json would reject end the fast path.
func (p *fastParser) str() (string, bool) {
	if p.i >= len(p.s) || p.s[p.i] != '"' {
		return "", false
	}
	start := p.i + 1
	escaped := false
	for j := start; j < len(p.s); j++ {
		switch c := p.s[j]; {
		case c == '"':
			p.i = j + 1
			if !escaped {
				// json would turn invalid UTF-8 into U+FFFD; a file that has any is not ours.
				return p.s[start:j], utf8.ValidString(p.s[start:j])
			}
			var out string
			if json.Unmarshal([]byte(p.s[start-1:j+1]), &out) != nil {
				return "", false
			}
			return out, true
		case c == '\\':
			escaped = true
			j++
		case c < 0x20:
			return "", false
		}
	}
	return "", false
}
