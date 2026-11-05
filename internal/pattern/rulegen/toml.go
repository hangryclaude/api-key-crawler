package main

import (
	"fmt"
	"strconv"
	"strings"
)

// The Go standard library has no TOML reader, and the one file this generator reads as TOML,
// rules/keyguard.toml, uses a small corner of it: tables, and keys whose values are basic or
// literal strings (one line, or '''multi-line literals'''), arrays of such strings on one line,
// integers and booleans. This reads that corner and refuses anything else, so a change to the
// file that leaves the corner fails the generator instead of being misread.

// table is one [[rules]] block, or the keys above the first table.
type table map[string]any

// parseTOML returns the top-level keys and the [[rules]] blocks of src.
func parseTOML(src string) (top table, rules []table, err error) {
	top = table{}
	cur := top
	section := ""
	lines := strings.Split(src, "\n")
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			switch line {
			case "[[rules]]":
				rules = append(rules, table{})
				cur, section = rules[len(rules)-1], "rules"
			case "[extend]":
				cur, section = table{}, "extend" // read nothing from it
			default:
				return nil, nil, fmt.Errorf("line %d: table %s is not one this reader knows", i+1, line)
			}
			continue
		}
		key, rest, ok := strings.Cut(line, "=")
		if !ok {
			return nil, nil, fmt.Errorf("line %d: %q is not key = value", i+1, line)
		}
		key = strings.TrimSpace(key)
		rest = strings.TrimSpace(rest)
		var val any
		switch {
		case strings.HasPrefix(rest, "'''"):
			body := rest[3:]
			if end := strings.Index(body, "'''"); end >= 0 {
				val = body[:end]
				break
			}
			var sb strings.Builder
			sb.WriteString(body)
			closed := false
			for i++; i < len(lines); i++ {
				if end := strings.Index(lines[i], "'''"); end >= 0 {
					sb.WriteString("\n" + lines[i][:end])
					closed = true
					break
				}
				sb.WriteString("\n" + lines[i])
			}
			if !closed {
				return nil, nil, fmt.Errorf("key %s: a ''' string is never closed", key)
			}
			val = strings.TrimPrefix(sb.String(), "\n") // a newline right after the opening ''' is not part of the string
		case strings.HasPrefix(rest, `"""`):
			return nil, nil, fmt.Errorf("key %s: \"\"\" strings are not read", key)
		case strings.HasPrefix(rest, `"`), strings.HasPrefix(rest, `'`):
			s, tail, err := oneString(rest)
			if err != nil || strings.TrimSpace(strings.SplitN(tail, "#", 2)[0]) != "" {
				return nil, nil, fmt.Errorf("key %s: not a single string", key)
			}
			val = s
		case strings.HasPrefix(rest, "["):
			arr, err := stringArray(rest)
			if err != nil {
				return nil, nil, fmt.Errorf("key %s: %w", key, err)
			}
			val = arr
		case rest == "true" || rest == "false":
			val = rest == "true"
		default:
			n, err := strconv.ParseInt(strings.TrimSpace(strings.SplitN(rest, "#", 2)[0]), 10, 64)
			if err != nil {
				return nil, nil, fmt.Errorf("key %s: %q is not a value this reader knows", key, rest)
			}
			val = n
		}
		if _, dup := cur[key]; dup {
			return nil, nil, fmt.Errorf("key %s is set twice in one table", key)
		}
		if section != "extend" {
			cur[key] = val
		}
	}
	return top, rules, nil
}

// oneString reads a basic ("...") or literal ('...') string from the start of s and returns the rest.
func oneString(s string) (val, rest string, err error) {
	q := s[0]
	var sb strings.Builder
	for i := 1; i < len(s); i++ {
		c := s[i]
		switch {
		case c == q:
			return sb.String(), s[i+1:], nil
		case c == '\\' && q == '"':
			i++
			if i >= len(s) {
				return "", "", fmt.Errorf("a string ends in a backslash")
			}
			switch s[i] {
			case '\\', '"':
				sb.WriteByte(s[i])
			case 'n':
				sb.WriteByte('\n')
			case 't':
				sb.WriteByte('\t')
			default:
				return "", "", fmt.Errorf("escape \\%c is not read", s[i])
			}
		default:
			sb.WriteByte(c)
		}
	}
	return "", "", fmt.Errorf("a string is never closed")
}

func stringArray(s string) ([]string, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "[") {
		return nil, fmt.Errorf("not an array")
	}
	s = s[1:]
	var out []string
	for {
		s = strings.TrimLeft(s, " \t")
		switch {
		case strings.HasPrefix(s, "]"):
			if tail := strings.TrimSpace(strings.SplitN(s[1:], "#", 2)[0]); tail != "" {
				return nil, fmt.Errorf("text after the array")
			}
			return out, nil
		case strings.HasPrefix(s, ","):
			s = s[1:]
		case strings.HasPrefix(s, `"`), strings.HasPrefix(s, `'`):
			v, rest, err := oneString(s)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
			s = rest
		default:
			return nil, fmt.Errorf("an array of strings on one line is all this reader knows")
		}
	}
}
