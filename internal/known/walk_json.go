package known

import (
	"bytes"
	"encoding/json"
	"io"
)

// liner turns byte offsets into 1-based line numbers. Offsets only ever grow, so one pass
// over the text serves all of them.
type liner struct {
	b    []byte
	off  int
	line int
}

func newLiner(b []byte) *liner { return &liner{b: b, line: 1} }

func (l *liner) at(off int) int {
	off = min(max(off, 0), len(l.b))
	if off < l.off {
		l.off, l.line = 0, 1
	}
	l.line += bytes.Count(l.b[l.off:off], []byte{'\n'})
	l.off = off
	return l.line
}

// walkJSON streams the tokens of a JSON document and holds only the stack of open
// containers: ~/.claude.json is tens of megabytes of chat history around a few kilobytes of
// configuration, and a decoded tree of it would cost several times its size in memory.
func walkJSON(data []byte, w *walker) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	type frame struct {
		obj       bool
		key       string // an object's current key; an array's strings take the key it sits under
		expectKey bool
		elems     []elem
		pushed    bool // whether this container added a segment to path
	}
	var (
		stack []frame
		path  []string
	)
	lines := newLiner(data)
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			if len(stack) > 0 { // the decoder does not mind containers left open
				return io.ErrUnexpectedEOF
			}
			return nil
		}
		if err != nil {
			return err
		}
		line := lines.at(int(dec.InputOffset()))
		n := len(stack)
		switch t := tok.(type) {
		case json.Delim:
			if t == '{' || t == '[' {
				// The segment a container adds to the path: the key it is the value of, or []
				// inside an array. The root adds none.
				key, pushed := "", n > 0
				if pushed {
					top := stack[n-1]
					key = top.key
					if top.obj {
						path = append(path, top.key)
					} else {
						path = append(path, "[]")
					}
				}
				stack = append(stack, frame{obj: t == '{', key: key, expectKey: t == '{', pushed: pushed})
				continue
			}
			top := stack[n-1]
			if !top.obj {
				w.list(path, top.elems)
			}
			if top.pushed {
				path = path[:len(path)-1]
			}
			stack = stack[:n-1]
			if n > 1 && stack[n-2].obj { // the closed container was the value of a key
				stack[n-2].expectKey = true
			}
		case string:
			if n == 0 { // a document that is just a string
				w.value(nil, t, line)
				continue
			}
			f := &stack[n-1]
			switch {
			case f.obj && f.expectKey:
				f.key, f.expectKey = t, false
			case f.obj:
				w.value(with(path, f.key), t, line)
				f.expectKey = true
			default:
				if w.any != nil && !holdsNames(path) {
					w.any(f.key, t)
				}
				if len(f.elems) < maxListElems {
					f.elems = append(f.elems, elem{v: t, line: line, ok: true})
				}
			}
		default: // a number, true, false or null
			if n == 0 {
				continue
			}
			f := &stack[n-1]
			if f.obj {
				f.expectKey = true
			} else if len(f.elems) < maxListElems {
				f.elems = append(f.elems, elem{})
			}
		}
	}
}

// stripJSONC removes // and /* */ comments and trailing commas that sit outside strings, so
// opencode.jsonc and the hand-edited settings files of editors parse as JSON. Line breaks are
// kept, so line numbers stay true.
func stripJSONC(data []byte) []byte {
	return dropTrailingCommas(dropComments(data))
}

// skipString returns the index of the quote that closes the string opening at data[i].
func skipString(data []byte, i int) int {
	j := i + 1
	for j < len(data) && data[j] != '"' {
		if data[j] == '\\' {
			j++
		}
		j++
	}
	return min(j, len(data)-1)
}

func dropComments(data []byte) []byte {
	out := make([]byte, 0, len(data))
	for i := 0; i < len(data); i++ {
		switch c := data[i]; {
		case c == '"':
			j := skipString(data, i)
			out = append(out, data[i:j+1]...)
			i = j
		case c == '/' && i+1 < len(data) && data[i+1] == '/':
			for i < len(data) && data[i] != '\n' {
				i++
			}
			if i < len(data) {
				out = append(out, '\n')
			}
		case c == '/' && i+1 < len(data) && data[i+1] == '*':
			i += 2
			for i+1 < len(data) && !(data[i] == '*' && data[i+1] == '/') {
				if data[i] == '\n' {
					out = append(out, '\n')
				}
				i++
			}
			i++
		default:
			out = append(out, c)
		}
	}
	return out
}

// dropTrailingCommas removes a comma followed only by white space and a closing bracket.
func dropTrailingCommas(data []byte) []byte {
	out := make([]byte, 0, len(data))
	for i := 0; i < len(data); i++ {
		switch c := data[i]; c {
		case '"':
			j := skipString(data, i)
			out = append(out, data[i:j+1]...)
			i = j
		case ',':
			j := i + 1
			for j < len(data) && (data[j] == ' ' || data[j] == '\t' || data[j] == '\n' || data[j] == '\r') {
				j++
			}
			if j < len(data) && (data[j] == '}' || data[j] == ']') {
				continue
			}
			out = append(out, c)
		default:
			out = append(out, c)
		}
	}
	return out
}
