package known

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"strings"
	"unicode/utf16"
)

// errPlist is deliberately bare: parser errors can quote the offending input, and a
// launchd plist is exactly where a secret sits next to the element that failed.
var errPlist = errors.New("not a readable property list")

// parsePlist reads a launchd plist: EnvironmentVariables is the plan's source, and
// ProgramArguments is checked too because agents pass keys as --token flags as often as
// as environment.
func parsePlist(l *learner, path string, data []byte) {
	tree, err := decodePlist(data)
	if err != nil {
		l.skip(path, "unreadable plist")
		return
	}
	root, _ := tree.(map[string]any)
	if env, ok := root["EnvironmentVariables"].(map[string]any); ok {
		for _, k := range sortedKeys(env) {
			if v, ok := env[k].(string); ok {
				l.ingest(k, v, path, false)
			}
		}
	}
	args, _ := root["ProgramArguments"].([]any)
	for i, a := range args {
		s, ok := a.(string)
		if !ok {
			continue
		}
		// --token=abc, --token abc, NAME=abc and `sh -c "export NAME=abc; ..."`.
		if flag, val, ok := strings.Cut(strings.TrimLeft(s, "-"), "="); ok && strings.HasPrefix(s, "-") {
			l.ingest(flag, val, path, false)
		} else if strings.HasPrefix(s, "-") && i+1 < len(args) {
			if next, ok := args[i+1].(string); ok && !strings.HasPrefix(next, "-") {
				l.ingest(strings.TrimLeft(s, "-"), next, path, false)
			}
		}
		for _, stmt := range tokenizeShell(s) {
			vals, names := shellAssignments(stmt)
			for k, v := range vals {
				if !v.dynamic {
					l.ingest(names[k], v.text, path, false)
				}
			}
		}
	}
}

// decodePlist returns the property list as map[string]any, []any and string; every other
// scalar becomes nil, since learn only wants text.
func decodePlist(data []byte) (any, error) {
	if bytes.HasPrefix(data, []byte("bplist00")) {
		return decodeBinaryPlist(data)
	}
	dec := xml.NewDecoder(bytes.NewReader(data))
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, errPlist
		}
		if se, ok := tok.(xml.StartElement); ok && se.Name.Local == "plist" {
			for {
				tok, err = dec.Token()
				if err != nil {
					return nil, errPlist
				}
				switch t := tok.(type) {
				case xml.StartElement:
					return readPlistValue(dec, t, 0)
				case xml.EndElement:
					return nil, errPlist
				}
			}
		}
	}
}

func readPlistValue(dec *xml.Decoder, start xml.StartElement, depth int) (any, error) {
	if depth > 32 {
		return nil, errPlist
	}
	switch start.Name.Local {
	case "dict":
		m := map[string]any{}
		for {
			tok, err := dec.Token()
			if err != nil {
				return nil, errPlist
			}
			switch t := tok.(type) {
			case xml.StartElement:
				if t.Name.Local != "key" {
					return nil, errPlist
				}
				key, err := plistText(dec)
				if err != nil {
					return nil, err
				}
				vs, err := nextStart(dec)
				if err != nil {
					return nil, err
				}
				v, err := readPlistValue(dec, vs, depth+1)
				if err != nil {
					return nil, err
				}
				m[key] = v
			case xml.EndElement:
				return m, nil
			}
		}
	case "array":
		var arr []any
		for {
			tok, err := dec.Token()
			if err != nil {
				return nil, errPlist
			}
			switch t := tok.(type) {
			case xml.StartElement:
				v, err := readPlistValue(dec, t, depth+1)
				if err != nil {
					return nil, err
				}
				arr = append(arr, v)
			case xml.EndElement:
				return arr, nil
			}
		}
	case "string":
		return plistText(dec)
	default: // integer, real, date, data, true, false
		if _, err := plistText(dec); err != nil {
			return nil, err
		}
		return nil, nil
	}
}

func nextStart(dec *xml.Decoder) (xml.StartElement, error) {
	for {
		tok, err := dec.Token()
		if err != nil {
			return xml.StartElement{}, errPlist
		}
		switch t := tok.(type) {
		case xml.StartElement:
			return t, nil
		case xml.EndElement:
			return xml.StartElement{}, errPlist
		}
	}
}

// plistText reads character data up to the end of the current element.
func plistText(dec *xml.Decoder) (string, error) {
	var sb strings.Builder
	for depth := 0; ; {
		tok, err := dec.Token()
		if err != nil {
			return "", errPlist
		}
		switch t := tok.(type) {
		case xml.CharData:
			sb.Write(t)
		case xml.StartElement:
			depth++
		case xml.EndElement:
			if depth == 0 {
				return sb.String(), nil
			}
			depth--
		}
	}
}

// decodeBinaryPlist reads the bplist00 format: a trailer that locates an offset table of
// objects, each tagged by a marker byte. Only strings, arrays and dictionaries are kept.
func decodeBinaryPlist(b []byte) (any, error) {
	if len(b) < 8+32 {
		return nil, errPlist
	}
	t := b[len(b)-32:]
	offSize, refSize := int(t[6]), int(t[7])
	num := binary.BigEndian.Uint64(t[8:])
	top := binary.BigEndian.Uint64(t[16:])
	tabOff := binary.BigEndian.Uint64(t[24:])
	if offSize < 1 || offSize > 8 || refSize < 1 || refSize > 8 || num == 0 || num > uint64(len(b)) ||
		tabOff >= uint64(len(b)) || top >= num || tabOff+num*uint64(offSize) > uint64(len(b)) {
		return nil, errPlist
	}
	uintAt := func(off uint64, n int) (uint64, bool) {
		if off+uint64(n) > uint64(len(b)) {
			return 0, false
		}
		var v uint64
		for _, c := range b[off : off+uint64(n)] {
			v = v<<8 | uint64(c)
		}
		return v, true
	}
	offsetOf := func(i uint64) (uint64, bool) {
		if i >= num {
			return 0, false
		}
		return uintAt(tabOff+i*uint64(offSize), offSize)
	}
	var obj func(i uint64, depth int) (any, error)
	obj = func(i uint64, depth int) (any, error) {
		off, ok := offsetOf(i)
		if !ok || off >= uint64(len(b)) || depth > 32 {
			return nil, errPlist
		}
		marker := b[off]
		kind, info := marker>>4, uint64(marker&15)
		pos := off + 1
		if kind == 0x4 || kind == 0x5 || kind == 0x6 || kind == 0xA || kind == 0xD {
			if info == 15 { // the length follows as an int object
				if pos >= uint64(len(b)) || b[pos]>>4 != 0x1 {
					return nil, errPlist
				}
				n := 1 << (b[pos] & 15)
				v, ok := uintAt(pos+1, n)
				if !ok {
					return nil, errPlist
				}
				info, pos = v, pos+1+uint64(n)
			}
			if info > uint64(len(b)) { // also keeps the offset arithmetic below from wrapping
				return nil, errPlist
			}
		}
		switch kind {
		case 0x5:
			if pos+info > uint64(len(b)) {
				return nil, errPlist
			}
			return string(b[pos : pos+info]), nil
		case 0x6:
			if pos+2*info > uint64(len(b)) {
				return nil, errPlist
			}
			u := make([]uint16, info)
			for k := range u {
				u[k] = binary.BigEndian.Uint16(b[pos+2*uint64(k):])
			}
			return string(utf16.Decode(u)), nil
		case 0xA:
			if info > num || pos+info*uint64(refSize) > uint64(len(b)) {
				return nil, errPlist
			}
			arr := make([]any, 0, info)
			for k := uint64(0); k < info; k++ {
				ref, _ := uintAt(pos+k*uint64(refSize), refSize)
				v, err := obj(ref, depth+1)
				if err != nil {
					return nil, err
				}
				arr = append(arr, v)
			}
			return arr, nil
		case 0xD:
			if info > num || pos+2*info*uint64(refSize) > uint64(len(b)) {
				return nil, errPlist
			}
			m := make(map[string]any, info)
			for k := uint64(0); k < info; k++ {
				kref, _ := uintAt(pos+k*uint64(refSize), refSize)
				vref, _ := uintAt(pos+(info+k)*uint64(refSize), refSize)
				kv, err := obj(kref, depth+1)
				ks, isStr := kv.(string)
				if err != nil || !isStr {
					return nil, errPlist
				}
				v, err := obj(vref, depth+1)
				if err != nil {
					return nil, err
				}
				m[ks] = v
			}
			return m, nil
		}
		return nil, nil
	}
	return obj(top, 0)
}
