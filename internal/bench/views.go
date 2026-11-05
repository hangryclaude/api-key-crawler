package bench

import "strings"

// percentDecode undoes %XX escapes the way the engines' decoders do: every well-formed
// escape becomes its byte, nothing else changes ('+' stays a plus).
func percentDecode(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	hexv := func(c byte) int {
		switch {
		case c >= '0' && c <= '9':
			return int(c - '0')
		case c >= 'a' && c <= 'f':
			return int(c-'a') + 10
		case c >= 'A' && c <= 'F':
			return int(c-'A') + 10
		}
		return -1
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if h, l := hexv(s[i+1]), hexv(s[i+2]); h >= 0 && l >= 0 {
				b.WriteByte(byte(h<<4 | l))
				i += 2
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// viewsOf lists the texts engines end up reading for a file: the text itself, with percent
// escapes decoded (betterleaks and gitleaks decode them in place and rescan), and, for a
// base64 file, with each encoded value decoded in place.
func viewsOf(f *fileRec, text string) []string {
	views := []string{text}
	if dec := percentDecode(text); dec != text {
		views = append(views, dec)
	}
	if f.rend.decodes {
		dec := text
		for _, s := range slotsOf(f) {
			for _, p := range s.pairs {
				dec = strings.ReplaceAll(dec, f.rend.esc(p.Value), f.rend.decoded(p.Value))
			}
			dec = strings.ReplaceAll(dec, f.rend.esc(s.value), f.rend.decoded(s.value))
		}
		if dec != text {
			views = append(views, dec)
			if pd := percentDecode(dec); pd != dec {
				views = append(views, pd)
			}
		}
	}
	return views
}

// lineAround returns the trimmed line of text that contains needle, or "" when it is absent
// or the line is too long to be a plausible reported extent.
func lineAround(text, needle string) string {
	if needle == "" {
		return ""
	}
	i := strings.Index(text, needle)
	if i < 0 {
		return ""
	}
	start := strings.LastIndex(text[:i], "\n") + 1
	end := strings.Index(text[i:], "\n")
	if end < 0 {
		end = len(text) - i
	}
	line := strings.TrimSpace(text[start : i+end])
	if len(line) > 400 {
		return ""
	}
	return line
}
