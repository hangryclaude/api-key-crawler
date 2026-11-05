package known

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
)

const (
	// maxKeyLines bounds how many body lines of one key become entries. A key leaks as a
	// file, so every line is there; a dozen is plenty to recognise it and a 4096-bit RSA
	// key has fifty.
	maxKeyLines = 12
	// A full-width body line: PEM wraps at 64, OpenSSH at 70, some tools at 76.
	minKeyLine = 60
	maxKeyLine = 200
)

// pemBlock is one private key: its type and its base64 body lines, however the text
// around it spelled the line breaks.
type pemBlock struct {
	kind  string
	lines []string
}

func findPrivateKeys(text string) []pemBlock {
	var out []pemBlock
	for from := 0; len(out) < 64; {
		i := strings.Index(text[from:], "-----BEGIN ")
		if i < 0 {
			break
		}
		i += from
		hdr := text[i+len("-----BEGIN "):]
		e := strings.Index(hdr, "-----")
		if e < 0 || e > 64 {
			from = i + len("-----BEGIN ")
			continue
		}
		kind := hdr[:e]
		bodyStart := i + len("-----BEGIN ") + e + 5
		from = bodyStart
		if !strings.Contains(kind, "PRIVATE KEY") {
			continue
		}
		endMark := "-----END " + kind + "-----"
		var body string
		if j := strings.Index(text[bodyStart:], endMark); j >= 0 {
			body = text[bodyStart : bodyStart+j]
			from = bodyStart + j + len(endMark)
		} else {
			body = text[bodyStart:min(len(text), bodyStart+64<<10)]
		}
		out = append(out, pemBlock{kind, bodyLines(body)})
	}
	return out
}

var lineBreaks = strings.NewReplacer(`\r\n`, "\n", `\n`, "\n", `\r`, "\n", "\r", "\n")

// bodyLines splits a PEM body on real line breaks and on the literal \n that JSON, YAML
// and .env files use, and keeps only base64 lines (armor headers like Proc-Type: and
// DEK-Info: have colons).
func bodyLines(body string) []string {
	var out []string
	for _, ln := range strings.Split(lineBreaks.Replace(body), "\n") {
		ln = strings.Trim(ln, " \t\"',\\")
		if ln != "" && isBase64Line(ln) {
			out = append(out, ln)
		}
	}
	return out
}

func isBase64Line(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '+' || c == '/' || c == '=') {
			return false
		}
	}
	return true
}

// privateKeys learns the body lines of every private key in text. Lines, not the whole
// block: the block's last twelve bytes are always -----END ... KEY-----, and a line is
// what survives rewrapping, JSON escaping and partial pastes.
func (l *learner) privateKeys(source, label, text string) {
	if !strings.Contains(text, "PRIVATE KEY") {
		return
	}
	for _, blk := range findPrivateKeys(text) {
		lines := blk.lines
		if len(lines) == 0 {
			continue
		}
		if len(lines) <= 2 {
			// The whole key on one line (a .env value with the newlines stripped): learn
			// that, and the canonical 64-column wrapping a file copy would have.
			joined := strings.Join(lines, "")
			if len(joined) <= 8192 && len(joined) > maxKeyLine {
				l.ingestTrusted(label+" (one line)", joined, source)
			}
			lines = wrap(joined, 64)
		}
		skip := 0
		if blk.kind == "OPENSSH PRIVATE KEY" {
			skip = opensshPublicChars(lines)
		}
		pos, n := 0, 0
		for k, ln := range lines {
			start := pos
			pos += len(ln)
			if len(ln) < minKeyLine || len(ln) > maxKeyLine || start < skip {
				continue
			}
			if n >= maxKeyLines {
				break
			}
			n++
			l.ingestTrusted(fmt.Sprintf("%s line %d", label, k+1), ln, source)
		}
	}
}

func wrap(s string, width int) []string {
	var out []string
	for len(s) > width {
		out = append(out, s[:width])
		s = s[width:]
	}
	return append(out, s)
}

// opensshPublicChars is how many base64 characters of an OpenSSH private key come before
// its private section. Everything earlier is the constant "openssh-key-v1" header and the
// public key, which every ed25519 key on earth shares in part: learning those lines would
// flag other people's keys (test fixtures, vendored code) as the user's.
func opensshPublicChars(lines []string) int {
	joined := strings.Join(lines, "")
	raw, err := base64.StdEncoding.DecodeString(joined)
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(joined, "="))
	}
	const magic = "openssh-key-v1\x00"
	if err != nil || !bytes.HasPrefix(raw, []byte(magic)) {
		return len(lines[0]) // not parseable: at least drop the constant first line
	}
	p := len(magic)
	skipString := func() bool {
		if p+4 > len(raw) {
			return false
		}
		n := int(binary.BigEndian.Uint32(raw[p:]))
		if n < 0 || p+4+n > len(raw) {
			return false
		}
		p += 4 + n
		return true
	}
	for i := 0; i < 3; i++ { // cipher, kdf, kdf options
		if !skipString() {
			return len(lines[0])
		}
	}
	if p+4 > len(raw) {
		return len(lines[0])
	}
	keys := int(binary.BigEndian.Uint32(raw[p:]))
	p += 4
	for i := 0; i < keys && i < 16; i++ { // public key blobs
		if !skipString() {
			return len(lines[0])
		}
	}
	if p+4 > len(raw) {
		return len(lines[0])
	}
	p += 4 // the private section's own length prefix
	return p/3*4 + 4
}
