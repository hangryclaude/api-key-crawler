package known

import (
	"bytes"
	"strings"
	"testing"
	"unicode/utf16"

	"keyguard/internal/fp"
)

// utf16Bytes is how a Windows tool or an editor that saves "Unicode" writes text: a BOM, then two
// bytes to a character.
func utf16Bytes(text string, bigEndian bool) []byte {
	out := []byte{0xff, 0xfe}
	if bigEndian {
		out = []byte{0xfe, 0xff}
	}
	for _, u := range utf16.Encode([]rune(text)) {
		if bigEndian {
			out = append(out, byte(u>>8), byte(u))
		} else {
			out = append(out, byte(u), byte(u>>8))
		}
	}
	return out
}

// STEAL P1-16: betterleaks and gitleaks read a UTF-16 file as binary and find nothing in it, so
// the learned-secret matcher is the one thing that can. The bench found its nine UTF-16 plants
// were exactly the ones it missed.
func TestAKeyInAUTF16FileIsFoundInEitherByteOrder(t *testing.T) {
	kr := fp.NewEphemeral()
	rng := newRNG(t)
	raw := "sk-proj-" + randFrom(rng, urlchars, 48)
	m, err := NewMatcher(kr, EntriesFor(kr, "OPENAI_API_KEY", "test", []byte(raw)))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"little endian with a BOM", utf16Bytes("export OPENAI_API_KEY="+raw+"\r\n", false)},
		{"big endian with a BOM", utf16Bytes("export OPENAI_API_KEY="+raw+"\r\n", true)},
		{"inside a longer document", utf16Bytes(strings.Repeat("padding text ", 200)+raw+strings.Repeat(" more", 100), false)},
		{"the value alone, big endian", utf16Bytes(raw, true)},
		{"the value alone, little endian", utf16Bytes(raw, false)},
	} {
		// One finding, whichever byte order the file has: ASCII text in one byte order contains the
		// other order's form one byte along, and that is the same bytes found twice.
		got := m.Match(tc.data)
		if len(got) != 1 || !utf16Label(got[0].Variant) || got[0].FP != kr.FP(raw) || got[0].Len != 2*len(raw) {
			t.Errorf("%s: %+v", tc.name, got)
			continue
		}
		if bytes.Contains(tc.data, []byte(raw)) {
			t.Fatalf("%s: the raw value is in the file, so this proves nothing", tc.name)
		}
	}
	if got := m.Match(utf16Bytes("nothing secret here, "+raw[:len(raw)-1], false)); len(got) != 0 {
		t.Errorf("a value with its last character missing matched: %+v", got)
	}
	// The match covers the bytes as they sit in the file.
	data := utf16Bytes("k="+raw, false)
	want := 2 + 2*len("k=") // after the BOM and the two characters before it
	if got := m.Match(data); len(got) != 1 || got[0].Len != 2*len(raw) || got[0].Offset < want-1 || got[0].Offset > want+1 {
		t.Errorf("offset and length are of the UTF-16 bytes, give or take the byte of the other order: %+v", got)
	}
	// Two copies of the value are two findings, not one.
	if got := m.Match(utf16Bytes(raw+"\r\n"+raw, false)); len(got) != 2 {
		t.Errorf("two copies: %+v", got)
	}
}

func TestOnlyTextHasAUTF16Form(t *testing.T) {
	labels := func(raw []byte) map[string]bool {
		out := map[string]bool{}
		for _, v := range variantsOf(raw) {
			out[v.label] = true
		}
		return out
	}
	text := []byte("sk-proj-" + strings.Repeat("a1B2", 12))
	if l := labels(text); !l["utf16le"] || !l["utf16be"] {
		t.Errorf("a text value lacks its UTF-16 forms: %v", l)
	}
	if l := labels(append([]byte{0xff, 0xfe, 0x80}, text...)); l["utf16le"] || l["utf16be"] {
		t.Errorf("bytes that are not UTF-8 have no UTF-16 form worth finding: %v", l)
	}
	// A value in another script is still text, and its code units are not single bytes.
	if got := utf16Text([]byte("é"+strings.Repeat("x", 12)), false); len(got) != 2*13 || got[0] != 0xe9 || got[1] != 0 {
		t.Errorf("utf16Text(é...) = % x", got)
	}
}
