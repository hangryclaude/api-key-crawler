package known

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// slowParse is the reference: what readStore did before the fast path existed.
func slowParse(b []byte) (*Store, bool) {
	var s Store
	if json.Unmarshal(b, &s) != nil {
		return nil, false
	}
	return &s, true
}

// agrees checks the one property the fast path must keep: if it accepts a file, the
// standard library accepts it too and reads exactly the same thing.
func agrees(t testing.TB, b []byte) (fastOK bool) {
	t.Helper()
	fast, ok := parseStoreFast(b)
	if !ok {
		return false
	}
	slow, sok := slowParse(b)
	if !sok {
		t.Fatalf("the fast parser accepted %d bytes that encoding/json rejects", len(b))
	}
	if !reflect.DeepEqual(fast, slow) {
		t.Fatalf("the fast parser and encoding/json read the same %d bytes differently", len(b))
	}
	return true
}

func trickyString(r interface{ IntN(int) int }) string {
	parts := []string{
		"plain", `quote"inside`, `back\slash`, "tab\there", "new\nline", "\x01ctrl\x1f", "<tag>&amp;", "café", "emoji 🔑",
		" sep", "/Users/me/dev/x y/.env", "\xff\xfeinvalid", "NUL\x00byte", `A`, `"`, `\`, "",
	}
	n := 1 + r.IntN(4)
	out := ""
	for i := 0; i < n; i++ {
		out += parts[r.IntN(len(parts))]
	}
	return out
}

func TestFastStoreParserReadsWhatWriteStoreWrites(t *testing.T) {
	r := newRNG(t)
	dir := t.TempDir()
	for i := 0; i < 200; i++ {
		var entries []Entry
		for j := r.IntN(20); j > 0; j-- {
			entries = append(entries, Entry{
				ID: "kg" + randFrom(r, hexchars, 6), Name: trickyString(r), Source: trickyString(r), Len: r.IntN(100000),
				Tail: trickyString(r), FP: randFrom(r, hexchars, 32), VFP: randFrom(r, hexchars, 32),
				Variant: "raw", SuffixHash: randFrom(r, hexchars, 16), Shape: trickyString(r),
			})
		}
		st := &Store{Version: storeVersion, SaltCheck: randFrom(r, hexchars, 32), Updated: now(), Entries: entries}
		if err := writeStore(dir, st); err != nil {
			t.Fatal(err)
		}
		b, _ := os.ReadFile(filepath.Join(dir, storeFile))
		if !agrees(t, b) {
			t.Fatalf("store %d: the fast parser refused a file writeStore wrote (%d entries)", i, len(entries))
		}
		// And through the real entry point.
		got, err := readStore(dir)
		if err != nil {
			t.Fatal(err)
		}
		want, _ := slowParse(b)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("store %d: readStore differs from encoding/json", i)
		}
	}
}

func TestFastStoreParserNeverDisagreesWithJSON(t *testing.T) {
	r := newRNG(t)
	dir := t.TempDir()
	var entries []Entry
	for j := 0; j < 12; j++ {
		entries = append(entries, Entry{ID: "kgabcdef", Name: trickyString(r), Source: "/x/.env", Len: 40, Tail: "abcd",
			FP: randFrom(r, hexchars, 32), VFP: randFrom(r, hexchars, 32), Variant: "base64", SuffixHash: randFrom(r, hexchars, 16), Shape: "sk-…abcd"})
	}
	writeStore(dir, &Store{Version: storeVersion, SaltCheck: randFrom(r, hexchars, 32), Updated: now(), Entries: entries})
	good, _ := os.ReadFile(filepath.Join(dir, storeFile))
	accepted, rejected := 0, 0
	for i := 0; i < 30000; i++ {
		b := append([]byte(nil), good...)
		switch r.IntN(6) {
		case 0: // truncate
			b = b[:r.IntN(len(b))]
		case 1: // flip a byte
			b[r.IntN(len(b))] ^= byte(1 << r.IntN(8))
		case 2: // insert a byte
			at := r.IntN(len(b))
			b = append(b[:at], append([]byte{byte(r.IntN(256))}, b[at:]...)...)
		case 3: // delete a byte
			at := r.IntN(len(b))
			b = append(b[:at], b[at+1:]...)
		case 4: // duplicate a chunk
			at, n := r.IntN(len(b)), 1+r.IntN(40)
			if at+n < len(b) {
				b = append(b[:at+n], append(append([]byte(nil), b[at:at+n]...), b[at+n:]...)...)
			}
		case 5: // swap two bytes
			x, y := r.IntN(len(b)), r.IntN(len(b))
			b[x], b[y] = b[y], b[x]
		}
		if agrees(t, b) {
			accepted++
		} else {
			rejected++
		}
	}
	if accepted == 0 || rejected == 0 {
		t.Fatalf("mutations accepted %d rejected %d: the test is not exercising both outcomes", accepted, rejected)
	}
	// Layouts that are valid JSON but not ours go to encoding/json and still load.
	for name, doc := range map[string]string{
		"spaces":      `{ "version": 1, "salt_check": "x", "updated": "y", "entries": [ ] }`,
		"reordered":   `{"entries":[],"version":1,"salt_check":"x","updated":"y"}`,
		"extra field": `{"version":1,"salt_check":"x","updated":"y","note":"hi","entries":[]}`,
	} {
		if _, ok := parseStoreFast([]byte(doc)); ok {
			t.Errorf("%s: the fast parser accepted a layout it does not own", name)
		}
		os.WriteFile(filepath.Join(dir, storeFile), []byte(doc), 0o600)
		if st, err := readStore(dir); err != nil || st.Version != 1 {
			t.Errorf("%s: readStore: %v", name, err)
		}
	}
}

func FuzzParseStore(f *testing.F) {
	dir := f.TempDir()
	writeStore(dir, &Store{Version: storeVersion, SaltCheck: "aa", Updated: "t", Entries: []Entry{
		{ID: "kg1", Name: "N\"\\", Source: "s", Len: 12, Tail: "t", FP: "f", VFP: "v", Variant: "raw", SuffixHash: "h", Shape: "x"}}})
	good, _ := os.ReadFile(filepath.Join(dir, storeFile))
	f.Add(good)
	f.Add([]byte(`{"version":1,"salt_check":"","updated":"","entries":[` + "\n]}\n"))
	f.Fuzz(func(t *testing.T, b []byte) { agrees(t, b) })
}
