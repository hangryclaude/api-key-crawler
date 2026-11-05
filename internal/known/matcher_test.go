package known

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"math/rand/v2"
	"net/url"
	"os"
	"runtime"
	"sort"
	"testing"
	"time"

	"keyguard/internal/core"
	"keyguard/internal/fp"
)

type planted struct {
	name string
	raw  []byte
	fp   string
	vars []plantedVariant
}

type plantedVariant struct {
	label string
	b     []byte
}

// plantValues registers n random values and returns, for each, the four encodings the
// task names, made with the standard library rather than with variantsOf so the matcher
// is checked against an encoder it does not share code with.
func plantValues(t testing.TB, r *rand.Rand, kr *fp.Keyring, n int) ([]planted, []Entry) {
	t.Helper()
	var ps []planted
	var entries []Entry
	for i := 0; i < n; i++ {
		raw := []byte(fakeSecret(r))
		// Every value gets a character a URL escapes, so each really has four different
		// variants: raw, base64, base64url and urlenc.
		if bytes.Equal([]byte(url.QueryEscape(string(raw))), raw) {
			at := 1 + r.IntN(len(raw)-2)
			raw = append(raw[:at:at], append([]byte{"+/=@!"[r.IntN(5)]}, raw[at:]...)...)
		}
		p := planted{name: fmt.Sprintf("SECRET_%d", i), raw: raw, fp: kr.FPBytes(raw)}
		entries = append(entries, EntriesFor(kr, p.name, "/tmp/test/.env", raw)...)
		std := []byte(base64.StdEncoding.EncodeToString(raw))
		urlb := []byte(base64.RawURLEncoding.EncodeToString(raw))
		p.vars = append(p.vars, plantedVariant{"raw", raw}, plantedVariant{"base64", std}, plantedVariant{"base64url", urlb})
		p.vars = append(p.vars, plantedVariant{"urlenc", []byte(url.QueryEscape(string(raw)))})
		ps = append(ps, p)
	}
	return ps, entries
}

func TestRecall500ValuesFourVariants(t *testing.T) {
	r := newRNG(t)
	kr := fp.NewEphemeral()
	ps, entries := plantValues(t, r, kr, 500)
	m, err := NewMatcher(kr, entries)
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for pi, p := range ps {
		for _, v := range p.vars {
			size := 12 + r.IntN(60_000)
			if size < len(v.b)+1 {
				size = len(v.b) + 1
			}
			content := noise(r, size, r.IntN(2) == 0)
			var off int
			switch r.IntN(8) {
			case 0:
				off = 0
			case 1:
				off = len(content) - len(v.b)
			default:
				off = r.IntN(len(content) - len(v.b) + 1)
			}
			copy(content[off:], v.b)
			ms := m.Match(content)
			if len(ms) != 1 {
				t.Fatalf("value %d variant %s: %d matches, want 1 (content %d bytes, offset %d)", pi, v.label, len(ms), len(content), off)
			}
			g := ms[0]
			// The noise holds '=' characters, so a no-padding encoding followed by one is,
			// truthfully, also the padded encoding: up to two bytes longer.
			if g.FP != p.fp || g.Offset != off || g.Len < len(v.b) || g.Len > len(v.b)+2 || g.EntryID != fp.ID(p.fp) || g.Name != p.name {
				t.Fatalf("value %d variant %s: got offset %d len %d id %s name %s, want offset %d len %d", pi, v.label, g.Offset, g.Len, g.EntryID, g.Name, off, len(v.b))
			}
			// Where the std and url alphabets (or their padded and unpadded forms) spell the
			// same bytes, either label is true.
			b64 := func(l string) bool { return l == "base64" || l == "base64url" }
			if g.Variant != v.label && !(b64(g.Variant) && b64(v.label)) {
				t.Fatalf("value %d: variant %s reported as %s", pi, v.label, g.Variant)
			}
			if g.Shape != fp.Shape(string(p.raw)) {
				t.Fatalf("value %d: shape is not fp.Shape of the raw value", pi)
			}
			checked++
		}
	}
	if checked != 500*4 {
		t.Fatalf("only %d (value, variant) pairs checked", checked)
	}
	t.Logf("recall: %d/%d (value, variant) pairs found at their offsets; %d entries", checked, checked, m.Len())
}

// All of them at once, in one buffer, back to back and overlapping the segment seams the
// scanner splits large inputs on.
func TestRecallManyInOneBuffer(t *testing.T) {
	r := newRNG(t)
	kr := fp.NewEphemeral()
	ps, entries := plantValues(t, r, kr, 300)
	m, _ := NewMatcher(kr, entries)
	wants := map[string]int{} // offset/fp -> planted length

	buf := noise(r, 4<<20, true)
	pos := 0
	for _, p := range ps {
		for _, v := range p.vars {
			pos += 100 + r.IntN(3000)
			if pos+len(v.b) >= len(buf) {
				t.Fatal("buffer too small")
			}
			copy(buf[pos:], v.b)
			wants[fmt.Sprintf("%d/%s", pos, p.fp)] = len(v.b)
			pos += len(v.b)
		}
	}
	got := m.Match(buf)
	if len(got) != len(wants) {
		t.Fatalf("%d matches, want %d", len(got), len(wants))
	}
	for _, g := range got {
		n, ok := wants[fmt.Sprintf("%d/%s", g.Offset, g.FP)]
		if !ok || g.Len < n || g.Len > n+2 { // '=' in the noise can extend a no-padding form
			t.Fatalf("unexpected match at %d len %d", g.Offset, g.Len)
		}
	}
	if !sort.SliceIsSorted(got, func(i, j int) bool { return got[i].Offset < got[j].Offset }) {
		t.Fatal("matches not sorted by offset")
	}
}

// naive finds every form of every value by brute force and applies the same collapse rule
// as tidy, as an oracle for the rolling-hash scanner.
func naive(kr *fp.Keyring, entries []Entry, raws map[string][]byte, data []byte) map[string]bool {
	type hit struct {
		fp       string
		off, len int
		utf16    bool
	}
	var hits []hit
	for _, e := range entries {
		// Reconstruct the variant's bytes from the raw value with the same generator the
		// entry came from.
		for _, v := range variantsOf(raws[e.FP]) {
			if kr.FPBytes(v.b) != e.VFP {
				continue
			}
			for from := 0; ; {
				i := bytes.Index(data[from:], v.b)
				if i < 0 {
					break
				}
				hits = append(hits, hit{e.FP, from + i, len(v.b), v.label == "utf16le" || v.label == "utf16be"})
				from += i + 1
			}
		}
	}
	sort.Slice(hits, func(i, j int) bool {
		a, b := hits[i], hits[j]
		if a.off != b.off {
			return a.off < b.off
		}
		return a.len > b.len
	})
	out := map[string]bool{}
	reach := map[string]int{}
	// ASCII text in one UTF-16 byte order holds the other order's form one byte along, whenever
	// the byte next to it happens to be zero: the same bytes found twice, which is one finding.
	reach16 := map[string]int{}
	for _, h := range hits {
		if r, ok := reach[h.fp]; ok && r >= h.off+h.len {
			continue
		}
		if h.utf16 && h.off < reach16[h.fp] {
			continue
		}
		if h.utf16 {
			reach16[h.fp] = h.off + h.len
		}
		reach[h.fp] = h.off + h.len
		out[fmt.Sprintf("%s/%d/%d", h.fp, h.off, h.len)] = true
	}
	return out
}

func TestScannerAgreesWithBruteForce(t *testing.T) {
	r := newRNG(t)
	kr := fp.NewEphemeral()
	var entries []Entry
	raws := map[string][]byte{}
	var vals [][]byte
	for i := 0; i < 40; i++ {
		raw := []byte(fakeSecret(r))
		entries = append(entries, EntriesFor(kr, "N", "s", raw)...)
		raws[kr.FPBytes(raw)] = raw
		vals = append(vals, raw)
	}
	m, _ := NewMatcher(kr, entries)
	var forms [][]byte
	for _, v := range vals {
		for _, f := range variantsOf(v) {
			forms = append(forms, f.b)
		}
	}
	// Every length class: below the window, the scalar path, the four-stream path with
	// each remainder, and a plant at every offset so each seam is crossed.
	lengths := []int{0, 1, 11, 12, 13, 100, 255, 256, 257, 258, 259, 260, 300, 517, 1000, 1001, 1002, 1003}
	for _, n := range lengths {
		for iter := 0; iter < 6; iter++ {
			data := noise(r, n, iter%2 == 0)
			for k := r.IntN(4); k > 0; k-- {
				f := forms[r.IntN(len(forms))]
				if len(f) <= n {
					copy(data[r.IntN(n-len(f)+1):], f)
				}
			}
			want := naive(kr, entries, raws, data)
			got := map[string]bool{}
			for _, g := range m.Match(data) {
				got[fmt.Sprintf("%s/%d/%d", g.FP, g.Offset, g.Len)] = true
			}
			if len(got) != len(want) {
				t.Fatalf("n=%d: scanner found %d, brute force %d", n, len(got), len(want))
			}
			for k := range want {
				if !got[k] {
					t.Fatalf("n=%d: scanner missed %s", n, k)
				}
			}
		}
	}
	// A plant at every offset of a buffer that exercises all four seams.
	v := vals[0]
	for _, n := range []int{300, 519, 1030} {
		for off := 0; off+len(v) <= n; off++ {
			data := noise(r, n, true)
			copy(data[off:], v)
			ms := m.Match(data)
			ok := false
			for _, g := range ms {
				if g.Offset == off && g.Len == len(v) {
					ok = true
				}
			}
			if !ok {
				t.Fatalf("n=%d: plant at offset %d not found", n, off)
			}
		}
	}
}

// FuzzMatch holds the scanner to the brute-force oracle on arbitrary bytes: it must find
// exactly what bytes.Index finds, with no panic, at any length and alignment.
func FuzzMatch(f *testing.F) {
	r := newRNG(f)
	kr := fp.NewEphemeral()
	var entries []Entry
	raws := map[string][]byte{}
	var forms [][]byte
	for _, v := range []string{fakeSecret(r), fakeSecret(r), randFrom(r, alnum, 12), "sk-proj-" + randFrom(r, alnum, 40), randFrom(r, punct, 30)} {
		entries = append(entries, EntriesFor(kr, "N", "s", []byte(v))...)
		raws[kr.FP(v)] = []byte(v)
		for _, form := range variantsOf([]byte(v)) {
			forms = append(forms, form.b)
		}
	}
	m, _ := NewMatcher(kr, entries)
	for i, form := range forms {
		f.Add(append(noise(r, i%7+1, true), form...))
		f.Add(append(append(noise(r, 300, false), form...), noise(r, 300, true)...))
	}
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		want := naive(kr, entries, raws, data)
		got := map[string]bool{}
		for _, g := range m.Match(data) {
			if g.Offset < 0 || g.Len < window || g.Offset+g.Len > len(data) {
				t.Fatalf("match outside the data: offset %d len %d of %d", g.Offset, g.Len, len(data))
			}
			got[fmt.Sprintf("%s/%d/%d", g.FP, g.Offset, g.Len)] = true
		}
		if len(got) != len(want) {
			t.Fatalf("scanner found %d matches, brute force %d", len(got), len(want))
		}
		for k := range want {
			if !got[k] {
				t.Fatalf("scanner missed %s", k)
			}
		}
	})
}

func TestShortInputsAndEmptyMatcher(t *testing.T) {
	kr := fp.NewEphemeral()
	m, err := NewMatcher(kr, nil)
	if err != nil || m.Len() != 0 || m.Match([]byte("anything at all, long enough to scan")) != nil {
		t.Fatal("empty matcher should match nothing")
	}
	raw := []byte("exactly-12ch")
	m, _ = NewMatcher(kr, EntriesFor(kr, "N", "s", raw))
	if got := m.Match(raw); len(got) != 1 || got[0].Offset != 0 || got[0].Len != 12 {
		t.Fatalf("a value exactly one window long: %+v", got)
	}
	for n := 0; n < 12; n++ {
		if got := m.Match(raw[:n]); got != nil {
			t.Fatalf("%d bytes matched", n)
		}
	}
	if got := m.Match(raw[:11]); got != nil {
		t.Fatal("truncated value matched")
	}
	if len(EntriesFor(kr, "N", "s", []byte("short-11-ch"))) != 0 {
		t.Fatal("a value under 12 bytes was registered")
	}
}

func TestMatchLimitTruncates(t *testing.T) {
	r := newRNG(t)
	kr := fp.NewEphemeral()
	raw := []byte(fakeSecret(r))
	m, _ := NewMatcher(kr, EntriesFor(kr, "N", "s", raw))
	fifty := bytes.Repeat(append(append([]byte(nil), raw...), '\n'), 50)
	// The first copy sits at offset 0 (the window tested up front); with padding after the
	// copies the scan takes the four-stream path as well as the scalar one.
	for _, pad := range []int{0, 5000} {
		data := append(append([]byte(nil), fifty...), noise(r, pad, true)...)
		for limit := 1; limit <= 60; limit++ {
			ms, trunc := m.MatchLimit(data, limit)
			want := min(limit, 50)
			if len(ms) != want || trunc != (limit < 50) {
				t.Fatalf("pad %d limit %d: %d matches (truncated=%v), want %d (truncated=%v)", pad, limit, len(ms), trunc, want, limit < 50)
			}
			for i, g := range ms { // the earliest matches in the data, in order
				if g.Offset != i*(len(raw)+1) {
					t.Fatalf("limit %d: match %d at offset %d", limit, i, g.Offset)
				}
			}
		}
	}
	if ms, trunc := m.MatchLimit(fifty, 0); len(ms) != 50 || trunc {
		t.Fatalf("limit 0 should mean the default: %d matches, truncated=%v", len(ms), trunc)
	}
	// Several roots each fill their own quota; the merged answer still honours the limit.
	kr2 := fp.NewEphemeral()
	two := &Matcher{}
	for _, k := range []*fp.Keyring{kr, kr2} {
		ri, _ := newRootIndex(k, EntriesFor(k, "N", "s", raw))
		two.roots = append(two.roots, ri)
	}
	if ms, trunc := two.MatchLimit(fifty, 10); len(ms) != 10 || !trunc {
		t.Fatalf("two roots: %d matches, truncated=%v", len(ms), trunc)
	}
}

// The matcher must be usable from many goroutines at once (the sweep scans blobs in
// parallel).
func TestConcurrentMatch(t *testing.T) {
	r := newRNG(t)
	kr := fp.NewEphemeral()
	ps, entries := plantValues(t, r, kr, 50)
	m, _ := NewMatcher(kr, entries)
	done := make(chan error, 8)
	for g := 0; g < 8; g++ {
		seed := r.Uint64()
		go func() {
			rr := rand.New(rand.NewPCG(seed, 1))
			for i := 0; i < 50; i++ {
				p := ps[rr.IntN(len(ps))]
				v := p.vars[rr.IntN(len(p.vars))]
				c := noise(rr, 2000+rr.IntN(5000), true)
				off := rr.IntN(len(c) - len(v.b))
				copy(c[off:], v.b)
				ms := m.Match(c)
				if len(ms) != 1 || ms[0].Offset != off {
					done <- fmt.Errorf("goroutine saw %d matches", len(ms))
					return
				}
			}
			done <- nil
		}()
	}
	for g := 0; g < 8; g++ {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
}

func TestNoFalsePositivesOnRandomContentAndWords(t *testing.T) {
	r := newRNG(t)
	kr := fp.NewEphemeral()
	_, entries := plantValues(t, r, kr, 250) // ~1,000+ entries
	m, _ := NewMatcher(kr, entries)
	if m.Len() < 1000 {
		t.Fatalf("only %d entries", m.Len())
	}
	var scanned int64
	var st scanStats
	runtime.GC()
	start := time.Now()
	// 256 MB of mixed uniform-random binary and text-like content.
	for i := 0; i < 8; i++ {
		buf := noise(r, 32<<20, i%2 == 0)
		ms, _, s := m.match(buf, 0)
		if len(ms) != 0 {
			t.Fatalf("chunk %d: %d false positives", i, len(ms))
		}
		st.add(s)
		scanned += int64(len(buf))
	}
	words, err := os.ReadFile("/usr/share/dict/words")
	if err != nil {
		t.Fatal(err)
	}
	for _, view := range [][]byte{
		words,
		bytes.ReplaceAll(words, []byte("\n"), []byte(" ")),
		bytes.ToUpper(words),
		bytes.Join(bytes.Split(words, []byte("\n")), []byte("_")),
	} {
		ms, _, s := m.match(view, 0)
		if len(ms) != 0 {
			t.Fatalf("dictionary: %d false positives", len(ms))
		}
		st.add(s)
		scanned += int64(len(view))
	}
	if scanned < 200<<20 {
		t.Fatalf("scanned only %d MB", scanned>>20)
	}
	t.Logf("scanned %d MB in %v, 0 matches; bitset passes %d, exact-map hits %d, HMAC checks %d",
		scanned>>20, time.Since(start).Round(time.Millisecond), st.bitHits, st.mapHits, st.checks)
}

// Content that contains the real last-12-byte window of every value, but not the value:
// every one of these reaches the HMAC check and every one must be rejected.
func TestHMACRejectsEveryNearMiss(t *testing.T) {
	r := newRNG(t)
	kr := fp.NewEphemeral()
	ps, entries := plantValues(t, r, kr, 200)
	m, _ := NewMatcher(kr, entries)
	var content bytes.Buffer
	nearMisses := 0
	for _, p := range ps {
		for _, v := range p.vars {
			suffix := v.b[len(v.b)-window:]
			// different prefix, real suffix (a value exactly one window long is all suffix)
			content.Write(noise(r, 40, true))
			if len(v.b) > window {
				content.Write(noise(r, len(v.b)-window, false))
				content.Write(suffix)
				nearMisses++
			}
			// one byte flipped in the middle of an otherwise intact value
			flipped := append([]byte(nil), v.b...)
			flipped[len(flipped)/2] ^= 0x01
			content.Write([]byte("\n"))
			content.Write(flipped)
			// the value minus its first byte, so the suffix is intact but the length is off
			content.Write([]byte("\n"))
			content.Write(v.b[1:])
			content.Write([]byte("\n"))
			nearMisses += 2
		}
	}
	ms, _, st := m.match(content.Bytes(), 0)
	if len(ms) != 0 {
		for _, g := range ms {
			t.Logf("reported: %s %s offset %d len %d", g.Name, g.Variant, g.Offset, g.Len)
		}
		t.Fatalf("%d near misses were reported as matches", len(ms))
	}
	if st.checks < nearMisses/2 {
		t.Fatalf("only %d HMAC checks for %d near misses: the test is not reaching the confirm step", st.checks, nearMisses)
	}
	t.Logf("%d near misses, %d reached the HMAC check, %d confirmed", nearMisses, st.checks, st.confirms)
}

func TestTidyKeepsDistinctValuesAndDropsContained(t *testing.T) {
	in := []core.KnownMatch{
		{FP: "a", Offset: 10, Len: 20},
		{FP: "a", Offset: 10, Len: 18}, // the stable part of the same encoding
		{FP: "b", Offset: 12, Len: 14}, // a different value nested inside: kept
		{FP: "a", Offset: 100, Len: 20},
		{FP: "c", Offset: 100, Len: 20}, // same bytes under a second root: dropped
	}
	out := tidy(in)
	if len(out) != 3 {
		t.Fatalf("got %d: %+v", len(out), out)
	}
}

// BenchmarkMatch scans 64 MB of mixed content against 1,000 registered forms, no hits: the
// shape of a hook looking at a clean diff or the sweep walking clean blobs.
func BenchmarkMatch(b *testing.B) {
	for _, tc := range []struct {
		name string
		text bool
	}{{"text", true}, {"binary", false}} {
		b.Run("1000entries/"+tc.name, func(b *testing.B) {
			r := newRNG(b)
			kr := fp.NewEphemeral()
			var entries []Entry
			for len(entries) < 1000 {
				entries = append(entries, EntriesFor(kr, "N", "s", []byte(fakeSecret(r)))...)
			}
			entries = entries[:1000]
			m, _ := NewMatcher(kr, entries)
			buf := noise(r, 64<<20, tc.text)
			b.SetBytes(int64(len(buf)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if len(m.Match(buf)) != 0 {
					b.Fatal("false positive")
				}
			}
			b.ReportMetric(float64(len(buf))*float64(b.N)/b.Elapsed().Seconds()/1e6, "MB/s")
		})
	}
}
