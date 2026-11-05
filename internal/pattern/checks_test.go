package pattern

import (
	"hash/crc32"
	"slices"
	"strings"
	"testing"
)

// githubToken makes a classic token whose tail is right, or wrong in one character.
func (f *fakes) githubToken(prefix string, valid bool) string {
	payload := f.run(alnum, 30)
	tail := base62(crc32.ChecksumIEEE([]byte(payload)), 6)
	if !valid {
		tail[5] = base62Alphabet[(strings.IndexByte(base62Alphabet, tail[5])+1)%62]
	}
	return prefix + payload + string(tail)
}

func TestGithubChecksum(t *testing.T) {
	f := newFakes(21)
	for _, prefix := range []string{"gh" + "p_", "gh" + "o_", "gh" + "u_", "gh" + "s_", "gh" + "r_", "np" + "m_"} {
		for i := 0; i < 20; i++ {
			if known, ok := githubChecksum([]byte(f.githubToken(prefix, true))); !known || !ok {
				t.Fatalf("a token with the right tail: known %v ok %v", known, ok)
			}
			if known, ok := githubChecksum([]byte(f.githubToken(prefix, false))); !known || ok {
				t.Fatalf("a token with a wrong tail: known %v ok %v", known, ok)
			}
		}
	}
	for _, other := range []string{"", "gh" + "p_short", "xx" + "p_" + f.run(alnum, 36), "gh" + "p_" + f.run(alnum, 35) + "!"} {
		if known, _ := githubChecksum([]byte(other)); known {
			t.Errorf("%d bytes claimed to have a checksum", len(other))
		}
	}
}

// luhnNumber makes a number of n digits that passes the test.
func (f *fakes) luhnNumber(n int) string {
	body := []byte(f.run("0123456789", n-1))
	sum, double := 0, true
	for i := len(body) - 1; i >= 0; i-- {
		d := int(body[i] - '0')
		if double {
			if d *= 2; d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return string(body) + string(rune('0'+(10-sum%10)%10))
}

func TestLuhn(t *testing.T) {
	f := newFakes(22)
	for _, n := range []int{13, 15, 16, 19} {
		for i := 0; i < 50; i++ {
			num := f.luhnNumber(n)
			if !Luhn([]byte(num)) {
				t.Fatalf("a number built to pass fails (%d digits)", n)
			}
			// any single changed digit breaks it
			pos := i % n
			bad := []byte(num)
			bad[pos] = '0' + (bad[pos]-'0'+1+byte(i%8))%10
			if Luhn(bad) {
				t.Fatalf("a number with one digit changed passes (%d digits, position %d)", n, pos)
			}
		}
	}
	if Luhn([]byte("1")) || Luhn([]byte("12a4")) {
		t.Error("degenerate input passes")
	}
}

func TestTestCardNumbersAreRecognised(t *testing.T) {
	for _, n := range []string{strings.Repeat("4242", 4), "4" + strings.Repeat("1", 15), strings.Repeat("5555", 3) + "4444"} {
		if !isTestPAN([]byte(n)) {
			t.Errorf("a published test number (%d digits) is not recognised", len(n))
		}
	}
	if isTestPAN([]byte(newFakes(23).luhnNumber(16))) {
		t.Error("a made-up valid number is taken for a test number")
	}
}

func TestShapeChecks(t *testing.T) {
	f := newFakes(24)
	uuid := f.run(lowerHex, 8) + "-" + f.run(lowerHex, 4) + "-" + f.run(lowerHex, 4) + "-" + f.run(lowerHex, 4) + "-" + f.run(lowerHex, 12)
	if !isUUID([]byte(uuid)) || isUUID([]byte(uuid[:35])) || isUUID([]byte(strings.Replace(uuid, "-", "_", 1))) {
		t.Error("isUUID")
	}
	for _, n := range []int{32, 40, 56, 64, 96, 128} {
		if !isDigestHex([]byte(f.run(lowerHex, n))) {
			t.Errorf("a %d digit hex string is not a digest shape", n)
		}
	}
	if isDigestHex([]byte(f.run(lowerHex, 36))) || isDigestHex([]byte(f.run(alnum, 32))) {
		t.Error("isDigestHex too wide")
	}
	for _, v := range []string{"${DB_PASSWORD}", "{{ secrets.token }}", "<your-token-here>", "$TOKEN", "%s", "%API_KEY%", "prefix-${X}-suffix", "$(cat key)"} {
		if !isTemplated([]byte(v)) {
			t.Errorf("%q is not seen as a template", v)
		}
	}
	if isTemplated([]byte(f.run(alnum, 30))) {
		t.Error("random text is a template")
	}
	for _, v := range []string{"abcdefghij", "ABCDEFGHIJKLMN", "0123456789", "9876543210", "qwertyuiop", "abcabcabcabc", "1212121212", "aaaaaaaa"} {
		if !isSequential([]byte(v)) {
			t.Errorf("%q is not seen as a sequence", v)
		}
	}
	if isSequential([]byte(f.run(alnum, 30))) || isSequential([]byte("abc")) {
		t.Error("isSequential too wide")
	}
}

func TestIDLikeNames(t *testing.T) {
	for _, c := range []struct {
		before string
		want   bool
	}{
		{`  client_id = "`, true},
		{`"requestId": "`, true},
		{`commitHash: `, true},
		{`file.sha256 = '`, true},
		{`const traceUuid = "`, true},
		{`api_key = "`, false},
		{`password: `, false},
		{`token=`, false},
		{`provide = "`, false}, // ends in "ide" and no other word
		{`no assignment here `, false},
	} {
		if got := idLikeName([]byte(c.before)); got != c.want {
			t.Errorf("idLikeName(%q) = %v, want %v", c.before, got, c.want)
		}
	}
}

func TestDigitTest(t *testing.T) {
	f := newFakes(25)
	flagged := 0
	for i := 0; i < 4000; i++ {
		if unlikelyRandom([]byte(f.run(alnum, 40))) {
			flagged++
		}
	}
	if flagged > 12 { // 1 in 1,000 by the bar, so 4 expected; a tolerance for the draw
		t.Errorf("%d of 4000 random keys were flagged", flagged)
	}
	for _, v := range []string{
		strings.Repeat("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUV", 1), // 48 letters, no digit
		strings.Repeat("1234567890", 3) + "aB" + "cD",
		strings.Repeat("a", 24),
	} {
		if !unlikelyRandom([]byte(v)) {
			t.Errorf("%d bytes starting %q: not flagged", len(v), v[:8])
		}
	}
	if unlikelyRandom([]byte("short")) || unlikelyRandom([]byte(strings.Repeat("1", 30))) || unlikelyRandom([]byte("has space in it and is longer than sixteen")) {
		t.Error("flagged what the test does not judge")
	}
}

// The scorer must tell words from random text, on words it was not taught.
func TestWordiness(t *testing.T) {
	f := newFakes(26)
	held := strings.Fields(`parrot lantern harbour mosaic velvet pebble orchard compass thunder whisper marble canyon
		blanket cactus dolphin ember falcon glacier harvest island jigsaw kettle lemon meadow nutmeg olive pepper quartz
		rabbit saddle tulip umbrella violin walnut yogurt zipper anchor bamboo candle donkey eagle fabric garden hammer
		igloo jacket kitten ladder magnet napkin oyster pillow quiver ribbon spider turtle`)
	wordy := func(parts ...string) []byte { return []byte(strings.Join(parts, "")) }
	hit, total := 0, 0
	for i := 0; i < 400; i++ {
		a, b, c := held[f.r.IntN(len(held))], held[f.r.IntN(len(held))], held[f.r.IntN(len(held))]
		for _, v := range [][]byte{
			wordy(a, "_", b), wordy(a, strings.ToUpper(b[:1]), b[1:], strings.ToUpper(c[:1]), c[1:]), wordy(a, "-", b, "-", c),
		} {
			total++
			if Wordy(v) {
				hit++
			}
		}
	}
	t.Logf("words found wordy: %d of %d", hit, total)
	if float64(hit) < 0.88*float64(total) {
		t.Errorf("only %d of %d word runs read as words", hit, total)
	}
	false := 0
	for i := 0; i < 2000; i++ {
		if Wordy([]byte(f.run(alnum, 20+f.r.IntN(30)))) {
			false++
		}
	}
	t.Logf("random strings found wordy: %d of 2000", false)
	if false > 20 {
		t.Errorf("%d of 2000 random strings read as words", false)
	}
	if Wordy([]byte("short")) || Wordy(nil) {
		t.Error("short input is judged")
	}
}

// The tags reach the findings.
func TestFindingsCarryTheirTags(t *testing.T) {
	f := newFakes(27)
	good, bad := f.githubToken("gh"+"p_", true), f.githubToken("gh"+"p_", false)
	tagsOf := func(data string) []string {
		got := Default().ScanBytes("a.txt", []byte(data))
		if len(got) != 1 {
			t.Fatalf("%d findings", len(got))
		}
		return got[0].Tags
	}
	if tags := tagsOf("x = " + good + "\n"); !slices.Contains(tags, TagChecksumOK) {
		t.Errorf("a token with a good checksum: %v", tags)
	}
	if tags := tagsOf("x = " + bad + "\n"); !slices.Contains(tags, TagChecksumBad) {
		t.Errorf("a token with a bad checksum: %v", tags)
	}
	// And a bad checksum does not cost the finding.
	if len(Default().ScanBytes("a.txt", []byte(bad))) != 1 {
		t.Error("a token with a bad checksum was dropped")
	}
}
