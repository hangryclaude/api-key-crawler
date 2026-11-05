package rules

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"math"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"keyguard/internal/testkit"
)

var (
	idLine    = regexp.MustCompile(`(?m)^id = "([^"]+)"$`)
	countLine = regexp.MustCompile(`OK: (\d+) rules`)
)

// The file the binary embeds is the file in the tree.
func TestTheEmbeddedCopyIsTheFileInTheTree(t *testing.T) {
	disk, err := os.ReadFile("keyguard.toml")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(disk, KeyguardTOML) {
		t.Error("the embedded rules differ from rules/keyguard.toml")
	}
}

// Shape of the file (docs/STEAL.md P0-11): new ids only, none repeated, no top-level prefilter or
// filter, which a child's would replace upstream's and silently stop skipping node_modules/.
func TestTheFileIsSafeToExtend(t *testing.T) {
	text := string(KeyguardTOML)
	ids := idLine.FindAllStringSubmatch(text, -1)
	if n := strings.Count(text, "[[rules]]"); n != len(ids) || n != 12 {
		t.Fatalf("%d [[rules]] blocks and %d ids, want 12 of each", n, len(ids))
	}
	seen := map[string]bool{}
	for _, m := range ids {
		if seen[m[1]] {
			t.Errorf("rule id %s appears twice: betterleaks keeps the later block and the earlier one is dead weight", m[1])
		}
		seen[m[1]] = true
		if !strings.HasPrefix(m[1], "kg-") {
			t.Errorf("rule id %s does not start with kg-, so it may replace a default rule", m[1])
		}
	}
	head, _, _ := strings.Cut(text, "[[rules]]")
	for _, l := range strings.Split(head, "\n") {
		if strings.HasPrefix(l, "prefilter") || strings.HasPrefix(l, "filter") {
			t.Errorf("a top-level %q replaces the default and skips nothing it should: %s", strings.Fields(l)[0], l)
		}
	}
	for _, want := range []string{"[extend]", "useDefault = true", `betterleaksMinVersion = "v1.8.0"`, `title = "keyguard"`} {
		if !strings.Contains(head, want) {
			t.Errorf("the header lacks %q", want)
		}
	}
}

func betterleaks(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(testkit.EnginePath(t, "betterleaks"), args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func ruleCount(t *testing.T, args ...string) int {
	t.Helper()
	out, err := betterleaks(t, append([]string{"config", "check"}, args...)...)
	if err != nil {
		t.Fatalf("betterleaks config check %v: %v: %s", args, err, out)
	}
	m := countLine.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no rule count in %q", out)
	}
	n, _ := strconv.Atoi(m[1])
	return n
}

// betterleaks accepts the file and counts the defaults plus the twelve (475 on 1.9.0). The same
// check belongs in doctor (P0-11).
func TestBetterleaksAcceptsTheFileAndCountsItsRules(t *testing.T) {
	file, err := filepath.Abs("keyguard.toml")
	if err != nil {
		t.Fatal(err)
	}
	defaults, withKG := ruleCount(t), ruleCount(t, "-c", file)
	if withKG != defaults+12 {
		t.Errorf("%d rules with the file, %d without: want twelve more", withKG, defaults)
	}
	out, _ := betterleaks(t, "version")
	if strings.TrimSpace(out) == "1.9.0" && withKG != 475 {
		t.Errorf("betterleaks 1.9.0 counts %d rules, docs/STEAL.md recorded 475", withKG)
	}
	t.Logf("betterleaks %s: %d default rules, %d with rules/keyguard.toml", strings.TrimSpace(out), defaults, withKG)
}

// A made-up value of a format, drawn until it clears the rule's entropy gate by a margin, the way the
// bench draws its fakes. Nothing here is a literal key: every value is assembled at run time.
type maker struct{ r *rand.Rand }

func (m maker) str(set string, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = set[m.r.IntN(len(set))]
	}
	return string(b)
}

const (
	hexSet   = "0123456789abcdef"
	alnumSet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	urlSet   = alnumSet + "_-"
	b32Set   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
)

func entropy(s string) float64 {
	n := map[rune]int{}
	for _, c := range s {
		n[c]++
	}
	h := 0.0
	for _, c := range n {
		p := float64(c) / float64(len(s))
		h -= p * math.Log2(p)
	}
	return h
}

// above draws until the part of the value the rule gates has entropy above floor+0.3.
func (m maker) above(floor float64, gen func() (value, gated string)) string {
	for i := 0; i < 20000; i++ {
		v, g := gen()
		if entropy(g) > floor+0.3 {
			return v
		}
	}
	panic("a value cannot reach the entropy floor")
}

// Every rule is shown to fire on a value of its format, in the place its format sits, and to stay
// quiet on a near miss of it (a length off, a prefix off): the shipped examples of W-09, run against
// the engine that will use them. The bench measures the rules at scale; this pins each one.
func TestEveryRuleFiresOnItsFormatAndNotOnANearMiss(t *testing.T) {
	m := maker{rand.New(rand.NewPCG(11, 22))}
	snowflakeB64 := func() string {
		id := m.str("123456789", 1) + m.str("0123456789", 17)
		return base64.RawURLEncoding.EncodeToString([]byte(id))
	}
	type fmtCase struct {
		rule     string
		positive string // file contents with a value of the format
		nearMiss string // file contents with a value one thing wrong
	}
	uuid := func() string {
		return m.str(hexSet, 8) + "-" + m.str(hexSet, 4) + "-" + m.str(hexSet, 4) + "-" + m.str(hexSet, 4) + "-" + m.str(hexSet, 12)
	}
	cases := []fmtCase{
		{"kg-anthropic-oauth-token",
			"CLAUDE_CODE_OAUTH_TOKEN=" + m.above(3.5, func() (string, string) { s := "sk-ant-oat01-" + m.str(urlSet, 90); return s, s }) + "\n",
			"CLAUDE_CODE_OAUTH_TOKEN=sk-ant-oat01-" + m.str(urlSet, 40) + "\n"},
		{"kg-discord-bot-token",
			"token = '" + m.above(3.8, func() (string, string) {
				s := snowflakeB64() + "." + m.str(urlSet, 6) + "." + m.str(urlSet, 30)
				return s, s
			}) + "'\n",
			"token = 'QQ" + m.str(urlSet, 22) + "." + m.str(urlSet, 6) + "." + m.str(urlSet, 30) + "'\n"},
		{"kg-discord-webhook-url",
			"hook = https://discord.com/api/webhooks/" + m.str("0123456789", 19) + "/" + m.str(urlSet, 68) + "\n",
			"hook = https://discord.com/api/webhooks/" + m.str("0123456789", 19) + "/" + m.str(urlSet, 30) + "\n"},
		{"kg-telegram-bot-token",
			m.above(3.5, func() (string, string) { s := m.str("0123456789", 10) + ":A" + m.str(urlSet, 34); return s, s }) + "\n",
			m.str("0123456789", 10) + ":A" + m.str(urlSet, 30) + "\n"},
		{"kg-stripe-webhook-secret",
			"secret = '" + m.above(3.0, func() (string, string) { s := "whsec_" + m.str(alnumSet, 40); return s, s }) + "'\n",
			"secret = 'whsec_" + m.str(alnumSet, 12) + "'\n"},
		{"kg-elevenlabs-key",
			m.above(3.2, func() (string, string) { s := "sk_" + m.str(hexSet, 48); return s, s }) + "\n",
			"sk_" + m.str(hexSet, 40) + "\n"},
		{"kg-fal-key",
			"FAL = " + uuid() + ":" + m.above(3.2, func() (string, string) { s := m.str(hexSet, 32); return s, s }) + "\n",
			"FAL = " + uuid() + ":" + m.str(hexSet, 20) + "\n"},
		{"kg-supabase-secret-key",
			"key = " + m.above(3.5, func() (string, string) { s := "sb_secret_" + m.str(urlSet, 31); return s, s }) + "\n",
			"key = sb_secret_" + m.str(urlSet, 10) + "\n"},
		{"kg-aws-access-key-id",
			"id = " + m.above(3.0, func() (string, string) { s := "AKIA" + m.str(b32Set, 16); return s, s }) + "\n",
			"id = AKIA" + m.str(b32Set, 12) + "\n"},
		{"kg-calcom-api-key",
			"CAL_API_KEY=" + m.above(3.5, func() (string, string) { s := "cal_live_" + m.str(alnumSet, 32); return s, s }) + "\n",
			"CAL_API_KEY=cal_live_" + m.str(alnumSet, 10) + "\n"},
		{"kg-twilio-auth-token",
			"TWILIO_AUTH_TOKEN=" + m.above(2.8, func() (string, string) { s := m.str(hexSet, 32); return s, s }) + "\n",
			"TWILIO_AUTH_TOKEN=" + m.str(hexSet, 30) + "\n"},
		{"kg-zerobounce-api-key",
			"ZEROBOUNCE_API_KEY=" + m.above(2.8, func() (string, string) { s := m.str(hexSet, 32); return s, s }) + "\n",
			"ZEROBOUNCE_API_KEY=" + m.str(hexSet, 30) + "\n"},
	}
	file, err := filepath.Abs("keyguard.toml")
	if err != nil {
		t.Fatal(err)
	}
	ids := idLine.FindAllStringSubmatch(string(KeyguardTOML), -1)
	if len(cases) != len(ids) {
		t.Fatalf("%d cases for %d rules: every rule needs a positive and a near miss", len(cases), len(ids))
	}
	fired := func(dir, rule string) map[string]bool {
		out, err := exec.Command(testkit.EnginePath(t, "betterleaks"), "dir", dir, "-c", file, "--no-banner", "--no-color", "-l", "error",
			"-f", "json", "-r", "-", "--redact", "--exit-code", "0").Output()
		if err != nil {
			t.Fatalf("betterleaks dir: %v", err)
		}
		var fs []struct{ RuleID, File string }
		if err := json.Unmarshal(out, &fs); err != nil && len(bytes.TrimSpace(out)) > 0 {
			t.Fatal(err)
		}
		got := map[string]bool{}
		for _, f := range fs {
			if f.RuleID == rule {
				got[filepath.Base(f.File)] = true
			}
		}
		return got
	}
	for _, c := range cases {
		dir := t.TempDir()
		for name, body := range map[string]string{"positive.txt": c.positive, "nearmiss.txt": c.nearMiss} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		got := fired(dir, c.rule)
		if !got["positive.txt"] {
			t.Errorf("%s did not fire on a value of its format", c.rule)
		}
		if got["nearmiss.txt"] {
			t.Errorf("%s fired on a near miss of its format", c.rule)
		}
	}
}
