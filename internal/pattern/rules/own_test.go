package rules_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"math"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"keyguard/internal/pattern/rules"
	"keyguard/internal/pattern/rules/fidelity"
	"keyguard/internal/testkit"
)

// The 12 rules of our own have no upstream examples, so this is their fidelity check: for each one
// a value of its format and a near miss, built at run time (invariant 2: no key-shaped literal in
// the source), go through the table and through the real betterleaks with rules/keyguard.toml. The two
// must agree with each other and with what the rule is for.

type fakes struct{ r *rand.Rand }

const (
	hexSet   = "0123456789abcdef"
	alnumSet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	urlSet   = alnumSet + "_-"
	b32Set   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	digits   = "0123456789"
)

func (f fakes) str(set string, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = set[f.r.IntN(len(set))]
	}
	return string(b)
}

func entropy(s string) float64 {
	var n [256]float64
	for i := 0; i < len(s); i++ {
		n[s[i]]++
	}
	h := 0.0
	for _, c := range n {
		if c > 0 {
			p := c / float64(len(s))
			h -= p * math.Log2(p)
		}
	}
	return h
}

// above draws until the gated part of a value clears the rule's entropy floor by a margin.
func (f fakes) above(floor float64, gen func() (value, gated string)) string {
	for i := 0; i < 20000; i++ {
		if v, g := gen(); entropy(g) > floor+0.3 {
			return v
		}
	}
	panic("a value cannot reach the entropy floor")
}

func (f fakes) uuid() string {
	return f.str(hexSet, 8) + "-" + f.str(hexSet, 4) + "-" + f.str(hexSet, 4) + "-" + f.str(hexSet, 4) + "-" + f.str(hexSet, 12)
}

func TestOwnRulesAgreeWithBetterleaksOnRunTimeFakes(t *testing.T) {
	bl := testkit.EnginePath(t, "betterleaks")
	f := fakes{rand.New(rand.NewPCG(31, 41))}
	same := func(s string) (string, string) { return s, s }
	snowflake := func() string {
		return base64.RawURLEncoding.EncodeToString([]byte(f.str("123456789", 1) + f.str(digits, 17)))
	}
	floorOf := func(id string) float64 {
		for _, r := range rules.All {
			if r.ID == id {
				return r.Filter.Entropy.Min
			}
		}
		t.Fatalf("no rule %s in the table", id)
		return 0
	}
	type fmtCase struct{ rule, positive, nearMiss string }
	cases := []fmtCase{
		{"kg-anthropic-oauth-token",
			"CLAUDE_CODE_OAUTH_TOKEN=" + f.above(floorOf("kg-anthropic-oauth-token"), func() (string, string) { return same("sk-ant-oat01-" + f.str(urlSet, 90)) }) + "\n",
			"CLAUDE_CODE_OAUTH_TOKEN=sk-ant-oat01-" + f.str(urlSet, 40) + "\n"},
		{"kg-discord-bot-token",
			"token = '" + f.above(floorOf("kg-discord-bot-token"), func() (string, string) { return same(snowflake() + "." + f.str(urlSet, 6) + "." + f.str(urlSet, 30)) }) + "'\n",
			"token = 'QQ" + f.str(urlSet, 22) + "." + f.str(urlSet, 6) + "." + f.str(urlSet, 30) + "'\n"},
		{"kg-discord-webhook-url",
			"hook = https://discord.com/api/webhooks/" + f.str(digits, 19) + "/" + f.str(urlSet, 68) + "\n",
			"hook = https://discord.com/api/webhooks/" + f.str(digits, 19) + "/" + f.str(urlSet, 30) + "\n"},
		{"kg-telegram-bot-token",
			f.above(floorOf("kg-telegram-bot-token"), func() (string, string) { return same(f.str(digits, 10) + ":A" + f.str(urlSet, 34)) }) + "\n",
			f.str(digits, 10) + ":A" + f.str(urlSet, 30) + "\n"},
		{"kg-stripe-webhook-secret",
			"secret = '" + f.above(floorOf("kg-stripe-webhook-secret"), func() (string, string) { return same("whsec_" + f.str(alnumSet, 40)) }) + "'\n",
			"secret = 'whsec_" + f.str(alnumSet, 12) + "'\n"},
		{"kg-elevenlabs-key",
			f.above(floorOf("kg-elevenlabs-key"), func() (string, string) { return same("sk_" + f.str(hexSet, 48)) }) + "\n",
			"sk_" + f.str(hexSet, 40) + "\n"},
		{"kg-fal-key",
			"FAL = " + f.uuid() + ":" + f.above(floorOf("kg-fal-key"), func() (string, string) { return same(f.str(hexSet, 32)) }) + "\n",
			"FAL = " + f.uuid() + ":" + f.str(hexSet, 20) + "\n"},
		{"kg-supabase-secret-key",
			"key = " + f.above(floorOf("kg-supabase-secret-key"), func() (string, string) { return same("sb_secret_" + f.str(urlSet, 31)) }) + "\n",
			"key = sb_secret_" + f.str(urlSet, 10) + "\n"},
		{"kg-aws-access-key-id",
			"id = " + f.above(floorOf("kg-aws-access-key-id"), func() (string, string) { return same("AKIA" + f.str(b32Set, 16)) }) + "\n",
			"id = AKIA" + f.str(b32Set, 12) + "\n"},
		{"kg-calcom-api-key",
			"CAL_API_KEY=" + f.above(floorOf("kg-calcom-api-key"), func() (string, string) { return same("cal_live_" + f.str(alnumSet, 32)) }) + "\n",
			"CAL_API_KEY=cal_live_" + f.str(alnumSet, 10) + "\n"},
		{"kg-twilio-auth-token",
			"TWILIO_AUTH_TOKEN=" + f.above(floorOf("kg-twilio-auth-token"), func() (string, string) { return same(f.str(hexSet, 32)) }) + "\n",
			"TWILIO_AUTH_TOKEN=" + f.str(hexSet, 30) + "\n"},
		{"kg-zerobounce-api-key",
			"ZEROBOUNCE_API_KEY=" + f.above(floorOf("kg-zerobounce-api-key"), func() (string, string) { return same(f.str(hexSet, 32)) }) + "\n",
			"ZEROBOUNCE_API_KEY=" + f.str(hexSet, 30) + "\n"},
	}
	own := map[string]*rules.Rule{}
	for i := range rules.All {
		if rules.All[i].Src.Lineage == "own" {
			own[rules.All[i].ID] = &rules.All[i]
		}
	}
	if len(cases) != len(own) {
		t.Fatalf("%d cases for %d rules of our own: every one needs a value and a near miss", len(cases), len(own))
	}
	toml, err := filepath.Abs(filepath.Join("..", "..", "..", "rules", "keyguard.toml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		r := own[c.rule]
		if r == nil {
			t.Errorf("%s is not a rule of our own in the table", c.rule)
			continue
		}
		dir := t.TempDir()
		for name, body := range map[string]string{"positive.txt": c.positive, "nearmiss.txt": c.nearMiss} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		out, err := exec.Command(bl, "dir", dir, "-c", toml, "--no-banner", "--no-color", "-l", "error",
			"-f", "json", "-r", "-", "--redact", "--exit-code", "0").Output()
		if err != nil {
			t.Fatalf("betterleaks: %v", err)
		}
		var reported []struct{ RuleID, File string }
		if err := json.Unmarshal(out, &reported); err != nil && len(bytes.TrimSpace(out)) > 0 {
			t.Fatal(err)
		}
		theirs := map[string]bool{}
		for _, x := range reported {
			if x.RuleID == c.rule {
				theirs[filepath.Base(x.File)] = true
			}
		}
		for name, body := range map[string]string{"positive.txt": c.positive, "nearmiss.txt": c.nearMiss} {
			ours := len(fidelity.Findings(r, rules.Global, body, name)) > 0
			if ours != theirs[name] {
				t.Errorf("%s on %s: the table says %v, betterleaks says %v", c.rule, name, ours, theirs[name])
			}
			if want := name == "positive.txt"; ours != want {
				t.Errorf("%s on %s: fired %v, want %v", c.rule, name, ours, want)
			}
		}
	}
}
