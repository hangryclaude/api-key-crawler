package report

import (
	"net/url"
	"strings"
	"testing"
)

// benchTypes are the provider formats PLAN.md's bench list names, written the way an
// engine's type column would plausibly spell them.
var benchTypes = []string{
	"anthropic", "openai", "github", "github-pat", "ghp", "gho", "aws", "aws-access-key-id", "aws-secret-access-key",
	"stripe", "slack", "discord", "telegram", "google", "gcp", "gcp-service-account", "firebase", "supabase",
	"supabase-service-role", "supabase-anon", "vercel", "cloudflare", "fal", "replicate", "huggingface", "groq",
	"xai", "openrouter", "elevenlabs", "twilio", "sendgrid", "mailgun", "shopify", "npm", "pypi", "dockerhub",
	"digitalocean", "linear", "notion", "airtable", "zoom", "cal.com", "calcom", "zerobounce",
	"postgres", "postgres-url", "mongodb", "mongo-url", "redis", "redis-url",
	"rsa-private-key", "ec-private-key", "openssh-private-key", "private-key",
	"generic", "generic-api-key", "api_key", "card", "card-number",
}

func TestEveryBenchProviderHasARotateEntry(t *testing.T) {
	for _, typ := range benchTypes {
		p, ok := Rotation(typ)
		if !ok {
			t.Errorf("no rotate entry for %q", typ)
			continue
		}
		if p.Name == "" || p.Hint == "" {
			t.Errorf("%q: entry lacks a name or hint", typ)
		}
	}
}

func TestRotateTableIsSound(t *testing.T) {
	seen := map[string]string{}
	noURL := 0
	for _, p := range providers {
		if p.Type != normType(p.Type) {
			t.Errorf("canonical type %q is not in normalized form %q", p.Type, normType(p.Type))
		}
		for _, k := range append([]string{p.Type}, p.Aliases...) {
			if k != normType(k) {
				t.Errorf("%s: key %q is not normalized (%q)", p.Type, k, normType(k))
			}
			if other, dup := seen[k]; dup {
				t.Errorf("key %q is claimed by both %s and %s", k, other, p.Type)
			}
			seen[k] = p.Type
		}
		if p.URL == "" {
			noURL++
			if !strings.Contains(p.Hint, ".") {
				t.Errorf("%s has no link, so its hint must be a full instruction", p.Type)
			}
			continue
		}
		u, err := url.Parse(p.URL)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
			t.Errorf("%s: %q is not a plain https URL", p.Type, p.URL)
		}
		if hasSecretLike(p.URL) {
			t.Errorf("%s: %q looks like a key to the page's own guard", p.Type, p.URL)
		}
		if len(p.Hint) > 80 {
			t.Errorf("%s: hint is %d characters; keep it to one short line", p.Type, len(p.Hint))
		}
	}
	// Only the two types with no vendor page: an unknown service and a payment card.
	if noURL != 2 {
		t.Errorf("%d entries without a link, want 2 (generic, card)", noURL)
	}
}

func TestRotationLookup(t *testing.T) {
	for in, want := range map[string]string{
		"OpenAI":                  "openai",
		"openai-api-key":          "openai",
		"aws-secret-access-key":   "aws",
		"github_pat":              "github",
		"cal.com":                 "calcom",
		"Hugging Face":            "huggingface",
		"  Stripe ":               "stripe",
		"slack-bot-token":         "slack",
		"gcp-api-key":             "google",
		"google-api-key":          "google",
		"gcp-service-account":     "gcp",
		"google-service-account":  "gcp",
		"SLACKWEBHOOK":            "slack",
		"postgresql":              "postgres",
		"MongoDB":                 "mongodb",
		"RSA_PRIVATE_KEY":         "private-key",
		"generic-password":        "generic",
		"credit-card":             "card",
		"supabase-service-role-k": "supabase",
	} {
		p, ok := Rotation(in)
		if !ok || p.Type != want {
			t.Errorf("Rotation(%q) = %q (%v), want %q", in, p.Type, ok, want)
		}
	}
	for _, in := range []string{"", "   ", "totally-unknown-vendor", "---", "🙂"} {
		if _, ok := Rotation(in); ok {
			t.Errorf("Rotation(%q) matched something", in)
		}
	}
	if RotateURL("anthropic") != "https://platform.claude.com/settings/keys" || RotateURL("generic") != "" || RotateURL("nope") != "" {
		t.Error("RotateURL")
	}
	if len(Providers()) != len(providers) {
		t.Error("Providers must return the whole table")
	}
}
