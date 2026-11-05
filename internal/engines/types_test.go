package engines

import (
	"bufio"
	"bytes"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"testing"
)

func TestNormalizeType(t *testing.T) {
	cases := []struct{ engine, rule, want string }{
		{"betterleaks", "generic-username", Generic},
		{"titus", "kingfisher.intra42.1", "intra42"},
		{"titus", "kingfisher.privkey.2", "private-key"},
		{"titus", "kingfisher.credentials.1", "uri"},
		{"titus", "np.s3.1", "aws"},
		{"titus", "np.auth0.1", "auth0"},
		{"trufflehog", "AzureOpenAI", "azure"},
		// betterleaks and gitleaks ids
		{"betterleaks", "anthropic-api-key", "anthropic"},
		{"betterleaks", "anthropic-admin-api-key", "anthropic"},
		{"betterleaks", "openai-api-key", "openai"},
		{"betterleaks", "github-pat", "github"},
		{"betterleaks", "github-fine-grained-pat", "github"},
		{"betterleaks", "github-oauth", "github"},
		{"betterleaks", "aws-access-token", "aws"},
		{"betterleaks", "stripe-access-token", "stripe"},
		{"betterleaks", "slack-bot-token", "slack"},
		{"betterleaks", "slack-webhook-url", "slack"},
		{"betterleaks", "gcp-api-key", "google"},
		{"betterleaks", "huggingface-access-token", "huggingface"},
		{"betterleaks", "npm-access-token", "npm"},
		{"betterleaks", "sendgrid-api-token", "sendgrid"},
		{"betterleaks", "digitalocean-pat", "digitalocean"},
		{"betterleaks", "dockerhub-personal-access-token", "dockerhub"},
		{"betterleaks", "linear-api-key", "linear"},
		{"betterleaks", "groq-api-key", "groq"},
		{"betterleaks", "xai-api-key", "xai"},
		{"betterleaks", "openrouter-api-key", "openrouter"},
		{"betterleaks", "elevenlabs-api-key", "elevenlabs"},
		{"betterleaks", "replicate-api-token", "replicate"},
		{"betterleaks", "fal-api-key.1", "fal"},
		{"betterleaks", "twilio-api-key", "twilio"},
		{"betterleaks", "mailgun-private-api-token", "mailgun"},
		{"betterleaks", "shopify-access-token", "shopify"},
		{"betterleaks", "shopify-shared-secret", "shopify"},
		{"betterleaks", "pypi-upload-token", "pypi"},
		{"betterleaks", "telegram-bot-api-token", "telegram"},
		{"betterleaks", "azure-ad-client-secret", "azure"},
		{"betterleaks", "hashicorp-tf-api-token", "hashicorp"},
		{"betterleaks", "1password-secret-key", "1password"},
		{"betterleaks", "mongodb-connection-string", "mongodb"},
		{"betterleaks", "polymarket-private-key", "polymarket"},
		{"gitleaks", "gcp-api-key", "google"},
		// things that are not a provider
		{"betterleaks", "generic-api-key", Generic},
		{"betterleaks", "generic-password", Generic},
		{"betterleaks", "curl-auth-header", Generic},
		{"betterleaks", "private-key", "private-key"},
		{"betterleaks", "pkcs12-file", "private-key"},
		{"betterleaks", "jwt", "jwt"},
		{"betterleaks", "jwt-base64", "jwt"},
		// trufflehog detector names
		{"trufflehog", "Github", "github"},
		{"trufflehog", "GitHubApp", "github"},
		{"trufflehog", "GitHubOauth2", "github"},
		{"trufflehog", "AWS", "aws"},
		{"trufflehog", "AWSSessionKey", "aws"},
		{"trufflehog", "GCP", "google"},
		{"trufflehog", "GoogleGeminiAPIKey", "google"},
		{"trufflehog", "OpenAI", "openai"},
		{"trufflehog", "OpenAIAdmin", "openai"},
		{"trufflehog", "Anthropic", "anthropic"},
		{"trufflehog", "Slack", "slack"},
		{"trufflehog", "SlackWebhook", "slack"},
		{"trufflehog", "Stripe", "stripe"},
		{"trufflehog", "StripePaymentIntent", "stripe"},
		{"trufflehog", "DigitalOceanV2", "digitalocean"},
		{"trufflehog", "DigitalOceanSpaces", "digitalocean"},
		{"trufflehog", "NpmToken", "npm"},
		{"trufflehog", "SendGrid", "sendgrid"},
		{"trufflehog", "LinearAPI", "linear"},
		{"trufflehog", "TelegramBotToken", "telegram"},
		{"trufflehog", "HuggingFace", "huggingface"},
		{"trufflehog", "Mailgun", "mailgun"},
		{"trufflehog", "Groq", "groq"},
		{"trufflehog", "ElevenLabs", "elevenlabs"},
		{"trufflehog", "OpenRouter", "openrouter"},
		{"trufflehog", "Replicate", "replicate"},
		{"trufflehog", "XAI", "xai"},
		{"trufflehog", "AzureStorage", "azure"},
		{"trufflehog", "PrivateKey", "private-key"},
		{"trufflehog", "JWT", "jwt"},
		{"trufflehog", "URI", "uri"},
		{"trufflehog", "Postgres", "postgres"},
		{"trufflehog", "MongoDB", "mongodb"},
		{"trufflehog", "Redis", "redis"},
		{"trufflehog", "Generic", Generic},
		{"trufflehog", "CustomRegex", Generic},
		{"trufflehog", "CurrencyCloud", "currencycloud"},
		{"trufflehog", "Twilio", "twilio"},
		{"trufflehog", "Vercel", "vercel"},
		{"trufflehog", "CloudflareApiToken", "cloudflare"},
		{"trufflehog", "Supabase", "supabase"},
		{"trufflehog", "Airtable", "airtable"},
		{"trufflehog", "Notion", "notion"},
		{"trufflehog", "Discord", "discord"},
		{"trufflehog", "Mapbox", "mapbox"},
		{"trufflehog", "Sentry", "sentry"},
		{"trufflehog", "PosthogApp", "posthog"},
		{"trufflehog", "Algolia", "algolia"},
		// titus
		{"titus", "np.github.1", "github"},
		{"titus", "np.github.7", "github"},
		{"titus", "np.aws.1", "aws"},
		{"titus", "np.google.8", "google"},
		{"titus", "np.anthropic.1", "anthropic"},
		{"titus", "np.openai.1", "openai"},
		{"titus", "np.slack.2", "slack"},
		{"titus", "np.stripe.1", "stripe"},
		{"titus", "np.digitalocean.2", "digitalocean"},
		{"titus", "kingfisher.linear.1", "linear"},
		{"titus", "kingfisher.openrouter.1", "openrouter"},
		{"titus", "kingfisher.elevenlabs.1", "elevenlabs"},
		{"titus", "np.pem.1", "private-key"},
		{"titus", "np.generic.2", Generic},
		{"titus", "np.jwt.1", "jwt"},
		// nothing claims these
		{"betterleaks", "totally-unknown-rule-xyz", Generic},
		{"trufflehog", "ZzzNotADetector", Generic},
		{"titus", "np.zzz.1", Generic},
		{"betterleaks", "", Generic},
	}
	for _, c := range cases {
		if got := NormalizeType(c.engine, c.rule); got != c.want {
			t.Errorf("NormalizeType(%s, %q) = %q, want %q", c.engine, c.rule, got, c.want)
		}
	}
}

// The same provider must get the same type from every engine, or a secret seen by two
// engines becomes two kinds of secret.
func TestEnginesAgreeOnType(t *testing.T) {
	agree := map[string][]struct{ engine, rule string }{
		"github":       {{"betterleaks", "github-pat"}, {"trufflehog", "Github"}, {"titus", "np.github.1"}},
		"openai":       {{"betterleaks", "openai-api-key"}, {"trufflehog", "OpenAI"}, {"titus", "np.openai.1"}},
		"slack":        {{"betterleaks", "slack-bot-token"}, {"trufflehog", "Slack"}, {"titus", "np.slack.2"}},
		"digitalocean": {{"betterleaks", "digitalocean-pat"}, {"trufflehog", "DigitalOceanV2"}, {"titus", "np.digitalocean.2"}},
		"linear":       {{"betterleaks", "linear-api-key"}, {"trufflehog", "LinearAPI"}, {"titus", "kingfisher.linear.1"}},
		"google":       {{"betterleaks", "gcp-api-key"}, {"trufflehog", "GCP"}, {"titus", "np.google.8"}},
	}
	for want, rules := range agree {
		for _, r := range rules {
			if got := NormalizeType(r.engine, r.rule); got != want {
				t.Errorf("%s %q = %q, want %q", r.engine, r.rule, got, want)
			}
		}
	}
}

// knownGeneric are installed-engine rules that are not about one provider. Everything else
// must resolve to a provider, so a new engine release that adds a rule shows up here.
func knownGeneric(engine, id string) bool {
	switch k := ruleKey(engine, id); {
	case strings.HasPrefix(k, "generic"), strings.HasPrefix(k, "curl"):
		return true
	case k == "html", k == "http": // titus: password inputs and HTTP auth headers, any site
		return true
	}
	return false
}

// TestTypeTableCoverage walks every rule of the installed betterleaks and titus and reports
// the ones the table does not place.
func TestTypeTableCoverage(t *testing.T) {
	var unplaced []string
	total := 0
	t.Run("betterleaks", func(t *testing.T) {
		bin := needEngine(t, "betterleaks")
		out, err := exec.Command(bin, "config", "show", "--no-banner").Output()
		if err != nil {
			t.Fatal(err)
		}
		re := regexp.MustCompile(`(?m)^id = '([^']+)'`)
		for _, m := range re.FindAllSubmatch(out, -1) {
			total++
			id := string(m[1])
			if NormalizeType("betterleaks", id) == Generic && !knownGeneric("betterleaks", id) {
				unplaced = append(unplaced, "betterleaks "+id)
			}
			if NormalizeType("betterleaks", id) != Generic && knownGeneric("betterleaks", id) {
				t.Errorf("betterleaks %s is generic by design but got type %q", id, NormalizeType("betterleaks", id))
			}
		}
	})
	t.Run("titus", func(t *testing.T) {
		bin := needEngine(t, "titus")
		out, err := exec.Command(bin, "rules", "list").Output()
		if err != nil {
			t.Fatal(err)
		}
		sc := bufio.NewScanner(bytes.NewReader(out))
		for i := 0; sc.Scan(); i++ {
			f := strings.Fields(sc.Text())
			if i < 2 || len(f) == 0 {
				continue
			}
			total++
			if NormalizeType("titus", f[0]) == Generic && !knownGeneric("titus", f[0]) {
				unplaced = append(unplaced, "titus "+f[0])
			}
			if NormalizeType("titus", f[0]) != Generic && knownGeneric("titus", f[0]) {
				t.Errorf("titus %s is generic by design but got type %q", f[0], NormalizeType("titus", f[0]))
			}
		}
	})
	sort.Strings(unplaced)
	t.Logf("%d installed rules checked, %d unplaced", total, len(unplaced))
	if len(unplaced) > 0 {
		t.Errorf("rules the type table does not place (add the provider to providers.txt or the id to knownGeneric):\n  %s", strings.Join(unplaced, "\n  "))
	}
}
