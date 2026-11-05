package report

import "strings"

// Provider says where a leaked key of one type gets revoked. URL is empty when no single
// page exists (a database password, a card number): Hint then carries the whole instruction,
// and the report prints it instead of a button rather than invent a link.
type Provider struct {
	Type    string   // canonical lookup key
	Name    string   // how the report names the provider
	URL     string   // https page that revokes or regenerates the key
	Hint    string   // one short line: what to do there
	Aliases []string // other normalized type names that mean the same thing
}

// providers covers every format in PLAN.md's bench list, plus the providers engines name
// most often. Every URL was fetched with curl on 2026-11-03 and none was a 404; seven
// (Airtable, Algolia, Cloudflare, GitLab, npm, OpenAI, xAI) answered 403, which is their bot
// protection, so those are known to exist but not confirmed. The ones that had moved
// (Anthropic, ElevenLabs, Mapbox, Perplexity, Vercel) point at where they landed.
var providers = []Provider{
	{Type: "anthropic", Name: "Anthropic", URL: "https://platform.claude.com/settings/keys",
		Hint: "Delete the key, then make a new one.", Aliases: []string{"claude"}},
	{Type: "openai", Name: "OpenAI", URL: "https://platform.openai.com/api-keys",
		Hint: "Revoke the key, then make a new one.", Aliases: []string{"chatgpt"}},
	{Type: "github", Name: "GitHub", URL: "https://github.com/settings/tokens",
		Hint:    "Delete the token. Make a new one if you still need it.",
		Aliases: []string{"gh", "ghp", "gho", "ghu", "ghs", "ghr", "github-pat", "github-oauth", "github-app"}},
	{Type: "aws", Name: "AWS", URL: "https://console.aws.amazon.com/iam/home#/security_credentials",
		Hint:    "Make the access key inactive, then delete it.",
		Aliases: []string{"amazon", "amazon-web-services"}},
	{Type: "stripe", Name: "Stripe", URL: "https://dashboard.stripe.com/apikeys",
		Hint: "Roll the key and expire the old one now."},
	{Type: "slack", Name: "Slack", URL: "https://api.slack.com/apps",
		Hint: "Open the app, then regenerate the token or webhook.", Aliases: []string{"slackwebhook"}},
	{Type: "discord", Name: "Discord", URL: "https://discord.com/developers/applications",
		Hint: "Open the app, then Bot, then Reset Token.", Aliases: []string{"discordwebhook"}},
	{Type: "telegram", Name: "Telegram", URL: "https://t.me/BotFather",
		Hint: "Send /revoke to @BotFather.", Aliases: []string{"telegram-bot"}},
	{Type: "google", Name: "Google Cloud", URL: "https://console.cloud.google.com/apis/credentials",
		Hint:    "Delete the API key, then make a new one.",
		Aliases: []string{"gcp-api-key", "gemini"}},
	{Type: "gcp", Name: "Google service account", URL: "https://console.cloud.google.com/iam-admin/serviceaccounts",
		Hint:    "Open the account, then Keys: delete this key, add a new one.",
		Aliases: []string{"gcp-service-account", "google-service-account", "service-account", "gcp-credentials"}},
	{Type: "firebase", Name: "Firebase", URL: "https://console.firebase.google.com/",
		Hint:    "Project settings, Service accounts: make a new key, delete the old.",
		Aliases: []string{"firebase-adminsdk", "firebase-service-account"}},
	{Type: "supabase", Name: "Supabase", URL: "https://supabase.com/dashboard/project/_/settings/api-keys",
		Hint:    "Project settings, API keys: roll the secret key.",
		Aliases: []string{"supabase-service-role", "supabase-anon", "supabase-jwt"}},
	{Type: "vercel", Name: "Vercel", URL: "https://vercel.com/account/settings/tokens",
		Hint: "Delete the token, then make a new one."},
	{Type: "cloudflare", Name: "Cloudflare", URL: "https://dash.cloudflare.com/profile/api-tokens",
		Hint: "Roll the token, or delete it and make a new one."},
	{Type: "fal", Name: "fal", URL: "https://fal.ai/dashboard/keys",
		Hint: "Delete the key, then make a new one.", Aliases: []string{"fal-ai", "falai"}},
	{Type: "replicate", Name: "Replicate", URL: "https://replicate.com/account/api-tokens",
		Hint: "Delete the token, then make a new one."},
	{Type: "huggingface", Name: "Hugging Face", URL: "https://huggingface.co/settings/tokens",
		Hint: "Delete the token, then make a new one.", Aliases: []string{"hf", "hugging-face"}},
	{Type: "groq", Name: "Groq", URL: "https://console.groq.com/keys",
		Hint: "Delete the key, then make a new one."},
	{Type: "xai", Name: "xAI", URL: "https://console.x.ai/",
		Hint: "Open API keys, delete the key, make a new one.", Aliases: []string{"x-ai", "grok"}},
	{Type: "openrouter", Name: "OpenRouter", URL: "https://openrouter.ai/settings/keys",
		Hint: "Delete the key, then make a new one."},
	{Type: "elevenlabs", Name: "ElevenLabs", URL: "https://elevenlabs.io/app/developers/api-keys",
		Hint: "Delete the key, then make a new one.", Aliases: []string{"eleven-labs", "11labs"}},
	{Type: "twilio", Name: "Twilio", URL: "https://console.twilio.com/us1/account/keys-credentials/api-keys",
		Hint: "Delete the API key, or roll the auth token."},
	{Type: "sendgrid", Name: "SendGrid", URL: "https://app.sendgrid.com/settings/api_keys",
		Hint: "Delete the key, then make a new one."},
	{Type: "mailgun", Name: "Mailgun", URL: "https://app.mailgun.com/settings/api_security",
		Hint: "Regenerate the API key, or delete the sending key."},
	{Type: "shopify", Name: "Shopify", URL: "https://admin.shopify.com/",
		Hint: "Open the app's API credentials and rotate the token.", Aliases: []string{"shpat"}},
	{Type: "npm", Name: "npm", URL: "https://www.npmjs.com/settings/~/tokens",
		Hint: "Delete the token, then make a new one.", Aliases: []string{"npm-token", "npm-access-token"}},
	{Type: "pypi", Name: "PyPI", URL: "https://pypi.org/manage/account/token/",
		Hint: "Remove the token, then make a new one.", Aliases: []string{"pypi-token", "pypi-upload-token"}},
	{Type: "dockerhub", Name: "Docker Hub", URL: "https://hub.docker.com/settings/security",
		Hint: "Delete the access token, then make a new one.", Aliases: []string{"docker", "docker-hub"}},
	{Type: "digitalocean", Name: "DigitalOcean", URL: "https://cloud.digitalocean.com/account/api/tokens",
		Hint: "Delete the token, then make a new one.", Aliases: []string{"digital-ocean"}},
	{Type: "linear", Name: "Linear", URL: "https://linear.app/settings/account/security",
		Hint: "Revoke the API key, then make a new one."},
	{Type: "notion", Name: "Notion", URL: "https://www.notion.so/profile/integrations",
		Hint: "Open the integration, then refresh its secret."},
	{Type: "airtable", Name: "Airtable", URL: "https://airtable.com/create/tokens",
		Hint: "Delete the token, then make a new one."},
	{Type: "zoom", Name: "Zoom", URL: "https://marketplace.zoom.us/user/build",
		Hint: "Open the app, then regenerate its secret."},
	{Type: "calcom", Name: "Cal.com", URL: "https://app.cal.com/settings/developer/api-keys",
		Hint: "Delete the key, then make a new one.", Aliases: []string{"cal-com"}},
	{Type: "zerobounce", Name: "ZeroBounce", URL: "https://www.zerobounce.net/members/apikey/",
		Hint: "Generate a new API key."},
	{Type: "postgres", Name: "Postgres", URL: "https://www.postgresql.org/docs/current/sql-alterrole.html",
		Hint:    "Change the role password, then update every app that uses it.",
		Aliases: []string{"postgresql", "pg"}},
	{Type: "mongodb", Name: "MongoDB", URL: "https://cloud.mongodb.com/",
		Hint:    "Atlas, Database Access: set a new password for the user.",
		Aliases: []string{"mongo", "mongodb-atlas"}},
	{Type: "redis", Name: "Redis", URL: "https://cloud.redis.io/",
		Hint: "Set a new password, then update every app that uses it.", Aliases: []string{"rediss"}},
	{Type: "private-key", Name: "Private key", URL: "https://github.com/settings/keys",
		Hint: "Make a new key pair. Remove the old public key everywhere it was added.",
		Aliases: []string{"rsa-private-key", "ec-private-key", "dsa-private-key", "openssh-private-key",
			"ssh-private-key", "pgp-private-key", "pem", "ssh-key", "rsa", "openssh", "ssh"}},

	// Not in the bench list, but engines name them often.
	{Type: "gitlab", Name: "GitLab", URL: "https://gitlab.com/-/user_settings/personal_access_tokens",
		Hint: "Revoke the token, then make a new one.", Aliases: []string{"glpat"}},
	{Type: "sentry", Name: "Sentry", URL: "https://sentry.io/settings/account/api/auth-tokens/",
		Hint: "Revoke the token, then make a new one."},
	{Type: "mapbox", Name: "Mapbox", URL: "https://console.mapbox.com/account/access-tokens/",
		Hint: "Delete the token, then make a new one."},
	{Type: "algolia", Name: "Algolia", URL: "https://dashboard.algolia.com/account/api-keys",
		Hint: "Delete the key, then make a new one."},
	{Type: "tavily", Name: "Tavily", URL: "https://app.tavily.com/home",
		Hint: "Delete the key, then make a new one."},
	{Type: "perplexity", Name: "Perplexity", URL: "https://console.perplexity.ai/",
		Hint: "Open API keys, delete the key, make a new one.", Aliases: []string{"pplx"}},
	{Type: "deepseek", Name: "DeepSeek", URL: "https://platform.deepseek.com/api_keys",
		Hint: "Delete the key, then make a new one."},
	{Type: "mistral", Name: "Mistral", URL: "https://console.mistral.ai/api-keys/",
		Hint: "Delete the key, then make a new one."},
	{Type: "cohere", Name: "Cohere", URL: "https://dashboard.cohere.com/api-keys",
		Hint: "Delete the key, then make a new one."},
	{Type: "together", Name: "Together AI", URL: "https://api.together.ai/settings/api-keys",
		Hint: "Delete the key, then make a new one.", Aliases: []string{"together-ai"}},
	{Type: "resend", Name: "Resend", URL: "https://resend.com/api-keys",
		Hint: "Delete the key, then make a new one."},
	{Type: "netlify", Name: "Netlify", URL: "https://app.netlify.com/user/applications",
		Hint: "Revoke the token, then make a new one."},
	{Type: "heroku", Name: "Heroku", URL: "https://dashboard.heroku.com/account",
		Hint: "Account settings, API Key: regenerate."},

	// No vendor page exists for these. The hint is the instruction.
	{Type: "generic", Name: "Unknown service",
		Hint: "Find which service issued it (see the file). Rotate it there.",
		Aliases: []string{"generic-api-key", "generic-password", "generic-secret", "generic-token",
			"api-key", "apikey", "password", "secret", "token", "credentials", "high-entropy"}},
	{Type: "card", Name: "Payment card",
		Hint:    "Call the card issuer. Cancel and reissue the card.",
		Aliases: []string{"card-number", "credit-card", "payment-card"}},
}

var providerIndex = func() map[string]int {
	m := make(map[string]int, len(providers)*3)
	for i, p := range providers {
		m[p.Type] = i
		for _, a := range p.Aliases {
			m[a] = i
		}
	}
	return m
}()

// Providers returns a copy of the type→rotate table, for tests and docs.
func Providers() []Provider { return append([]Provider(nil), providers...) }

// Rotation finds where a key of this type is rotated. Engines name types differently
// ("openai", "openai-api-key", "OpenAI"), so lookup lowercases, folds punctuation to dashes,
// then drops trailing dash-parts until something matches: "aws-secret-access-key" finds "aws".
func Rotation(typ string) (Provider, bool) {
	k := normType(typ)
	for k != "" {
		if i, ok := providerIndex[k]; ok {
			return providers[i], true
		}
		j := strings.LastIndexByte(k, '-')
		if j < 0 {
			break
		}
		k = k[:j]
	}
	return Provider{}, false
}

// RotateURL is the rotate page for a type, or "" when there is none. Notification bodies
// use it so the link is one tap away.
func RotateURL(typ string) string {
	p, _ := Rotation(typ)
	return p.URL
}

func normType(t string) string {
	var b strings.Builder
	dash := true // swallows leading dashes
	for _, r := range strings.ToLower(strings.TrimSpace(t)) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
			dash = false
		} else if !dash {
			b.WriteByte('-')
			dash = true
		}
	}
	return strings.TrimRight(b.String(), "-")
}
