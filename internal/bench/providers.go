package bench

import (
	"net/url"
	"strings"

	"keyguard/internal/fp"
)

// Format authorities. "betterleaks/<id>" is a rule in betterleaks 1.9.0's default config
// (`betterleaks config show`), the primary regex engine; rules_betterleaks_gen.go holds a
// verbatim copy that a test compares with the live binary. "trufflehog/<name>" is the detector
// of that name, whose pattern rules.go quotes with its source path. Providers with neither
// follow the provider's own documentation, cited in a comment above the entry.

// discordWhy: betterleaks and gitleaks ship no Discord rule. trufflehog has two detectors, but an
// unverified match must survive its false-positive wordlist first (checked on 3.99.8): a webhook
// URL, which contains "api" and "webhooks", never does, and a bot token is only reported live.
const discordWhy = "betterleaks and gitleaks have no Discord rule; trufflehog drops unverified Discord matches through its " +
	"false-positive wordlist, so they need a live check"

const ghDoc = "github.blog/engineering/platform-security/behind-githubs-new-authentication-token-formats"

// Providers is every secret format the corpus plants as a real leak.
var Providers = []Provider{
	// --- AI and developer APIs ---
	flat("anthropic", "anthropic", "ANTHROPIC_API_KEY", "betterleaks/anthropic-api-key",
		bl("anthropic-api-key"), 4.5, lit("sk-ant-api03-"), rnd(urlsafe, 93), lit("AA")),
	flat("anthropic-admin", "anthropic", "ANTHROPIC_ADMIN_API_KEY", "betterleaks/anthropic-admin-api-key",
		bl("anthropic-admin-api-key"), 4.5, lit("sk-ant-admin01-"), rnd(urlsafe, 93), lit("AA")),
	flat("openai-project", "openai", "OPENAI_API_KEY", "betterleaks/openai-api-key (sk-proj form; T3BlbkFJ is base64 of OpenAI)",
		bl("openai-api-key"), 4.5, lit("sk-proj-"), rnd(urlsafe, 74), lit("T3BlbkFJ"), rnd(urlsafe, 74)),
	flat("openai-legacy", "openai", "OPENAI_API_KEY", "betterleaks/openai-api-key (pre-project sk- form)",
		bl("openai-api-key"), 4.2, lit("sk-"), rnd(alnum, 20), lit("T3BlbkFJ"), rnd(alnum, 20)),
	flat("openai-svcacct", "openai", "OPENAI_API_KEY", "betterleaks/openai-api-key (service-account form)",
		bl("openai-api-key"), 4.5, lit("sk-svcacct-"), rnd(urlsafe, 58), lit("T3BlbkFJ"), rnd(urlsafe, 58)),
	flat("google-aiza", "google", "GOOGLE_API_KEY", "betterleaks/gcp-api-key",
		bl("gcp-api-key"), 4.2, lit("AIza"), rnd(urlsafe, 35)),
	flat("gemini-aq", "google", "GEMINI_API_KEY", "betterleaks/gcp-gemini-api",
		bl("gcp-gemini-api"), 4.2, lit("AQ.Ab8RN6"), rnd(urlsafe, 44)),
	flat("xai", "xai", "XAI_API_KEY", "betterleaks/xai-api-key",
		bl("xai-api-key"), 4.5, lit("xai-"), rnd(alnum, 80)),
	flat("groq", "groq", "GROQ_API_KEY", "betterleaks/groq-api-key",
		bl("groq-api-key"), 4.2, lit("gsk_"), rnd(alnum, 52)),
	flat("openrouter", "openrouter", "OPENROUTER_API_KEY", "betterleaks/openrouter-api-key",
		bl("openrouter-api-key"), 3.7, lit("sk-or-v1-"), rnd(hexLower, 64)),
	flat("replicate", "replicate", "REPLICATE_API_TOKEN", "betterleaks/replicate-api-token",
		bl("replicate-api-token"), 4.0, lit("r8_"), rnd(alnum, 37)),
	flat("huggingface", "huggingface", "HF_TOKEN", "betterleaks/huggingface-access-token",
		bl("huggingface-access-token"), 3.8, lit("hf_"), rnd(letters, 34)),
	// fal: betterleaks 1.9.0 has a rule (fal-api-key.1), contrary to the assumption that fal is
	// unruled. https://docs.fal.ai (authentication) says FAL_KEY is "key_id:key_secret"; the
	// rule's pattern pins that to a UUID and 32 hex characters.
	{
		ID: "fal", Type: "fal", Env: "FAL_KEY",
		Doc:   "betterleaks/fal-api-key.1; docs.fal.ai: FAL_KEY is key_id:key_secret, a UUID and 32 hex",
		Rules: bl("fal-api-key.1"),
		Gen: func(g *Gen) Fake {
			s := g.token(3.6, rnd(hexLower, 8), lit("-"), rnd(hexLower, 4), lit("-"), rnd(hexLower, 4), lit("-"),
				rnd(hexLower, 4), lit("-"), rnd(hexLower, 12), lit(":"), rnd(hexLower, 32))
			id, secret, _ := strings.Cut(s, ":")
			return Fake{Value: s, Raw: s, Alt: []string{id, secret}} // key_id and key_secret are each reportable
		},
	},
	flat("elevenlabs", "elevenlabs", "ELEVENLABS_API_KEY", "betterleaks/elevenlabs-api-key; trufflehog elevenlabs v2 (sk_ + 48 hex)",
		bl("elevenlabs-api-key"), 3.7, lit("sk_"), rnd(hexLower, 48)),
	flat("perplexity", "perplexity", "PERPLEXITY_API_KEY", "betterleaks/perplexity-api-key",
		bl("perplexity-api-key"), 4.3, lit("pplx-"), rnd(alnum, 48)),
	flat("cerebras", "cerebras", "CEREBRAS_API_KEY", "betterleaks/cerebras-api-key",
		bl("cerebras-api-key"), 3.7, lit("csk-"), rnd(lowerNum, 48)),
	flat("together", "togetherai", "TOGETHER_API_KEY", "betterleaks/togetherai-api-key",
		bl("togetherai-api-key"), 4.2, lit("tgp_v1_"), rnd(urlsafe, 43)),
	flat("deepseek", "deepseek", "DEEPSEEK_API_KEY", "betterleaks/deepseek-api-key",
		bl("deepseek-api-key"), 3.6, lit("sk-"), rnd(hexLower, 32)),
	flat("mistral", "mistral", "MISTRAL_API_KEY", "betterleaks/mistral-api-key",
		bl("mistral-api-key"), 4.0, rnd(alnum, 32)),
	flat("cohere", "cohere", "COHERE_API_KEY", "betterleaks/cohere-api-token",
		bl("cohere-api-token"), 4.2, rnd(alnum, 40)),
	flat("pinecone", "pinecone", "PINECONE_API_KEY", "betterleaks/pinecone-api-key.2",
		bl("pinecone-api-key.2"), 4.2, lit("pcsk_"), rnd(alnum, 6), lit("_"), rnd(alnum, 63)),
	flat("langsmith", "langsmith", "LANGSMITH_API_KEY", "betterleaks/langchain-langsmith-personal-access-token",
		bl("langchain-langsmith-personal-access-token"), 4.05, lit("lsv2_pt_"), rnd(hexLower, 32), lit("_"), rnd(hexLower, 10)),
	// tavily: no engine has a rule. Tavily's examples show a tvly- prefix; the dev- infix and the
	// 32-character body are assumptions, because https://docs.tavily.com states no format.
	unruled("tavily", "tavily", "TAVILY_API_KEY", "tvly- prefix per Tavily's examples; the dev- infix and 32-character body are assumed",
		"no installed engine has a Tavily rule; a rules/keyguard.toml entry would close it",
		4.0, lit("tvly-dev-"), rnd(alnum, 32)),
	flat("vercel", "vercel", "VERCEL_TOKEN", "betterleaks/vercel-personal-access-token",
		bl("vercel-personal-access-token"), 4.2, lit("vcp_"), rnd(urlsafe, 56)),
	flat("cloudflare", "cloudflare", "CLOUDFLARE_API_TOKEN", "betterleaks/cloudflare-api-key; trufflehog cloudflareapitoken",
		bl("cloudflare-api-key"), 4.0, rnd(urlsafe, 40)),
	flat("cloudflare-global", "cloudflare", "CLOUDFLARE_API_KEY", "betterleaks/cloudflare-global-api-key",
		bl("cloudflare-global-api-key"), 3.5, rnd(hexLower, 37)),

	// --- code hosts, registries, cloud platforms ---
	{
		ID: "github-classic", Type: "github", Env: "GITHUB_TOKEN", Doc: "betterleaks/github-pat; " + ghDoc + " (CRC32 base62 checksum)",
		Rules: bl("github-pat"),
		Gen: func(g *Gen) Fake {
			s := "ghp_" + withChecksum(g.token(4.0, rnd(alnum, 30)))
			return Fake{Value: s, Raw: s}
		},
		Twins: crcTwins("ghp_"),
	},
	{
		ID: "github-oauth", Type: "github", Env: "GITHUB_OAUTH_TOKEN", Doc: "betterleaks/github-oauth; " + ghDoc,
		Rules: bl("github-oauth"),
		Gen: func(g *Gen) Fake {
			s := "gho_" + withChecksum(g.token(4.0, rnd(alnum, 30)))
			return Fake{Value: s, Raw: s}
		},
		Twins: crcTwins("gho_"),
	},
	{
		ID: "github-app", Type: "github", Env: "GITHUB_APP_TOKEN", Doc: "betterleaks/github-app-token (ghs_ installation token); " + ghDoc,
		Rules: bl("github-app-token"),
		Gen: func(g *Gen) Fake {
			s := "ghs_" + withChecksum(g.token(4.0, rnd(alnum, 30)))
			return Fake{Value: s, Raw: s}
		},
		Twins: crcTwins("ghs_"),
	},
	flat("github-fine-grained", "github", "GH_TOKEN", "betterleaks/github-fine-grained-pat: github_pat_ + 22 + _ + 59",
		bl("github-fine-grained-pat"), 4.5, lit("github_pat_"), rnd(alnum, 22), lit("_"), rnd(alnum, 59)),
	flat("gitlab", "gitlab", "GITLAB_TOKEN", "betterleaks/gitlab-pat",
		bl("gitlab-pat"), 3.6, lit("glpat-"), rnd(urlsafe, 20)),
	{
		ID: "npm", Type: "npm", Env: "NPM_TOKEN", Doc: "betterleaks/npm-access-token; npm adopted GitHub's checksum format",
		Rules: bl("npm-access-token"),
		Gen: func(g *Gen) Fake {
			s := "npm_" + withChecksum(g.token(4.0, rnd(alnum, 30)))
			return Fake{Value: s, Raw: s}
		},
		Twins: crcTwins("npm_"),
	},
	flat("pypi", "pypi", "PYPI_API_TOKEN", "betterleaks/pypi-upload-token (macaroon, prefix is base64 of the pypi.org location)",
		bl("pypi-upload-token"), 4.5, lit("pypi-AgEIcHlwaS5vcmc"), rnd(urlsafe, 150)),
	flat("dockerhub", "dockerhub", "DOCKERHUB_TOKEN", "betterleaks/dockerhub-personal-access-token",
		bl("dockerhub-personal-access-token"), 4.0, lit("dckr_pat_"), rnd(urlsafe, 27)),
	flat("digitalocean", "digitalocean", "DIGITALOCEAN_ACCESS_TOKEN", "betterleaks/digitalocean-pat",
		bl("digitalocean-pat"), 3.7, lit("dop_v1_"), rnd(hexLower, 64)),
	flat("render", "render", "RENDER_API_KEY", "betterleaks/render-api-key",
		bl("render-api-key"), 4.0, lit("rnd_"), rnd(alnum, 28)),
	flat("neon", "neon", "NEON_API_KEY", "betterleaks/neon-api-key",
		bl("neon-api-key"), 3.7, lit("napi_"), rnd(lowerNum, 64)),
	{
		ID: "planetscale", Type: "planetscale", Env: "PLANETSCALE_SERVICE_TOKEN",
		Doc:   "betterleaks/planetscale-api-token, a composite rule: it reports only with a planetscale-id beside it, and the CLI's own variables are the pair TOKEN_ID + TOKEN",
		Rules: bl("planetscale-api-token"),
		Gen: func(g *Gen) Fake {
			s := g.token(4.2, lit("pscale_tkn_"), rnd(urlsafe, 43))
			return Fake{Value: s, Raw: s, Pairs: []Pair{{"PLANETSCALE_SERVICE_TOKEN_ID", g.token(3.1, rnd(lowerNum, 12))}}}
		},
	},
	{
		ID: "planetscale-lone", Type: "planetscale", Env: "PLANETSCALE_SERVICE_TOKEN",
		Doc:   "the same token with its id in another file: betterleaks drops it, which is the composite-rule blind spot",
		Rules: bl("planetscale-api-token"),
		Gen: func(g *Gen) Fake {
			s := g.token(4.2, lit("pscale_tkn_"), rnd(urlsafe, 43))
			return Fake{Value: s, Raw: s}
		},
	},
	flat("heroku", "heroku", "HEROKU_API_KEY", "betterleaks/heroku-api-key-v2",
		bl("heroku-api-key-v2"), 4.5, lit("HRKU-AA"), rnd(urlsafe, 58)),
	flat("netlify", "netlify", "NETLIFY_AUTH_TOKEN", "betterleaks/netlify-access-token",
		bl("netlify-access-token"), 3.8, lit("nfp_"), rnd(lowerNum, 36)),
	flat("supabase-mgmt", "supabase", "SUPABASE_ACCESS_TOKEN", "betterleaks/supabase-management-token (needs two digits)",
		bl("supabase-management-token"), 3.6, lit("sbp_"), rnd(hexLower, 40)),
	{
		ID: "supabase-secret", Type: "supabase", Env: "SUPABASE_SECRET_KEY",
		Doc:   "betterleaks/supabase-project-api-key, a composite rule: it reports only with a supabase-project-url in the file",
		Rules: bl("supabase-project-api-key"),
		Gen: func(g *Gen) Fake {
			s := g.token(4.2, lit("sb_secret_"), rnd(urlsafe, 31))
			return Fake{Value: s, Raw: s, Pairs: []Pair{{"SUPABASE_URL", "https://" + g.token(3.2, rnd(lower, 20)) + ".supabase.co"}}}
		},
	},
	{
		ID: "supabase-secret-lone", Type: "supabase", Env: "SUPABASE_SECRET_KEY",
		Doc:   "the same key without the project url beside it: betterleaks drops it (composite-rule blind spot)",
		Rules: bl("supabase-project-api-key"),
		Gen: func(g *Gen) Fake {
			s := g.token(4.2, lit("sb_secret_"), rnd(urlsafe, 31))
			return Fake{Value: s, Raw: s}
		},
	},
	{
		ID: "supabase-service-role", Type: "supabase", Env: "SUPABASE_SERVICE_ROLE_KEY",
		Doc:   "betterleaks/jwt; supabase project keys are HS256 JWTs with claims iss, ref, role, iat, exp",
		Rules: bl("jwt"),
		Gen: func(g *Gen) Fake {
			s := supabaseJWT(g, "service_role")
			return Fake{Value: s, Raw: s}
		},
	},
	flat("sentry", "sentry", "SENTRY_AUTH_TOKEN", "betterleaks/sentry-user-token",
		bl("sentry-user-token"), 3.7, lit("sntryu_"), rnd(hexLower, 64)),
	flat("posthog", "posthog", "POSTHOG_PERSONAL_API_KEY", "betterleaks/posthog-personal-api-key",
		bl("posthog-personal-api-key"), 4.2, lit("phx_"), rnd(urlsafe, 43)),
	flat("datadog", "datadog", "DATADOG_API_KEY", "betterleaks/datadog-api-key",
		bl("datadog-api-key"), 3.6, rnd(hexLower, 32)),

	// --- messaging and email ---
	flat("slack-bot", "slack", "SLACK_BOT_TOKEN", "betterleaks/slack-bot-token",
		bl("slack-bot-token"), 3.4, lit("xoxb-"), rnd(digits, 12), lit("-"), rnd(digits, 13), lit("-"), rnd(alnum, 24)),
	flat("slack-user", "slack", "SLACK_USER_TOKEN", "betterleaks/slack-user-token",
		bl("slack-user-token"), 3.4, lit("xoxp-"), rnd(digits, 12), lit("-"), rnd(digits, 12), lit("-"), rnd(digits, 13), lit("-"), rnd(hexLower, 32)),
	flat("slack-app", "slack", "SLACK_APP_TOKEN", "betterleaks/slack-app-token",
		bl("slack-app-token"), 3.4, lit("xapp-1-A"), rnd(upperNum, 10), lit("-"), rnd(digits, 13), lit("-"), rnd(hexLower, 64)),
	flat("slack-webhook", "slack", "SLACK_WEBHOOK_URL", "betterleaks/slack-webhook-url",
		bl("slack-webhook-url"), 0, lit("https://hooks.slack.com/services/T"), rnd(upperNum, 10), lit("/B"), rnd(upperNum, 10), lit("/"), rnd(alnum, 24)),
	// discord: the formats are trufflehog's (pkg/detectors/discordbottoken and discordwebhook, whose
	// patterns rules.go quotes). A bot token is base64url(user id), 6 timestamp characters and 27
	// hmac characters, dot separated; a webhook is discord.com/api/webhooks/<18-19 digits>/<68
	// characters>. Neither survives trufflehog's unverified filter, see discordWhy.
	{
		ID: "discord-bot", Type: "discord", Env: "DISCORD_BOT_TOKEN",
		Doc:        "base64url(user id).timestamp.hmac, 24.6.27 (trufflehog discordbottoken)",
		Undetected: discordWhy,
		Gen: func(g *Gen) Fake {
			id := g.str("123456789", 1) + g.str(digits, 17)
			s := b64url([]byte(id)) + "." + g.str("GY", 1) + g.str(urlsafe, 5) + "." + g.token(4.0, rnd(urlsafe, 26)) + g.str(alnum, 1)
			return Fake{Value: s, Raw: s}
		},
	},
	{
		ID: "discord-webhook", Type: "discord", Env: "DISCORD_WEBHOOK_URL",
		Doc:        "https://discord.com/api/webhooks/<id>/<68> (trufflehog discordwebhook)",
		Undetected: discordWhy,
		Gen: func(g *Gen) Fake {
			s := "https://discord.com/api/webhooks/" + g.str(digits, 19) + "/" + g.token(4.0, rnd(alnum+"-", 68))
			return Fake{Value: s, Raw: s}
		},
	},
	flat("telegram", "telegram", "TELEGRAM_BOT_TOKEN", "betterleaks/telegram-bot-api-token (bot id, colon, AA + 33)",
		bl("telegram-bot-api-token"), 4.0, rnd(digits, 10), lit(":AA"), rnd(urlsafe, 33)),
	flat("twilio", "twilio", "TWILIO_API_KEY", "betterleaks/twilio-api-key",
		bl("twilio-api-key"), 3.5, lit("SK"), rnd(hexLower, 32)),
	flat("sendgrid", "sendgrid", "SENDGRID_API_KEY", "betterleaks/sendgrid-api-token",
		bl("sendgrid-api-token"), 4.2, lit("SG."), rnd(urlsafe, 22), lit("."), rnd(urlsafe, 43)),
	flat("mailgun", "mailgun", "MAILGUN_API_KEY", "betterleaks/mailgun-private-api-token",
		bl("mailgun-private-api-token"), 3.4, lit("key-"), rnd(hexLower, 32)),
	flat("resend", "resend", "RESEND_API_KEY", "betterleaks/resend-api-key.1",
		bl("resend-api-key.1"), 3.6, lit("re_"), rnd(b58, 8), lit("_"), rnd(b58, 24)),
	flat("brevo", "brevo", "BREVO_API_KEY", "betterleaks/sendinblue-api-token",
		bl("sendinblue-api-token"), 3.6, lit("xkeysib-"), rnd(hexLower, 64), lit("-"), rnd(alnum, 16)),

	// --- payments, commerce, productivity ---
	flat("stripe-secret", "stripe", "STRIPE_SECRET_KEY", "betterleaks/stripe-access-token; docs.stripe.com/keys",
		bl("stripe-access-token"), 4.5, lit("sk_live_51"), rnd(alnum, 89)),
	flat("stripe-restricted", "stripe", "STRIPE_RESTRICTED_KEY", "betterleaks/stripe-access-token (rk_ restricted key)",
		bl("stripe-access-token"), 4.5, lit("rk_live_51"), rnd(alnum, 89)),
	flat("shopify", "shopify", "SHOPIFY_ACCESS_TOKEN", "betterleaks/shopify-access-token",
		bl("shopify-access-token"), 3.5, lit("shpat_"), rnd(hexLower, 32)),
	flat("linear", "linear", "LINEAR_API_KEY", "betterleaks/linear-api-key",
		bl("linear-api-key"), 4.2, lit("lin_api_"), rnd(alnum, 40)),
	flat("notion", "notion", "NOTION_API_KEY", "betterleaks/notion-api-token",
		bl("notion-api-token"), 4.2, lit("ntn_"), rnd(digits, 11), rnd(alnum, 35)),
	flat("airtable", "airtable", "AIRTABLE_API_KEY", "betterleaks/airtable-personnal-access-token",
		bl("airtable-personnal-access-token"), 4.0, lit("pat"), rnd(alnum, 14), lit("."), rnd(hexLower, 64)),
	flat("figma", "figma", "FIGMA_ACCESS_TOKEN", "betterleaks/figma-personal-access-token",
		bl("figma-personal-access-token"), 4.0, lit("figd_"), rnd(urlsafe, 40)),
	// zoom: no engine has a rule. Zoom documents the three Server-to-Server OAuth credentials
	// (account id, client id, client secret) at
	// https://developers.zoom.us/docs/internal-apps/s2s-oauth/ but no prefix or length, so the
	// secret is modelled as 32 alphanumerics; only its variable name can give it away.
	unruled("zoom", "zoom", "ZOOM_CLIENT_SECRET", "developers.zoom.us/docs/internal-apps/s2s-oauth: opaque client secret, modelled as 32 alphanumerics",
		"Zoom credentials have no fixed prefix and no engine ships a rule", 4.0, rnd(alnum, 32)),
	// calcom: no engine has a rule. https://cal.com/docs/api-reference/v2/introduction says live
	// keys start cal_live_ (test keys cal_) and states no body; 32 hex characters is an assumption.
	unruled("calcom", "calcom", "CALCOM_API_KEY", "cal.com/docs/api-reference/v2/introduction: live keys start cal_live_; the 32-hex body is assumed",
		"no installed engine has a Cal.com rule", 3.5, lit("cal_live_"), rnd(hexLower, 32)),
	// zerobounce: betterleaks and gitleaks have no rule; trufflehog's zerobounce detector expects
	// the keyword and then 32 lowercase alphanumerics (pkg/detectors/zerobounce).
	flat("zerobounce", "zerobounce", "ZEROBOUNCE_API_KEY", "trufflehog/zerobounce: keyword within 40 chars of 32 [a-z0-9]",
		[]string{"trufflehog/zerobounce"}, 3.6, rnd(hexLower, 32)),

	// --- cloud credentials ---
	{
		ID: "aws", Type: "aws", Env: "AWS_SECRET_ACCESS_KEY",
		Doc:   "betterleaks/aws-access-token (+ aws-secret-access-key component); AKIA + 16 base32, secret is 40 base64",
		Rules: bl("aws-access-token"),
		Gen: func(g *Gen) Fake {
			id := g.token(3.3, lit("AKIA"), rnd(b32, 16))
			var sec string
			for { // real secrets carry '/' and '+' about three times in four; the url-encoded plants rely on them
				sec = g.token(4.3, rnd(b64std, 40))
				if strings.ContainsAny(sec, "/+") {
					break
				}
			}
			return Fake{Value: sec, Raw: sec, Alt: []string{id}, Name: "AWS_SECRET_ACCESS_KEY",
				Pairs: []Pair{{"AWS_ACCESS_KEY_ID", id}}}
		},
	},
	{
		ID: "aws-lone", Type: "aws", Env: "AWS_ACCESS_KEY_ID",
		Doc:   "an AKIA key id alone: betterleaks' aws-access-token is composite and drops it without the secret key within 5 lines (checked on 1.9.0); gitleaks reports it",
		Rules: bl("aws-access-token"),
		Gen: func(g *Gen) Fake {
			id := g.token(3.3, lit("AKIA"), rnd(b32, 16))
			return Fake{Value: id, Raw: id}
		},
	},
	{
		ID: "gcp-service-account", Type: "gcp", Env: "GOOGLE_APPLICATION_CREDENTIALS_JSON", Multi: true,
		Doc:   "betterleaks/gcp-service-account; the key file gcloud iam service-accounts keys create writes",
		Rules: bl("gcp-service-account", "private-key"),
		Gen: func(g *Gen) Fake {
			s, key, email := serviceAccountJSON(g, false)
			return Fake{Value: s, Raw: s, Alt: saAlt(key, email)}
		},
	},
	{
		ID: "firebase-admin", Type: "firebase", Env: "FIREBASE_SERVICE_ACCOUNT", Multi: true,
		Doc:   "betterleaks/gcp-service-account on a firebase-adminsdk-<5>@ account",
		Rules: bl("gcp-service-account", "private-key"),
		Gen: func(g *Gen) Fake {
			s, key, email := serviceAccountJSON(g, true)
			return Fake{Value: s, Raw: s, Alt: saAlt(key, email)}
		},
	},
	flat("firebase-web", "firebase", "FIREBASE_API_KEY", "betterleaks/gcp-api-key: the apiKey in a firebaseConfig is an AIza key (PLAN: low, not info)",
		bl("gcp-api-key"), 4.2, lit("AIza"), rnd(urlsafe, 35)),

	// --- connection strings: the password is the secret, the URL is how it travels ---
	dbProvider("postgres", "postgres", "DATABASE_URL", "postgres", bl("generic-credential-uri"),
		func(g *Gen) (string, string) {
			if g.intn(2) == 0 {
				return "postgres", "app_user@ep-" + g.pick([]string{"cool", "quiet", "wild", "tiny"}) + "-" + g.pick([]string{"river", "field", "dawn", "frost"}) +
					"-" + g.str(digits, 6) + ".us-east-2.aws.neon.tech/neondb?sslmode=require"
			}
			return "postgres", "postgres@db." + g.str(lower, 20) + ".supabase.co:5432/postgres"
		}),
	dbProvider("mongodb", "mongodb", "MONGODB_URI", "mongodb+srv", bl("generic-credential-uri", "mongodb-connection-string"),
		func(g *Gen) (string, string) {
			return "mongodb+srv", "svc_" + g.pick([]string{"api", "worker", "etl"}) + "@cluster0." + g.str(lowerNum, 5) +
				".mongodb.net/" + g.pick([]string{"prod", "app", "core"}) + "?retryWrites=true&w=majority"
		}),
	dbProvider("redis", "redis", "REDIS_URL", "rediss", bl("generic-credential-uri"),
		func(g *Gen) (string, string) {
			return "rediss", "default@redis-" + g.str(digits, 5) + ".c" + g.str("123456789", 1) + ".us-east-1-2.ec2.redns.redis-cloud.com:" + g.str(digits, 5)
		}),

	// --- key files ---
	{
		ID: "rsa-key", Type: "private-key", Env: "DEPLOY_PRIVATE_KEY", Multi: true,
		Doc:   "betterleaks/private-key; PKCS#1 RSA-2048 as ssh-keygen -m PEM writes it",
		Rules: bl("private-key"),
		Gen: func(g *Gen) Fake {
			s := strings.TrimRight(rsaPEM(g.r, 2048), "\n")
			return Fake{Value: s, Raw: s, Alt: []string{s + "\n"}}
		},
	},
	{
		ID: "ec-key", Type: "private-key", Env: "SIGNING_PRIVATE_KEY", Multi: true,
		Doc:   "betterleaks/private-key; SEC1 P-256 as openssl ecparam -genkey writes it",
		Rules: bl("private-key"),
		Gen: func(g *Gen) Fake {
			s := strings.TrimRight(ecPEM(g.r), "\n")
			return Fake{Value: s, Raw: s, Alt: []string{s + "\n"}}
		},
	},
	{
		ID: "openssh-key", Type: "private-key", Env: "SSH_PRIVATE_KEY", Multi: true,
		Doc:   "betterleaks/private-key; openssh-key-v1 ed25519 as ssh-keygen writes it",
		Rules: bl("private-key"),
		Gen: func(g *Gen) Fake {
			s := strings.TrimRight(openSSHPEM(g.r, "deploy@"+g.str(lower, 6)), "\n")
			return Fake{Value: s, Raw: s, Alt: []string{s + "\n"}}
		},
	},

	// --- no provider prefix: found by context or by nothing ---
	{
		ID: "generic-api-key", Type: "generic", Env: "API_KEY",
		Doc:   "betterleaks/generic-api-key: a high-entropy value assigned to a name containing key/secret/token",
		Rules: bl("generic-api-key"),
		Gen: func(g *Gen) Fake {
			// A digit every fourth character keeps accidental dictionary words (the rule drops
			// secrets containing any of ~1,500 stopwords) out of the value.
			for {
				b := []byte(g.str(b64std, 44))
				for i := 3; i < len(b); i += 4 {
					b[i] = digits[g.intn(10)]
				}
				if s := string(b); fp.Entropy(s) > 4.3 {
					return Fake{Value: s, Raw: s, Name: g.pick([]string{"API_KEY", "SECRET_KEY", "AUTH_TOKEN", "CLIENT_SECRET"})}
				}
			}
		},
	},
	// card-number: a 16-digit PAN with a valid Luhn digit under Visa's 400000 test BIN. Payment
	// card numbers have no secret-scanner rule; keyguard's known matcher registers them
	// (13-19 digits passing Luhn), so only that layer can find this plant.
	{
		ID: "card-number", Type: "card", Env: "CARD_NUMBER",
		Doc:        "PAN with a valid Luhn digit under Visa's 400000 test BIN",
		Undetected: "no engine ships a payment-card rule; only the known matcher (Luhn-gated) can find it",
		Gen: func(g *Gen) Fake {
			s := "400000" + g.str(digits, 9)
			s += string(luhn(s))
			return Fake{Value: s, Raw: s}
		},
	},
}

// dbProvider builds a connection-string provider. The password carries reserved characters
// (people paste them percent-encoded into URLs, so the encoded form is what the file holds),
// which makes the url-encoded form of the raw password a real variant for the known matcher.
func dbProvider(id, typ, env, scheme string, rules []string, target func(g *Gen) (string, string)) Provider {
	return Provider{
		ID: id, Type: typ, Env: env,
		Doc:   "betterleaks/generic-credential-uri (password is the secret group); " + scheme + "://user:password@host",
		Rules: rules,
		Gen: func(g *Gen) Fake {
			pw := reservedPassword(g)
			sch, rest := target(g)
			user, tail, _ := strings.Cut(rest, "@")
			enc := url.QueryEscape(pw)
			u := sch + "://" + user + ":" + enc + "@" + tail
			hostport, _, _ := strings.Cut(tail, "/")
			hostport, _, _ = strings.Cut(hostport, "?")
			alt := []string{enc, user + ":" + enc, u, sch + "://" + url.UserPassword(user, pw).String() + "@" + tail}
			// trufflehog reports scheme://user:password@host:port, password decoded, port defaulted
			alt = append(alt, sch+"://"+user+":"+pw+"@"+hostport, sch+"://"+user+":"+enc+"@"+hostport)
			if sch == "postgres" && !strings.Contains(hostport, ":") {
				alt = append(alt, sch+"://"+user+":"+pw+"@"+hostport+":5432")
			}
			return Fake{Value: u, Raw: pw, Alt: alt}
		},
	}
}

func reservedPassword(g *Gen) string {
	const specials = "@/:#?&=+$%"
	b := []byte(g.token(3.6, rnd(alnum, 18)))
	for i := 0; i < 2; i++ {
		pos := 1 + g.intn(len(b)-2)
		b = append(b[:pos], append([]byte{specials[g.intn(len(specials))]}, b[pos:]...)...)
	}
	return string(b)
}

// PublicProviders are real-format values that are public by design. They are planted as
// negatives: an engine that flags them is noisy, and triage is expected to drop them.
var PublicProviders = []Provider{
	flat("stripe-publishable", "stripe", "STRIPE_PUBLISHABLE_KEY", "docs.stripe.com/keys: publishable keys ship in client code",
		nil, 4.5, lit("pk_live_51"), rnd(alnum, 89)),
	{
		ID: "supabase-anon", Type: "supabase", Env: "SUPABASE_ANON_KEY",
		Doc: "supabase anon key: the same JWT shape as service_role with role=anon, safe in browsers behind RLS",
		Gen: func(g *Gen) Fake {
			s := supabaseJWT(g, "anon")
			return Fake{Value: s, Raw: s}
		},
	},
	flat("supabase-publishable", "supabase", "SUPABASE_PUBLISHABLE_KEY", "supabase sb_publishable_ keys are client-side",
		nil, 4.2, lit("sb_publishable_"), rnd(urlsafe, 31)),
	flat("posthog-project", "posthog", "NEXT_PUBLIC_POSTHOG_KEY", "betterleaks/posthog-project-api-key; phc_ keys are client-side",
		nil, 4.2, lit("phc_"), rnd(urlsafe, 43)),
	flat("mapbox-public", "mapbox", "MAPBOX_PUBLIC_TOKEN", "betterleaks/mapbox-api-token matches pk. tokens; they are public by design",
		nil, 3.8, lit("pk."), rnd(lowerNum, 60), lit("."), rnd(lowerNum, 22)),
	flat("sentry-dsn", "sentry", "SENTRY_DSN", "sentry DSNs are embedded in client bundles",
		nil, 3.6, lit("https://"), rnd(hexLower, 32), lit("@o"), rnd(digits, 7), lit(".ingest.sentry.io/"), rnd(digits, 7)),
	flat("algolia-search", "algolia", "ALGOLIA_SEARCH_API_KEY", "betterleaks/algolia-api-key matches the 32-hex search-only key, which is public",
		nil, 3.6, rnd(hexLower, 32)),
	flat("recaptcha-site", "recaptcha", "NEXT_PUBLIC_RECAPTCHA_SITE_KEY", "google reCAPTCHA site keys start 6L and are 40 characters",
		nil, 4.0, lit("6L"), rnd(urlsafe, 38)),
}

// saAlt lists the extents of a service-account file engines report besides the whole object:
// its private key (as PEM, with the trailing newline trufflehog normalizes to, and as the
// JSON text escapes it) and its client email, which trufflehog's GCP detector reports.
func saAlt(key, email string) []string {
	return []string{key, key + "\n", strings.ReplaceAll(key, "\n", `\n`), email}
}
