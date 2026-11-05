package ghsettings

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"unicode/utf8"

	"keyguard/internal/core"
	"keyguard/internal/fp"
	"keyguard/internal/inventory/ghcli"
)

// maxAlertPages bounds the walk. 100 pages of 100 is five hundred times what any of these
// repos has; reaching it is reported, not silently cut.
const maxAlertPages = 100

// ErrTooManyAlerts accompanies the hits read before the page limit stopped the walk.
var ErrTooManyAlerts = errors.New("ghsettings: more alert pages than the walk allows")

// Alerts reads a repo's open secret scanning alerts as hits, one per alert.
//
// Every request passes hide_secret=true (STEAL P0-20), so GitHub leaves the value out and the raw
// secret never enters this process: stronger than hashing it on arrival. An alert with no value
// is keyed to the alert itself (hitOf). If a reply carries a value anyway, as an old server or a
// test double might, it is fingerprinted, shaped and dropped inside decodeAlerts: no struct that
// leaves it carries the value, the response bytes are wiped as soon as a page is decoded, and no
// error text quotes a body. The query string sits in the path and never in a -f or -F, which
// would turn this GET into a POST. Source.Account's token must have admin rights on the repo, or
// GitHub answers as if the feature were off.
//
// A private repo is answered without a request (STEAL P0-18): on a free plan GitHub has no alerts
// for it, and asking would be one more call per private repo, 448 of them, to hear 404.
func (s *Settings) Alerts(ctx context.Context, src core.Source) ([]core.Hit, error) {
	path, err := repoPath(src)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", core.ErrUnsupported, err)
	}
	if src.Visibility == core.Private && !s.privateAlerts {
		return nil, fmt.Errorf("ghsettings: alerts of %s: %w: a private repo, which this plan cannot scan", src.ID, ErrDisabled)
	}
	var hits []core.Hit
	for page := 1; page <= maxAlertPages; page++ {
		resp, err := s.cl.Do(ctx, src.Account, ghcli.Request{
			Path: fmt.Sprintf("%s/secret-scanning/alerts?state=open&per_page=%d&page=%d&hide_secret=true", path, s.perPage, page),
		})
		if err != nil {
			return hits, err
		}
		if !resp.OK() {
			err := alertsError(src, resp)
			resp.Wipe()
			return hits, err
		}
		got, n, err := decodeAlerts(resp.Body, src, s.fp)
		resp.Wipe()
		if err != nil {
			return hits, fmt.Errorf("ghsettings: alerts of %s: %w", src.ID, err)
		}
		hits = append(hits, got...)
		if n < s.perPage {
			return hits, nil
		}
	}
	return hits, fmt.Errorf("%w (%s)", ErrTooManyAlerts, src.ID)
}

// alertsError types a failed alerts request. GitHub answers 404 for a repo with scanning
// switched off and 403/422 where the plan lacks it; all three say so in the message.
func alertsError(src core.Source, resp ghcli.Response) error {
	err := resp.Err()
	var ae *ghcli.APIError
	if errors.As(err, &ae) {
		m := strings.ToLower(ae.Message)
		switch ae.Status {
		case http.StatusNotFound, http.StatusForbidden, http.StatusUnprocessableEntity:
			if strings.Contains(m, "secret scanning") || strings.Contains(m, "advanced security") {
				return fmt.Errorf("ghsettings: alerts of %s: %w: %s", src.ID, ErrDisabled, ae.Message)
			}
		}
	}
	return fmt.Errorf("ghsettings: alerts of %s: %w", src.ID, err)
}

// rawAlert is one alert as the API sends it. With hide_secret=true Secret is absent or null. It
// stays raw JSON so that a value sent anyway can be overwritten after use; every other field is
// metadata.
type rawAlert struct {
	Number            int             `json:"number"`
	CreatedAt         string          `json:"created_at"`
	HTMLURL           string          `json:"html_url"`
	SecretType        string          `json:"secret_type"`
	SecretTypeDisplay string          `json:"secret_type_display_name"`
	Validity          string          `json:"validity"`
	Secret            json.RawMessage `json:"secret"`
}

// decodeAlerts turns one page of the alerts API into hits and reports how many alerts the
// page held. The raw secret exists only in here. Parse failures say nothing about the body:
// an error message built from a response that carries secrets would carry them too.
func decodeAlerts(body []byte, src core.Source, f core.Fingerprinter) ([]core.Hit, int, error) {
	var alerts []rawAlert
	if err := json.Unmarshal(body, &alerts); err != nil {
		for i := range alerts {
			clear(alerts[i].Secret)
		}
		return nil, 0, errors.New("the reply is not a JSON array of alerts")
	}
	hits := make([]core.Hit, 0, len(alerts))
	for i := range alerts {
		a := &alerts[i]
		var secret string
		if len(a.Secret) > 0 && string(a.Secret) != "null" {
			_ = json.Unmarshal(a.Secret, &secret)
		}
		clear(a.Secret)
		a.Secret = nil
		hits = append(hits, hitOf(a, secret, src, f))
		secret = ""
	}
	return hits, len(alerts), nil
}

// hitOf builds the hit for one alert. When GitHub withheld the value the hit is keyed to the
// alert itself, so the alert is still tracked and still dedups against its own re-imports.
func hitOf(a *rawAlert, secret string, src core.Source, f core.Fingerprinter) core.Hit {
	h := core.Hit{
		Engine:   "github-alerts",
		Rule:     a.SecretType,
		Type:     providerOf(a.SecretType),
		Verified: verifiedOf(a.Validity),
		Loc: core.Location{
			Source: src.ID,
			// An alert is not a place in git: its Source is the repo it belongs to and its Kind says
			// it came from GitHub's own scanner (core.Location).
			Kind:       "alert",
			Visibility: src.Visibility,
			URL:        a.HTMLURL,
			Date:       a.CreatedAt,
		},
	}
	label := fmt.Sprintf("secret scanning alert #%d: %s", a.Number, cmp.Or(a.SecretTypeDisplay, a.SecretType))
	if secret == "" {
		h.FP = f.FP(fmt.Sprintf("github-alert:%s#%d", src.ID, a.Number))
		h.Shape = "…"
		h.Context = fp.Context(label, "")
		return h
	}
	h.FP = f.FP(secret)
	h.Shape = fp.Shape(secret)
	h.Len = utf8.RuneCountInString(secret)
	h.Entropy = fp.Entropy(secret)
	h.Context = fp.Context(label, secret)
	return h
}

func verifiedOf(validity string) core.Verified {
	switch validity {
	case "active":
		return core.Live
	case "inactive":
		return core.Dead
	}
	return core.Unverified
}

// providerPrefixes maps the leading word(s) of GitHub's secret_type to the provider names
// the rest of keyguard uses. Longest first within a provider family does not matter: no
// prefix here is a prefix of another that maps elsewhere.
var providerPrefixes = []struct{ prefix, provider string }{
	{"github_", "github"}, {"aws_", "aws"}, {"amazon_", "aws"}, {"stripe_", "stripe"}, {"slack_", "slack"},
	{"google_", "google"}, {"gcp_", "google"}, {"firebase_", "google"}, {"openai_", "openai"}, {"anthropic_", "anthropic"},
	{"azure_", "azure"}, {"npm_", "npm"}, {"pypi_", "pypi"}, {"twilio_", "twilio"}, {"sendgrid_", "sendgrid"},
	{"mailgun_", "mailgun"}, {"shopify_", "shopify"}, {"discord_", "discord"}, {"telegram_", "telegram"},
	{"hugging_face_", "huggingface"}, {"huggingface_", "huggingface"}, {"digitalocean_", "digitalocean"},
	{"cloudflare_", "cloudflare"}, {"supabase_", "supabase"}, {"vercel_", "vercel"}, {"linear_", "linear"},
	{"notion_", "notion"}, {"airtable_", "airtable"}, {"docker_", "dockerhub"}, {"dockerhub_", "dockerhub"},
	{"replicate_", "replicate"}, {"groq_", "groq"}, {"xai_", "xai"}, {"openrouter_", "openrouter"},
}

// providerOf normalizes GitHub's secret_type ("github_personal_access_token") to a provider
// name ("github"). Types with no entry keep their GitHub name: more informative than a guess.
func providerOf(secretType string) string {
	for _, p := range providerPrefixes {
		if strings.HasPrefix(secretType, p.prefix) {
			return p.provider
		}
	}
	return secretType
}

// AlertsResult is one source's alerts, or why they could not be read.
type AlertsResult struct {
	Source core.Source
	Hits   []core.Hit
	Err    error // ErrDisabled when scanning is off there; callers usually count that, not report it
}

// AlertsAll reads the alerts of every repo in sources, in parallel, one result per source in
// input order. Wikis and gists have no alerts and carry core.ErrUnsupported.
func (s *Settings) AlertsAll(ctx context.Context, sources []core.Source) []AlertsResult {
	out := make([]AlertsResult, len(sources))
	s.each(len(sources), func(i int) {
		out[i].Source = sources[i]
		out[i].Hits, out[i].Err = s.Alerts(ctx, sources[i])
	})
	return out
}
