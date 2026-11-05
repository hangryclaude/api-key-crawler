package ghsettings

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"

	"keyguard/internal/core"
	"keyguard/internal/fp"
	"keyguard/internal/inventory/ghcli"
	"keyguard/internal/inventory/ghcli/ghclitest"
)

func alertsFor(t *testing.T, secrets ...string) []halert {
	t.Helper()
	var out []halert
	for i, sec := range secrets {
		out = append(out, halert{
			number: i + 1, typ: "github_personal_access_token", display: "GitHub Personal Access Token",
			secret: sec, validity: "unknown", created: fmt.Sprintf("2026-11-0%dT10:00:00Z", i%9+1),
		})
	}
	return out
}

func TestAlertsPagesThroughEveryOpenAlert(t *testing.T) {
	for _, n := range []int{0, 1, 4, 5} { // 4 is an exact multiple of the page size: a short page never arrives
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			var secrets []string
			for i := 0; i < n; i++ {
				secrets = append(secrets, fakeSecret(t, "ghp_", 36))
			}
			g := newGhub()
			g.add("o/r", hrepo{alerts: alertsFor(t, secrets...)})
			fx := newFixture(t, g, nil) // two alerts per page
			hits, err := fx.s.Alerts(bg(), repoSrc("o", "r", core.Public))
			if err != nil {
				t.Fatal(err)
			}
			if len(hits) != n {
				t.Fatalf("%d hits for %d alerts", len(hits), n)
			}
			for i, h := range hits {
				// GitHub hides the value, so each alert is keyed to itself, in the order served.
				if want := fx.kr.FP(fmt.Sprintf("github-alert:github.com/o/r#%d", i+1)); h.FP != want {
					t.Errorf("hit %d out of order or wrong FP", i)
				}
			}
			var gets []string
			for _, c := range fx.f.Calls() {
				gets = append(gets, c.Path)
			}
			wantPages := n/2 + 1
			if len(gets) != wantPages {
				t.Errorf("%d requests, want %d: %v", len(gets), wantPages, gets)
			}
			for i, p := range gets {
				want := fmt.Sprintf("repos/o/r/secret-scanning/alerts?state=open&per_page=2&page=%d&hide_secret=true", i+1)
				if p != want {
					t.Errorf("request %d = %s, want %s", i, p, want)
				}
			}
		})
	}
}

// pemOf wraps body lines in BEGIN and END lines built at run time, so no key-shaped block is
// written out in this source (PLAN invariant 2: the repo passes its own scanners).
func pemOf(kind string, lines ...string) string {
	dashes := strings.Repeat("-", 5)
	return dashes + "BEGIN " + kind + dashes + "\n" + strings.Join(lines, "\n") + "\n" + dashes + "END " + kind + dashes + "\n"
}

func TestAlertHitCarriesFingerprintShapeAndProvenance(t *testing.T) {
	pat := fakeSecret(t, "ghp_", 36)
	aws := fakeSecret(t, "AKIA", 16)
	pem := pemOf("RSA PRIVATE KEY", fakeSecret(t, "", 64), fakeSecret(t, "", 64))
	g := newGhub()
	// This server sends the values although hide_secret=true was asked, the case where
	// fingerprinting on arrival is all that stands between a value and keyguard's memory.
	g.add("o/r", hrepo{ignoresHide: true, alerts: []halert{
		{number: 7, typ: "github_personal_access_token", display: "GitHub Personal Access Token", secret: pat, validity: "active", created: "2026-11-01T10:00:00Z"},
		{number: 8, typ: "aws_access_key_id", display: "AWS Access Key ID", secret: aws, validity: "inactive", created: "2026-11-02T10:00:00Z"},
		{number: 9, typ: "rsa_private_key", display: "RSA Private Key", secret: pem, validity: "", created: "2026-11-03T10:00:00Z"},
	}})
	fx := newFixture(t, g, func(c *Config) { c.PerPage = 100 })
	src := repoSrc("o", "r", core.Public)
	hits, err := fx.s.Alerts(bg(), src)
	if err != nil || len(hits) != 3 {
		t.Fatalf("%v %d", err, len(hits))
	}
	for i, tc := range []struct {
		raw      string
		rule     string
		typ      string
		verified core.Verified
		url      string
	}{
		{pat, "github_personal_access_token", "github", core.Live, "https://github.com/o/r/security/secret-scanning/7"},
		{aws, "aws_access_key_id", "aws", core.Dead, "https://github.com/o/r/security/secret-scanning/8"},
		{pem, "rsa_private_key", "rsa_private_key", core.Unverified, "https://github.com/o/r/security/secret-scanning/9"},
	} {
		h := hits[i]
		want := core.Hit{
			Engine: "github-alerts", Rule: tc.rule, Type: tc.typ, FP: fx.kr.FP(tc.raw), Shape: fp.Shape(tc.raw),
			Len: utf8.RuneCountInString(tc.raw), Entropy: fp.Entropy(tc.raw), Verified: tc.verified,
			Loc: core.Location{Source: "github.com/o/r", Kind: "alert", Visibility: core.Public, URL: tc.url, Date: fmt.Sprintf("2026-11-0%dT10:00:00Z", i+1)},
		}
		ctx := h.Context
		h.Context = ""
		if !reflect.DeepEqual(h, want) { // Hit holds a Tags slice, so == no longer compiles
			t.Errorf("hit %d:\n got %+v\nwant %+v", i, h, want)
		}
		if !strings.HasPrefix(ctx, fmt.Sprintf("secret scanning alert #%d: ", i+7)) || utf8.RuneCountInString(ctx) > 200 {
			t.Errorf("hit %d context = %q", i, ctx)
		}
	}
	if hits[2].Shape != "-----BEGIN…KEY-----" {
		t.Errorf("a PEM key must display as its fixed marker, got %q", hits[2].Shape)
	}
	// Re-importing the same alert yields the same FP: it dedups with itself and with engines.
	again, _ := fx.s.Alerts(bg(), src)
	if again[0].FP != hits[0].FP {
		t.Error("FP is not stable across imports")
	}
}

func TestAlertWithoutAValueIsKeyedToTheAlertItself(t *testing.T) {
	g := newGhub()
	g.add("o/r", hrepo{alerts: []halert{
		{number: 3, typ: "stripe_api_key", display: "Stripe API Key", secret: "", validity: "unknown", created: "2026-11-01T10:00:00Z"},
		{number: 4, typ: "stripe_api_key", display: "Stripe API Key", secret: "", validity: "unknown", created: "2026-11-01T10:00:00Z"},
	}})
	fx := newFixture(t, g, nil)
	src := repoSrc("o", "r", core.Public)
	src.Visibility = core.Unknown // not private, so asked; and not public, so the hit must not claim it is
	hits, err := fx.s.Alerts(bg(), src)
	if err != nil || len(hits) != 2 {
		t.Fatalf("%v %v", err, hits)
	}
	if hits[0].FP == "" || hits[0].FP == hits[1].FP || hits[0].Shape != "…" || hits[0].Len != 0 || hits[0].Type != "stripe" {
		t.Errorf("hits = %+v", hits)
	}
	if hits[0].Loc.Visibility != core.Unknown {
		t.Errorf("visibility must come from the source: %+v", hits[0].Loc)
	}
}

// The central promise: a secret read from the alerts API is fingerprinted and forgotten.
func TestAlertSecretsAreNeverRetained(t *testing.T) {
	raws := []string{fakeSecret(t, "ghp_", 36), fakeSecret(t, "sk_live_", 40), pemOf("OPENSSH PRIVATE KEY", fakeSecret(t, "", 70))}
	g := newGhub()
	g.add("o/r", hrepo{ignoresHide: true, alerts: alertsFor(t, raws...)})
	fx := newFixture(t, g, func(c *Config) { c.PerPage = 100 })
	hits, err := fx.s.Alerts(bg(), repoSrc("o", "r", core.Public))
	if err != nil || len(hits) != 3 {
		t.Fatalf("%v %d", err, len(hits))
	}

	var seen []string
	if b, err := json.Marshal(hits); err == nil {
		seen = append(seen, string(b))
	}
	seen = append(seen, fmt.Sprintf("%v", hits), fmt.Sprintf("%+v", hits), fmt.Sprintf("%#v", hits))
	for _, view := range seen {
		for i, raw := range raws {
			for _, piece := range pieces(raw) {
				if strings.Contains(view, piece) {
					t.Fatalf("the returned hits expose part of secret %d", i)
				}
			}
		}
	}
	// What the fake handed the code under test — the actual response bytes — was overwritten.
	bufs := fx.f.Buffers()
	if len(bufs) == 0 {
		t.Fatal("no response buffers were seen")
	}
	for i, b := range bufs {
		for j, raw := range raws {
			for _, piece := range pieces(raw) {
				if strings.Contains(string(b), piece) {
					t.Errorf("response buffer %d still holds part of secret %d", i, j)
				}
			}
		}
	}
	fx.assertNoTokens(t, hits)
}

// pieces yields substrings long enough to be unmistakable: the whole value and its first
// and last 16 characters, so partial retention is caught as well as whole.
func pieces(raw string) []string {
	lines := strings.Split(strings.TrimSpace(raw), "\n")
	long := lines[0]
	for _, l := range lines {
		if len(l) > len(long) {
			long = l
		}
	}
	return []string{long, long[:16], long[len(long)-16:]}
}

func (fx *fixture) assertNoTokens(t *testing.T, vals ...any) {
	t.Helper()
	for _, acct := range []string{"hangryclaude", "alt-builds"} {
		tok := fx.f.Token(acct)
		for _, v := range vals {
			if strings.Contains(fmt.Sprintf("%#v", v), tok) {
				t.Errorf("token for %s reached %T", acct, v)
			}
		}
	}
}

func TestAlertFailurePathsNeverQuoteTheBody(t *testing.T) {
	raw := fakeSecret(t, "ghp_", 36)
	bodies := map[string]ghclitest.Reply{
		"truncated JSON":    {Status: 200, Body: []byte(`[{"number":1,"secret":"` + raw + `","created_at":`)},
		"wrong field type":  {Status: 200, Body: []byte(`[{"number":"one","secret":"` + raw + `"}]`)},
		"not an array":      {Status: 200, Body: []byte(`{"secret":"` + raw + `"}`)},
		"error with secret": ghclitest.JSON(500, map[string]any{"message": "boom", "secret": raw}),
	}
	for name, reply := range bodies {
		t.Run(name, func(t *testing.T) {
			g := newGhub()
			g.add("o/r", hrepo{})
			fx := newFixture(t, g, nil)
			h := g.handler(t)
			fx.f = ghclitest.New(t, func(c ghclitest.Call) ghclitest.Reply {
				if strings.Contains(c.Path, "alerts") {
					return reply
				}
				return h(c)
			}, "hangryclaude", "alt-builds")
			fx.s.cl = newClient(fx.f)
			hits, err := fx.s.Alerts(bg(), repoSrc("o", "r", core.Public))
			if err == nil {
				t.Fatalf("a broken reply was accepted: %v", hits)
			}
			for _, piece := range pieces(raw) {
				if strings.Contains(err.Error(), piece) {
					t.Fatal("the error quotes the response")
				}
				if strings.Contains(fmt.Sprintf("%#v", hits), piece) {
					t.Fatal("hits carry the secret")
				}
			}
			for i, b := range fx.f.Buffers() {
				if strings.Contains(string(b), raw) {
					t.Errorf("buffer %d still holds the secret after the failure", i)
				}
			}
		})
	}
}

func newClient(r ghcli.Runner) *ghcli.Client {
	c := ghcli.New(r)
	c.Backoff = 1
	return c
}

func TestAlertsOnARepoWithScanningOffAreTypedNotFatal(t *testing.T) {
	cases := map[int]string{
		404: "Secret scanning is disabled on this repository.",
		403: "Secret scanning is not available for this repository.",
		422: "Advanced Security must be enabled for this repository to use secret scanning.",
	}
	for status, msg := range cases {
		g := newGhub()
		g.add("o/r", hrepo{alertsStatus: status, alertsMsg: msg})
		fx := newFixture(t, g, nil)
		_, err := fx.s.Alerts(bg(), repoSrc("o", "r", core.Public))
		if !errors.Is(err, ErrDisabled) {
			t.Errorf("HTTP %d %q: err = %v, want ErrDisabled", status, msg, err)
		}
		if len(g.log) != 1 {
			t.Errorf("HTTP %d: %d requests, want the one that was refused", status, len(g.log))
		}
	}
	// A missing repo, a bad token and a server fault are not "disabled".
	g := newGhub()
	g.add("o/missing", hrepo{missing: true})
	g.add("o/down", hrepo{alertsStatus: 500, alertsMsg: "Server Error"})
	g.add("o/denied", hrepo{alertsStatus: 403, alertsMsg: "Must have admin rights to Repository."})
	fx := newFixture(t, g, nil)
	for _, name := range []string{"missing", "down", "denied"} {
		_, err := fx.s.Alerts(bg(), repoSrc("o", name, core.Public))
		if err == nil || errors.Is(err, ErrDisabled) {
			t.Errorf("%s: err = %v", name, err)
		}
		var ae *ghcli.APIError
		if !errors.As(err, &ae) {
			t.Errorf("%s: the HTTP status must stay inspectable: %v", name, err)
		}
	}
}

func TestAlertsAreOnlyForRepos(t *testing.T) {
	g := newGhub()
	fx := newFixture(t, g, nil)
	for _, src := range []core.Source{
		{ID: "github.com/o/r.wiki", Kind: "wiki", Owner: "o", Name: "r.wiki", Account: "hangryclaude"},
		{ID: "gist.github.com/o/abc", Kind: "gist", Owner: "o", Name: "abc", Account: "hangryclaude"},
	} {
		_, err := fx.s.Alerts(bg(), src)
		if !errors.Is(err, core.ErrUnsupported) || !errors.Is(err, ErrNotRepo) {
			t.Errorf("%s: err = %v", src.Kind, err)
		}
	}
	if _, err := fx.s.Alerts(bg(), repoSrc("o", "a/b", core.Public)); err == nil {
		t.Error("a name that escapes the URL path was used")
	}
	if len(g.log) != 0 {
		t.Errorf("GitHub was contacted for sources with no alerts: %q", g.log)
	}
}

func TestAlertWalkLimitIsReportedWithTheHitsSoFar(t *testing.T) {
	var as []halert
	for i := range maxAlertPages + 1 {
		as = append(as, halert{number: i + 1, typ: "x", secret: fmt.Sprintf("value-%d", i)})
	}
	g := newGhub()
	g.add("o/r", hrepo{alerts: as})
	fx := newFixture(t, g, func(c *Config) { c.PerPage = 1 })
	hits, err := fx.s.Alerts(bg(), repoSrc("o", "r", core.Public))
	if !errors.Is(err, ErrTooManyAlerts) || len(hits) != maxAlertPages {
		t.Fatalf("hits=%d err=%v", len(hits), err)
	}
}

func TestAlertsAllKeepsOrderAndSeparatesFailures(t *testing.T) {
	sec := fakeSecret(t, "ghp_", 36)
	g := newGhub()
	g.add("o/ok", hrepo{alerts: alertsFor(t, sec)})
	g.add("o/off", hrepo{alertsStatus: 404, alertsMsg: "Secret scanning is disabled on this repository."})
	fx := newFixture(t, g, nil)
	srcs := []core.Source{
		repoSrc("o", "off", core.Private),
		repoSrc("o", "ok", core.Public),
		{ID: "github.com/o/ok.wiki", Kind: "wiki", Owner: "o", Name: "ok.wiki"},
	}
	res := fx.s.AlertsAll(bg(), srcs)
	if len(res) != 3 || res[0].Source.ID != srcs[0].ID || res[1].Source.ID != srcs[1].ID || res[2].Source.ID != srcs[2].ID {
		t.Fatalf("order lost: %+v", res)
	}
	if !errors.Is(res[0].Err, ErrDisabled) || len(res[0].Hits) != 0 {
		t.Errorf("off: %+v", res[0])
	}
	if res[1].Err != nil || len(res[1].Hits) != 1 || res[1].Hits[0].FP != fx.kr.FP("github-alert:github.com/o/ok#1") {
		t.Errorf("ok: %+v", res[1])
	}
	if res[1].Hits[0].FP == fx.kr.FP(sec) {
		t.Error("the alert is keyed to a value GitHub should never have sent")
	}
	if !errors.Is(res[2].Err, core.ErrUnsupported) {
		t.Errorf("wiki: %+v", res[2])
	}
}

func TestProviderAndValidityNormalization(t *testing.T) {
	for in, want := range map[string]string{
		"github_personal_access_token": "github", "github_oauth_access_token": "github", "aws_access_key_id": "aws",
		"amazon_aws_secret_access_key": "aws", "stripe_api_key": "stripe", "openai_api_key": "openai",
		"anthropic_api_key": "anthropic", "google_api_key": "google", "slack_api_token": "slack", "hugging_face_access_token": "huggingface",
		"rsa_private_key": "rsa_private_key", "": "",
	} {
		if got := providerOf(in); got != want {
			t.Errorf("providerOf(%q) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]core.Verified{"active": core.Live, "inactive": core.Dead, "unknown": core.Unverified, "": core.Unverified, "weird": core.Unverified} {
		if got := verifiedOf(in); got != want {
			t.Errorf("verifiedOf(%q) = %q", in, got)
		}
	}
}

// STEAL P0-20: the value must never reach keyguard, so every alerts request asks GitHub to leave
// it out, on every page of every repo, and asks as a GET with the query in the path.
func TestEveryAlertsRequestAsksGitHubToHideTheSecret(t *testing.T) {
	g := newGhub()
	var srcs []core.Source
	for i, n := range []int{0, 1, 3, 5} {
		name := fmt.Sprintf("r%d", i)
		var secrets []string
		for range n {
			secrets = append(secrets, fakeSecret(t, "ghp_", 36))
		}
		g.add("o/"+name, hrepo{alerts: alertsFor(t, secrets...)})
		srcs = append(srcs, repoSrc("o", name, core.Public))
	}
	fx := newFixture(t, g, nil) // two alerts per page: 1 + 1 + 2 + 3 pages
	for _, r := range fx.s.AlertsAll(bg(), srcs) {
		if r.Err != nil {
			t.Fatalf("%s: %v", r.Source.ID, r.Err)
		}
	}
	var alertCalls int
	for _, c := range fx.f.Calls() {
		if !strings.Contains(c.Path, "/secret-scanning/alerts") {
			continue
		}
		alertCalls++
		q, err := url.ParseQuery(c.Path[strings.IndexByte(c.Path, '?')+1:])
		if err != nil || q.Get("hide_secret") != "true" || q.Get("state") != "open" || c.Method != "GET" || len(c.Body) != 0 {
			t.Errorf("request %s %s (body %q): want a GET with hide_secret=true in the path", c.Method, c.Path, c.Body)
		}
	}
	if alertCalls != 7 {
		t.Errorf("%d alerts requests, want 7 (1+1+2+3 pages)", alertCalls)
	}
	assertNoParameterFlags(t, fx)
}

func TestHiddenSecretsMeanTheValueNeverArrives(t *testing.T) {
	raws := []string{fakeSecret(t, "ghp_", 36), fakeSecret(t, "sk_live_", 40)}
	g := newGhub()
	g.add("o/r", hrepo{alerts: alertsFor(t, raws...)})
	fx := newFixture(t, g, func(c *Config) { c.PerPage = 100 })
	hits, err := fx.s.Alerts(bg(), repoSrc("o", "r", core.Public))
	if err != nil || len(hits) != 2 {
		t.Fatalf("%v %d", err, len(hits))
	}
	// GitHub never sent the values, so there is nothing to wipe: the proof is in the bytes the
	// fake handed over, which never held them.
	for i, b := range fx.f.Buffers() {
		for _, raw := range raws {
			if strings.Contains(string(b), raw) {
				t.Errorf("response %d carried a secret although hide_secret was asked", i)
			}
		}
	}
	for i, h := range hits {
		if h.FP == fx.kr.FP(raws[i]) || h.Shape != "…" || h.Len != 0 {
			t.Errorf("hit %d = %+v: it is keyed to the alert, not to a value", i, h)
		}
		if h.Rule != "github_personal_access_token" || h.Loc.URL == "" || h.Engine != "github-alerts" {
			t.Errorf("hit %d lost its provenance: %+v", i, h)
		}
	}
}

// A free plan has no alerts for a private repo, and asking each of 448 for it is 448 requests to
// hear 404 (STEAL P0-18).
func TestPrivateReposAreAnsweredWithoutARequest(t *testing.T) {
	g := newGhub()
	var srcs []core.Source
	for i := range 100 {
		name := fmt.Sprintf("p%d", i)
		g.add("o/"+name, hrepo{null: true})
		srcs = append(srcs, repoSrc("o", name, core.Private))
	}
	fx := newFixture(t, g, nil)
	for _, r := range fx.s.AlertsAll(bg(), srcs) {
		if !errors.Is(r.Err, ErrDisabled) || len(r.Hits) != 0 {
			t.Fatalf("%s: %+v", r.Source.ID, r)
		}
	}
	if n := len(fx.f.Calls()); n != 0 || len(g.log) != 0 {
		t.Errorf("%d requests for 100 private repos, want none", n)
	}

	// A plan that does have them can say so.
	paid := newFixture(t, g, func(c *Config) { c.PrivateAlerts = true })
	paid.s.AlertsAll(bg(), srcs[:3])
	if n := len(paid.f.Calls()); n != 3 {
		t.Errorf("with PrivateAlerts on, %d requests for 3 repos", n)
	}
}
