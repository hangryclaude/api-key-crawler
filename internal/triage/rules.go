package triage

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"path"
	"regexp"
	"strings"

	"keyguard/internal/core"
)

// ctx is a Secret and its evidence prepared once for the rules.
type ctx struct {
	s      *core.Secret
	ev     Evidence
	prefix string // the shape before its ellipsis: a constant token prefix such as "pk_live_", or ""
	tail   string // the shape after its last ellipsis: at most four characters of the value's end
	text   string // the evidence lines, lowercased and joined
	rules  string // the rule names, lowercased and joined
	typ    string
}

func newCtx(s *core.Secret, ev Evidence) ctx {
	c := ctx{s: s, ev: ev, typ: strings.ToLower(s.Type)}
	if i := strings.Index(s.Shape, "…"); i >= 0 {
		c.prefix = s.Shape[:i]
		c.tail = s.Shape[strings.LastIndex(s.Shape, "…")+len("…"):]
	}
	c.text = strings.ToLower(strings.Join(ev.Contexts, "\n"))
	c.rules = strings.ToLower(strings.Join(s.Rules, " "))
	return c
}

// placeholderPhrases are words that, on the line a value sits on, say it is not real. The
// value itself is already replaced by its shape in the evidence, so these describe the
// surroundings: a comment or a neighbouring name. "example" alone is not here: example.com
// and examples/ are everywhere.
var placeholderPhrases = []string{
	"placeholder", "dummy", "fake key", "fake token", "fake secret", "not a real", "your_api_key", "your-api-key",
	"your_key", "your-key", "your key", "<your", "[your", "changeme", "change_me", "replace_me", "replace-me",
	"replace me", "redacted", "example key", "sample key", "demo key", "test key", "xxxxxxxx",
}

func (t *Triager) placeholder(c ctx) (string, bool) {
	switch {
	case has(c.ev.Tags, TagPlaceholder):
		return "the scanner that read the raw value says it matches a placeholder pattern", true
	case t.examples[c.s.FP] != "":
		return "this is " + t.examples[c.s.FP] + ", a value published in documentation", true
	case tailLooksFake(c.tail):
		return "its last characters (" + c.tail + ") are a run or a word, not random", true
	case c.ev.Entropy > 0 && c.s.Len >= 16 && c.ev.Entropy < 2.5:
		return fmt.Sprintf("its entropy is %.1f bits a character, far below a real key's", c.ev.Entropy), true
	case hasAny(c.text, placeholderPhrases...):
		return "the line around it says it is a placeholder", true
	}
	return "", false
}

var fakeTails = map[string]bool{
	"test": true, "fake": true, "demo": true, "here": true, "todo": true, "null": true, "none": true,
	"1234": true, "4321": true, "abcd": true, "dcba": true, "0123": true, "3210": true, "wxyz": true,
}

// tailLooksFake reports whether the four visible trailing characters are one repeated
// character (xxxx, 0000), an ascending or descending run (1234, abcd), or a placeholder word.
// A random key ends this way about once in a hundred thousand, and shapes with fewer visible
// characters are never judged.
func tailLooksFake(tail string) bool {
	orig := []rune(tail)
	if len(orig) != 4 {
		return false
	}
	same := true
	for _, x := range orig[1:] {
		same = same && x == orig[0] // exact: "xXxX" is not the pattern, "XXXX" is
	}
	r := []rune(strings.ToLower(tail))
	if same || fakeTails[string(r)] {
		return true
	}
	step := r[1] - r[0]
	if step != 1 && step != -1 {
		return false
	}
	for i := 2; i < 4; i++ {
		if r[i]-r[i-1] != step {
			return false
		}
	}
	return true
}

var (
	supabaseAnon  = regexp.MustCompile(`anon[_-]?(public[_-]?)?key|anonkey|role["']?\s*[:=]\s*["']?anon\b`)
	localService  = regexp.MustCompile(`://[^\s/@]*@(localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|\[::1\]|host\.docker\.internal|db|postgres|postgresql|mysql|mariadb|mongo|mongodb|redis|rabbitmq|elasticsearch|memcached)([:/\s]|$)`)
	recaptchaSite = []string{"recaptcha", "sitekey", "site_key", "site-key"}
)

// publicByDesign recognises the keys their providers ship to browsers on purpose. A leak of
// one is not a leak, so the label is Info; verification overrides it if the provider insists.
func publicByDesign(c ctx) (string, bool) {
	switch {
	case c.prefix == "pk_live_" || c.prefix == "pk_test_":
		return "a Stripe publishable key; it is meant to ship in client code", true
	case c.prefix == "phc_":
		return "a PostHog project key; it is meant to ship in client code", true
	case c.prefix == "pk.":
		return "a Mapbox public token; it is meant to ship in client code", true
	case has(c.ev.Tags, TagJWTAnon):
		return "a JWT with role=anon, the public key of a Supabase project", true
	case c.prefix == "AIza":
		return "a Google API key; browser keys (Maps, Firebase) look like this, so check it is restricted", true
	}
	t := c.text
	switch {
	case (c.typ == "supabase" || c.typ == "jwt" || c.prefix == "eyJ") && supabaseAnon.MatchString(t) &&
		!hasAny(t, "service_role", "service-role", "servicerole") && !has(c.ev.Tags, TagJWTServiceRole):
		return "the line names it as a Supabase anon key, which is meant to ship in client code", true
	case (c.typ == "sentry" || strings.Contains(c.rules, "sentry") || strings.Contains(t, "sentry")) &&
		(strings.Contains(c.rules, "dsn") || strings.Contains(t, "dsn") || strings.Contains(t, "ingest.sentry.io")) &&
		!hasAny(c.prefix, "sntrys_", "sntryu_") && !hasAny(t, "auth_token", "auth-token", "authtoken"):
		return "a Sentry DSN; it is meant to ship in client code", true
	case (c.typ == "algolia" || strings.Contains(t, "algolia")) && strings.Contains(t, "search") &&
		!hasAny(t, "admin", "write", "master", "secret"):
		return "an Algolia search-only key; it is meant to ship in client code", true
	case hasAny(t, recaptchaSite...) && !strings.Contains(t, "secret"):
		return "a reCAPTCHA site key; it is meant to ship in client code", true
	}
	return "", false
}

// isGoogleKey is a Google API key by its AIza prefix.
func isGoogleKey(s *core.Secret) bool { return strings.HasPrefix(s.Shape, "AIza") }

var testDirs = map[string]bool{
	"test": true, "tests": true, "__tests__": true, "spec": true, "specs": true, "__specs__": true,
	"fixtures": true, "fixture": true, "testdata": true, "test-data": true, "test_data": true,
	"mocks": true, "__mocks__": true, "mock": true, "stubs": true, "e2e": true,
	"examples": true, "example": true, "samples": true, "sample": true, "demo": true, "demos": true,
}

// testPath reports whether a repository path is a test, fixture or example file.
func testPath(p string) bool {
	segs := strings.Split(strings.ToLower(path.Clean(strings.ReplaceAll(p, "\\", "/"))), "/")
	for _, d := range segs[:len(segs)-1] {
		if testDirs[d] {
			return true
		}
	}
	base := segs[len(segs)-1]
	switch {
	case strings.HasPrefix(base, "test_"), strings.HasPrefix(base, "test-"), strings.HasPrefix(base, "mock"),
		strings.HasSuffix(base, "_test.go"), strings.HasSuffix(base, "_test.py"), strings.HasSuffix(base, "_spec.rb"),
		base == "conftest.py":
		return true
	}
	// .env.example, config.sample.json, settings.template.yml, appsettings.dist: a template
	// or a test double somewhere in the name. The leading dot of a dotfile is not a separator.
	// A name that starts with example, sample or test (example.env, test.json) counts too, but
	// "template" and "dist" only after a dot: templates/ and dist/ hold real code.
	parts := strings.Split(strings.TrimPrefix(base, "."), ".")
	if len(parts) > 1 {
		switch parts[0] {
		case "example", "sample", "test":
			return true
		}
	}
	for _, part := range parts[1:] {
		switch part {
		case "example", "sample", "template", "dist", "defaults", "test", "spec", "tmpl":
			return true
		}
	}
	return false
}

func testLike(c ctx) (string, bool) {
	switch {
	case c.prefix == "sk_test_" || c.prefix == "rk_test_":
		return "a Stripe test-mode key; it cannot touch live money", true
	case has(c.ev.Tags, TagTestMode):
		return "a provider test-mode key", true
	case localService.MatchString(c.text):
		return "a credential for a service on this machine or in a dev container", true
	}
	if len(c.s.Locations) == 0 {
		return "", false
	}
	for _, l := range c.s.Locations {
		if l.Path == "" || !testPath(l.Path) {
			return "", false
		}
	}
	return "every place it appears is a test, fixture or example file (" + c.s.Locations[0].Path + ")", true
}

// weakTypes name formats too loose to call real on format alone: the catch-all, tokens that
// are JWTs of any purpose, Google keys (usually public), and credentials embedded in URLs
// (which are as often a placeholder password).
var weakTypes = map[string]bool{
	"": true, "generic": true, "unknown": true, "other": true, "jwt": true, "google": true,
	"password": true, "url": true, "uri": true, "basic-auth": true, "bearer": true,
}

func weakType(t string) bool { return weakTypes[t] || strings.HasPrefix(t, "generic-") }

// detectorFamilies counts independent detectors that reported a secret. betterleaks and
// gitleaks are one lineage with largely shared rules, so their agreement says little; the
// known matcher and filename rules are not detectors of this kind and are not counted.
func detectorFamilies(engines []string) int {
	seen := map[string]bool{}
	for _, e := range engines {
		switch e {
		case "", "known", "filename":
			continue
		case "betterleaks", "gitleaks":
			e = "regex"
		}
		seen[e] = true
	}
	return len(seen)
}

// realByRule is the positive case: nothing above rejected it and something vouches for it.
func realByRule(c ctx) (string, bool) {
	if n := detectorFamilies(c.s.Engines); n >= 2 {
		return fmt.Sprintf("%d independent detectors agree on it", n), true
	}
	if !weakType(c.typ) && !(c.ev.Entropy > 0 && c.ev.Entropy < 3.0) {
		return "it matches the " + c.s.Type + " key format and sits outside test paths", true
	}
	return "", false
}

type example struct{ value, what string }

// documentationExamples are values that providers print in their docs, so they appear in
// countless repos and are never real credentials. They are assembled from pieces, none
// long enough to look like a credential, so this file trips no scanner.
func documentationExamples() []example {
	jwtHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	jwtBody := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"1234567890","name":"John Doe","iat":1516239022}`))
	m := hmac.New(sha256.New, []byte("your-256-bit-secret"))
	m.Write([]byte(jwtHeader + "." + jwtBody))
	jwtSample := jwtHeader + "." + jwtBody + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
	return []example{
		{"AKIA" + "IOSFODNN7" + "EXAMPLE", "the AWS documentation access key"},
		{"wJalrXUt" + "nFEMI/K7" + "MDENG/bP" + "xRfiCYEX" + "AMPLEKEY", "the AWS documentation secret key"},
		{"AKIA" + "I44QH8DHB" + "EXAMPLE", "the older AWS documentation access key"},
		{"je7MtGbC" + "lwBF/2Zp" + "9Utk/h3y" + "Co8nvbEX" + "AMPLEKEY", "the older AWS documentation secret key"},
		{jwtSample, "the sample token on jwt.io"},
	}
}
