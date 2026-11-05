package known

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"

	"keyguard/internal/fp"
)

// nameWords are the PLAN.md name filter, matched anywhere in a variable name: a value
// called PRIVATE_THING or apiKey is a secret candidate, ANTHROPIC_MODEL is not.
var nameWords = []string{
	"KEY", "TOKEN", "SECRET", "PASS", "PWD", "AUTH", "CRED", "PRIVATE", "DSN", "WEBHOOK",
	"SESSION", "COOKIE", "BEARER", "SID", "SIGNING", "CARDNUMBER",
}

// nameLooksSecret is checked on the name as written and with separators squeezed out, so
// CARD_NUMBER, card-number and cardNumber all reach CARDNUMBER.
func nameLooksSecret(name string) bool {
	u := strings.ToUpper(name)
	squeezed := strings.Map(func(r rune) rune {
		if r == '_' || r == '-' || r == '.' || r == ' ' {
			return -1
		}
		return r
	}, u)
	for _, w := range nameWords {
		if strings.Contains(u, w) || strings.Contains(squeezed, w) {
			return true
		}
	}
	return false
}

// Reasons a value is not learned, as counted in Report.Rejected.
const (
	rejShort       = "short"
	rejPlaceholder = "placeholder"
	rejURL         = "url"
	rejPath        = "path"
	rejNumber      = "number"
	rejEntropy     = "entropy"
	rejPublic      = "public" // an issuer publishes these on purpose; see publicByDesign
	rejName        = "name"   // passed every value filter but nothing says it is a secret
)

// rejection reports why v cannot be a secret worth learning, or "" when it can. These are
// the PLAN.md value filters: length, a placeholder check, not a plain URL/path/number/bool,
// and enough entropy unless it is a card number.
func rejection(v string) string { return reject(v, false) }

// reject is rejection with one refinement. A value that is a credential by position (a
// netrc password, a line of a private key's body, the password inside a URL) has already
// been told apart from URLs, paths and numbers by where it was found, and base64 lines
// start with a slash often enough that the path test would throw away real key material.
func reject(v string, trusted bool) string {
	if len(v) < MinLen {
		return rejShort
	}
	if _, ok := cardNumber(v); ok {
		return "" // digits, so the entropy bar below would refuse it
	}
	if !trusted && isNumberish(v) {
		return rejNumber
	}
	if isPlaceholder(v) {
		return rejPlaceholder
	}
	if !trusted && plainURL(v) {
		return rejURL
	}
	if !trusted && isPath(v) {
		return rejPath
	}
	e := fp.Entropy(v)
	if e < 3.0 && !(len(v) >= 32 && e >= 2.5) {
		return rejEntropy
	}
	return ""
}

// publicByDesign recognises values their issuers expect to ship in front-end code and
// public repositories: Stripe and Clerk publishable keys, PostHog project keys, Mapbox
// public tokens, Supabase's publishable keys and anon JWT. Learned, each would make the
// commit gate block ordinary client code. Only the value's own shape counts, never the
// variable name: a real secret in a NEXT_PUBLIC_ variable is still a secret, and the
// commonest way to leak one.
func publicByDesign(v string) bool {
	for _, p := range []string{"pk_live_", "pk_test_", "phc_", "pk.eyJ", "sb_publishable_"} {
		if strings.HasPrefix(v, p) {
			return true
		}
	}
	parts := strings.Split(v, ".")
	if len(parts) != 3 || !strings.HasPrefix(v, "eyJ") {
		return false
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return false
	}
	var claims struct {
		Role string `json:"role"`
	}
	return json.Unmarshal(payload, &claims) == nil && claims.Role == "anon"
}

// cardNumber recognises 13-19 digits (spaces and dashes allowed between groups) that pass
// the Luhn check and are not a degenerate run, and returns just the digits.
func cardNumber(v string) (digits string, ok bool) {
	var d []byte
	for i := 0; i < len(v); i++ {
		switch c := v[i]; {
		case c >= '0' && c <= '9':
			d = append(d, c)
		case c == ' ' || c == '-':
		default:
			return "", false
		}
	}
	if len(d) < 13 || len(d) > 19 {
		return "", false
	}
	var seen [10]bool
	distinct := 0
	for _, c := range d {
		if !seen[c-'0'] {
			seen[c-'0'] = true
			distinct++
		}
	}
	// 0000000000000 and 1111111111116 pass Luhn; nobody's card looks like them.
	if distinct < 4 || !luhn(d) {
		return "", false
	}
	return string(d), true
}

func luhn(d []byte) bool {
	sum := 0
	for i := range d {
		x := int(d[len(d)-1-i] - '0')
		if i%2 == 1 {
			x *= 2
			if x > 9 {
				x -= 9
			}
		}
		sum += x
	}
	return sum%10 == 0
}

// isNumberish is a plain decimal number, a version string, or one of the literals config
// files use for "no value".
func isNumberish(v string) bool {
	switch strings.ToLower(v) {
	case "true", "false", "yes", "no", "on", "off", "null", "none", "nil", "undefined":
		return true
	}
	digits, dots := 0, 0
	for i := 0; i < len(v); i++ {
		switch c := v[i]; {
		case c >= '0' && c <= '9':
			digits++
		case c == '.' || c == '-' || c == '+' || c == ',' || c == ' ' || c == ':' || c == '/':
			dots++
		default:
			return false
		}
	}
	return digits > 0
}

// placeholderWords are long enough that a random key cannot contain one by accident
// (seven letters of "example" case-insensitively is about one in 10^9 per position).
var placeholderWords = []string{
	"changeme", "change_me", "change-me", "example", "dummy", "placeholder", "redacted",
	"xxxxx", "yourkey", "your_key", "your-key", "your_api", "your-api", "yourapi",
	"replace_me", "replace-me", "replaceme", "insert_", "notreal", "not_real", "not-real",
	"fakekey", "fake_key", "fake-key", "<your", "enter_your", "put_your", "paste_your",
}

// placeholderFiller are the words a placeholder is spelled with ("my-secret-token-here"). A
// value made only of these is a prompt, not a key; one stray word in a real key (sk_test_…)
// proves nothing, so this is whole-value only.
var placeholderFiller = map[string]bool{
	"todo": true, "tbd": true, "fixme": true, "none": true, "null": true, "sample": true,
	"secret": true, "password": true, "token": true, "test": true, "fake": true, "demo": true,
	"key": true, "api": true, "here": true, "goes": true, "your": true, "my": true, "the": true,
	"value": true, "enter": true, "paste": true, "insert": true, "put": true, "replace": true,
	"with": true, "xxx": true, "abc": true, "secretkey": true, "apikey": true, "yourtoken": true,
	"private": true, "public": true, "access": true, "auth": true, "bearer": true,
}

func isPlaceholder(v string) bool {
	l := strings.ToLower(v)
	switch {
	case strings.HasPrefix(l, "your_"), strings.HasPrefix(l, "your-"), strings.HasPrefix(l, "your "):
		return true
	case strings.HasPrefix(l, "<") && strings.HasSuffix(l, ">"):
		return true
	case strings.HasPrefix(l, "$("), strings.HasPrefix(l, "{{"), strings.HasPrefix(l, "%("), strings.HasPrefix(l, "`"):
		return true
	case strings.HasPrefix(l, "$") && isIdent(l[1:]):
		return true
	case strings.Contains(l, "${"):
		// Anything with a template hole in it is not the final value.
		return true
	}
	for _, w := range placeholderWords {
		if strings.Contains(l, w) {
			return true
		}
	}
	toks := strings.FieldsFunc(l, func(r rune) bool { return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9') })
	allFiller := len(toks) > 0
	for _, tok := range toks {
		if !placeholderFiller[tok] {
			allFiller = false
			break
		}
	}
	return allFiller || mostlyOneChar(v) || mostlySequential(v)
}

func isIdent(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_' || i > 0 && c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

// mostlyOneChar catches ****, 0000..., xxxx-xxxx and friends that survive on length alone.
func mostlyOneChar(v string) bool {
	var n [256]int
	most := 0
	for i := 0; i < len(v); i++ {
		n[v[i]]++
		if n[v[i]] > most {
			most = n[v[i]]
		}
	}
	return most*2 > len(v)
}

// mostlySequential catches 0123456789abcdef and abcdefghijklmnop: they have the entropy of
// a key and the look of a keyboard.
func mostlySequential(v string) bool {
	steps := 0
	for i := 1; i < len(v); i++ {
		if d := int(v[i]) - int(v[i-1]); d == 1 || d == -1 {
			steps++
		}
	}
	return steps*10 >= (len(v)-1)*8
}

func isPath(v string) bool {
	if !(strings.HasPrefix(v, "/") || strings.HasPrefix(v, "./") || strings.HasPrefix(v, "../") || strings.HasPrefix(v, "~/")) {
		return false
	}
	// base64 can start with '/' and holds '/' by chance; paths do not hold + or = and keep
	// their segments short.
	if strings.ContainsAny(v, "+=") || strings.Count(v, "/") < 2 {
		return false
	}
	for _, seg := range strings.Split(v, "/") {
		if len(seg) > 32 {
			return false
		}
	}
	return true
}

// plainURL is a URL that carries no credential: no password in the userinfo and nothing
// after the host that looks like a token. Webhook URLs keep their secret in the path, so
// they are not plain.
func plainURL(v string) bool {
	i := strings.Index(v, "://")
	if i <= 0 || !isScheme(v[:i]) {
		return false
	}
	return len(urlPasswords(v)) == 0 && !urlSecretPath(v)
}

// urlSecretPath: something after the host looks like a token (a webhook URL keeps its secret
// in the path, a signed URL in the query).
func urlSecretPath(v string) bool {
	i := strings.Index(v, "://")
	if i < 0 {
		return false
	}
	rest := v[i+3:]
	if j := strings.IndexAny(rest, "/?#"); j >= 0 {
		rest = rest[j:]
	} else {
		return false
	}
	for _, seg := range strings.FieldsFunc(rest, func(r rune) bool { return strings.ContainsRune("/?&=#;", r) }) {
		if len(seg) >= 20 && looksRandomSegment(seg) {
			return true
		}
	}
	return false
}

func isScheme(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || i > 0 && (c >= '0' && c <= '9' || c == '+' || c == '-' || c == '.')) {
			return false
		}
	}
	return s != ""
}

func looksRandomSegment(s string) bool {
	lower, upper, digits := 0, 0, 0
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c >= '0' && c <= '9':
			digits++
		case c >= 'a' && c <= 'z':
			lower++
		case c >= 'A' && c <= 'Z':
			upper++
		case c == '-' || c == '_' || c == '%' || c == '.' || c == '+':
		default:
			return false
		}
	}
	// A slug is lowercase words; a token has digits or mixes case. (A random alnum token has
	// no digit one time in sixty, which is why digits alone are not the test.)
	mixed := digits > 0 || upper > 0 && lower > 0
	return mixed && fp.Entropy(s) >= 3.3
}

// urlPasswords returns the password of every URL in s that has one, both as written and
// percent-decoded, because configs hold the first and code holds the second.
func urlPasswords(s string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(p string) {
		if p != "" && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for from := 0; ; {
		j := strings.Index(s[from:], "://")
		if j < 0 {
			break
		}
		start := from + j + 3
		from = start
		if !isSchemeTail(s[:start-3]) {
			continue
		}
		end := start
		for end < len(s) && !strings.ContainsRune("/?#\"'` \t\r\n<>)]}", rune(s[end])) {
			end++
		}
		auth := s[start:end]
		at := strings.LastIndexByte(auth, '@')
		if at < 0 {
			continue
		}
		_, pw, ok := strings.Cut(auth[:at], ":")
		if !ok {
			continue
		}
		add(pw)
		if dec, err := url.PathUnescape(pw); err == nil {
			add(dec)
		}
	}
	return out
}

// isSchemeTail reports whether s ends in a URL scheme (so "x://" is a URL, "://" alone or
// "a b://" is not).
func isSchemeTail(s string) bool {
	i := len(s)
	for i > 0 {
		c := s[i-1]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '+' || c == '-' || c == '.' {
			i--
			continue
		}
		break
	}
	return i < len(s) && isScheme(s[i:])
}
