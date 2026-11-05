package fp

import (
	"net/url"
	"strings"
	"testing"
)

// pemParts builds a PEM block at run time from pieces, so this file holds no armor line a
// scanner would take for a key. body is the base64 text without line breaks.
func pemParts(kind, body string, wrap int, eol string) string {
	dashes := strings.Repeat("-", 5)
	var b strings.Builder
	b.WriteString(dashes + "BEGIN " + kind + dashes + eol)
	for len(body) > 0 {
		n := min(wrap, len(body))
		b.WriteString(body[:n] + eol)
		body = body[n:]
	}
	b.WriteString(dashes + "END " + kind + dashes + eol)
	return b.String()
}

func TestCanonicalFoldsOnePEMKeyIntoOneSecret(t *testing.T) {
	kind := "RSA " + "PRIVATE " + "KEY"
	body := randStr(t, alnum+"+/", 400)
	want := Canonical(pemParts(kind, body, 64, "\n"))

	forms := map[string]string{
		"wrapped at 76":          pemParts(kind, body, 76, "\n"),
		"CRLF line ends":         pemParts(kind, body, 64, "\r\n"),
		"one long line":          pemParts(kind, body, len(body), "\n"),
		"no trailing newline":    strings.TrimRight(pemParts(kind, body, 64, "\n"), "\n"),
		"extra trailing newline": pemParts(kind, body, 64, "\n") + "\n\n",
		"indented by a template": "    " + strings.ReplaceAll(strings.TrimRight(pemParts(kind, body, 64, "\n"), "\n"), "\n", "\n    "),
		"escaped as JSON text":   `{"private_key": "` + strings.ReplaceAll(pemParts(kind, body, 64, "\n"), "\n", `\n`) + `"}`,
		"inside an assignment":   "KEY=\"" + strings.ReplaceAll(pemParts(kind, body, 64, "\n"), "\n", `\n`) + "\"\n",
	}
	for name, f := range forms {
		if got := Canonical(f); got != want {
			t.Errorf("%s: canonical form differs (len %d vs %d)", name, len(got), len(want))
		}
	}

	// The form is still a PEM block, so Shape hides it the way it hides any key.
	if got := Shape(want); got != "-----BEGIN…KEY-----" {
		t.Errorf("Shape of the canonical form = %q", got)
	}
	if strings.Count(want, "\n") != 2 || strings.ContainsAny(strings.Split(want, "\n")[1], " \t\r") {
		t.Errorf("canonical PEM is not header, one body line, footer")
	}

	// A different key stays different, and so does one whose type differs.
	other := randStr(t, alnum+"+/", 400)
	if Canonical(pemParts(kind, other, 64, "\n")) == want {
		t.Error("two different keys collapsed into one")
	}
	if Canonical(pemParts("EC "+"PRIVATE "+"KEY", body, 64, "\n")) == want {
		t.Error("a different key type collapsed into the same record")
	}
	k := NewEphemeral()
	if k.FP(Canonical(forms["CRLF line ends"])) != k.FP(want) {
		t.Error("the same key did not fingerprint to one value")
	}
}

func TestCanonicalLeavesAnExtentItCannotCompleteAlone(t *testing.T) {
	dashes := strings.Repeat("-", 5)
	for name, in := range map[string]string{
		"header only":        dashes + "BEGIN OPENSSH PRIVATE KEY" + dashes + "\nabc",
		"footer before head": dashes + "END X" + dashes + "\nabc\n" + dashes + "BEGIN X" + dashes,
		"unterminated mark":  dashes + "BEGIN X",
		"footer unterminated": dashes + "BEGIN X" + dashes + "\nabc\n" +
			dashes + "END X",
	} {
		if got := Canonical(in); got != in {
			t.Errorf("%s: changed to %q", name, got)
		}
	}
}

func TestCanonicalURIIsThePassword(t *testing.T) {
	// pw is random, so no case may leave a bare "%" in front of it: "%" and two of its hex digits
	// make a valid escape, which Canonical rightly decodes (a bare "%" failed about one run in ten).
	pw := randStr(t, alnum, 24)
	uri := func(scheme, userinfo, rest string) string { return scheme + "://" + userinfo + "@" + rest }
	for name, c := range map[string]struct{ in, want string }{
		"postgres":                {uri("postgres", "app:"+pw, "db.internal:5432/app?sslmode=require"), pw},
		"mongodb+srv":             {uri("mongodb+srv", "admin:"+pw, "cluster0.example.net/db"), pw},
		"redis, empty user":       {uri("redis", ":"+pw, "cache:6379"), pw},
		"no path":                 {uri("mysql", "u:"+pw, "h"), pw},
		"fragment":                {uri("https", "u:"+pw, "h#frag"), pw},
		"password holds an @":     {uri("postgres", "u:pa@ss"+pw, "h/db"), "pa@ss" + pw},
		"password holds a colon":  {uri("x", "u:p:q"+pw, "h"), "p:q" + pw},
		"percent-encoded":         {uri("postgres", "u:"+url.PathEscape("p@ss/"+pw), "h/db"), "p@ss/" + pw},
		"a plus stays a plus":     {uri("postgres", "u:a+b"+pw, "h/db"), "a+b" + pw},
		"bad escape stays as is":  {uri("postgres", "u:100%zz"+pw, "h/db"), "100%zz" + pw},
		"upper-case scheme":       {uri("HTTPS", "u:"+pw, "h"), pw},
		"trailing newline on url": {uri("postgres", "u:"+pw, "h/db") + "\n", pw},
	} {
		if got := Canonical(c.in); got != c.want {
			t.Errorf("%s: canonical form is wrong (len %d, want %d)", name, len(got), len(c.want))
		}
	}

	// The point: whichever extent an engine reports, one credential gets one fingerprint.
	k := NewEphemeral()
	whole := uri("postgres", "app:"+url.PathEscape("p@ss"+pw), "db.internal:5432/app")
	if k.FP(Canonical(whole)) != k.FP(Canonical("p@ss"+pw)) || k.FP(Canonical(whole)) != k.FP("p@ss"+pw) {
		t.Error("the whole URL and the decoded password fingerprint differently")
	}
}

func TestCanonicalLeavesEverythingElseAlone(t *testing.T) {
	token := "sk-" + randStr(t, alnum, 48)
	for name, in := range map[string]string{
		"empty":                    "",
		"a token":                  token,
		"a url without userinfo":   "https://github.com/o/r",
		"a user, no secret":        "https://user@github.com/o/r",
		"an empty secret":          "redis://u:@h:6379",
		"empty userinfo":           "https://@h/x",
		"no scheme":                "user:" + token + "@host",
		"scheme must start letter": "1abc://u:" + token + "@h",
		"scheme with a space":      "my app://u:" + token + "@h",
		"@ only in the path":       "https://h/p?email=a:b@c.example",
		"text around a url":        "see https://u:" + token + "@h/x",
		"jdbc style":               "jdbc:" + "postgresql://h/db?user=u&" + "pass" + "word=" + token,
	} {
		if got := Canonical(in); got != in {
			t.Errorf("%s: changed", name)
		}
	}
}

func TestCanonicalIsIdempotent(t *testing.T) {
	body := randStr(t, alnum+"+/", 200)
	for _, in := range []string{
		pemParts("EC "+"PRIVATE "+"KEY", body, 64, "\r\n"),
		"postgres://u:" + url.PathEscape("p@ss/"+body[:20]) + "@h/db",
		body,
	} {
		once := Canonical(in)
		if twice := Canonical(once); twice != once {
			t.Errorf("not idempotent for a %d-byte input", len(in))
		}
	}
}
