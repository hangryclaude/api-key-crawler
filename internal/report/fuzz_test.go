package report

import (
	"regexp"
	"strings"
	"testing"

	"keyguard/internal/core"
)

var allowedTags = map[string]bool{
	"html": true, "head": true, "meta": true, "title": true, "style": true, "body": true, "div": true, "header": true,
	"p": true, "h1": true, "h2": true, "h3": true, "ul": true, "li": true, "span": true, "strong": true, "a": true,
	"nav": true, "main": true, "section": true, "table": true, "caption": true, "thead": true, "tbody": true,
	"tr": true, "th": true, "td": true, "code": true, "details": true, "summary": true, "footer": true,
}

var allowedAttrs = map[string]bool{
	"class": true, "href": true, "target": true, "rel": true, "data-label": true, "scope": true, "lang": true,
	"charset": true, "name": true, "content": true, "http-equiv": true, "aria-label": true, "aria-labelledby": true, "id": true,
}

var (
	attrRe   = regexp.MustCompile(`\s([a-zA-Z-]+)=`)
	quotedRe = regexp.MustCompile(`"[^"]*"`) // an attribute value may hold spaces and equals signs
)

// FuzzRender feeds arbitrary text into every free-text field. Whatever the fields hold, the
// page must render, close every tag it opens, and use only the tags and attributes the
// template itself writes: no input may add an element or an attribute.
func FuzzRender(f *testing.F) {
	for _, seed := range []string{
		"", "plain", "<script>alert(1)</script>", "\"><img src=x onerror=alert(1)>", "javascript:alert(1)",
		"a\u202eb", "\x00\xff", "{{.Hero}}", "&amp;&lt;", "</td></tr></table><h1>x</h1>", "-->", "<!--", "'\"",
		strings.Repeat("A1b2C3d4", 30), "日本語 🙂 é", "github.com/o/n.wiki", "gist.github.com/o/" + strings.Repeat("a", 32),
		"local:/Users/me/dev/x", "refs/pull/12/head", "kg123456 NAME",
	} {
		f.Add(seed, seed, seed, int8(4), 7, seed)
	}
	f.Fuzz(func(t *testing.T, text, path, typ string, sevv int8, line int, note string) {
		ss := []core.Secret{{
			ID: text, FP: path, Type: typ, Shape: text, Len: line, Known: note, Triage: typ, TriageBy: path, TriageWhy: note,
			Severity: core.Severity(sevv), Status: []string{"open", "", "resolved", "ignored", text}[uint8(sevv)%5],
			Verified: core.Verified(typ), VerifiedAt: text, FirstSeen: path,
			Locations: []core.Location{
				{Source: text, Kind: typ, Visibility: core.Visibility(path), Ref: note, Commit: text,
					Path: path, Line: line, Author: text, Date: note, URL: text},
				{Source: "github.com/" + path + "/" + typ, Path: note, Commit: path},
			},
		}}
		run := core.RunStats{Kind: typ, Started: text, Finished: path, Notes: []string{note, text},
			Engines: map[string]core.EngineStats{typ: {Seconds: float64(line), Hits: line, Errors: line}}}
		layers := []core.LayerStatus{{Name: text, OK: line%2 == 0, Detail: note, CheckedAt: path}}

		b, err := reporter("").Render(ss, run, layers)
		if err != nil {
			t.Fatal(err)
		}
		doc := string(b)
		balanced(t, doc)
		for _, m := range tagRe.FindAllStringSubmatch(styleRe.ReplaceAllString(doc, "<style></style>"), -1) {
			if m[1] == "" && !allowedTags[strings.ToLower(m[2])] {
				t.Fatalf("an input produced a <%s> element", m[2])
			}
			for _, a := range attrRe.FindAllStringSubmatch(quotedRe.ReplaceAllString(m[3], `""`), -1) {
				if !allowedAttrs[a[1]] {
					t.Fatalf("an input produced attribute %q on <%s>", a[1], m[2])
				}
			}
		}
		if n := Summarize(ss); n.Sev != core.None && (n.Title == "" || n.Body == "") {
			t.Fatalf("Summarize returned severity %v with an empty message", n.Sev)
		}
	})
}
