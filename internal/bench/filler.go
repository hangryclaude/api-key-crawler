package bench

import (
	"fmt"
	"math/rand/v2"
	"strings"
)

// The filler is the code and prose a real repository is mostly made of. It draws from a
// vocabulary with no security words in it (nothing containing key, token, secret, pass,
// auth, cred or api), so every engine hit on it is a false positive the bench can count
// rather than a plant it forgot about.
var vocab = strings.Fields(`adapter alpha anchor archive arrow atlas badge balance banner basket beacon binder bridge
buffer bundle cabinet cache canvas carbon carrier catalog channel chart circuit cluster cobalt column compass console
content context cursor dashboard delta device dialog digest dispatch domain driver editor element engine entry
envelope event exporter fabric feature field filter finder fixture flight folder format frame gateway glyph graph
grid handler harbor header helper hub index ingest input inspector journal kernel label ladder layer ledger legend
library lifecycle listener loader locator logger manifest mapper marker matrix memory merger message meta metric
mirror module monitor native network node notice object observer offset option origin output packet pager palette
panel parser partner pattern payload phase pipeline pixel planner plugin pointer policy pool portal preview printer
process profile program project protocol provider proxy publisher query queue quota range reader record registry
relay render replica report request resolver resource response result router runner sampler scanner schedule
schema scope script search segment selector sender sensor sequence server service shard signal snapshot socket
source spinner stage state status storage stream string summary switch symbol table target task template tenant
terminal theme thread ticket timeline timer toggle tracker traffic transfer tree trigger tunnel unit updater
upload usage vector version viewer volume watcher widget window worker wrapper writer zone`)

var verbs = strings.Fields(`refresh validate merge flush rebuild resolve normalize collect schedule compact retry index
split render prune sync batch record replay migrate archive estimate balance compose route trace sample`)

var adverbs = []string{"before the next run", "after startup", "on every request", "for the nightly job", "when the queue drains",
	"once the cache is warm", "per tenant", "until the deadline", "with a bounded buffer", "without blocking the loop"}

type filler struct {
	r *rand.Rand
}

func (f *filler) word() string { return vocab[f.r.IntN(len(vocab))] }

func (f *filler) verb() string { return verbs[f.r.IntN(len(verbs))] }

func (f *filler) ident() string { return f.word() + "_" + f.word() }

func (f *filler) pascal() string {
	a, b := f.word(), f.word()
	return strings.ToUpper(a[:1]) + a[1:] + strings.ToUpper(b[:1]) + b[1:]
}

func (f *filler) sentence() string {
	return fmt.Sprintf("%s the %s %s", f.verb(), f.word(), adverbs[f.r.IntN(len(adverbs))])
}

func (f *filler) message() string {
	kind := []string{"feat", "fix", "chore", "refactor", "docs", "test", "perf"}[f.r.IntN(7)]
	return fmt.Sprintf("%s(%s): %s", kind, f.word(), f.sentence())
}

// path picks a plausible location for a new file of the given extension.
func (f *filler) path(ext string) string {
	name := f.ident()
	switch ext {
	case "py":
		return fmt.Sprintf("services/%s/%s.py", f.word(), name)
	case "js":
		return fmt.Sprintf("web/src/%s/%s.js", f.word(), name)
	case "ts":
		return fmt.Sprintf("web/src/%s/%s.ts", f.word(), f.word())
	case "go":
		return fmt.Sprintf("internal/%s/%s.go", f.word(), f.word())
	case "sh":
		return fmt.Sprintf("scripts/%s.sh", name)
	case "md":
		return fmt.Sprintf("docs/%s/%s.md", f.word(), f.word())
	case "json":
		return fmt.Sprintf("data/%s/%s.json", f.word(), f.word())
	case "yaml":
		return fmt.Sprintf("deploy/%s/%s.yaml", f.word(), f.word())
	case "css":
		return fmt.Sprintf("web/styles/%s.css", f.word())
	case "sql":
		return fmt.Sprintf("db/migrations/%03d_%s.sql", f.r.IntN(999), f.word())
	case "toml":
		return fmt.Sprintf("config/%s.toml", f.word())
	case "html":
		return fmt.Sprintf("web/templates/%s.html", f.word())
	case "csv":
		return fmt.Sprintf("data/%s/%s.csv", f.word(), f.word())
	}
	return fmt.Sprintf("misc/%s.%s", name, ext)
}

var codeExts = []string{"py", "py", "py", "js", "js", "ts", "ts", "go", "go", "sh", "md", "md", "json", "yaml", "css", "sql", "toml", "html", "csv"}

func (f *filler) randomExt() string { return codeExts[f.r.IntN(len(codeExts))] }

// lines returns n lines of neutral code or prose in the language.
func (f *filler) lines(ext string, n int) []string {
	var out []string
	for len(out) < n {
		out = append(out, f.block(ext)...)
	}
	return out[:n]
}

func (f *filler) block(ext string) []string {
	fn, a, b, c := f.ident(), f.word(), f.word(), f.word()
	switch ext {
	case "py":
		return []string{
			"def " + fn + "(" + a + ", " + b + "=None):",
			`    """` + f.sentence() + `."""`,
			"    " + c + " = " + a + "." + f.verb() + "()",
			`    logger.info("` + f.sentence() + `: %s", ` + c + ")",
			"    return " + c,
			"",
		}
	case "js", "ts":
		typ := ""
		if ext == "ts" {
			typ = ": number"
		}
		return []string{
			"export function " + camel(fn) + "(" + a + ", " + b + ") {",
			"  const " + c + " = " + a + "." + f.verb() + "(" + b + ");",
			"  if (!" + c + ") return " + fmt.Sprint(f.r.IntN(100)) + ";",
			"  return " + c + ".length" + typ + ";",
			"}",
			"",
		}
	case "go":
		return []string{
			"// " + f.pascal() + " " + f.sentence() + ".",
			"func " + f.pascal() + "(" + a + " string, " + b + " int) (int, error) {",
			"\tif " + b + " < 0 {",
			"\t\treturn 0, fmt.Errorf(\"" + a + ": negative " + b + " %d\", " + b + ")",
			"\t}",
			"\treturn len(" + a + ") + " + b + ", nil",
			"}",
			"",
		}
	case "sh":
		return []string{
			"# " + f.sentence(),
			`mkdir -p "$ROOT/` + a + `/` + b + `"`,
			`for f in "$ROOT"/` + a + `/*.log; do gzip -9 "$f"; done`,
			`echo "` + f.sentence() + `"`,
		}
	case "md":
		return []string{
			"## " + strings.ToUpper(a[:1]) + a[1:] + " " + b,
			"",
			"The " + a + " " + f.verb() + "s the " + b + " " + adverbs[f.r.IntN(len(adverbs))] + ". See the " + c + " section.",
			"",
			"- " + f.sentence(),
			"- " + f.sentence(),
			"",
		}
	case "json":
		return []string{
			`  {"id": ` + fmt.Sprint(f.r.IntN(100000)) + `, "name": "` + a + `-` + b + `", "weight": ` + fmt.Sprintf("%.2f", f.r.Float64()*10) + `, "tags": ["` + c + `", "` + f.word() + `"]},`,
		}
	case "yaml":
		return []string{
			a + ":",
			"  enabled: " + []string{"true", "false"}[f.r.IntN(2)],
			"  interval: " + fmt.Sprint(5+f.r.IntN(55)) + "s",
			"  target: " + b + "-" + c,
		}
	case "css":
		return []string{
			"." + a + "-" + b + " {",
			"  color: #" + fmt.Sprintf("%06x", f.r.IntN(0xffffff)) + ";",
			"  margin: " + fmt.Sprint(f.r.IntN(32)) + "px " + fmt.Sprint(f.r.IntN(32)) + "px;",
			"}",
			"",
		}
	case "sql":
		return []string{
			"CREATE TABLE " + a + "_" + b + " (",
			"  id BIGSERIAL PRIMARY KEY,",
			"  " + c + " TEXT NOT NULL,",
			"  created_at TIMESTAMPTZ NOT NULL DEFAULT now()",
			");",
			"",
		}
	case "toml":
		return []string{
			"[" + a + "." + b + "]",
			"enabled = " + []string{"true", "false"}[f.r.IntN(2)],
			"retries = " + fmt.Sprint(f.r.IntN(9)),
			`name = "` + c + `"`,
			"",
		}
	case "html":
		return []string{
			`<section class="` + a + `">`,
			"  <h2>" + strings.ToUpper(b[:1]) + b[1:] + "</h2>",
			"  <p>" + f.sentence() + ".</p>",
			"</section>",
		}
	case "csv":
		return []string{fmt.Sprintf("%d,%s,%s,%.3f", f.r.IntN(100000), a, b, f.r.Float64()*100)}
	}
	return []string{f.sentence()}
}

// file returns a whole new file of about n lines.
func (f *filler) file(ext string, n int) string {
	var head []string
	switch ext {
	case "py":
		head = []string{`"""` + f.sentence() + `."""`, "import logging", "", "logger = logging.getLogger(__name__)", "", ""}
	case "js":
		head = []string{"// " + f.sentence(), "import { " + f.word() + " } from './" + f.word() + "';", ""}
	case "ts":
		head = []string{"// " + f.sentence(), "import type { " + f.pascal() + " } from './types';", ""}
	case "go":
		head = []string{"package " + f.word(), "", `import "fmt"`, ""}
	case "sh":
		head = []string{"#!/usr/bin/env bash", "set -euo pipefail", `ROOT="${ROOT:-/srv}"`, ""}
	case "md":
		head = []string{"# " + f.pascal(), ""}
	case "json":
		head = []string{"["}
	case "yaml":
		head = []string{"# " + f.sentence()}
	case "html":
		head = []string{"<!doctype html>", "<html>", "<body>"}
	case "csv":
		head = []string{"id,group,label,score"}
	}
	body := f.lines(ext, n)
	if ext == "json" {
		body[len(body)-1] = strings.TrimSuffix(body[len(body)-1], ",")
		body = append(body, "]")
	}
	if ext == "html" {
		body = append(body, "</body>", "</html>")
	}
	return strings.Join(append(head, body...), "\n") + "\n"
}

// mutate edits a file the way a day of work does: usually append a block, sometimes
// rewrite a few lines in place.
func (f *filler) mutate(content, ext string) string {
	ls := strings.Split(strings.TrimRight(content, "\n"), "\n")
	if f.r.IntN(10) < 6 || len(ls) < 8 {
		return strings.Join(append(ls, f.lines(ext, 4+f.r.IntN(14))...), "\n") + "\n"
	}
	at := 2 + f.r.IntN(len(ls)-4)
	span := 1 + f.r.IntN(min(5, len(ls)-at-1))
	repl := f.lines(ext, span)
	out := append(append(append([]string{}, ls[:at]...), repl...), ls[at+span:]...)
	return strings.Join(out, "\n") + "\n"
}
