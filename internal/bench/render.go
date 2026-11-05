package bench

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"fmt"
	"math/rand/v2"
	"net/url"
	"strings"
	"time"
)

// Variants are the places and encodings a secret is planted in. The first group is plain
// text in files of different kinds; the second changes how or where git holds the value.
const (
	vEnv        = "env"
	vShell      = "shell"
	vDockerfile = "dockerfile"
	vPy         = "py"
	vJS         = "js"
	vTS         = "ts"
	vGo         = "go"
	vJSON       = "json"
	vYAML       = "yaml"
	vTOML       = "toml"
	vIpynb      = "ipynb"
	vMinified   = "minified"
	vKeyFile    = "keyfile" // the secret is the whole file: id_rsa, service-account.json

	vB64     = "b64"     // base64 of the value, as in a Kubernetes Secret
	vURLEnc  = "urlenc"  // percent-encoded, as in a callback URL
	vDeleted = "deleted" // added, then removed by a later commit
	vBranch  = "branch"  // only reachable from a branch that was never merged
	vTag     = "tag"     // only reachable from a tag
	vPull    = "pull"    // only reachable from refs/pull/N/head
	vBigfile = "bigfile" // a line in a file over 1 MB
	vZip     = "zip"     // inside a zip archive
)

// slot is one assignment to write: a variable, its value, and companions.
type slot struct {
	name  string
	value string
	multi bool
	pairs []Pair
}

// rendered is a file and what is needed to find the slots in it.
type rendered struct {
	content string
	// esc maps a slot value to the text that appears in content (JSON escaping, base64...).
	esc func(string) string
	// decodes is set when engines undo esc exactly before matching (base64): the value then
	// also exists in decoded form in the engine's view of the file. Percent escapes need no
	// flag: every file is also read with them decoded.
	decodes bool
	// decode is the text an engine sees where esc(value) stood once it has decoded it, when that
	// is more than the value (a basic-auth header decodes to "user:value"). Nil means the value.
	decode func(string) string
	// inner is what an archive holds, or the text a UTF-16 file spells, for variants whose
	// content is not the text itself.
	inner string
	// archive is set when content is a compressed archive that a known-secret matcher opens
	// (the full scan expands zip, gzip and tar) and inner is what it finds inside.
	archive bool
	// opaque, when set, says why the regex engines cannot read the content: the file is UTF-16,
	// an archive format they skip, a recording that echoes a typed secret one character at a time.
	// A plant in it is undetected by design.
	opaque string
	// locate finds a value's lines when it is not one substring of the content (a recording of
	// typed keystrokes spreads it over one event per character).
	locate func(value string) (line, endLine int)
}

// decoded is what an engine sees in place of esc(value) after decoding it.
func (r rendered) decoded(value string) string {
	if r.decode != nil {
		return r.decode(value)
	}
	return value
}

func identity(s string) string { return s }

// camel turns OPENAI_API_KEY into openaiApiKey.
func camel(name string) string {
	parts := strings.Split(strings.ToLower(name), "_")
	for i := 1; i < len(parts); i++ {
		if parts[i] != "" {
			parts[i] = strings.ToUpper(parts[i][:1]) + parts[i][1:]
		}
	}
	return strings.Join(parts, "")
}

func snake(name string) string { return strings.ToLower(name) }

// goName is the exported-style identifier a Go author would pick.
func goName(name string) string {
	c := camel(name)
	return strings.ToUpper(c[:1]) + c[1:]
}

func dotenvEscape(s string) string { return strings.ReplaceAll(s, "\n", `\n`) }

// indent pads every line after the first, the way a YAML block scalar holds a PEM.
func indent(s, pad string) string { return strings.ReplaceAll(s, "\n", "\n"+pad) }

// renderFile writes the file for a variant. All slots in one file share the variant, which
// is how real leaks look: one config file with a handful of keys.
func renderFile(variant string, slots []slot, r *rand.Rand, fl *filler) rendered {
	switch variant {
	case vEnv, vDeleted, vBranch, vTag, vPull:
		return renderEnv(slots, r, fl)
	case vShell:
		return renderShell(slots, fl)
	case vDockerfile:
		return renderDockerfile(slots, fl)
	case vPy:
		return renderPy(slots, fl)
	case vJS:
		return renderJS(slots, fl, false)
	case vTS:
		return renderJS(slots, fl, true)
	case vGo:
		return renderGo(slots, fl)
	case vJSON, vKeyFile:
		return renderJSON(slots, variant == vKeyFile)
	case vYAML:
		return renderYAML(slots, fl)
	case vTOML:
		return renderTOML(slots, fl)
	case vIpynb:
		return renderIpynb(slots, fl)
	case vMinified:
		return renderMinified(slots, r, fl)
	case vB64:
		return renderB64(slots, fl)
	case vURLEnc:
		return renderURLEnc(slots, fl)
	case vBigfile:
		return renderBigfile(slots, r, fl)
	case vZip:
		return renderZip(slots, r, fl)
	}
	if rd, ok := renderAgentEra(variant, slots, r, fl); ok {
		return rd
	}
	panic("bench: unknown variant " + variant)
}

func renderEnv(slots []slot, r *rand.Rand, fl *filler) rendered {
	var b strings.Builder
	b.WriteString("# " + fl.sentence() + "\n")
	b.WriteString("NODE_ENV=production\nLOG_LEVEL=info\nPORT=" + fmt.Sprint(3000+r.IntN(5000)) + "\n")
	for _, s := range slots {
		for _, p := range s.pairs {
			b.WriteString(p.Name + "=" + p.Value + "\n")
		}
		switch {
		case s.multi:
			b.WriteString(s.name + `="` + dotenvEscape(s.value) + `"` + "\n")
		case r.IntN(3) == 0:
			b.WriteString(s.name + `="` + s.value + `"` + "\n")
		default:
			b.WriteString(s.name + "=" + s.value + "\n")
		}
	}
	b.WriteString("FEATURE_FLAGS=" + fl.word() + "," + fl.word() + "\n")
	return rendered{content: b.String(), esc: dotenvEscape}
}

func renderShell(slots []slot, fl *filler) rendered {
	var b strings.Builder
	b.WriteString("#!/usr/bin/env bash\n# " + fl.sentence() + "\nset -euo pipefail\n\n")
	for _, s := range slots {
		for _, p := range s.pairs {
			b.WriteString(`export ` + p.Name + `="` + p.Value + `"` + "\n")
		}
		if s.multi {
			b.WriteString("umask 077\ncat > \"$HOME/." + fl.word() + "_" + snake(s.name) + "\" <<'EOF'\n" + s.value + "\nEOF\n")
		} else {
			b.WriteString(`export ` + s.name + `="` + s.value + `"` + "\n")
		}
	}
	b.WriteString("\n" + strings.Join(fl.lines("sh", 4), "\n") + "\n")
	return rendered{content: b.String(), esc: identity}
}

func renderDockerfile(slots []slot, fl *filler) rendered {
	var b strings.Builder
	b.WriteString("FROM node:20-alpine AS " + fl.word() + "\nWORKDIR /app\nCOPY package*.json ./\nRUN npm ci --omit=dev\n")
	for _, s := range slots {
		for _, p := range s.pairs {
			b.WriteString("ENV " + p.Name + "=" + p.Value + "\n")
		}
		b.WriteString("ENV " + s.name + "=" + s.value + "\n")
	}
	b.WriteString("COPY . .\nEXPOSE 8080\nCMD [\"node\", \"server.js\"]\n")
	return rendered{content: b.String(), esc: identity}
}

func renderPy(slots []slot, fl *filler) rendered {
	var b strings.Builder
	b.WriteString(`"""` + fl.sentence() + `."""` + "\nimport os\n\nimport requests\n\n")
	for _, s := range slots {
		for _, p := range s.pairs {
			b.WriteString(p.Name + ` = "` + p.Value + `"` + "\n")
		}
		if s.multi {
			b.WriteString(s.name + ` = """` + s.value + "\n\"\"\"\n")
		} else {
			b.WriteString(s.name + ` = "` + s.value + `"` + "\n")
		}
	}
	b.WriteString("\n\n" + strings.Join(fl.lines("py", 6), "\n") + "\n")
	return rendered{content: b.String(), esc: identity}
}

func renderJS(slots []slot, fl *filler, ts bool) rendered {
	var b strings.Builder
	b.WriteString("// " + fl.sentence() + "\nimport fetch from 'node-fetch';\n\n")
	decl := func(name, value string, multi bool) {
		typ := ""
		if ts {
			typ = ": string"
		}
		if multi {
			b.WriteString("export const " + camel(name) + typ + " = `" + value + "\n`;\n")
		} else {
			b.WriteString("export const " + camel(name) + typ + " = '" + value + "';\n")
		}
	}
	for _, s := range slots {
		for _, p := range s.pairs {
			decl(p.Name, p.Value, false)
		}
		decl(s.name, s.value, s.multi)
	}
	b.WriteString("\n" + strings.Join(fl.lines("js", 6), "\n") + "\n")
	return rendered{content: b.String(), esc: identity}
}

func renderGo(slots []slot, fl *filler) rendered {
	var b strings.Builder
	b.WriteString("package config\n\n// " + fl.sentence() + "\nconst (\n")
	for _, s := range slots {
		for _, p := range s.pairs {
			b.WriteString("\t" + goName(p.Name) + ` = "` + p.Value + `"` + "\n")
		}
		if s.multi {
			b.WriteString("\t" + goName(s.name) + " = `" + s.value + "\n`\n")
		} else {
			b.WriteString("\t" + goName(s.name) + ` = "` + s.value + `"` + "\n")
		}
	}
	b.WriteString(")\n\n" + strings.Join(fl.lines("go", 6), "\n") + "\n")
	return rendered{content: b.String(), esc: identity}
}

func renderJSON(slots []slot, whole bool) rendered {
	if whole && len(slots) == 1 && slots[0].multi {
		// A key file or a service-account file is the value itself.
		return rendered{content: slots[0].value + "\n", esc: identity}
	}
	var b strings.Builder
	b.WriteString("{\n")
	var entries []string
	for _, s := range slots {
		for _, p := range s.pairs {
			entries = append(entries, "  "+jsonString(p.Name)+": "+jsonString(p.Value))
		}
		entries = append(entries, "  "+jsonString(s.name)+": "+jsonString(s.value))
	}
	entries = append(entries, `  "retries": 3`)
	b.WriteString(strings.Join(entries, ",\n") + "\n}\n")
	return rendered{content: b.String(), esc: jsonEscaped}
}

func renderYAML(slots []slot, fl *filler) rendered {
	var b strings.Builder
	b.WriteString("# " + fl.sentence() + "\nreplicaCount: 2\nimage:\n  repository: registry.internal/" + fl.word() + "\n  tag: \"1.4.2\"\nenv:\n")
	multiSeen := false
	for _, s := range slots {
		for _, p := range s.pairs {
			b.WriteString("  " + p.Name + ": " + p.Value + "\n")
		}
		if s.multi {
			multiSeen = true
			b.WriteString("  " + s.name + ": |\n    " + indent(s.value, "    ") + "\n")
		} else {
			b.WriteString("  " + s.name + ": " + s.value + "\n")
		}
	}
	b.WriteString("resources:\n  limits:\n    cpu: 500m\n")
	esc := identity
	if multiSeen {
		esc = func(s string) string { return indent(s, "    ") }
	}
	return rendered{content: b.String(), esc: esc}
}

func renderTOML(slots []slot, fl *filler) rendered {
	var b strings.Builder
	b.WriteString("# " + fl.sentence() + "\n[app]\nname = \"" + fl.word() + "\"\nworkers = 4\n\n[credentials]\n")
	for _, s := range slots {
		for _, p := range s.pairs {
			b.WriteString(snake(p.Name) + ` = "` + p.Value + `"` + "\n")
		}
		if s.multi {
			b.WriteString(snake(s.name) + " = '''\n" + s.value + "\n'''\n")
		} else {
			b.WriteString(snake(s.name) + ` = "` + s.value + `"` + "\n")
		}
	}
	return rendered{content: b.String(), esc: identity}
}

// renderIpynb writes a notebook whose code cell assigns the values and whose output cell
// echoes them, the way a debugging session leaves them.
func renderIpynb(slots []slot, fl *filler) rendered {
	var src, out []string
	src = append(src, "import os\n", "import requests\n", "\n")
	for _, s := range slots {
		for _, p := range s.pairs {
			src = append(src, p.Name+` = "`+p.Value+`"`+"\n")
		}
		src = append(src, s.name+` = "`+s.value+`"`+"\n")
	}
	src = append(src, "print(len("+slots[0].name+"))\n")
	out = append(out, fmt.Sprintf("%d\n", len(slots[0].value)))
	enc := func(lines []string) string {
		var parts []string
		for _, l := range lines {
			parts = append(parts, "    "+jsonString(l))
		}
		return strings.Join(parts, ",\n")
	}
	var b strings.Builder
	b.WriteString("{\n \"cells\": [\n  {\n   \"cell_type\": \"markdown\",\n   \"metadata\": {},\n   \"source\": [\n    " +
		jsonString("# "+fl.sentence()) + "\n   ]\n  },\n  {\n   \"cell_type\": \"code\",\n   \"execution_count\": 3,\n   \"metadata\": {},\n   \"outputs\": [\n    {\n     \"name\": \"stdout\",\n     \"output_type\": \"stream\",\n     \"text\": [\n  ")
	b.WriteString(enc(out) + "\n     ]\n    }\n   ],\n   \"source\": [\n" + enc(src) + "\n   ]\n  }\n ],\n \"metadata\": {\n  \"kernelspec\": {\n   \"display_name\": \"Python 3\",\n   \"language\": \"python\",\n   \"name\": \"python3\"\n  }\n },\n \"nbformat\": 4,\n \"nbformat_minor\": 5\n}\n")
	return rendered{content: b.String(), esc: jsonEscaped}
}

// renderMinified is a bundler's output: one long line, with the environment inlined by a
// DefinePlugin-style replacement as object properties.
func renderMinified(slots []slot, r *rand.Rand, fl *filler) rendered {
	var b strings.Builder
	b.WriteString("!function(e){var t={};function n(r){if(t[r])return t[r].exports;var o=t[r]={i:r,l:!1,exports:{}};return e[r].call(o.exports,o,o.exports,n),o.l=!0,o.exports}")
	b.WriteString(minifiedNoise(r, 2500))
	b.WriteString(`n.env={`)
	for i, s := range slots {
		if i > 0 {
			b.WriteString(",")
		}
		for _, p := range s.pairs {
			b.WriteString(p.Name + `:"` + p.Value + `",`)
		}
		b.WriteString(s.name + `:"` + s.value + `"`)
	}
	b.WriteString(`},`)
	b.WriteString(minifiedNoise(r, 2500))
	b.WriteString("n(n.s=0)}([function(e,t){e.exports=" + fl.word() + "}]);\n")
	return rendered{content: b.String(), esc: identity}
}

// minifiedNoise is bundler-looking code: short identifiers, no words, no secrets.
func minifiedNoise(r *rand.Rand, n int) string {
	var b strings.Builder
	for b.Len() < n {
		a, c := lower[r.IntN(26)], lower[r.IntN(26)]
		fmt.Fprintf(&b, "n.d=function(%c,%c){return %c&&%c.length?%c.map(function(t){return t+%d}):[]},", a, c, a, a, a, r.IntN(900))
	}
	return b.String()
}

// renderB64 is a Kubernetes Secret: each value is the base64 of the plain text.
func renderB64(slots []slot, fl *filler) rendered {
	var b strings.Builder
	b.WriteString("apiVersion: v1\nkind: Secret\nmetadata:\n  name: " + fl.word() + "-credentials\n  namespace: prod\ntype: Opaque\ndata:\n")
	for _, s := range slots {
		for _, p := range s.pairs {
			b.WriteString("  " + p.Name + ": " + base64.StdEncoding.EncodeToString([]byte(p.Value)) + "\n")
		}
		b.WriteString("  " + s.name + ": " + base64.StdEncoding.EncodeToString([]byte(s.value)) + "\n")
	}
	return rendered{content: b.String(), esc: func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }, decodes: true}
}

// renderURLEnc is a shell script that calls a webhook with the value in the query string.
func renderURLEnc(slots []slot, fl *filler) rendered {
	var b strings.Builder
	b.WriteString("#!/usr/bin/env bash\n# " + fl.sentence() + "\n")
	for _, s := range slots {
		b.WriteString(`curl -fsS -X POST "https://hooks.` + fl.word() + `.dev/ingest?` + snake(s.name) + `=` + url.QueryEscape(s.value) + `&env=prod"` + "\n")
	}
	return rendered{content: b.String(), esc: url.QueryEscape}
}

// renderBigfile is a service log over 1 MB with the value printed near the end, where a
// scanner that stops early or skips large files would never look.
func renderBigfile(slots []slot, r *rand.Rand, fl *filler) rendered {
	base := time.Date(2024, 5, 1, 0, 0, 0, 0, time.UTC)
	var b strings.Builder
	line := func(i int) {
		fmt.Fprintf(&b, "%s INFO  [%s] %s id=%d took=%dms\n", base.Add(time.Duration(i)*time.Second).Format("2006-01-02T15:04:05Z"),
			fl.word(), fl.sentence(), r.IntN(1_000_000), r.IntN(900))
	}
	i := 0
	for b.Len() < 1_300_000 {
		line(i)
		i++
	}
	for _, s := range slots {
		for _, p := range s.pairs {
			fmt.Fprintf(&b, "%s DEBUG [config] loaded %s=%s\n", base.Add(time.Duration(i)*time.Second).Format("2006-01-02T15:04:05Z"), p.Name, p.Value)
		}
		fmt.Fprintf(&b, "%s DEBUG [config] loaded %s=%s\n", base.Add(time.Duration(i)*time.Second).Format("2006-01-02T15:04:05Z"), s.name, s.value)
		i++
	}
	for j := 0; j < 400; j++ {
		line(i)
		i++
	}
	return rendered{content: b.String(), esc: identity}
}

// renderZip packs an .env into a deterministic archive (fixed times, no extra fields).
func renderZip(slots []slot, r *rand.Rand, fl *filler) rendered {
	inner := renderEnv(slots, r, fl)
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	h := &zip.FileHeader{Name: ".env", Method: zip.Deflate}
	h.Modified = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	w, err := zw.CreateHeader(h)
	if err != nil {
		panic(err)
	}
	if _, err := w.Write([]byte(inner.content)); err != nil {
		panic(err)
	}
	if err := zw.Close(); err != nil {
		panic(err)
	}
	return rendered{content: buf.String(), esc: inner.esc, inner: inner.content, archive: true}
}
