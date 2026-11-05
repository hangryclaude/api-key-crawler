package bench

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"math/rand/v2"
	"path"
	"strings"
	"time"
	"unicode/utf16"
)

// The agent-era placements of docs/STEAL.md section 4.3 (P0-26): the files and git metadata that
// AI tools, API clients, browsers and infrastructure tooling leave a secret in, none of which a
// .env-shaped corpus exercises.
const (
	vMCP       = "mcp"        // .mcp.json: the env block of an MCP server
	vClaudeEnv = "claude-env" // .claude/settings.json: the env block
	vCodex     = "codex"      // .codex/config.toml: an http_headers entry and a server's env table
	vHAR       = "har"        // a HAR capture: an x-api-key request header
	vPWState   = "pwstate"    // a Playwright storage state: a localStorage entry
	vCookies   = "cookies"    // a Netscape cookies.txt export
	vPostman   = "postman"    // a Postman environment
	vNbOut     = "nb-output"  // a notebook cell that printed the value
	vTFState   = "tfstate"    // terraform.tfstate: a Lambda's environment
	vWPConfig  = "wpconfig"   // wp-config.php
	vCast      = "cast"       // an asciinema recording of a pasted export
	vB64Basic  = "b64-basic"  // base64 of user:SECRET, as a Docker config or a Basic header holds it

	vCastTyped  = "cast-typed"  // a recording of the same export typed, echoed one character per event
	vUTF16      = "utf16"       // a UTF-16 file
	vTGZ        = "tgz"         // a .tgz archive
	vJAR        = "jar"         // a .jar archive
	vRename     = "rename"      // a commit that renames a file and adds the value in the same change
	vCommitMsg  = "commit-msg"  // the message of a commit
	vTagMsg     = "tag-msg"     // the annotation of a tag
	vBranchName = "branch-name" // the name of a branch
	vTwin       = "twin"        // a valid value beside its invalid twins
)

// agentPool is the placements every single-line format rotates through, three each, so that a
// format is planted in six or more places: the .env, two of the original rotation and three of
// these. They are all text an engine reads; the special placements below are not.
var agentPool = []string{vMCP, vClaudeEnv, vCodex, vHAR, vPWState, vCookies, vPostman, vNbOut, vTFState, vWPConfig, vCast, vB64Basic}

// jsonPool is where a value that spans lines can sit: inside a JSON string, newlines escaped.
var jsonPool = []string{vMCP, vTFState, vPostman}

// specialPool is the placements that one format in eight takes, each a different way for a
// scanner to be blind: git metadata, an encoding, a container, a rename.
var specialPool = []string{vCommitMsg, vTagMsg, vBranchName, vUTF16, vTGZ, vJAR, vRename, vCastTyped}

func jsonEntries(slots []slot, indent string) string {
	var out []string
	for _, s := range slots {
		for _, p := range s.pairs {
			out = append(out, indent+jsonString(p.Name)+": "+jsonString(p.Value))
		}
		out = append(out, indent+jsonString(s.name)+": "+jsonString(s.value))
	}
	return strings.Join(out, ",\n")
}

// agentPath names the file a placement writes. n keeps paths unique, w is a filler word.
func agentPath(variant string, n int, w string) (string, bool) {
	dir := fmt.Sprintf("%s-%d", w, n)
	switch variant {
	case vMCP:
		return path.Join("agents", dir, ".mcp.json"), true
	case vClaudeEnv:
		return path.Join("agents", dir, ".claude", "settings.json"), true
	case vCodex:
		return path.Join("agents", dir, ".codex", "config.toml"), true
	case vHAR:
		return path.Join("captures", dir, "trace.har"), true
	case vPWState:
		return path.Join("e2e", dir, "playwright", ".auth", "user.json"), true
	case vCookies:
		return path.Join("captures", dir, "cookies.txt"), true
	case vPostman:
		return path.Join("api", dir, "dev.postman_environment.json"), true
	case vNbOut:
		return path.Join("notebooks", dir+"-run.ipynb"), true
	case vTFState:
		return path.Join("infra", dir, "terraform.tfstate"), true
	case vWPConfig:
		return path.Join("sites", dir, "wp-config.php"), true
	case vCast:
		return path.Join("recordings", dir, "session.cast"), true
	case vCastTyped:
		return path.Join("recordings", dir, "typed.cast"), true
	case vB64Basic:
		return path.Join("deploy", dir, ".dockerconfigjson"), true
	case vUTF16:
		return path.Join("legacy", dir, "settings.env"), true
	case vTGZ:
		return path.Join("backups", dir, "config.tgz"), true
	case vJAR:
		return path.Join("libs", dir, "app-config.jar"), true
	case vRename:
		return path.Join("services", dir, "renamed.env"), true
	case vTwin:
		return path.Join("twins", dir, ".env"), true
	}
	return "", false
}

func renderAgentEra(variant string, slots []slot, r *rand.Rand, fl *filler) (rendered, bool) {
	switch variant {
	case vMCP:
		return renderMCP(slots, fl), true
	case vClaudeEnv:
		return renderClaudeEnv(slots), true
	case vCodex:
		return renderCodex(slots, fl), true
	case vHAR:
		return renderHAR(slots, fl), true
	case vPWState:
		return renderPWState(slots, fl), true
	case vCookies:
		return renderCookies(slots, fl), true
	case vPostman:
		return renderPostman(slots, fl), true
	case vNbOut:
		return renderNbOut(slots, fl), true
	case vTFState:
		return renderTFState(slots, fl), true
	case vWPConfig:
		return renderWPConfig(slots, fl), true
	case vCast:
		return renderCast(slots), true
	case vCastTyped:
		return renderCastTyped(slots), true
	case vB64Basic:
		return renderB64Basic(slots, fl), true
	case vUTF16:
		return renderUTF16(slots, r, fl), true
	case vTGZ:
		return renderTGZ(slots, r, fl), true
	case vJAR:
		return renderJAR(slots), true
	case vRename:
		// padded, so adding the secrets leaves the file similar enough for git to see a rename
		e := renderEnv(slots, r, fl)
		e.content += "\n" + strings.Join(fl.lines("sh", 40), "\n") + "\n"
		return e, true
	case vTwin:
		return renderTwin(slots, fl), true
	}
	return rendered{}, false
}

func renderMCP(slots []slot, fl *filler) rendered {
	name := fl.word()
	b := "{\n  \"mcpServers\": {\n    " + jsonString(name) + ": {\n      \"command\": \"npx\",\n      \"args\": [\"-y\", " +
		jsonString(name+"-mcp") + "],\n      \"env\": {\n" + jsonEntries(slots, "        ") + "\n      }\n    }\n  }\n}\n"
	return rendered{content: b, esc: jsonEscaped}
}

func renderClaudeEnv(slots []slot) rendered {
	b := "{\n  \"permissions\": {\n    \"allow\": [\"Bash(npm run test:*)\"]\n  },\n  \"env\": {\n" + jsonEntries(slots, "    ") +
		"\n  },\n  \"includeCoAuthoredBy\": false\n}\n"
	return rendered{content: b, esc: jsonEscaped}
}

// renderCodex puts the first value in an http_headers entry, where Codex takes a literal
// header, and the rest in the server's env table: the two forms docs/STEAL.md 4.2 calls leaks.
func renderCodex(slots []slot, fl *filler) rendered {
	name := fl.word()
	var b strings.Builder
	fmt.Fprintf(&b, "model = \"gpt-5\"\napproval_policy = \"on-request\"\n\n[mcp_servers.%s]\ncommand = \"npx\"\nargs = [\"-y\", \"%s-mcp\"]\n", name, name)
	rest := slots
	if len(slots) > 0 && !slots[0].multi {
		first := slots[0]
		fmt.Fprintf(&b, "http_headers = { \"x-api-key\" = \"%s\" }\n", first.value)
		for _, p := range first.pairs {
			fmt.Fprintf(&b, "# %s = \"%s\"\n", p.Name, p.Value)
		}
		rest = slots[1:]
	}
	if len(rest) > 0 {
		fmt.Fprintf(&b, "\n[mcp_servers.%s.env]\n", name)
		for _, s := range rest {
			for _, p := range s.pairs {
				fmt.Fprintf(&b, "%s = \"%s\"\n", p.Name, p.Value)
			}
			fmt.Fprintf(&b, "%s = \"%s\"\n", s.name, s.value)
		}
	}
	return rendered{content: b.String(), esc: identity}
}

func renderHAR(slots []slot, fl *filler) rendered {
	var entries []string
	for i, s := range slots {
		hdr := []string{`            {"name": "accept", "value": "application/json"}`}
		for _, p := range s.pairs {
			hdr = append(hdr, `            {"name": `+jsonString("x-"+strings.ToLower(strings.ReplaceAll(p.Name, "_", "-")))+`, "value": `+jsonString(p.Value)+`}`)
		}
		hdr = append(hdr, `            {"name": "x-api-key", "value": `+jsonString(s.value)+`}`)
		entries = append(entries, fmt.Sprintf(`        {
          "startedDateTime": "2024-05-01T10:%02d:00.000Z",
          "request": {
            "method": "GET",
            "url": "https://api.%s.dev/v1/me",
            "headers": [
%s
            ]
          },
          "response": {"status": 200, "content": {"mimeType": "application/json", "size": 2}}
        }`, i, fl.word(), strings.Join(hdr, ",\n")))
	}
	b := "{\n  \"log\": {\n    \"version\": \"1.2\",\n    \"creator\": {\"name\": \"WebInspector\", \"version\": \"537.36\"},\n    \"entries\": [\n" +
		strings.Join(entries, ",\n") + "\n    ]\n  }\n}\n"
	return rendered{content: b, esc: jsonEscaped}
}

func renderPWState(slots []slot, fl *filler) rendered {
	var items []string
	for _, s := range slots {
		for _, p := range s.pairs {
			items = append(items, `        {"name": `+jsonString(snake(p.Name))+`, "value": `+jsonString(p.Value)+`}`)
		}
		items = append(items, `        {"name": `+jsonString(snake(s.name))+`, "value": `+jsonString(s.value)+`}`)
	}
	b := "{\n  \"cookies\": [],\n  \"origins\": [\n    {\n      \"origin\": \"https://app." + fl.word() + ".dev\",\n      \"localStorage\": [\n" +
		strings.Join(items, ",\n") + "\n      ]\n    }\n  ]\n}\n"
	return rendered{content: b, esc: jsonEscaped}
}

func renderCookies(slots []slot, fl *filler) rendered {
	var b strings.Builder
	b.WriteString("# Netscape HTTP Cookie File\n# This file was generated by a browser export. Edit at your own risk.\n\n")
	domain := "." + fl.word() + ".dev"
	for _, s := range slots {
		for _, p := range s.pairs {
			fmt.Fprintf(&b, "%s\tTRUE\t/\tTRUE\t1795000000\t%s\t%s\n", domain, snake(p.Name), p.Value)
		}
		fmt.Fprintf(&b, "%s\tTRUE\t/\tTRUE\t1795000000\t%s\t%s\n", domain, snake(s.name), s.value)
	}
	return rendered{content: b.String(), esc: identity}
}

func renderPostman(slots []slot, fl *filler) rendered {
	var items []string
	add := func(name, value string) {
		items = append(items, `    {"key": `+jsonString(name)+`, "value": `+jsonString(value)+`, "type": "secret", "enabled": true}`)
	}
	for _, s := range slots {
		for _, p := range s.pairs {
			add(p.Name, p.Value)
		}
		add(s.name, s.value)
	}
	b := "{\n  \"id\": \"" + hexOf(fl.r, 32) + "\",\n  \"name\": " + jsonString(fl.word()+" dev") +
		",\n  \"values\": [\n" + strings.Join(items, ",\n") + "\n  ],\n  \"_postman_variable_scope\": \"environment\"\n}\n"
	return rendered{content: b, esc: jsonEscaped}
}

// renderNbOut is a notebook whose cell printed the value, so it sits bare in an output with no
// variable name beside it.
func renderNbOut(slots []slot, fl *filler) rendered {
	var src, out []string
	src = append(src, jsonString("import os\n"))
	for _, s := range slots {
		for _, p := range s.pairs {
			src = append(src, jsonString("print(os.environ["+jsonString(p.Name)+"])\n"))
			out = append(out, jsonString(p.Value+"\n"))
		}
		src = append(src, jsonString("print(os.environ["+jsonString(s.name)+"])\n"))
		out = append(out, jsonString(s.value+"\n"))
	}
	ind := func(xs []string) string { return "    " + strings.Join(xs, ",\n    ") }
	b := "{\n \"cells\": [\n  {\n   \"cell_type\": \"markdown\",\n   \"metadata\": {},\n   \"source\": [\n    " + jsonString("# "+fl.sentence()) +
		"\n   ]\n  },\n  {\n   \"cell_type\": \"code\",\n   \"execution_count\": 7,\n   \"metadata\": {},\n   \"outputs\": [\n    {\n     \"name\": \"stdout\",\n     \"output_type\": \"stream\",\n     \"text\": [\n" +
		strings.ReplaceAll(ind(out), "\n    ", "\n     ") + "\n     ]\n    }\n   ],\n   \"source\": [\n" + ind(src) +
		"\n   ]\n  }\n ],\n \"metadata\": {},\n \"nbformat\": 4,\n \"nbformat_minor\": 5\n}\n"
	return rendered{content: b, esc: jsonEscaped}
}

// renderTFState is the state of a Lambda whose environment holds the value, which is where
// Terraform keeps a secret it was given: in plain JSON, as it was passed in.
func renderTFState(slots []slot, fl *filler) rendered {
	b := "{\n  \"version\": 4,\n  \"terraform_version\": \"1.9.5\",\n  \"serial\": 14,\n  \"resources\": [\n    {\n      \"mode\": \"managed\",\n      \"type\": \"aws_lambda_function\",\n      \"name\": " +
		jsonString(fl.word()) + ",\n      \"instances\": [\n        {\n          \"attributes\": {\n            \"runtime\": \"nodejs20.x\",\n            \"timeout\": 30,\n            \"environment\": [\n              {\n                \"variables\": {\n" +
		jsonEntries(slots, "                  ") + "\n                }\n              }\n            ]\n          }\n        }\n      ]\n    }\n  ]\n}\n"
	return rendered{content: b, esc: jsonEscaped}
}

func renderWPConfig(slots []slot, fl *filler) rendered {
	var b strings.Builder
	fmt.Fprintf(&b, "<?php\ndefine( 'DB_NAME', '%s' );\ndefine( 'DB_USER', '%s' );\ndefine( 'DB_HOST', 'localhost' );\ndefine( 'DB_CHARSET', 'utf8mb4' );\n", fl.word(), fl.word())
	for _, s := range slots {
		for _, p := range s.pairs {
			fmt.Fprintf(&b, "define( '%s', '%s' );\n", p.Name, p.Value)
		}
		fmt.Fprintf(&b, "define( '%s', '%s' );\n", s.name, s.value)
	}
	b.WriteString("$table_prefix = 'wp_';\nif ( ! defined( 'ABSPATH' ) ) {\n\tdefine( 'ABSPATH', __DIR__ . '/' );\n}\nrequire_once ABSPATH . 'wp-settings.php';\n")
	return rendered{content: b.String(), esc: identity}
}

const castHeader = `{"version": 2, "width": 80, "height": 24, "timestamp": 1700000000, "env": {"SHELL": "/bin/zsh"}}`

// renderCast is an asciinema v2 recording of a session where the export was pasted: the whole
// command arrives in one output event, so a scanner reading the file sees it.
func renderCast(slots []slot) rendered {
	lines := []string{castHeader, `[0.103, "o", "$ "]`}
	t := 0.5
	for _, s := range slots {
		for _, p := range s.pairs {
			lines = append(lines, fmt.Sprintf(`[%.3f, "o", %s]`, t, jsonString("export "+p.Name+"="+p.Value+"\r\n")))
			t += 0.4
		}
		lines = append(lines, fmt.Sprintf(`[%.3f, "o", %s]`, t, jsonString("export "+s.name+"="+s.value+"\r\n")))
		t += 0.4
	}
	return rendered{content: strings.Join(lines, "\n") + "\n", esc: jsonEscaped}
}

// renderCastTyped is the same export typed at the keyboard. The terminal echoes each key as its
// own output event, so the file holds the value one character per line and no scanner sees it
// (docs/STEAL.md P1-24: 0 of 4 engines on a typed token, 4 of 4 on the same token pasted).
func renderCastTyped(slots []slot) rendered {
	lines := []string{castHeader, `[0.103, "o", "$ "]`}
	spans := map[string][2]int{}
	t := 0.5
	for _, s := range slots {
		for _, p := range s.pairs {
			lines = append(lines, fmt.Sprintf(`[%.3f, "o", %s]`, t, jsonString("export "+p.Name+"="+p.Value+"\r\n")))
			t += 0.4
		}
		for _, c := range "export " + s.name + "=" {
			lines = append(lines, fmt.Sprintf(`[%.3f, "o", %s]`, t, jsonString(string(c))))
			t += 0.07
		}
		first := len(lines) + 1
		for _, c := range s.value {
			lines = append(lines, fmt.Sprintf(`[%.3f, "o", %s]`, t, jsonString(string(c))))
			t += 0.07
		}
		spans[s.value] = [2]int{first, len(lines)}
		lines = append(lines, fmt.Sprintf(`[%.3f, "o", "\r\n"]`, t))
		t += 0.4
	}
	return rendered{
		content: strings.Join(lines, "\n") + "\n",
		esc:     identity,
		opaque:  "a typed secret is echoed one character per event, so the recording never holds it in one piece",
		locate:  func(v string) (int, int) { sp := spans[v]; return sp[0], sp[1] },
	}
}

// basicUser is the user of the basic-auth pair. Its length leaves the secret three bytes into a
// base64 group, so the encoded text differs from the base64 of the bare secret and a matcher
// that only registered that one would miss it (docs/STEAL.md P1-16).
const basicUser = "svc"

func renderB64Basic(slots []slot, fl *filler) rendered {
	enc := func(v string) string { return base64.StdEncoding.EncodeToString([]byte(basicUser + ":" + v)) }
	// the auths map is what Docker writes: each entry's auth is base64(user:secret)
	var auths, plain []string
	for _, s := range slots {
		auths = append(auths, "    "+jsonString("registry-"+fl.word()+".dev")+": {\"auth\": "+jsonString(enc(s.value))+"}")
		for _, p := range s.pairs {
			plain = append(plain, "  "+jsonString(p.Name)+": "+jsonString(p.Value))
		}
	}
	b := "{\n  \"auths\": {\n" + strings.Join(auths, ",\n") + "\n  }"
	if len(plain) > 0 {
		b += ",\n" + strings.Join(plain, ",\n")
	}
	b += "\n}\n"
	return rendered{content: b, esc: enc, decodes: true, decode: func(v string) string { return basicUser + ":" + v }}
}

func renderUTF16(slots []slot, r *rand.Rand, fl *filler) rendered {
	env := renderEnv(slots, r, fl)
	buf := []byte{0xff, 0xfe} // a byte order mark, little endian
	for _, c := range utf16.Encode([]rune(env.content)) {
		buf = append(buf, byte(c), byte(c>>8))
	}
	return rendered{content: string(buf), esc: env.esc, inner: env.content,
		opaque: "betterleaks and gitleaks read bytes as UTF-8, so a UTF-16 file shows them neither the keyword nor the token"}
}

var archiveTime = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

func renderTGZ(slots []slot, r *rand.Rand, fl *filler) rendered {
	inner := renderEnv(slots, r, fl)
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf) // no name and a zero time in the header: the bytes depend on the content only
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: ".env", Mode: 0o600, Size: int64(len(inner.content)), ModTime: archiveTime, Format: tar.FormatUSTAR}); err != nil {
		panic(err)
	}
	if _, err := tw.Write([]byte(inner.content)); err != nil {
		panic(err)
	}
	if err := tw.Close(); err != nil {
		panic(err)
	}
	if err := gz.Close(); err != nil {
		panic(err)
	}
	return rendered{content: buf.String(), esc: inner.esc, inner: inner.content, archive: true,
		opaque: "betterleaks opens .zip, .tar and .tar.gz but skips .tgz (checked on 1.9.0), and gitleaks opens no archive"}
}

func renderJAR(slots []slot) rendered {
	var props strings.Builder
	for _, s := range slots {
		for _, p := range s.pairs {
			fmt.Fprintf(&props, "%s=%s\n", strings.ReplaceAll(strings.ToLower(p.Name), "_", "."), p.Value)
		}
		fmt.Fprintf(&props, "%s=%s\n", strings.ReplaceAll(strings.ToLower(s.name), "_", "."), dotenvEscape(s.value))
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range []struct{ name, body string }{
		{"META-INF/MANIFEST.MF", "Manifest-Version: 1.0\nCreated-By: bench\n"},
		{"application.properties", props.String()},
	} {
		h := &zip.FileHeader{Name: f.name, Method: zip.Deflate, Modified: archiveTime}
		w, err := zw.CreateHeader(h)
		if err != nil {
			panic(err)
		}
		if _, err := w.Write([]byte(f.body)); err != nil {
			panic(err)
		}
	}
	if err := zw.Close(); err != nil {
		panic(err)
	}
	return rendered{content: buf.String(), esc: dotenvEscape, inner: props.String(), archive: true,
		opaque: "betterleaks skips .jar by extension and gitleaks opens no archive"}
}

// renderTwin is an env file whose lines are a valid value and its invalid twins, each under
// the name its slot carries.
func renderTwin(slots []slot, fl *filler) rendered {
	var b strings.Builder
	b.WriteString("# " + fl.sentence() + "\n")
	for _, s := range slots {
		for _, p := range s.pairs {
			b.WriteString(p.Name + "=" + p.Value + "\n")
		}
		b.WriteString(s.name + "=" + s.value + "\n")
	}
	return rendered{content: b.String(), esc: identity}
}
