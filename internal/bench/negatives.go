package bench

import (
	"encoding/base64"
	"fmt"
	mrand "math/rand/v2"
	"strings"
)

// negItem is one value a scanner must not alert on. It carries a fingerprint like a positive
// plant, so an engine that reports it can be told apart from one reporting noise.
type negItem struct {
	kind  string
	typ   string
	value string   // fingerprinted canonical text
	alt   []string // other extents an engine may report
	note  string
}

// negFile is a file whose content is mostly or only negatives.
type negFile struct {
	path    string
	content string
	items   []negItem
}

func uuidV4(r *mrand.Rand) string {
	b := make([]byte, 16)
	detReader{r}.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func randBytes(r *mrand.Rand, n int) []byte {
	b := make([]byte, n)
	detReader{r}.Read(b)
	return b
}

func hexOf(r *mrand.Rand, n int) string { return fmt.Sprintf("%x", randBytes(r, n/2)) }

func sri(r *mrand.Rand, bits int) string {
	return fmt.Sprintf("sha%d-", bits) + base64.StdEncoding.EncodeToString(randBytes(r, bits/8))
}

// pngDataURI is an inline image of the size icon sprites really are.
func pngDataURI(r *mrand.Rand, n int) (payload, uri string) {
	png := append([]byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x10\x00\x00\x00\x10\x08\x06\x00\x00\x00"), randBytes(r, n)...)
	payload = base64.StdEncoding.EncodeToString(png)
	return payload, "data:image/png;base64," + payload
}

// placeholderFor is the way documentation spells a provider's key without it being one.
func placeholderFor(g *Gen, p Provider, style int) string {
	switch style % 6 {
	case 0:
		// the real prefix at the real length, every random character an x
		s := p.Gen(g).Raw
		head := s[:min(len(s), 14)]
		pre := s[:3]
		if i := strings.LastIndexAny(head, "_-."); i >= 0 {
			pre = s[:i+1]
		}
		return pre + strings.Repeat("x", max(8, len(s)-len(pre)))
	case 1:
		return "your-" + strings.ReplaceAll(strings.ToLower(p.Env), "_", "-") + "-here"
	case 2:
		return "<" + p.Env + ">"
	case 3:
		return "${" + p.Env + "}"
	case 4:
		return "REPLACE_WITH_" + p.Env
	default:
		return "changeme"
	}
}

// negativeFiles builds every lookalike file the corpus carries. Content comes from the seeded
// stream so it is repeatable, and none of it may contain a real-looking provider secret.
func negativeFiles(seed uint64) []negFile {
	r := newRand(seed, "negatives")
	g := &Gen{r: r}
	fl := &filler{r: r}
	var out []negFile

	// placeholders: .env.example, a README, a docs page
	{
		var items []negItem
		var b strings.Builder
		b.WriteString("# Copy to .env and fill in. Never commit the real file.\n")
		for i, p := range Providers {
			if i%4 != 0 || p.Multi || p.ID == "card-number" {
				continue
			}
			v := placeholderFor(g, p, i/4)
			b.WriteString(p.Env + "=" + v + "\n")
			items = append(items, negItem{kind: "placeholder", typ: p.Type, value: v, note: "placeholder in .env.example"})
		}
		out = append(out, negFile{path: ".env.example", content: b.String(), items: items})
	}
	{
		var items []negItem
		var b strings.Builder
		b.WriteString("# Setup\n\nExport the credentials the service needs:\n\n```sh\n")
		for i, p := range Providers {
			if i%7 != 3 || p.Multi || p.ID == "card-number" {
				continue
			}
			v := placeholderFor(g, p, i)
			b.WriteString("export " + p.Env + "=\"" + v + "\"\n")
			items = append(items, negItem{kind: "placeholder", typ: p.Type, value: v, note: "placeholder in README"})
		}
		b.WriteString("```\n\n" + strings.Join(fl.lines("md", 10), "\n") + "\n")
		out = append(out, negFile{path: "README.md", content: b.String(), items: items})
	}
	// AWS documentation's example pair, built from parts so no literal ever sits in source.
	{
		id := "AKIA" + "IOSFODNN7" + "EXAMPLE"
		sec := "wJalrXUtnFEMI/K7MDENG/bPxRfiCY" + "EXAMPLEKEY"
		content := "# AWS setup\n\nThe docs use this pair for every example. It is not a credential.\n\n```\nAWS_ACCESS_KEY_ID=" + id +
			"\nAWS_SECRET_ACCESS_KEY=" + sec + "\n```\n"
		out = append(out, negFile{path: "docs/aws-setup.md", content: content, items: []negItem{
			{kind: "aws-example", typ: "aws", value: id, note: "AWS documentation example key id"},
			{kind: "aws-example", typ: "aws", value: sec, note: "AWS documentation example secret"},
		}})
	}

	// hashes: lockfiles, SRI, image digests, checksums
	{
		var items []negItem
		var b strings.Builder
		b.WriteString("{\n  \"name\": \"bench-app\",\n  \"lockfileVersion\": 3,\n  \"packages\": {\n")
		for i := 0; i < 8; i++ {
			name := fl.word() + "-" + fl.word()
			h := sri(r, 512)
			fmt.Fprintf(&b, "    \"node_modules/%s\": {\n      \"version\": \"%d.%d.%d\",\n      \"resolved\": \"https://registry.npmjs.org/%s/-/%s-1.%d.0.tgz\",\n      \"integrity\": \"%s\"\n    }%s\n",
				name, 1+r.IntN(4), r.IntN(20), r.IntN(20), name, name, i, h, map[bool]string{true: ",", false: ""}[i < 7])
			items = append(items, negItem{kind: "integrity-hash", typ: "hash", value: h, alt: []string{strings.TrimPrefix(h, "sha512-")}, note: "package-lock integrity"})
		}
		b.WriteString("  }\n}\n")
		out = append(out, negFile{path: "package-lock.json", content: b.String(), items: items})
	}
	{
		var items []negItem
		var b strings.Builder
		b.WriteString("# yarn lockfile v1\n\n")
		for i := 0; i < 6; i++ {
			name := fl.word() + "-" + fl.word()
			h := sri(r, 512)
			sha1 := hexOf(r, 40)
			fmt.Fprintf(&b, "%s@^1.%d.0:\n  version \"1.%d.2\"\n  resolved \"https://registry.yarnpkg.com/%s/-/%s-1.%d.2.tgz#%s\"\n  integrity %s\n\n", name, i, i, name, name, i, sha1, h)
			items = append(items,
				negItem{kind: "integrity-hash", typ: "hash", value: h, alt: []string{strings.TrimPrefix(h, "sha512-")}, note: "yarn.lock integrity"},
				negItem{kind: "commit-hash", typ: "hash", value: sha1, note: "yarn.lock resolved sha1"})
		}
		out = append(out, negFile{path: "yarn.lock", content: b.String(), items: items})
	}
	{
		var items []negItem
		var b strings.Builder
		b.WriteString("# This file is automatically @generated by Cargo.\nversion = 4\n\n")
		for i := 0; i < 6; i++ {
			name := fl.word() + "-" + fl.word()
			h := hexOf(r, 64)
			fmt.Fprintf(&b, "[[package]]\nname = \"%s\"\nversion = \"0.%d.1\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"%s\"\n\n", name, i+1, h)
			items = append(items, negItem{kind: "checksum", typ: "hash", value: h, note: "Cargo.lock checksum"})
		}
		out = append(out, negFile{path: "Cargo.lock", content: b.String(), items: items})
	}
	{
		var items []negItem
		var b strings.Builder
		for i := 0; i < 6; i++ {
			mod := "github.com/" + fl.word() + "/" + fl.word()
			h1 := "h1:" + base64.StdEncoding.EncodeToString(randBytes(r, 32))
			h2 := "h1:" + base64.StdEncoding.EncodeToString(randBytes(r, 32))
			fmt.Fprintf(&b, "%s v1.%d.0 %s\n%s v1.%d.0/go.mod %s\n", mod, i, h1, mod, i, h2)
			items = append(items,
				negItem{kind: "checksum", typ: "hash", value: h1, alt: []string{strings.TrimPrefix(h1, "h1:")}, note: "go.sum module hash"},
				negItem{kind: "checksum", typ: "hash", value: h2, alt: []string{strings.TrimPrefix(h2, "h1:")}, note: "go.sum go.mod hash"})
		}
		out = append(out, negFile{path: "go.sum", content: b.String(), items: items})
	}
	{
		var items []negItem
		var b strings.Builder
		for i := 0; i < 3; i++ {
			d := hexOf(r, 64)
			fmt.Fprintf(&b, "FROM %s@sha256:%s AS stage%d\nRUN echo ok\n", []string{"node", "python", "golang"}[i], d, i)
			items = append(items, negItem{kind: "image-digest", typ: "hash", value: d, note: "base image digest pin"})
		}
		out = append(out, negFile{path: "docker/Dockerfile.pinned", content: b.String(), items: items})
	}
	{
		var items []negItem
		var b strings.Builder
		b.WriteString("# Changelog\n\n")
		for i := 0; i < 8; i++ {
			h := hexOf(r, 40)
			fmt.Fprintf(&b, "- %s (%s)\n", fl.sentence(), h)
			items = append(items, negItem{kind: "commit-hash", typ: "hash", value: h, note: "full commit sha in a changelog"})
		}
		out = append(out, negFile{path: "CHANGELOG.md", content: b.String(), items: items})
	}

	// images and UUIDs
	{
		var items []negItem
		var b strings.Builder
		b.WriteString("<!doctype html>\n<html>\n<head>\n")
		for i := 0; i < 3; i++ {
			h := sri(r, 384)
			fmt.Fprintf(&b, "<script src=\"/assets/%s.js\" integrity=\"%s\" crossorigin=\"anonymous\"></script>\n", fl.word(), h)
			items = append(items, negItem{kind: "integrity-hash", typ: "hash", value: h, alt: []string{strings.TrimPrefix(h, "sha384-")}, note: "subresource integrity"})
		}
		payload, uri := pngDataURI(r, 900)
		fmt.Fprintf(&b, "<link rel=\"icon\" href=\"%s\">\n</head>\n<body></body>\n</html>\n", uri)
		items = append(items, negItem{kind: "base64-image", typ: "image", value: payload, alt: []string{uri}, note: "inline favicon"})
		out = append(out, negFile{path: "web/public/index.html", content: b.String(), items: items})
	}
	{
		var items []negItem
		var b strings.Builder
		for i := 0; i < 3; i++ {
			payload, uri := pngDataURI(r, 2500+i*1500)
			fmt.Fprintf(&b, ".icon-%s {\n  background: url(%s) no-repeat;\n}\n", fl.word(), uri)
			items = append(items, negItem{kind: "base64-image", typ: "image", value: payload, alt: []string{uri}, note: "css sprite"})
		}
		svg := base64.StdEncoding.EncodeToString([]byte(`<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24"><path d="M3 12h18M12 3v18" stroke="#333" stroke-width="2"/></svg>`))
		fmt.Fprintf(&b, ".icon-plus {\n  background: url(data:image/svg+xml;base64,%s);\n}\n", svg)
		items = append(items, negItem{kind: "base64-image", typ: "image", value: svg, alt: []string{"data:image/svg+xml;base64," + svg}, note: "svg icon"})
		out = append(out, negFile{path: "web/styles/sprites.css", content: b.String(), items: items})
	}
	{
		var items []negItem
		var b strings.Builder
		b.WriteString("[\n")
		names := []string{"request_id", "trace_id", "user_id", "order_id", "project_id", "device_id", "invoice_id", "run_id", "batch_id", "event_id"}
		for i, n := range names {
			u := uuidV4(r)
			fmt.Fprintf(&b, "  {\"%s\": \"%s\", \"seq\": %d}%s\n", n, u, i, map[bool]string{true: ",", false: ""}[i < len(names)-1])
			items = append(items, negItem{kind: "uuid", typ: "uuid", value: u, note: "UUID under " + n})
		}
		b.WriteString("]\n")
		out = append(out, negFile{path: "data/fixtures/ids.json", content: b.String(), items: items})
	}

	// public keys and certificates
	{
		var items []negItem
		var b strings.Builder
		for i := 0; i < 3; i++ {
			l := sshPublicLine(r, fl.word()+"@"+fl.word())
			b.WriteString(l + "\n")
			items = append(items, negItem{kind: "public-key", typ: "ssh-public-key", value: strings.Fields(l)[1], alt: []string{l}, note: "authorized_keys entry"})
		}
		out = append(out, negFile{path: "deploy/authorized_keys", content: b.String(), items: items})
	}
	{
		pubPEM := strings.TrimRight(publicPEM(r), "\n")
		certPEM := strings.TrimRight(certPEM(r, "bench.internal"), "\n")
		out = append(out,
			negFile{path: "deploy/server_public.pem", content: pubPEM + "\n", items: []negItem{{kind: "public-key", typ: "pem-public", value: pubPEM, note: "PEM public key"}}},
			negFile{path: "deploy/ca.pem", content: certPEM + "\n", items: []negItem{{kind: "certificate", typ: "pem-public", value: certPEM, note: "self-signed certificate"}}})
	}
	// jwt.io's sample token, in the docs and in a test
	{
		j := jwtIO()
		out = append(out,
			negFile{path: "docs/jwt-debugging.md", content: "# Decoding a JWT\n\nPaste a token into jwt.io. The sample there is:\n\n```\n" + j + "\n```\n", items: []negItem{{kind: "jwt-sample", typ: "jwt", value: j, note: "jwt.io sample token"}}},
			negFile{path: "tests/fixtures/sample_token.txt", content: j + "\n", items: []negItem{{kind: "jwt-sample", typ: "jwt", value: j, note: "jwt.io sample token in a fixture"}}})
	}

	// real format, public by design
	{
		var items []negItem
		var b strings.Builder
		b.WriteString("# Browser-visible configuration: these values ship in the client bundle.\n")
		for _, p := range PublicProviders {
			f := p.Gen(&Gen{r: newRand(seed, "public/"+p.ID)})
			b.WriteString(p.Env + "=" + f.Value + "\n")
			items = append(items, negItem{kind: "public-by-design", typ: p.Type, value: f.Raw, note: p.Doc})
		}
		out = append(out, negFile{path: ".env.production", content: b.String(), items: items})
	}
	{
		var items []negItem
		var b strings.Builder
		b.WriteString("// Client-side analytics and maps configuration.\nexport const clientConfig = {\n")
		for _, id := range []string{"posthog-project", "sentry-dsn", "mapbox-public", "recaptcha-site", "supabase-anon"} {
			for _, p := range PublicProviders {
				if p.ID != id {
					continue
				}
				f := p.Gen(&Gen{r: newRand(seed, "public2/"+p.ID)})
				fmt.Fprintf(&b, "  %s: '%s',\n", camel(p.Env), f.Value)
				items = append(items, negItem{kind: "public-by-design", typ: p.Type, value: f.Raw, note: p.Doc})
			}
		}
		b.WriteString("};\n")
		out = append(out, negFile{path: "web/src/clientConfig.ts", content: b.String(), items: items})
	}

	// code that reads credentials from the environment: no value to find
	for i, ext := range []string{"py", "js", "ts", "go", "sh", "yaml", "py", "go"} {
		var b strings.Builder
		switch ext {
		case "py":
			b.WriteString("import os\nimport getpass\n\napi_key = os.environ[\"OPENAI_API_KEY\"]\ntoken = os.getenv(\"GITHUB_TOKEN\", \"\")\npassword = getpass.getpass(\"password: \")\nheaders = {\"Authorization\": f\"Bearer {token}\"}\nsecret = settings.SECRET_KEY\n")
		case "js":
			b.WriteString("const apiKey = process.env.STRIPE_SECRET_KEY;\nconst token = localStorage.getItem('session');\nconst headers = { Authorization: 'Bearer ' + token };\nconst secret = config.get('webhook_secret');\n")
		case "ts":
			b.WriteString("const apiKey: string = process.env.ANTHROPIC_API_KEY ?? '';\nconst authToken = req.headers.authorization?.split(' ')[1];\nexport const secretKey = import.meta.env.VITE_SECRET_KEY;\n")
		case "go":
			b.WriteString("package config\n\nimport \"os\"\n\nvar apiKey = os.Getenv(\"ANTHROPIC_API_KEY\")\nvar dbPassword = os.Getenv(\"DB_PASSWORD\")\n\nfunc token() string { return os.Getenv(\"AUTH_TOKEN\") }\n")
		case "sh":
			b.WriteString("#!/usr/bin/env bash\nexport OPENAI_API_KEY=\"$(op read op://dev/openai/credential)\"\nTOKEN=$(security find-generic-password -s ci -w)\ncurl -H \"Authorization: Bearer $TOKEN\" \"$URL\"\n")
		case "yaml":
			b.WriteString("env:\n  OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}\n  DATABASE_URL: ${{ secrets.DATABASE_URL }}\n  AWS_SECRET_ACCESS_KEY: ${AWS_SECRET_ACCESS_KEY}\n")
		}
		path := fmt.Sprintf("src/clients/%s_%d.%s", fl.word(), i, ext)
		if ext == "yaml" {
			path = fmt.Sprintf(".github/workflows/deploy_%d.yml", i)
		}
		out = append(out, negFile{path: path, content: b.String(), items: []negItem{{kind: "code-ref", typ: "reference", note: "reads the credential from the environment"}}})
	}
	return out
}
