package known

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

// parseJSON reads every string in a JSON document, naming each by its own key (or, inside
// an array, by the key of the array), and then the positions the walker knows to be
// credentials: arguments after --api-key, header values, query parameters (STEAL P0-15). A
// file that is not JSON even with comments and trailing commas allowed falls back to the line
// reader, which also copes with JSON written that way.
func parseJSON(l *learner, path string, data []byte) {
	if err := walk(JSON, data, l.walker(path, true)); err != nil {
		parseKV(l, path, data)
	}
}

// parseTOML reads TOML and YAML with the line reader, which finds the keys and scalars
// secrets live in, and then with the walker for the positions that need the structure: a
// value in [mcp_servers.x.env] or under --api-key in an args array.
func parseTOML(l *learner, path string, data []byte) {
	parseKV(l, path, data)
	_ = walk(TOML, data, l.walker(path, false))
}

func parseYAML(l *learner, path string, data []byte) {
	parseKV(l, path, data)
	_ = walk(YAML, data, l.walker(path, false))
}

// walker is the learn side of the shared config walker: every credential it finds is a
// credential by position, so the name filter is skipped and the value filters are not. With
// generic set it also takes every string under its own key, as learn always has for JSON.
func (l *learner) walker(path string, generic bool) *walker {
	w := &walker{emit: func(c cred) {
		if v, ok := c.learnable(); ok {
			l.ingestTrusted(c.label(), v, path)
		}
	}}
	if generic {
		w.any = func(key, value string) { l.ingest(key, value, path, false) }
	}
	return w
}

// parseDocker handles ~/.docker/config.json: besides every string in it, each auths entry
// holds base64(user:password), and the password (and the whole pair, which protects a
// short password) is what gets typed into scripts.
func parseDocker(l *learner, path string, data []byte) {
	parseJSON(l, path, data)
	var cfg struct {
		Auths map[string]struct {
			Auth string `json:"auth"`
		} `json:"auths"`
	}
	if json.Unmarshal(data, &cfg) != nil {
		return
	}
	for _, h := range sortedKeys(cfg.Auths) {
		if pair, ok := decodeBase64(cfg.Auths[h].Auth); ok {
			if _, pw, ok := strings.Cut(pair, ":"); ok {
				l.ingestTrusted("docker "+h+" password", pw, path)
			}
			l.ingestTrusted("docker "+h+" login", pair, path)
		}
	}
}

// decodeBase64 accepts std and url alphabets, padded or not, and only text results.
func decodeBase64(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if len(s) < 8 {
		return "", false
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil && isMostlyText(b) {
			return string(b), true
		}
	}
	return "", false
}

func isMostlyText(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	bad := 0
	for _, c := range b {
		if c < 0x20 && c != '\n' && c != '\r' && c != '\t' || c == 0x7f {
			bad++
		}
	}
	return bad*20 < len(b)
}

// parseKV reads the line-oriented formats that share one shape: key = value (TOML, INI,
// aws credentials, .pypirc) and key: value (YAML, kube config). It does not parse the
// languages; it finds the keys and scalars secrets live in, which is all learn needs.
func parseKV(l *learner, path string, data []byte) {
	for _, line := range strings.Split(string(data), "\n") {
		t := strings.TrimSpace(line)
		if t == "" || t[0] == '#' || t[0] == ';' || t[0] == '[' && !strings.Contains(t, "=") {
			continue
		}
		for strings.HasPrefix(t, "- ") {
			t = strings.TrimSpace(t[2:])
		}
		t = strings.TrimPrefix(t, ":") // Ruby symbol keys, as in ~/.gem/credentials
		key, val, ok := splitKV(t)
		if !ok || nameHolder(key) {
			continue
		}
		switch {
		case strings.HasPrefix(val, "{"):
			for _, kv := range inlinePairs(val) {
				l.ingest(kv[0], kv[1], path, false)
			}
		case strings.HasPrefix(val, "["):
			for _, kv := range inlinePairs(val) {
				l.ingest(key, kv[1], path, false)
			}
		default:
			if v, ok := scalar(val); ok {
				l.ingest(key, v, path, false)
			}
		}
	}
}

// splitKV cuts at the first = or : that is outside a leading quote.
func splitKV(t string) (key, val string, ok bool) {
	start := 0
	quoted := t != "" && (t[0] == '"' || t[0] == '\'')
	if quoted {
		end := strings.IndexByte(t[1:], t[0])
		if end < 0 {
			return "", "", false
		}
		start = end + 2
	}
	i := strings.IndexAny(t[start:], "=:")
	if i < 0 {
		return "", "", false
	}
	i += start
	key = strings.Trim(strings.TrimSpace(t[:i]), `"'`)
	// A bare key is one word; "some sentence: with a colon" is prose, not a setting.
	if key == "" || !quoted && strings.ContainsAny(key, " \t{}[]") {
		return "", "", false
	}
	return key, strings.TrimSpace(t[i+1:]), true
}

// scalar extracts a value: quoted strings up to their closing quote, otherwise the text up
// to an inline comment. Block scalars, anchors, aliases and tags have no value on this
// line.
func scalar(val string) (string, bool) {
	if val == "" {
		return "", false
	}
	switch val[0] {
	case '"':
		for i := 1; i < len(val); i++ {
			if val[i] == '\\' {
				i++
				continue
			}
			if val[i] == '"' {
				return unescapeDouble(val[1:i]), true
			}
		}
		return "", false
	case '\'':
		if i := strings.IndexByte(val[1:], '\''); i >= 0 {
			return val[1 : 1+i], true
		}
		return "", false
	case '|', '>', '&', '*', '!':
		return "", false
	}
	return strings.TrimSpace(cutInlineComment(val)), true
}

// inlinePairs reads the entries of a TOML inline table, a YAML flow map or an array:
// {token = "x", id: 7} gives ("token","x"),("id","7"); ["a","b"] gives ("","a"),("","b").
func inlinePairs(s string) [][2]string {
	var out [][2]string
	var cur strings.Builder
	key, word := "", ""
	afterSep := false
	flush := func() {
		if cur.Len() == 0 {
			return
		}
		w := cur.String()
		cur.Reset()
		if afterSep {
			out = append(out, [2]string{key, w})
			afterSep = false
		} else {
			word = w
		}
	}
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '"', '\'':
			flush()
			j := i + 1
			for j < len(s) && s[j] != c {
				if s[j] == '\\' && c == '"' {
					j++
				}
				j++
			}
			if j >= len(s) {
				return out
			}
			body := s[i+1 : j]
			if rest := strings.TrimSpace(s[j+1:]); strings.HasPrefix(rest, "=") || strings.HasPrefix(rest, ":") {
				word = body // a quoted key
			} else if afterSep {
				out = append(out, [2]string{key, body})
				afterSep = false
			} else {
				out = append(out, [2]string{"", body}) // an array element
			}
			i = j
		case '=', ':':
			flush()
			key, afterSep = word, true
		case ' ', '\t', ',', '{', '}', '[', ']':
			flush()
		default:
			cur.WriteByte(c)
		}
	}
	flush()
	return out
}

// parseNpmrc reads .npmrc: //registry/:_authToken=..., _auth (base64 user:pass) and
// _password (base64 password). The auth keys are credentials by position; every other
// line is judged by its name like any key = value file.
func parseNpmrc(l *learner, path string, data []byte) {
	for _, line := range strings.Split(string(data), "\n") {
		t := strings.TrimSpace(line)
		if t == "" || t[0] == '#' || t[0] == ';' {
			continue
		}
		k, v, ok := strings.Cut(t, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		if i := strings.LastIndexByte(k, ':'); i >= 0 {
			k = k[i+1:]
		}
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		switch strings.ToLower(k) {
		case "_authtoken":
			l.ingestTrusted("npmrc _authToken", v, path)
		case "_auth":
			l.ingestTrusted("npmrc _auth", v, path)
			if pair, ok := decodeBase64(v); ok {
				if _, pw, ok := strings.Cut(pair, ":"); ok {
					l.ingestTrusted("npmrc _auth password", pw, path)
				}
			}
		case "_password":
			l.ingestTrusted("npmrc _password", v, path)
			if pw, ok := decodeBase64(v); ok {
				l.ingestTrusted("npmrc _password decoded", pw, path)
			}
		default:
			l.ingest(k, v, path, false)
		}
	}
}

// parseNetrc reads machine/login/password tokens, which may share a line or span several.
// Passwords are credentials by position; a login is learned only if something else
// (an engine) says it is a token, since it is usually just a user name.
func parseNetrc(l *learner, path string, data []byte) {
	var toks []string
	macdef := false
	for _, line := range strings.Split(string(data), "\n") {
		if macdef {
			if strings.TrimSpace(line) == "" {
				macdef = false
			}
			continue
		}
		fields := strings.Fields(line)
		for i := 0; i < len(fields); i++ {
			if fields[i] == "macdef" {
				macdef = true
				break
			}
			toks = append(toks, strings.Trim(fields[i], `"'`))
		}
	}
	machine := "default"
	for i := 0; i+1 < len(toks); i++ {
		switch toks[i] {
		case "machine":
			machine = toks[i+1]
			i++
		case "default":
			machine = "default"
		case "login":
			l.ingest("netrc "+machine+" login", toks[i+1], path, false)
			i++
		case "account":
			l.ingest("netrc "+machine+" account", toks[i+1], path, false)
			i++
		case "password":
			l.ingestTrusted("netrc "+machine+" password", toks[i+1], path)
			i++
		}
	}
}

// parsePgpass reads ~/.pgpass: host:port:database:user:password, where a backslash escapes
// a colon or a backslash. The password is a credential by position.
func parsePgpass(l *learner, path string, data []byte) {
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}
		var fields []string
		var cur strings.Builder
		for i := 0; i < len(line); i++ {
			switch {
			case line[i] == '\\' && i+1 < len(line):
				i++
				cur.WriteByte(line[i])
			case line[i] == ':' && len(fields) < 4:
				fields = append(fields, cur.String())
				cur.Reset()
			default:
				cur.WriteByte(line[i])
			}
		}
		if len(fields) == 4 {
			l.ingestTrusted("pgpass "+fields[3]+"@"+fields[0], cur.String(), path)
		}
	}
}

// parseLines treats every line as a value: .git-credentials is one URL per line, and the
// URL carries the token.
func parseLines(l *learner, path string, data []byte) {
	name := strings.TrimPrefix(baseName(path), ".")
	for _, line := range strings.Split(string(data), "\n") {
		if t := strings.TrimSpace(line); t != "" && t[0] != '#' {
			l.ingest(name, t, path, false)
		}
	}
}

func baseName(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}
