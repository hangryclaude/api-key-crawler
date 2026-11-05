package known

import (
	"encoding/json"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// scratchLearner is a learner over an empty fake home, for running one parser on its own.
func scratchLearner(t testing.TB) *learner {
	t.Helper()
	home := t.TempDir()
	o, err := Options{Home: home, Root: filepath.Join(home, "kg"), GHUsers: []string{}}.withDefaults()
	if err != nil {
		t.Fatal(err)
	}
	return &learner{o: o, rep: &Report{Rejected: map[string]int{}}, cands: map[string]*cand{}, read: map[string]bool{}}
}

// parsed runs parse over content and returns every candidate that got past the value
// filters, with whether its name (or the parser) vouched for it. Values in these tests are
// 30 random characters so they pass the filters.
func parsed(t testing.TB, parse parseFunc, content string) map[string]*cand {
	t.Helper()
	l := scratchLearner(t)
	parse(l, "x/file", []byte(content))
	return l.cands
}

// wantLearned checks that exactly the wanted values were accepted, under the wanted names.
func wantLearned(t *testing.T, label string, got map[string]*cand, want map[string]string) {
	t.Helper()
	for v, name := range want {
		if c := got[v]; c == nil || !c.ok || c.name != name {
			t.Errorf("%s: the value for %s was not learned under that name", label, name)
		}
	}
	for v, c := range got {
		if _, ok := want[v]; ok {
			continue
		}
		if c.ok {
			t.Errorf("%s: unexpected value learned as %q", label, c.name)
		}
	}
}

func TestDotenvParser(t *testing.T) {
	r := newRNG(t)
	v := func() string { return randFrom(r, alnum, 30) }
	a, b, c, d, e, f, g, h, i, j := v(), v(), v(), v(), v(), v(), v(), v(), v(), v()
	content := "# comment\r\n" +
		"A_KEY=" + a + "\r\n" +
		"export B_KEY=" + b + "\n" +
		"export\tC_KEY\t=\t" + c + "\n" +
		"D_KEY=\"" + d + " # not a comment\"\n" +
		"E_KEY='" + e + "' # a comment\n" +
		"F_KEY=" + f + "#notacomment\n" +
		"G_KEY=" + g + " # a comment\n" +
		"H_KEY=\"" + h + "\n" + i + "\"\n" +
		"export ONLY_NAME\n" +
		"a.dotted-name_KEY=" + b + "\n" +
		"9STARTS_WITH_DIGIT_KEY=" + c + "\n" +
		"=" + d + "\n" +
		"EMPTY_KEY=\n" +
		"ESCAPED_KEY=\"" + a + "\\n" + b + "\"\n"
	got := parsed(t, parseDotenv, content)
	wantLearned(t, "dotenv", got, map[string]string{
		a: "A_KEY", b: "B_KEY", c: "C_KEY", d + " # not a comment": "D_KEY", e: "E_KEY", f + "#notacomment": "F_KEY",
		g: "G_KEY", h + "\n" + i: "H_KEY",
		a + "\n" + b: "ESCAPED_KEY", a + `\n` + b: "ESCAPED_KEY", // expanded, and as written in the file
	})

	// A stray quote opens a "multi-line" value that swallows the lines after it until the
	// next quote. The assignments inside must still be learned.
	k, m := v(), v()
	got = parsed(t, parseDotenv, "BROKEN_KEY=\""+j+"\nLATER_KEY="+k+"\nQUOTED_LATER_KEY=\""+m+"\"\nLAST_KEY="+a+"\n")
	wantLearned(t, "stray quote", got, map[string]string{
		k: "LATER_KEY", m: "QUOTED_LATER_KEY", a: "LAST_KEY",
		j + "\nLATER_KEY=" + k + "\nQUOTED_LATER_KEY=": "BROKEN_KEY", // what a dotenv library would call the value
	})
}

func TestReadFileStripsByteOrderMark(t *testing.T) {
	f := newFixture(t)
	v := f.secret("sk-proj-", 40, "OPENAI_API_KEY")
	f.write("dev/a/.env", "\xef\xbb\xbfOPENAI_API_KEY="+v+"\n")
	f.learn(Options{})
	f.check()
}

func TestShellTokenizer(t *testing.T) {
	r := newRNG(t)
	v := func() string { return randFrom(r, alnum, 30) }
	a, b, c, d, e, f, g := v(), v(), v(), v(), v(), v(), v()
	src := "export A_KEY=" + a + " B_KEY=\"" + b + "\"\n" +
		"C_KEY='" + c + "' run-something --flag\n" +
		"declare -x D_KEY=" + d + "\n" +
		"export -n E_KEY=" + e + "\n" +
		"export F_KEY=$'" + f + "\\ttab'\n" +
		"export G_KEY=a" + g + "\\ b # comment\n" +
		"H_KEY=$(cat /etc/secret)\n" +
		"export I_KEY=\"$HOME/x\"\n" +
		"export J_KEY=`date`\n" +
		"export K_KEY=\"" + a + "\\\"" + "\"\n" +
		"export L_KEY=" + b + "; export M_KEY=" + c + " && N_KEY=" + d + "\n" +
		"alias ll='ls -l'\nnotanassignment is here\n" +
		"export O_KEY=part1\\\n" + e + "\n" +
		"export P_KEY=\"multi\nline" + f + "\"\n"
	var got []string
	dynamic := 0
	for _, stmt := range tokenizeShell(src) {
		vals, names := shellAssignments(stmt)
		for k := range vals {
			if vals[k].dynamic {
				dynamic++
				continue
			}
			got = append(got, names[k]+"="+vals[k].text)
		}
	}
	want := []string{
		"A_KEY=" + a, "B_KEY=" + b, "C_KEY=" + c, "D_KEY=" + d, "E_KEY=" + e,
		"F_KEY=" + f + "\ttab", "G_KEY=a" + g + " b", "K_KEY=" + a + "\"",
		"L_KEY=" + b, "M_KEY=" + c, "N_KEY=" + d, "O_KEY=part1" + e, "P_KEY=multi\nline" + f,
	}
	if len(got) != len(want) {
		t.Errorf("%d assignments, want %d", len(got), len(want))
	}
	for i := range want {
		if i >= len(got) || got[i] != want[i] {
			t.Errorf("assignment %d (%s) differs", i, strings.SplitN(want[i], "=", 2)[0])
		}
	}
	if dynamic != 3 { // $(...), "$HOME/x", `date`
		t.Errorf("%d dynamic values, want 3", dynamic)
	}
}

func TestKVParser(t *testing.T) {
	r := newRNG(t)
	v := func() string { return randFrom(r, alnum, 30) }
	a, b, c, d, e, f, g := v(), v(), v(), v(), v(), v(), v()
	yaml := "users:\n" +
		"- name: u\n" +
		"  token: " + a + "\n" +
		"  api_key: \"" + b + "\" # comment\n" +
		"  secret: '" + c + "'\n" +
		"  auth: {token: " + d + ", id: 12}\n" +
		"  keys: [\"" + e + "\", \"" + f + "\"]\n" +
		"  private_key: |\n    block scalar lines are not values\n" +
		"  anchor_key: &x " + g + "\n" +
		"  prose: this sentence: has a colon\n"
	wantLearned(t, "yaml", parsed(t, parseKV, yaml), map[string]string{a: "token", b: "api_key", c: "secret", d: "token", e: "keys", f: "keys"})

	toml := "[section]\n" +
		"token = \"" + a + "\"\n" +
		"inline = { api_token = \"" + b + "\", id = \"1\" }\n" +
		"token_list = [\"" + c + "\"]\n" +
		"'quoted.name' = '" + d + "'\n" +
		"multi = \"\"\"\nignored\n\"\"\"\n" +
		"bare_secret = " + e + " # trailing\n"
	got := parsed(t, parseKV, toml)
	wantLearned(t, "toml", got, map[string]string{a: "token", b: "api_token", c: "token_list", e: "bare_secret"})
	if got[d] == nil || got[d].ok {
		t.Error("a quoted key with a harmless name should be seen but not vouched for")
	}

	ini := "[default]\naws_access_key_id = " + a + "\naws_secret_access_key=" + b + "\n; comment\n# comment\nregion = us-east-1\n"
	wantLearned(t, "ini", parsed(t, parseKV, ini), map[string]string{a: "aws_access_key_id", b: "aws_secret_access_key"})
}

func TestNpmrcNetrcAndDockerParsers(t *testing.T) {
	r := newRNG(t)
	v := func() string { return randFrom(r, alnum, 30) }
	a, b, c, d := v(), v(), v(), v()
	wantLearned(t, "npmrc", parsed(t, parseNpmrc, "//r.example.org/:_authToken="+a+"\n_auth="+b64("user:"+b)+"\n; c\n//x/:_authToken=${TOKEN}\n_password=\""+b64(c)+"\"\nemail=me@example.org\n"),
		map[string]string{
			a: "npmrc _authToken", b: "npmrc _auth password", c: "npmrc _password decoded",
			b64("user:" + b): "npmrc _auth", b64(c): "npmrc _password",
		})
	wantLearned(t, "netrc", parsed(t, parseNetrc, "machine a.example.org login me password "+a+"\nmacdef init\n  password "+b+"\n\ndefault\n  login anonymous\n  password "+c+"\n"),
		map[string]string{a: "netrc a.example.org password", c: "netrc default password"})
	wantLearned(t, "docker", parsed(t, parseDocker, `{"auths":{"r.example.org":{"auth":"`+b64("me:"+d)+`","email":"x"},"bad":{"auth":"!!!notbase64!!!"}},"credHelpers":{"x":"y"}}`),
		map[string]string{d: "docker r.example.org password", "me:" + d: "docker r.example.org login", b64("me:" + d): "auth"})
}

func TestPlistParserXMLAndBinary(t *testing.T) {
	r := newRNG(t)
	a, b, c, d := randFrom(r, alnum, 30), randFrom(r, alnum, 30), randFrom(r, alnum, 30)+"é€", randFrom(r, alnum, 30)
	xml := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<!-- a comment -->
<dict>
  <key>Label</key><string>x</string>
  <key>Nested</key><dict><key>EnvironmentVariables</key><dict><key>IGNORED_KEY</key><string>` + randFrom(r, alnum, 30) + `</string></dict></dict>
  <key>EnvironmentVariables</key>
  <dict>
    <key>A_KEY</key><string>` + a + `</string>
    <key>EMPTY_KEY</key><string></string>
    <key>EMPTY2_KEY</key><string/>
    <key>NUM_KEY</key><integer>7</integer>
    <key>ENTITY_KEY</key><string>` + b + `&amp;&lt;x</string>
    <key>UTF_KEY</key><string>` + c + `</string>
  </dict>
  <key>ProgramArguments</key>
  <array><string>/bin/sh</string><string>-c</string><string>export SH_KEY=` + d + `; run</string><string>--api-key</string><string>` + a + `</string></array>
  <key>Flag</key><true/>
  <key>Date</key><date>2026-11-03T00:00:00Z</date>
  <key>Data</key><data>AAAA</data>
</dict></plist>`
	check := func(label string, content []byte) {
		t.Helper()
		l := scratchLearner(t)
		parsePlist(l, "x.plist", content)
		wantLearned(t, label, l.cands, map[string]string{a: "A_KEY", b + "&<x": "ENTITY_KEY", c: "UTF_KEY", d: "SH_KEY"})
		if len(l.rep.Skipped) != 0 {
			t.Errorf("%s: skipped %v", label, l.rep.Skipped)
		}
	}
	check("xml", []byte(xml))
	dir := t.TempDir()
	src, dst := filepath.Join(dir, "in.plist"), filepath.Join(dir, "out.plist")
	os.WriteFile(src, []byte(xml), 0o600)
	if out, err := exec.Command("plutil", "-convert", "binary1", "-o", dst, src).CombinedOutput(); err != nil {
		t.Fatalf("plutil: %v (%d bytes)", err, len(out))
	}
	bin, _ := os.ReadFile(dst)
	if string(bin[:8]) != "bplist00" {
		t.Fatal("plutil did not write a binary plist")
	}
	check("binary", bin)
}

func TestSourceFollowingStaysInsideHomeAndTerminates(t *testing.T) {
	f := newFixture(t)
	a := f.secret("", 30, "A_KEY")
	b := f.secret("", 30, "B_KEY")
	outside := f.reject("", 30, "outside the home directory")
	out := filepath.Join(t.TempDir(), "outside.sh")
	os.WriteFile(out, []byte("export OUTSIDE_KEY="+outside+"\n"), 0o600)
	f.write(".zshrc", "source ~/.one\nsource "+out+"\nsource /etc/hosts\nsource $UNSET/x\nsource '~/.nonexistent'\n")
	f.write(".one", "export A_KEY="+a+"\nsource ~/.two\n")
	f.write(".two", "export B_KEY="+b+"\nsource ~/.one\nsource ~/.three\n")
	f.write(".three", "source ~/.four\n")
	f.write(".four", "source ~/.five\n")
	f.write(".five", "export TOO_DEEP_KEY="+f.reject("", 30, "five levels down")+"\n")
	f.learn(Options{})
	f.check() // the cycle .one -> .two -> .one terminated, and the deep and outside files were not read
}

// Whatever is in a file, no parser may panic, hang, or print.
func FuzzParsers(f *testing.F) {
	r := newRNG(f)
	secret := randFrom(r, alnum, 30)
	begin, end := pemArmor("OPENSSH PRIVATE KEY")
	for _, s := range []string{
		"A_KEY=" + secret + "\n", "export A_KEY=\"" + secret + "\n", "A=$(x) B='" + secret, "{\"a\": [\"" + secret + "\"",
		"<plist><dict><key>EnvironmentVariables</key><dict><key>A</key><string>" + secret + "</string></dict></dict></plist>",
		"bplist00\xd1\x01\x02\x5a" + secret, "machine x login y password " + secret, "[s]\nk = { a = \"" + secret + "\" }\n",
		begin + "\n" + secret + secret + secret + "\n" + end + "\n",
		"postgres://u:" + secret + "@h/db", "- a: [b, {c: d}]\nk: |\n  x\n", "\x00\x01\x02", "'''", "\"\"\"", "\\", "$'\\",
	} {
		f.Add([]byte(s))
	}
	parsers := []parseFunc{parseDotenv, parseShell, parsePlist, parseJSON, parseKV, parseNpmrc, parseNetrc, parseDocker, parseLines}
	l := scratchLearner(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		l.cands = map[string]*cand{}
		l.read = map[string]bool{}
		start := time.Now()
		for _, p := range parsers {
			p(l, "x", data)
		}
		l.privateKeys("x", "x", string(data))
		urlPasswords(string(data))
		rejection(string(data))
		if d := time.Since(start); d > 5*time.Second {
			t.Fatalf("parsers took %v on %d bytes", d, len(data))
		}
	})
}

// randomJSON builds a document of nested objects and arrays with every scalar type. Keys
// are unique within an object, so a decoded tree and the token stream describe the same thing.
func randomJSON(r *rand.Rand, depth int) any {
	switch k := r.IntN(8); {
	case k < 2 && depth < 5:
		m := map[string]any{}
		for i := r.IntN(5); i >= 0; i-- {
			m[randFrom(r, "abcdefgh_KEY", 1+r.IntN(6))+"-"+randFrom(r, alnum, 3)] = randomJSON(r, depth+1)
		}
		return m
	case k < 4 && depth < 5:
		var a []any
		for i := r.IntN(5); i >= 0; i-- {
			a = append(a, randomJSON(r, depth+1))
		}
		return a
	case k == 4:
		return float64(r.IntN(1000))
	case k == 5:
		return r.IntN(2) == 0
	case k == 6:
		return nil
	default:
		return trickyString(r) + randFrom(r, alnum, r.IntN(30))
	}
}

func TestJSONStreamMatchesTreeWalk(t *testing.T) {
	r := newRNG(t)
	for i := 0; i < 400; i++ {
		doc := randomJSON(r, 0)
		b, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		var got, want []string
		if err := walkJSON(b, &walker{emit: func(cred) {}, any: func(k, v string) { got = append(got, k+"\x00"+v) }}); err != nil {
			t.Fatalf("doc %d: %v", i, err)
		}
		var walk func(key string, v any)
		walk = func(key string, v any) {
			switch x := v.(type) {
			case map[string]any:
				for k, e := range x {
					walk(k, e)
				}
			case []any:
				for _, e := range x {
					walk(key, e)
				}
			case string:
				want = append(want, key+"\x00"+x)
			}
		}
		// The reference walks what a decoder makes of the bytes, not the Go value: marshalling
		// turns invalid UTF-8 into U+FFFD, and both readers must see that.
		var tree any
		if err := json.Unmarshal(b, &tree); err != nil {
			t.Fatal(err)
		}
		walk("", tree)
		sort.Strings(got)
		sort.Strings(want)
		if strings.Join(got, "\n") != strings.Join(want, "\n") {
			t.Fatalf("doc %d: the token stream and the tree walk disagree (%d vs %d strings)", i, len(got), len(want))
		}
	}
	// Broken JSON is an error the caller can fall back on, not a panic.
	for _, bad := range []string{`{"a": [`, `{"a" "b"}`, `]`, `{`, `{"a":1,}`} {
		if err := walkJSON([]byte(bad), &walker{emit: func(cred) {}}); err == nil {
			t.Errorf("broken JSON %q read as complete", bad)
		}
	}
}
