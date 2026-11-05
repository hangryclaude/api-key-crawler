package known

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"keyguard/internal/core"
	"keyguard/internal/fp"
	"keyguard/internal/testkit"
)

// fixture is a fake home directory full of the kinds of files Learn reads, with fake
// secrets assembled at runtime. Every value it hands out is remembered so the leak checks
// can look for it.
type fixture struct {
	t      *testing.T
	r      *rand.Rand
	home   string
	root   string
	values []string          // every planted secret, learnable or not
	want   map[string]string // value -> substring its learned name must contain
	not    map[string]string // value -> why it must not be learned
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	root := testEnv(t)
	return &fixture{t: t, r: newRNG(t), home: t.TempDir(), root: root, want: map[string]string{}, not: map[string]string{}}
}

func (f *fixture) write(rel, content string) string {
	f.t.Helper()
	p := filepath.Join(f.home, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		f.t.Fatal(err)
	}
	return p
}

// secret makes a fake with a short public prefix (so fp.Shape never shows a 12-byte window
// of it), remembers it, and says it must be learned under a name containing wantName.
func (f *fixture) secret(prefix string, n int, wantName string) string {
	v := prefix + randFrom(f.r, alnum, n)
	f.values = append(f.values, v)
	if wantName != "" {
		f.want[v] = wantName
	}
	return v
}

func (f *fixture) reject(prefix string, n int, why string) string {
	v := prefix + randFrom(f.r, alnum, n)
	f.values = append(f.values, v)
	f.not[v] = why
	return v
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// fakeOpenSSHKey builds an unencrypted openssh-key-v1 file around random bytes: the real
// layout (magic, none/none, one public blob, a private section), wrapped at 70 columns.
func fakeOpenSSHKey(r *rand.Rand) (text string, lines []string) {
	str := func(b []byte) []byte {
		out := binary.BigEndian.AppendUint32(nil, uint32(len(b)))
		return append(out, b...)
	}
	rnd := func(n int) []byte {
		b := make([]byte, n)
		for i := range b {
			b[i] = byte(r.IntN(256))
		}
		return b
	}
	pub := append(str([]byte("ssh-ed25519")), str(rnd(32))...)
	raw := []byte("openssh-key-v1\x00")
	raw = append(raw, str([]byte("none"))...)
	raw = append(raw, str([]byte("none"))...)
	raw = append(raw, str(nil)...)
	raw = binary.BigEndian.AppendUint32(raw, 1)
	raw = append(raw, str(pub)...)
	raw = append(raw, str(rnd(200))...)
	enc := base64.StdEncoding.EncodeToString(raw)
	lines = wrap(enc, 70)
	begin, end := pemArmor("OPENSSH PRIVATE KEY")
	return begin + "\n" + strings.Join(lines, "\n") + "\n" + end + "\n", lines
}

// pemArmor builds the BEGIN and END lines of a PEM block at run time, so no key-shaped block
// is written out in this source (PLAN invariant 2: the repo passes its own scanners).
func pemArmor(kind string) (begin, end string) {
	dashes := strings.Repeat("-", 5)
	return dashes + "BEGIN " + kind + dashes, dashes + "END " + kind + dashes
}

func fakeRSAKey(r *rand.Rand, nLines int) (text string, lines []string) {
	for i := 0; i < nLines; i++ {
		lines = append(lines, randFrom(r, b64chars[:62]+"+/", 64))
	}
	begin, end := pemArmor("RSA PRIVATE KEY")
	return begin + "\n" + strings.Join(lines, "\n") + "\n" + end + "\n", lines
}

func luhnNumber(r *rand.Rand, digits int) string {
	d := make([]byte, digits)
	for i := 0; i < digits-1; i++ {
		d[i] = byte('0' + r.IntN(10))
	}
	for c := byte('0'); c <= '9'; c++ {
		d[digits-1] = c
		if luhn(d) {
			break
		}
	}
	return string(d)
}

func (f *fixture) learn(opts Options) (*Report, string) {
	f.t.Helper()
	opts.Home, opts.Root = f.home, f.root
	if opts.GHUsers == nil {
		opts.GHUsers = []string{}
	}
	var log bytes.Buffer
	opts.Log = &log
	rep, err := Learn(opts)
	if err != nil {
		f.t.Fatalf("Learn: %v", err)
	}
	return rep, log.String()
}

func (f *fixture) store() (*Store, *fp.Keyring) {
	f.t.Helper()
	dir := core.PathsAt(f.root).Known
	st, err := readStore(dir)
	if err != nil || st == nil {
		f.t.Fatalf("store unreadable: %v", err)
	}
	kr, err := fp.Load(dir)
	if err != nil {
		f.t.Fatal(err)
	}
	return st, kr
}

// check asserts every wanted value is in the store under the right name with all of its
// forms, and every refused value is absent.
func (f *fixture) check() {
	f.t.Helper()
	st, kr := f.store()
	byFP := map[string][]Entry{}
	for _, e := range st.Entries {
		byFP[e.FP] = append(byFP[e.FP], e)
	}
	for v, name := range f.want {
		es := byFP[kr.FP(v)]
		if len(es) == 0 {
			f.t.Errorf("value planted for %q was not learned", name)
			continue
		}
		if !strings.Contains(es[0].Name, name) {
			f.t.Errorf("value planted for %q was learned as %q", name, es[0].Name)
		}
		if es[0].Variant != "raw" || es[0].Len != len(v) {
			f.t.Errorf("%q: first form is %s/%d, want raw/%d", name, es[0].Variant, es[0].Len, len(v))
		}
		// The encodings are checked against the standard library's, not variantsOf.
		vfps := map[string]bool{}
		for _, e := range es {
			vfps[e.VFP] = true
		}
		for label, enc := range map[string]string{
			"std":    base64.StdEncoding.EncodeToString([]byte(v)),
			"url":    base64.RawURLEncoding.EncodeToString([]byte(v)),
			"padurl": base64.URLEncoding.EncodeToString([]byte(v)),
		} {
			if !vfps[kr.FP(enc)] {
				f.t.Errorf("%q: the %s base64 form was not registered", name, label)
			}
		}
	}
	for v, why := range f.not {
		if len(byFP[kr.FP(v)]) != 0 {
			f.t.Errorf("a value that must be refused (%s) was learned as %q", why, byFP[kr.FP(v)][0].Name)
		}
	}
}

// fataler is the part of *testing.T the leak audit uses, so the audit itself can be tested
// against a recorder.
type fataler interface {
	Helper()
	Fatalf(format string, args ...any)
}

// assertNoValue is the leak audit: no 12-byte window of any planted value, in any of the
// forms learn registers, may appear in any output. Twelve bytes is the matcher's own
// window: if no window survives, no usable part of the value does. The public prefix
// fp.Shape shows is shorter than that by construction.
func assertNoValue(t fataler, values []string, outputs map[string][]byte) {
	t.Helper()
	checked := 0
	for _, v := range values {
		for _, form := range variantsOf([]byte(v)) {
			for i := 0; i+window <= len(form.b); i++ {
				w := form.b[i : i+window]
				for name, out := range outputs {
					if bytes.Contains(out, w) {
						t.Fatalf("a %s window of a planted value (offset %d, form %s) appears in %s", form.label, i, form.label, name)
					}
				}
				checked++
			}
		}
	}
	if checked == 0 {
		t.Fatalf("leak audit checked nothing")
	}
}

// captureStd runs fn with os.Stdout and os.Stderr redirected into buffers.
func captureStd(t *testing.T, fn func()) (stdout, stderr []byte) {
	t.Helper()
	oo, oe := os.Stdout, os.Stderr
	ro, wo, _ := os.Pipe()
	re, we, _ := os.Pipe()
	os.Stdout, os.Stderr = wo, we
	var wg sync.WaitGroup
	var bo, be bytes.Buffer
	wg.Add(2)
	go func() { defer wg.Done(); io.Copy(&bo, ro) }()
	go func() { defer wg.Done(); io.Copy(&be, re) }()
	defer func() {
		os.Stdout, os.Stderr = oo, oe
	}()
	fn()
	wo.Close()
	we.Close()
	wg.Wait()
	return bo.Bytes(), be.Bytes()
}

func TestLearnEveryFormat(t *testing.T) {
	f := newFixture(t)

	// dotenv: export, quotes, inline comments, spaces around =, a multi-line value, the
	// URL password, and every kind of value that must be refused.
	s1 := f.secret("sk-proj-", 48, "OPENAI_API_KEY")
	s2 := f.secret("sk_live_", 30, "STRIPE_SECRET_KEY")
	s3 := f.secret("", 40, "QUOTED_TOKEN")
	s4 := f.secret("", 36, "SPACED_SECRET")
	pw1 := f.secret("", 24, "DATABASE_URL (url password)")
	m1, m2 := randFrom(f.r, alnum, 30), randFrom(f.r, alnum, 30)
	f.values = append(f.values, m1, m2)
	f.want[m1+"\n"+m2] = "MULTI_SECRET"
	esc := f.secret("", 20, "ESCAPED_TOKEN")
	unnamed := f.reject("", 40, "unnamed and no engine vouches for it")
	noModule := f.reject("ghp_", 36, "inside node_modules")
	skipped := f.reject("", 40, "inside a SkipDir")
	f.write("dev/app/.env", fmt.Sprintf(`# a comment
OPENAI_API_KEY=%s
export STRIPE_SECRET_KEY='%s'
QUOTED_TOKEN="%s"   # inline comment
SPACED_SECRET = %s
DATABASE_URL=postgres://app:%s@db.internal:5432/app
MULTI_SECRET="%s
%s"
ESCAPED_TOKEN="%s\"x"
DEBUG=true
PLACEHOLDER_KEY=your_api_key_here
SHORT_TOKEN=abc123
LOW_ENTROPY_SECRET=aaaaaaaaaaaaaaaaaaaaaaaa
CHANGEME_TOKEN=changeme-changeme-changeme
TEMPLATE_KEY=${SOME_OTHER_VAR}
HARMLESS_THING=%s
EMPTY_TOKEN=
DOCS_URL=https://example.org/docs/page
PATH_SECRET=/usr/local/bin/some/long/path
VERSION_KEY=1.2.3.4.5.6.7.8
`, s1, s2, s3, s4, pw1, m1, m2, esc, unnamed))
	// ESCAPED_TOKEN's real value ends in "x after the unescape; adjust the expectation.
	delete(f.want, esc)
	f.want[esc+`"x`] = "ESCAPED_TOKEN"
	f.write("dev/app/node_modules/pkg/.env", "HIDDEN_TOKEN="+noModule+"\n")
	f.write("sec/tools/.env", "TOOLS_TOKEN="+skipped+"\n")
	s5 := f.secret("", 40, "PROJ_API_KEY")
	f.write("sec/proj/.env.local", "PROJ_API_KEY="+s5+"\n")

	card := luhnNumber(f.r, 16)
	f.values = append(f.values, card)
	f.want[card] = "CARD_NUMBER"
	f.write("projects/shop/.env", fmt.Sprintf("CARD_NUMBER=%s %s %s %s\n", card[:4], card[4:8], card[8:12], card[12:]))
	f.want[card[:4]+" "+card[4:8]+" "+card[8:12]+" "+card[12:]] = "CARD_NUMBER"

	// shell rc: exports, several per line, a dynamic value, a sourced file.
	z1 := f.secret("ghp_", 36, "ZSH_TOKEN")
	z2 := f.secret("", 32, "B_SECRET")
	z3 := f.secret("", 32, "SOURCED_API_KEY")
	dyn := f.reject("", 30, "dynamic")
	f.write(".zshrc", fmt.Sprintf(`export ZSH_TOKEN=%s
export A=1 B_SECRET="%s"
alias ll='ls -l'
export DYN_TOKEN=$(cat ~/x)
export HOME_REF_TOKEN="$HOME/abc%s"
[ -f ~/.secrets ] && source "$HOME/.secrets"
`, z1, z2, dyn))
	f.write(".secrets", "export SOURCED_API_KEY='"+z3+"'\n")

	// launchd: XML plist with EnvironmentVariables and a --token flag in ProgramArguments.
	p1 := f.secret("", 40, "SERVICE_API_KEY")
	p2 := f.secret("", 36, "token")
	f.write("Library/LaunchAgents/com.test.plist", fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>com.test</string>
<key>EnvironmentVariables</key><dict>
  <key>SERVICE_API_KEY</key><string>%s</string>
  <key>PATH</key><string>/usr/bin:/bin</string>
</dict>
<key>ProgramArguments</key><array><string>/bin/run</string><string>--token=%s</string></array>
<key>RunAtLoad</key><true/>
</dict></plist>`, p1, p2))
	// The same shape through Apple's own binary encoder.
	p3 := f.secret("", 40, "BIN_PLIST_SECRET")
	xml := filepath.Join(t.TempDir(), "x.plist")
	os.WriteFile(xml, []byte(fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>EnvironmentVariables</key><dict><key>BIN_PLIST_SECRET</key><string>%s</string></dict></dict></plist>`, p3)), 0o600)
	binPath := filepath.Join(f.home, "Library/LaunchAgents/com.binary.plist")
	if out, err := exec.Command("plutil", "-convert", "binary1", "-o", binPath, xml).CombinedOutput(); err != nil {
		t.Fatalf("plutil: %v (%d bytes of output)", err, len(out))
	}

	// npm, netrc, aws, docker, pypirc, git-credentials.
	n1 := f.secret("npm_", 36, "npmrc _authToken")
	n2 := f.secret("", 24, "npmrc _password decoded")
	f.write(".npmrc", fmt.Sprintf("registry=https://registry.npmjs.org/\n//registry.npmjs.org/:_authToken=%s\n_password=%s\nusername=me\n//other/:_authToken=${NPM_TOKEN}\n", n1, b64(n2)))
	nt1 := f.secret("", 28, "netrc api.example.com password")
	nt2 := f.secret("", 28, "netrc other.example.com password")
	f.write(".netrc", fmt.Sprintf("machine api.example.com login me password %s\nmachine other.example.com\n  login bob\n  password %s\n", nt1, nt2))
	a1 := f.secret("AKIA", 16, "aws_access_key_id")
	a2 := f.secret("", 40, "aws_secret_access_key")
	f.write(".aws/credentials", fmt.Sprintf("[default]\naws_access_key_id = %s\naws_secret_access_key = %s\nregion = us-east-1\n", a1, a2))
	d1 := f.secret("", 26, "docker ghcr.io password")
	f.write(".docker/config.json", fmt.Sprintf(`{"auths":{"ghcr.io":{"auth":"%s"}},"credsStore":"desktop"}`, b64("someone:"+d1)))
	f.want["someone:"+d1] = "docker ghcr.io login"
	f.values = append(f.values, "someone:"+d1)
	py := f.secret("pypi-", 60, "password")
	f.write(".pypirc", fmt.Sprintf("[pypi]\nusername = __token__\npassword: %s\n", py))
	gc := f.secret("", 36, "git-credentials (url password)")
	f.write(".git-credentials", fmt.Sprintf("https://someone:%s@github.com\n", gc))

	// JSON, TOML, YAML under ~/.config, plus a file past the size limit.
	j1 := f.secret("", 40, "api_key")
	j2 := f.secret("", 40, "refresh_token")
	f.write(".config/app/settings.json", fmt.Sprintf(`{"name":"x","auth":{"api_key":"%s","tokens":[{"refresh_token":"%s"}]},"count":3}`, j1, j2))
	t1 := f.secret("", 36, "token")
	t2 := f.secret("", 36, "api_token")
	f.write(".config/tool/config.toml", fmt.Sprintf("[server]\nname = \"x\"\n[auth]\ntoken = \"%s\"\nclient = { api_token = \"%s\", id = \"12\" }\n", t1, t2))
	y1 := f.secret("gho_", 36, "oauth_token")
	f.write(".config/gh/hosts.yml", fmt.Sprintf("github.com:\n    user: someone\n    oauth_token: %s\n    git_protocol: https\n", y1))
	f.write(".config/big/huge.json", `{"api_key":"`+strings.Repeat("x", 300<<10)+`"}`)

	// kube config: a token, and client-key-data holding a base64 PEM key.
	k1 := f.secret("", 40, "token")
	kubeKey, kubeLines := fakeRSAKey(f.r, 20)
	f.write(".kube/config", fmt.Sprintf("apiVersion: v1\nusers:\n- name: u\n  user:\n    token: %s\n    client-key-data: %s\n", k1, b64(kubeKey)))
	// codex auth.json
	c1 := f.secret("sk-proj-", 60, "OPENAI_API_KEY")
	f.write(".codex/auth.json", fmt.Sprintf(`{"OPENAI_API_KEY":"%s","last_refresh":"2026-11-03T10:00:00Z"}`, c1))

	// ssh keys: OpenSSH (public part must be skipped), RSA (capped), a public key, a config.
	sshText, sshLines := fakeOpenSSHKey(f.r)
	f.write(".ssh/id_ed25519", sshText)
	f.write(".ssh/id_ed25519.pub", "ssh-ed25519 "+randFrom(f.r, b64chars, 68)+" me@host\n")
	rsaText, rsaLines := fakeRSAKey(f.r, 25)
	f.write(".ssh/deploy_key", rsaText)
	f.write(".ssh/config", "Host *\n  IdentityFile ~/.ssh/id_ed25519\n")

	// A key inside a JSON service account (literal \n), and one on a single .env line.
	gcpKey, gcpLines := fakeRSAKey(f.r, 8)
	esc2 := strings.ReplaceAll(gcpKey, "\n", `\n`)
	f.write(".config/gcp/sa.json", fmt.Sprintf(`{"type":"service_account","private_key":"%s"}`, esc2))
	_, oneLines := fakeRSAKey(f.r, 6)
	begin, end := pemArmor("RSA PRIVATE KEY")
	oneLine := begin + strings.Join(oneLines, "") + end
	f.write("dev/app2/.env", fmt.Sprintf("ONE_LINE_PRIVATE_KEY=\"%s\"\n", oneLine))

	// gh: the runner is a fake; nothing asks the real gh for anything.
	g1 := f.secret("gho_", 36, "gh auth token --user hangryclaude")
	g2 := f.secret("ghp_", 36, "gh auth token --user alt-builds")
	var asked []string
	run := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		asked = append(asked, name+" "+strings.Join(args, " "))
		switch args[len(args)-1] {
		case "hangryclaude":
			return []byte(g1 + "\n"), nil
		case "alt-builds":
			return []byte(g2 + "\n"), nil
		}
		return nil, errors.New("not logged in")
	}

	var rep *Report
	var log string
	stdout, stderr := captureStd(t, func() {
		rep, log = f.learn(Options{GHUsers: []string{"hangryclaude", "alt-builds", "nobody"}, Run: run})
	})
	if len(asked) != 3 || asked[0] != "gh auth token --user hangryclaude" {
		t.Fatalf("gh was asked %q", asked)
	}
	f.check()

	// The key lines.
	st, kr := f.store()
	learnedLine := func(line string) bool {
		for _, e := range st.Entries {
			if e.FP == kr.FP(line) {
				return true
			}
		}
		return false
	}
	for i, ln := range sshLines {
		want := i >= 2 && len(ln) >= minKeyLine // lines 0 and 1 are the header and the public key
		if learnedLine(ln) != want {
			t.Errorf("OpenSSH key line %d (%d chars): learned=%v, want %v", i, len(ln), !want, want)
		}
	}
	for i, ln := range rsaLines {
		if want := i < maxKeyLines; learnedLine(ln) != want {
			t.Errorf("RSA key line %d: learned=%v, want %v", i, !want, want)
		}
	}
	for i, ln := range gcpLines[:maxKeyLines/2] {
		if !learnedLine(ln) {
			t.Errorf("JSON-escaped service account key line %d not learned", i)
		}
	}
	for i, ln := range oneLines[:3] {
		if !learnedLine(ln) {
			t.Errorf("one-line env key: wrapped line %d not learned", i)
		}
	}
	if !learnedLine(strings.Join(oneLines, "")) {
		t.Error("one-line env key not learned whole")
	}
	for i, ln := range kubeLines[:3] {
		if !learnedLine(ln) {
			t.Errorf("kube client-key-data: decoded key line %d not learned", i)
		}
	}
	// The ed25519 public key is public.
	pubLine := strings.Fields(mustRead(t, filepath.Join(f.home, ".ssh/id_ed25519.pub")))[1]
	if learnedLine(pubLine) {
		t.Error("the .pub file was learned")
	}

	// Rejections are counted by reason; the oversized file is listed, not silently dropped.
	for _, why := range []string{rejShort, rejPlaceholder, rejEntropy, rejURL, rejPath, rejNumber, rejName} {
		if rep.Rejected[why] == 0 {
			t.Errorf("no value was rejected for %q", why)
		}
	}
	if rep.Rejected["dynamic"] == 0 {
		t.Error("the $(…) export was not counted as dynamic")
	}
	if !containsSub(rep.Skipped, "huge.json") {
		t.Errorf("the 300 KB config file was not reported as skipped: %v", rep.Skipped)
	}
	if rep.Files < 20 || len(rep.Learned) < 30 {
		t.Errorf("read %d files and learned %d secrets", rep.Files, len(rep.Learned))
	}

	// The leak audit: no usable part of any planted value, in any output of the run.
	storeBytes := mustRead(t, filepath.Join(core.PathsAt(f.root).Known, storeFile))
	saltBytes := mustRead(t, filepath.Join(core.PathsAt(f.root).Known, "salt"))
	assertNoValue(t, append(f.values, sshLines...), map[string][]byte{
		"known.json": []byte(storeBytes),
		"salt":       []byte(saltBytes),
		"summary":    []byte(rep.Summary()),
		"report":     []byte(fmt.Sprintf("%+v", *rep)),
		"log":        []byte(log),
		"stdout":     stdout,
		"stderr":     stderr,
	})
	if len(stdout)+len(stderr) != 0 {
		t.Errorf("Learn printed %d bytes to stdout and %d to stderr", len(stdout), len(stderr))
	}
	// And nothing but the store and the salt was written under the root.
	var files []string
	filepath.WalkDir(f.root, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			rel, _ := filepath.Rel(f.root, p)
			files = append(files, rel)
		}
		return nil
	})
	if got := strings.Join(files, ","); got != "state/known/.learn.lock,state/known/known.json,state/known/salt" {
		t.Errorf("files under the data root: %s", got)
	}
}

func mustRead(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func containsSub(list []string, sub string) bool {
	for _, s := range list {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func TestLearnPermsAtomicAndMerge(t *testing.T) {
	f := newFixture(t)
	a := f.secret("sk-proj-", 40, "A_API_KEY")
	b := f.secret("sk-proj-", 40, "B_API_KEY")
	envA := f.write("dev/a/.env", "A_API_KEY="+a+"\n")
	f.write("dev/b/.env", "B_API_KEY="+b+"\n")

	rep, _ := f.learn(Options{})
	if rep.Added != 2 || rep.Refreshed != 0 || len(rep.Learned) != 2 {
		t.Fatalf("first run: %+v", rep)
	}
	dir := core.PathsAt(f.root).Known
	for p, want := range map[string]os.FileMode{
		dir:                            0o700,
		filepath.Join(dir, storeFile):  0o600,
		filepath.Join(dir, "salt"):     0o600,
		filepath.Join(dir, lockFile):   0o600,
		filepath.Join(f.root, "state"): 0o700,
		filepath.Join(f.root):          0o700,
	} {
		st, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != want {
			t.Errorf("%s is %v, want %v", strings.TrimPrefix(p, f.root), st.Mode().Perm(), want)
		}
	}
	ents, _ := os.ReadDir(dir)
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	// known.json, the salt and the lock file; a temp file here would mean a write was not finished.
	if strings.Join(names, ",") != ".learn.lock,known.json,salt" {
		t.Errorf("files in the store dir: %v", names)
	}
	f.check()
	first := mustRead(t, filepath.Join(dir, storeFile))

	// A second run over the same machine changes nothing but the timestamp.
	rep, _ = f.learn(Options{})
	if rep.Added != 0 || rep.Refreshed != 2 || rep.Retained != 0 {
		t.Fatalf("second run: added %d refreshed %d retained %d", rep.Added, rep.Refreshed, rep.Retained)
	}
	strip := func(s string) string { i := strings.Index(s, `"entries"`); return s[i:] }
	if strip(first) != strip(mustRead(t, filepath.Join(dir, storeFile))) {
		t.Error("a repeated run produced different entries")
	}

	// The source moves away. The secret stays learned: a live key must not lose protection
	// because its file went to the archive.
	os.Rename(envA, filepath.Join(filepath.Dir(envA), "moved.txt"))
	rep, _ = f.learn(Options{})
	if rep.Retained != 1 || rep.Refreshed != 1 || rep.Pruned != 0 {
		t.Fatalf("after the move: %+v", rep)
	}
	f.check()
	// Prune is the explicit way to forget it.
	rep, _ = f.learn(Options{Prune: true})
	if rep.Pruned != 1 || rep.Retained != 0 {
		t.Fatalf("prune: %+v", rep)
	}
	delete(f.want, a)
	f.not[a] = "pruned"
	f.check()

	// Prune with nothing readable proves nothing: it must not wipe the store.
	empty := newFixture(t)
	empty.root = f.root
	rep, _ = empty.learn(Options{Prune: true})
	if rep.Pruned != 0 || !containsSub(rep.Notes, "prune skipped") {
		t.Fatalf("prune over an empty home: %+v", rep)
	}
	empty.want[b] = "B_API_KEY"
	empty.check()
}

func TestLearnDiscardsStoreOfAnotherSalt(t *testing.T) {
	f := newFixture(t)
	a := f.secret("sk-proj-", 40, "A_API_KEY")
	f.write("dev/a/.env", "A_API_KEY="+a+"\n")
	f.learn(Options{})
	// Replace the salt (as if ~/.keyguard/state/known/salt were lost and recreated).
	dir := core.PathsAt(f.root).Known
	os.Remove(filepath.Join(dir, "salt"))
	if _, err := fp.Load(dir); err != nil {
		t.Fatal(err)
	}
	// The hook-side loader must say so instead of matching nothing in silence.
	m, err := LoadMatcher([]string{f.root})
	if err == nil || !strings.Contains(err.Error(), "different salt") || m.Len() != 0 {
		t.Fatalf("LoadMatcher with a replaced salt: len %d, err %v", m.Len(), err)
	}
	rep, _ := f.learn(Options{})
	if !containsSub(rep.Notes, "different salt") || rep.Retained != 0 {
		t.Fatalf("notes: %v", rep.Notes)
	}
	f.check()
	if m, err := LoadMatcher([]string{f.root}); err != nil || m.Len() == 0 {
		t.Fatalf("after relearn: len %d err %v", m.Len(), err)
	}
}

// fakeEngine flags the planted values it is told about when "scanning" a file that holds
// them, fingerprinting with the keyring it was built with, the way a real normalizer does.
type fakeEngine struct {
	kr        *fp.Keyring
	detect    []string
	scanned   []string
	available bool
	mu        sync.Mutex
}

func (e *fakeEngine) Name() string    { return "fake" }
func (e *fakeEngine) Version() string { return "0" }
func (e *fakeEngine) Available() bool { return e.available }
func (e *fakeEngine) ScanGit(context.Context, string, core.Range, core.ScanOpts, core.Emit) error {
	return core.ErrUnsupported
}
func (e *fakeEngine) ScanStaged(context.Context, string, core.ScanOpts, core.Emit) error {
	return core.ErrUnsupported
}
func (e *fakeEngine) ScanDir(ctx context.Context, path string, o core.ScanOpts, emit core.Emit) error {
	e.mu.Lock()
	e.scanned = append(e.scanned, path)
	e.mu.Unlock()
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	for _, v := range e.detect {
		if bytes.Contains(b, []byte(v)) {
			emit(core.Hit{Engine: "fake", FP: e.kr.FP(v), Loc: o.Loc})
		}
	}
	return nil
}

func TestLearnEngineVouchesForUnnamedValues(t *testing.T) {
	f := newFixture(t)
	named := f.secret("", 40, "STRIPE_KEY")
	vouched := f.secret("", 40, "SOMETHING_ID")
	ignored := f.reject("", 40, "unnamed and the engine did not flag it")
	const placeholder = "your_api_key_goes_here_ok"
	f.not[placeholder] = "flagged by the engine but a placeholder"
	f.write("dev/a/.env", fmt.Sprintf("STRIPE_KEY=%s\nSOMETHING_ID=%s\nOTHER_THING=%s\nPLACEHOLDER_ID=%s\nDEBUG=1\n", named, vouched, ignored, placeholder))
	f.write("dev/clean/.env", "ONLY_NAMED_SECRET="+f.secret("", 40, "ONLY_NAMED_SECRET")+"\n")

	kr, err := fp.Load(core.PathsAt(f.root).Known)
	if err != nil {
		t.Fatal(err)
	}
	eng := &fakeEngine{kr: kr, detect: []string{vouched, placeholder}, available: true}
	off := &fakeEngine{kr: kr, detect: []string{ignored}, available: false}
	rep, _ := f.learn(Options{Engines: []core.Engine{off, eng}})
	f.check()
	// Only the file that holds an unnamed candidate is handed to an engine.
	if len(eng.scanned) != 1 || !strings.HasSuffix(eng.scanned[0], filepath.Join("dev", "a", ".env")) {
		t.Fatalf("engine was given %v", eng.scanned)
	}
	if len(off.scanned) != 0 || !containsSub(rep.Notes, "fake is not installed") {
		t.Fatalf("an unavailable engine was used or not reported: %v %v", off.scanned, rep.Notes)
	}
}

// The real engines, through a test-only adapter that does what the engines package does:
// run with the report piped to us, fingerprint each secret, drop it. The three CLIs differ
// only in arguments and report shape.
type cliEngine struct {
	kr    *fp.Keyring
	name  string
	bin   string
	args  func(path string) []string
	parse func(report []byte) ([]string, error) // the raw secrets the report names
}

func (e cliEngine) Name() string    { return e.name }
func (e cliEngine) Version() string { return "test" }
func (e cliEngine) Available() bool { return true }
func (e cliEngine) ScanGit(context.Context, string, core.Range, core.ScanOpts, core.Emit) error {
	return core.ErrUnsupported
}
func (e cliEngine) ScanStaged(context.Context, string, core.ScanOpts, core.Emit) error {
	return core.ErrUnsupported
}
func (e cliEngine) ScanDir(ctx context.Context, path string, o core.ScanOpts, emit core.Emit) error {
	out, err := exec.CommandContext(ctx, e.bin, e.args(path)...).Output()
	var ee *exec.ExitError
	if err != nil && !(errors.As(err, &ee) && ee.ExitCode() == 1) { // 1 means "found leaks"
		return err
	}
	secrets, err := e.parse(out)
	if err != nil {
		return errors.New("unparseable report")
	}
	for _, s := range secrets {
		emit(core.Hit{Engine: e.name, FP: e.kr.FP(s), Loc: o.Loc})
	}
	return nil
}

// gitleaksFamily reads the JSON array betterleaks and gitleaks both write.
func gitleaksFamily(report []byte) ([]string, error) {
	var findings []struct{ Secret string }
	if err := json.Unmarshal(report, &findings); err != nil {
		return nil, err
	}
	var out []string
	for _, f := range findings {
		out = append(out, f.Secret)
	}
	return out, nil
}

func truffleHogLines(report []byte) ([]string, error) {
	var out []string
	for _, line := range bytes.Split(report, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var f struct{ Raw string }
		if err := json.Unmarshal(line, &f); err != nil {
			return nil, err
		}
		out = append(out, f.Raw)
	}
	return out, nil
}

func TestLearnWithRealEngines(t *testing.T) {
	dirArgs := func(path string) []string {
		return []string{"dir", path, "-r", "-", "-f", "json", "--no-banner", "--no-color", "-l", "error"}
	}
	for _, tc := range []struct {
		name  string
		args  func(string) []string
		parse func([]byte) ([]string, error)
	}{
		{"betterleaks", dirArgs, gitleaksFamily},
		{"gitleaks", dirArgs, gitleaksFamily},
		{"trufflehog", func(p string) []string {
			return []string{"filesystem", p, "--json", "--no-verification", "--no-update"}
		}, truffleHogLines},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bin := testkit.EnginePath(t, tc.name) // skipped where the engine is absent, failed in CI
			f := newFixture(t)
			// A GitHub token under a name that says nothing, and a random string under another
			// that no rule recognises.
			token := f.secret("ghp_", 36, "UNNAMED_THING")
			nothing := f.reject("", 40, "no engine rule matches it and the name is harmless")
			f.write("dev/a/.env", fmt.Sprintf("UNNAMED_THING=%s\nOTHER_THING=%s\n", token, nothing))
			kr, err := fp.Load(core.PathsAt(f.root).Known)
			if err != nil {
				t.Fatal(err)
			}
			f.learn(Options{Engines: []core.Engine{cliEngine{kr, tc.name, bin, tc.args, tc.parse}}})
			f.check()
		})
	}
}

func TestLearnErrorsAndSkipsCarryNoContent(t *testing.T) {
	f := newFixture(t)
	v := f.secret("", 40, "")
	// Broken versions of every structured format, each with a planted value inside.
	f.write(".config/a/bad.json", `{"api_key": "`+v+`", "oops": [`)
	f.write("Library/LaunchAgents/bad.plist", `<plist><dict><key>EnvironmentVariables</key><dict><key>A_TOKEN</key><string>`+v)
	f.write("Library/LaunchAgents/bad2.plist", "bplist00"+v)
	f.write(".config/a/bin.toml", "\x00\x01\x02"+v)
	f.write("dev/x/.env", "BROKEN_TOKEN=\""+v+"\nNEXT=1\n")
	f.write(".config/c/big.yaml", "token: "+v+strings.Repeat("\n# padding", 40000))
	unreadable := f.write(".config/d/locked.yml", "token: "+v)
	os.Chmod(unreadable, 0)
	t.Cleanup(func() { os.Chmod(unreadable, 0o600) })

	var rep *Report
	var log string
	stdout, stderr := captureStd(t, func() { rep, log = f.learn(Options{}) })
	if len(rep.Skipped) == 0 {
		t.Fatal("no skip was reported for broken files")
	}
	assertNoValue(t, []string{v}, map[string][]byte{
		"summary": []byte(rep.Summary()), "report": []byte(fmt.Sprintf("%+v", *rep)),
		"log": []byte(log), "stdout": stdout, "stderr": stderr,
		"store": []byte(mustRead(t, filepath.Join(core.PathsAt(f.root).Known, storeFile))),
	})
}

func TestNameFilter(t *testing.T) {
	for _, n := range []string{"OPENAI_API_KEY", "token", "AccessToken", "client_secret", "DB_PASSWORD", "dbPwd",
		"Authorization", "AWS_CREDENTIALS", "PRIVATE_THING", "SENTRY_DSN", "SLACK_WEBHOOK_URL", "session_id",
		"COOKIE_JAR", "BEARER", "TWILIO_ACCOUNT_SID", "SIGNING_STRING", "CARD_NUMBER", "cardNumber", "card-number"} {
		if !nameLooksSecret(n) {
			t.Errorf("%q should pass the name filter", n)
		}
	}
	for _, n := range []string{"DEBUG", "PORT", "ANTHROPIC_MODEL", "NODE_ENV", "HOME", "region", "LOG_LEVEL", "name", "CARD"} {
		if nameLooksSecret(n) {
			t.Errorf("%q should not pass the name filter", n)
		}
	}
}

func TestValueFilter(t *testing.T) {
	r := newRNG(t)
	// Failures name the case, never print it: the first two values are generated fakes.
	for _, tc := range []struct{ name, value, want string }{
		{"random 40-char key", randFrom(r, alnum, 40), ""},
		{"test-mode key is still a key", "sk_test_" + randFrom(r, alnum, 24), ""},
		{"11 bytes", "short-11-ch", rejShort},
		{"your_ prefix", "your_api_key_goes_here_please", rejPlaceholder},
		{"angle brackets", "<your-token-here-ok>", rejPlaceholder},
		{"template", "${OPENAI_API_KEY}", rejPlaceholder},
		{"changeme", "changeme-changeme", rejPlaceholder},
		{"documented AWS example", "AKIA" + "IOSFODNN7" + "EXAMPLE", rejPlaceholder},
		{"filler words only", "my-secret-token-here", rejPlaceholder},
		{"one repeated letter", "xxxxxxxxxxxxxxxxxxxx", rejPlaceholder},
		{"alphabet", "abcdefghijklmnopqrstuvwxyz", rejPlaceholder},
		{"hex counting", "0123456789abcdef0123", rejPlaceholder},
		{"mostly one character", "aaaaaaaaaaaaaaabbbbb", rejPlaceholder},
		{"two characters evenly", "aaaaaaaaaabbbbbbbbbb", rejEntropy},
		{"example host", "https://api.example.org/v1/x", rejPlaceholder},
		{"plain API URL", "https://api.openai.com/v1/models", rejURL},
		{"localhost URL", "http://localhost:3000/health", rejURL},
		{"absolute path", "/usr/local/lib/python3/site-pkg", rejPath},
		{"relative path", "./relative/dir/to/something", rejPath},
		{"home path", "~/projects/some/where/else", rejPath},
		{"13 digits that fail Luhn", "1234567890123", rejNumber},
		{"version string", "3.14.15.92.65.35.89", rejNumber},
		{"timestamp", "2026-11-03 10:00:00", rejNumber},
	} {
		if got := rejection(tc.value); got != tc.want {
			t.Errorf("%s: rejection = %q, want %q", tc.name, got, tc.want)
		}
	}
	// URLs that carry a credential are kept.
	for _, v := range []string{
		"https://user:" + randFrom(r, alnum, 20) + "@host.internal/db",
		"https://hooks.slack.com/services/T01ABCDEF/B02GHIJKL/" + randFrom(r, alnum, 24),
	} {
		if got := rejection(v); got != "" {
			t.Errorf("a URL with a credential was rejected (%s)", got)
		}
	}
	// What the path test would call a path is key material when its position says so.
	slashy := "/" + randFrom(r, alnum, 10) + "/" + randFrom(r, alnum, 20)
	if rejection(slashy) != rejPath || reject(slashy, true) != "" {
		t.Errorf("slash-delimited base64: untrusted %q, trusted %q", rejection(slashy), reject(slashy, true))
	}
	// A base64 value that starts with a slash is not a path: paths do not hold + or =, and a
	// lone slash is not a path either.
	for _, v := range []string{"/" + randFrom(r, b64chars, 38) + "+", "/" + randFrom(r, alnum, 39), "/" + randFrom(r, alnum, 20) + "=="} {
		if got := rejection(v); got != "" {
			t.Errorf("slash-leading base64 rejected as %s", got)
		}
	}
	// The relaxed entropy bar for long values.
	if got := rejection(strings.Repeat("ab12cd34", 5)); got == rejEntropy {
		t.Error("a 40-character value at 2.5+ bits was rejected on entropy")
	}
	// Cards: Luhn and not degenerate.
	good := luhnNumber(r, 16)
	if _, ok := cardNumber(good); !ok {
		t.Errorf("a Luhn-valid 16-digit number was not a card")
	}
	broken := []byte(good)
	broken[15] = '0' + (broken[15]-'0'+1)%10 // any other check digit fails Luhn
	if _, ok := cardNumber(string(broken)); ok {
		t.Error("a Luhn-invalid number was a card")
	}
	if _, ok := cardNumber(strings.Repeat("0", 16)); ok {
		t.Error("a degenerate Luhn-valid number was a card")
	}
}

func TestURLPasswords(t *testing.T) {
	// The URLs are put together here, not written out, so no connection string sits in this source.
	uri := func(scheme, userinfo, rest string) string { return scheme + "://" + userinfo + "@" + rest }
	for in, want := range map[string][]string{
		uri("postgres", "u:p%40ss", "h/db"): {"p%40ss", "p@ss"},
		uri("redis", ":onlypw", "h:6379"):   {"onlypw"},
		"https://u@h/x":                     nil,
		"https://h/x":                       nil,
		"a " + uri("http", "u:pw1", "h/") + " and " + uri("https", "v:pw2", "k/"): {"pw1", "pw2"},
		"user:pw@h without a scheme":                         nil,
		uri("x", "u:p:q", "h"):                               {"p:q"},
		uri("postgres", "u:pa@ss", "h/db"):                   {"pa@ss"},
		"see https://github.com/x/y for details":             nil,
		uri("mongodb+srv", "admin:s3cr3t", "cluster0.x.net"): {"s3cr3t"},
	} {
		got := urlPasswords(in)
		if strings.Join(got, "|") != strings.Join(want, "|") {
			t.Errorf("urlPasswords(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestVariantsAreRecognisedByIndependentEncoders(t *testing.T) {
	r := newRNG(t)
	for i := 0; i < 200; i++ {
		raw := []byte(fakeSecret(r))
		forms := map[string]bool{}
		for _, v := range variantsOf(raw) {
			forms[string(v.b)] = true
		}
		// Base64 of the value inside a longer blob, at each of the three alignments.
		for shift := 0; shift < 3; shift++ {
			for _, tail := range []int{0, 1, 2} {
				blob := append(append(bytes.Repeat([]byte{'p'}, shift), raw...), bytes.Repeat([]byte{'q'}, tail)...)
				for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding} {
					e := enc.EncodeToString(blob)
					found := false
					for f := range forms {
						if len(f) >= window && strings.Contains(e, f) {
							found = true
						}
					}
					if !found {
						t.Fatalf("value %d: its base64 inside a blob (shift %d, tail %d) contains none of its forms", i, shift, tail)
					}
				}
			}
		}
	}
}

type recorder struct{ failed bool }

func (r *recorder) Helper()               {}
func (r *recorder) Fatalf(string, ...any) { r.failed = true }

// The audit is only worth trusting if it fails when it should.
func TestLeakAuditCatchesLeaks(t *testing.T) {
	r := newRNG(t)
	v := "sk-proj-" + randFrom(r, alnum+"+/", 40)
	forms := variantsOf([]byte(v))
	if len(forms) < 3 {
		t.Fatalf("only %d forms", len(forms))
	}
	for _, f := range forms {
		for _, at := range []int{0, len(f.b) / 2, len(f.b) - window} {
			rec := &recorder{}
			assertNoValue(rec, []string{v}, map[string][]byte{"out": append([]byte("prefix "), append(f.b[at:at+window:at+window], " suffix"...)...)})
			if !rec.failed {
				t.Fatalf("a leaked window of the %s form at %d went unnoticed", f.label, at)
			}
		}
	}
	rec := &recorder{}
	assertNoValue(rec, []string{v}, map[string][]byte{"out": []byte("kgabcdef OPENAI_API_KEY sk-proj-…" + v[len(v)-4:] + " len 48")})
	if rec.failed {
		t.Fatal("the shape of a value was reported as a leak")
	}
}
