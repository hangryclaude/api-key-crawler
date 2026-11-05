package pattern

import (
	"bytes"
	"context"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"

	"keyguard/internal/pattern/rules"
)

// ids lists the rules that fired, with the line, in the order of the scan.
func ids(fs []Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.Rule.ID+":"+itoa(f.Line))
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}

func TestScanFindsATokenAndNamesItsLine(t *testing.T) {
	tok := newFakes(1).githubPAT()
	data := "line one\nline two\ntoken = \"" + tok + "\"\nlast\n"
	got := Default().ScanBytes("src/app.py", []byte(data))
	if want := []string{"github-pat:3"}; !slices.Equal(ids(got), want) {
		t.Fatalf("got %v, want %v", ids(got), want)
	}
	f := got[0]
	if s := string(f.Secret([]byte(data))); s != tok {
		t.Errorf("the secret span holds %d bytes that are not the token", len(s))
	}
	if f.Entropy < 3 {
		t.Errorf("entropy %v", f.Entropy)
	}
}

// The prefilter ignores case, so a keyword in any case wakes its rule, and the rule's regex decides:
// a case-insensitive one finds the name in any case, a case-sensitive one only its own.
func TestKeywordInAnyCase(t *testing.T) {
	v := newFakes(2).run(alnum, 30)
	for _, name := range []string{"api_key", "API_KEY", "Api_Key"} {
		got := Default().ScanBytes("a.txt", []byte(name+" = \""+v+"\"\n"))
		if len(got) != 1 {
			t.Errorf("%d findings for a name written %s", len(got), name)
		}
	}
	tok := newFakes(3).githubPAT()
	if got := Default().ScanBytes("a.txt", []byte("x "+strings.ToUpper(tok[:4])+tok[4:]+" y\n")); len(got) != 0 {
		t.Errorf("a case-sensitive rule found %s", strings.ToUpper(tok[:4]))
	}
}

// A value on the line after its name is the same assignment, and the line reported is the name's.
func TestAssignmentAcrossAnEndOfLine(t *testing.T) {
	v := newFakes(3).run(alnum, 30)
	data := "service:\n  api_key:\n    " + v + "\nother: 1\n"
	got := Default().ScanBytes("conf.yaml", []byte(data))
	if want := []string{"generic-api-key:2"}; !slices.Equal(ids(got), want) {
		t.Fatalf("got %v, want %v", ids(got), want)
	}
}

// The gap between a name and its value may hold blank lines; a window of the keyword's line and the
// next would miss it.
func TestAssignmentAcrossBlankLines(t *testing.T) {
	v := newFakes(4).run(alnum, 30)
	data := "api_key =\n\n\n  " + v + "\n"
	got := Default().ScanBytes("x.conf", []byte(data))
	if want := []string{"generic-api-key:1"}; !slices.Equal(ids(got), want) {
		t.Fatalf("got %v, want %v", ids(got), want)
	}
}

func TestNothingToFind(t *testing.T) {
	if got := Default().ScanBytes("a.go", []byte("package main\n\nfunc main() {}\n")); len(got) != 0 {
		t.Errorf("%v", ids(got))
	}
	if got := Default().ScanBytes("a.go", nil); len(got) != 0 {
		t.Errorf("%v", ids(got))
	}
}

// An entropy floor drops a value of the right shape and too little variety.
func TestEntropyFloorDropsAFlatValue(t *testing.T) {
	flat := "gh" + "p_" + strings.Repeat("a", 36)
	if got := Default().ScanBytes("a.txt", []byte(flat+"\n")); len(got) != 0 {
		t.Errorf("a flat token was reported: %v", ids(got))
	}
}

func TestPathOnlyRule(t *testing.T) {
	got := Default().ScanBytes("keys/store.p12", []byte("not looked at"))
	if len(got) != 1 || got[0].Rule.ID != "pkcs12-file" || got[0].Line != 0 {
		t.Errorf("got %v", ids(got))
	}
	if got := Default().ScanBytes("keys/store.txt", []byte("x")); len(got) != 0 {
		t.Errorf("%v", ids(got))
	}
}

// aws-access-token is a composite rule: the id alone is not a finding, the id with a secret key
// within five lines is.
func TestCompositeRuleNeedsItsOtherHalf(t *testing.T) {
	f := newFakes(5)
	id, secret := f.awsKeyID(), f.awsSecret()
	near := "AWS_ACCESS_KEY_ID=" + id + "\nAWS_SECRET_ACCESS_KEY=" + secret + "\n"
	far := "AWS_ACCESS_KEY_ID=" + id + strings.Repeat("\nfiller", 9) + "\nAWS_SECRET_ACCESS_KEY=" + secret + "\n"
	alone := "AWS_ACCESS_KEY_ID=" + id + "\n"
	has := func(data string) bool {
		for _, fd := range Default().ScanBytes("env.txt", []byte(data)) {
			if fd.Rule.ID == "aws-access-token" {
				return true
			}
		}
		return false
	}
	if !has(near) {
		t.Error("an id with its secret key beside it was not reported")
	}
	if has(far) {
		t.Error("an id with its secret key nine lines away was reported")
	}
	if has(alone) {
		t.Error("an id alone was reported")
	}
}

// A more specific rule's finding silences a generic one on the same line when it contains it.
func TestSpecificRuleSilencesTheGenericOne(t *testing.T) {
	pw := newFakes(6).run(alnum, 14)
	data := "db_password = \"" + pw + "\"\n"
	for _, f := range Default().ScanBytes("a.py", []byte(data)) {
		if f.Rule.ID == "generic-api-key" {
			t.Errorf("generic-api-key reported where generic-password covers the value")
		}
	}
}

// The path policy: a dependency tree is not scanned by the generic rules, and is by the rest.
func TestPathPolicy(t *testing.T) {
	f := newFakes(7)
	pat := f.githubPAT()
	generic := "api_key = \"" + f.run(alnum, 30) + "\"\n"
	nat := Default()
	up := New(rules.All, rules.Global, Options{Paths: PathsUpstream})
	pathIn := "node_modules/pkg/index.js"
	count := func(s *Scanner, path, data string) map[string]bool {
		m := map[string]bool{}
		for _, fd := range s.ScanBytes(path, []byte(data)) {
			m[fd.Rule.ID] = true
		}
		return m
	}
	if m := count(nat, pathIn, generic+"x = "+pat+"\n"); !m["github-pat"] || m["generic-api-key"] {
		t.Errorf("native in node_modules: %v", m)
	}
	if m := count(up, pathIn, generic+"x = "+pat+"\n"); len(m) != 0 {
		t.Errorf("upstream in node_modules: %v", m)
	}
	if m := count(nat, "src/index.js", generic+"x = "+pat+"\n"); !m["github-pat"] || !m["generic-api-key"] {
		t.Errorf("native in src: %v", m)
	}
}

func TestScanDir(t *testing.T) {
	f := newFakes(8)
	pat := f.githubPAT()
	dir := writeTree(t, map[string]string{
		"a/one.txt":             "x = " + pat + "\n",
		"a/b/two.txt":           "nothing here\n",
		"bin/blob.dat":          "abc\x00def " + pat,
		"node_modules/dep/x.js": "x = " + pat + "\n",
		".git/config":           "x = " + pat + "\n",
		"keys/server.p12":       "\x00\x01",
		"empty.txt":             "",
	})
	var got []string
	st, err := Default().ScanDir(context.Background(), dir, func(fd Finding, data []byte) {
		got = append(got, fd.Rule.ID+" "+fd.Path+":"+itoa(fd.Line))
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(got)
	want := []string{"github-pat a/one.txt:1", "github-pat node_modules/dep/x.js:1", "pkcs12-file keys/server.p12:0"}
	if !slices.Equal(got, want) {
		t.Errorf("got %v\nwant %v", got, want)
	}
	if st.Binary != 2 || st.Empty != 1 || st.Findings != 3 {
		t.Errorf("stats %+v", st)
	}
	if n := st.Notes(); len(n) == 0 || !strings.Contains(n[0], "binary") {
		t.Errorf("notes %v", n)
	}
}

func TestScanDirOfOneFile(t *testing.T) {
	pat := newFakes(9).githubPAT()
	dir := writeTree(t, map[string]string{"sub/k.env": "T=" + pat + "\n"})
	var n int
	_, err := Default().ScanDir(context.Background(), dir+"/sub/k.env", func(fd Finding, _ []byte) {
		n++
		if fd.Path != "k.env" {
			t.Errorf("path %q", fd.Path)
		}
	})
	if err != nil || n != 1 {
		t.Errorf("%d findings, err %v", n, err)
	}
}

func TestScanDirStopsOnCancel(t *testing.T) {
	files := map[string]string{}
	for i := 0; i < 50; i++ {
		files["d/f"+itoa(i+1)+".txt"] = "hello\n"
	}
	dir := writeTree(t, files)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Default().ScanDir(ctx, dir, func(Finding, []byte) {}); err == nil {
		t.Error("a cancelled scan returned no error")
	}
}

// seamFile is a text a little over one tile long with a token that straddles the seam between the first
// tile and the second, and the line the token is on.
func seamFile(t testing.TB, seed uint64) (data []byte, token string, line int) {
	t.Helper()
	token = newFakes(seed).githubPAT()
	// Lines of 28 bytes up to a short last one, so that the token starts a few bytes before the seam
	// and ends a few after it.
	const fill = "filler filler filler filler\n"
	head := tileSize - 4 - len(token)/2
	var b strings.Builder
	for b.Len()+len(fill) <= head {
		b.WriteString(fill)
	}
	if rest := head - b.Len(); rest > 1 {
		b.WriteString(strings.Repeat("x", rest-1) + "\n")
	}
	line = strings.Count(b.String(), "\n") + 1
	b.WriteString("t = " + token + "\n")
	for b.Len() < tileSize+3*tileOverlap {
		b.WriteString(fill)
	}
	data = []byte(b.String())
	if start := bytes.Index(data, []byte(token)); start >= tileSize || start+len(token) <= tileSize {
		t.Fatalf("the token at %d..%d is not on the seam at %d", start, start+len(token), tileSize)
	}
	return data, token, line
}

// Tiles: a big input is scanned in pieces that overlap, and a secret on a seam is found once, with the
// right line.
func TestTilesFindASecretOnTheSeamOnce(t *testing.T) {
	if testing.Short() {
		t.Skip("allocates 17 MB")
	}
	data, pat, line := seamFile(t, 10)
	got := Default().ScanBytes("big.txt", data)
	if len(got) != 1 {
		t.Fatalf("%d findings: %v", len(got), ids(got))
	}
	if got[0].Line != line || string(got[0].Secret(data)) != pat {
		t.Errorf("line %d (want %d), secret ok: %v", got[0].Line, line, string(got[0].Secret(data)) == pat)
	}
}

// The same file on disk, which ScanDir reads in tiles of its own: the finding comes back once, with the
// buffer it indexes and where that buffer starts in the file.
func TestScanDirReadsABigFileInTiles(t *testing.T) {
	if testing.Short() {
		t.Skip("writes 17 MB")
	}
	data, pat, line := seamFile(t, 11)
	dir := writeTree(t, map[string]string{"big/log.txt": string(data)})
	var got []Finding
	var secrets []string
	st, err := Default().ScanDir(context.Background(), dir, func(f Finding, buf []byte) {
		got = append(got, f)
		secrets = append(secrets, string(f.Secret(buf)))
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || secrets[0] != pat {
		t.Fatalf("%d findings (%v)", len(got), ids(got))
	}
	if got[0].Line != line || got[0].Base == 0 && got[0].Start > tileSize {
		t.Errorf("line %d (want %d), base %d, start %d", got[0].Line, line, got[0].Base, got[0].Start)
	}
	if st.Tiled != 1 {
		t.Errorf("tiled %d files", st.Tiled)
	}
	if n := st.Notes(); len(n) == 0 || !strings.Contains(strings.Join(n, " "), "tiles") {
		t.Errorf("notes %v", n)
	}
}

// The scan runs a rule that is a part of another only as that part. That is exact only if every part is a
// rule that reports nothing alone; otherwise a finding that is also somebody's component would have to be
// dropped from the report, as the reference does. The table has none of those, and this keeps it so.
func TestEveryComponentReportsNothingAlone(t *testing.T) {
	composites := 0
	for _, r := range rules.All {
		if len(r.Needs) > 0 {
			composites++
		}
		for _, n := range r.Needs {
			c := ruleByID(t, n.ID)
			if !c.ComponentOnly {
				t.Errorf("%s needs %s, which also reports on its own", r.ID, n.ID)
			}
			if c.Re == "" {
				t.Errorf("%s needs %s, a rule about a path", r.ID, n.ID)
			}
			if w := parseWithin(n.Within); !w.none && !w.box && !n.Optional {
				t.Errorf("%s needs %s within columns only, which no reference rule does", r.ID, n.ID)
			}
		}
	}
	if composites != 36 {
		t.Errorf("%d composite rules, the doc says 36", composites)
	}
}

// One scanner serves many goroutines: its pooled state is per scan and its lazily built parts are built once.
// Run under -race, this is the test of that; run without it, it checks that concurrency changes no result.
func TestConcurrentScansShareOneScanner(t *testing.T) {
	s := New(rules.All, rules.Global, Options{})
	var inputs [][]byte
	var want [][]string
	f := newFakes(40)
	for i := 0; i < 24; i++ {
		var b strings.Builder
		for j := 0; j < 30; j++ {
			switch (i + j) % 5 {
			case 0:
				b.WriteString("token = \"" + f.githubPAT() + "\"\n")
			case 1:
				b.WriteString("api_key = \"" + f.run(alnum, 28) + "\"\n")
			case 2:
				b.WriteString("AWS_ACCESS_KEY_ID=" + f.awsKeyID() + "\nAWS_SECRET_ACCESS_KEY=" + f.awsSecret() + "\n")
			default:
				b.WriteString("nothing to see here, just a line of text\n")
			}
		}
		inputs = append(inputs, []byte(b.String()))
		var ks []string
		for _, fd := range New(rules.All, rules.Global, Options{}).ScanBytes("a.txt", inputs[i]) {
			ks = append(ks, key(fd))
		}
		want = append(want, ks)
	}
	var wg sync.WaitGroup
	errs := make(chan string, 64)
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for round := 0; round < 5; round++ {
				for i, in := range inputs {
					var ks []string
					for _, fd := range s.ScanBytes("a.txt", in) {
						ks = append(ks, key(fd))
					}
					if !slices.Equal(ks, want[i]) {
						errs <- "a concurrent scan disagreed with a serial one"
						return
					}
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}
