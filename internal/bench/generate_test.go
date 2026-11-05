package bench

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"unicode/utf16"
)

func readFile(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestGenerateIsDeterministic(t *testing.T) {
	a, err := Generate(filepath.Join(t.TempDir(), "a"), Options{Seed: 1})
	if err != nil {
		t.Fatal(err)
	}
	b, err := Generate(filepath.Join(t.TempDir(), "b"), Options{Seed: 1})
	if err != nil {
		t.Fatal(err)
	}
	c, err := Generate(filepath.Join(t.TempDir(), "c"), Options{Seed: 2})
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(readFile(t, filepath.Join(a.Dir, "truth.json")), readFile(t, filepath.Join(b.Dir, "truth.json"))) {
		t.Error("truth.json differs between two runs of seed 1")
	}
	for _, args := range [][]string{
		{"for-each-ref", "--format=%(objectname) %(refname)"},
		{"rev-list", "--all", "--objects"},
	} {
		if x, y := gitOut(t, a.Repo, args...), gitOut(t, b.Repo, args...); x != y {
			t.Errorf("git %s differs between two runs of seed 1", args[0])
		}
	}
	if x, y := gitOut(t, a.Repo, "for-each-ref", "--format=%(objectname)"), gitOut(t, c.Repo, "for-each-ref", "--format=%(objectname)"); x == y {
		t.Error("seeds 1 and 2 produced the same history")
	}

	// the structure is seed-independent; only values and filler change
	ids := func(c *Corpus) string {
		var out []string
		for _, p := range c.Truth.Plants {
			out = append(out, p.ID+"|"+p.Variant+"|"+p.Location.Path[:strings.IndexByte(p.Location.Path+"/", '/')])
		}
		return strings.Join(out, "\n")
	}
	if ids(a) != ids(c) {
		t.Error("plant ids/variants changed with the seed; scores across seeds would not compare")
	}
	fps := map[string]bool{}
	for _, p := range a.Truth.Plants {
		fps[p.FP] = true
	}
	same := 0
	for _, p := range c.Truth.Plants {
		if p.Positive && fps[p.FP] {
			same++
		}
	}
	if same != 0 {
		t.Errorf("%d positive fingerprints are identical across seeds", same)
	}
}

func TestLoadRebuildsTheKeyring(t *testing.T) {
	c := sharedCorpus(t)
	l, err := Load(c.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if l.Key.FP("probe") != c.Key.FP("probe") || l.Key.FP("probe") != KeyringFor(1).FP("probe") {
		t.Error("a loaded corpus fingerprints differently from the one that was generated")
	}
	if len(l.Truth.Plants) != len(c.Truth.Plants) || l.Repo != c.Repo {
		t.Error("Load lost plants or moved the repo")
	}
}

func TestPlantsAreWhereTruthSays(t *testing.T) {
	c := sharedCorpus(t)
	if len(c.recs) != len(c.Truth.Plants) {
		t.Fatalf("%d records, %d plants", len(c.recs), len(c.Truth.Plants))
	}
	for i, p := range c.Truth.Plants {
		rec := c.recs[i]
		if rec.id != p.ID {
			t.Fatalf("record %d is %s, truth says %s", i, rec.id, p.ID)
		}
		loc := p.Location
		if len(loc.Commit) != 40 {
			t.Errorf("%s: commit %q is not a sha", p.ID, loc.Commit)
			continue
		}
		if rec.neg != nil && rec.neg.value == "" {
			continue // a code reference carries no value, only a file
		}
		if p.FP != c.Key.FP(rec.fake.Raw) {
			t.Errorf("%s: fp is not the bench-keyring fingerprint of the planted value", p.ID)
		}
		if loc.Where == "ref" {
			// the value is in a branch name: truth.json shows the ref with the value shortened, and
			// the real ref is the one git holds
			real := rec.file.ref
			if !strings.Contains(real, rec.fake.Raw) || strings.Contains(loc.Ref, rec.fake.Raw) {
				t.Errorf("%s: the ref should carry the value in git and only its shape in truth.json", p.ID)
			}
			if tip := strings.TrimSpace(gitOut(t, c.Repo, "rev-parse", real)); tip != loc.Commit {
				t.Errorf("%s: %s is at %s, truth says %s", p.ID, loc.Ref, tip, loc.Commit)
			}
			continue
		}
		text := plantText(t, c, rec, p)
		lines := strings.Split(text, "\n")
		if loc.Line < 1 || loc.Line > len(lines) {
			t.Errorf("%s: line %d of %d", p.ID, loc.Line, len(lines))
			continue
		}
		if rec.file.rend.locate != nil {
			// a typed recording spreads the value over one event per character: the events from
			// Line to EndLine, joined, spell it
			var got strings.Builder
			for _, l := range lines[loc.Line-1 : loc.EndLine] {
				var ev [3]any
				if err := json.Unmarshal([]byte(l), &ev); err != nil {
					t.Fatalf("%s: line %q is not an event: %v", p.ID, l, err)
				}
				got.WriteString(ev[2].(string))
			}
			if got.String() != rec.fake.Value {
				t.Errorf("%s: the keystrokes on lines %d-%d do not spell the value", p.ID, loc.Line, loc.EndLine)
			}
		} else {
			first, _, _ := strings.Cut(rec.file.rend.esc(rec.fake.Value), "\n")
			if !strings.Contains(lines[loc.Line-1], first) {
				t.Errorf("%s: value is not on %s:%d at %s", p.ID, loc.Path, loc.Line, loc.Commit[:8])
			}
			whole := rec.file.rend.esc(rec.fake.Value)
			if n := strings.Count(whole, "\n"); n > 0 {
				last := whole[strings.LastIndex(whole, "\n")+1:]
				if loc.EndLine != loc.Line+n || loc.EndLine > len(lines) || !strings.Contains(lines[loc.EndLine-1], last) {
					t.Errorf("%s: a %d-line value ends on line %d, truth says %d", p.ID, n+1, loc.Line+n, loc.EndLine)
				}
			} else if loc.EndLine != 0 {
				t.Errorf("%s: a one-line value has end_line %d", p.ID, loc.EndLine)
			}
		}
		if !gitOK(c.Repo, "merge-base", "--is-ancestor", loc.Commit, loc.Ref) {
			t.Errorf("%s: commit %s is not on %s", p.ID, loc.Commit[:8], loc.Ref)
		}
	}
}

// plantText is the text a plant's line number counts in: the file as stored, or what a message,
// an annotation, an archive or a UTF-16 file spells.
func plantText(t *testing.T, c *Corpus, rec *plantRec, p Plant) string {
	t.Helper()
	loc := p.Location
	switch loc.Where {
	case "message":
		return objectBody(gitOut(t, c.Repo, "cat-file", "commit", loc.Commit))
	case "tag":
		return objectBody(gitOut(t, c.Repo, "cat-file", "tag", loc.Ref))
	}
	blob := gitOut(t, c.Repo, "show", loc.Commit+":"+loc.Path)
	switch rec.variant {
	case vZip:
		return unzipOne(t, blob, ".env")
	case vJAR:
		return unzipOne(t, blob, "application.properties")
	case vTGZ:
		return untgz(t, blob, ".env")
	case vUTF16:
		return decodeUTF16LE(t, blob)
	}
	return blob
}

// objectBody is the message of a commit or tag object: everything after the header's blank line.
func objectBody(obj string) string {
	_, body, _ := strings.Cut(obj, "\n\n")
	return body
}

func untgz(t *testing.T, blob, name string) string {
	t.Helper()
	gz, err := gzip.NewReader(strings.NewReader(blob))
	if err != nil {
		t.Fatalf("not a gzip: %v", err)
	}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err != nil {
			t.Fatalf("no %s in the tarball: %v", name, err)
		}
		if h.Name == name {
			b, err := io.ReadAll(tr)
			if err != nil {
				t.Fatal(err)
			}
			return string(b)
		}
	}
}

func decodeUTF16LE(t *testing.T, blob string) string {
	t.Helper()
	b := []byte(blob)
	if len(b) < 2 || b[0] != 0xff || b[1] != 0xfe {
		t.Fatal("a UTF-16LE file should start with its byte order mark")
	}
	var u []uint16
	for i := 2; i+1 < len(b); i += 2 {
		u = append(u, uint16(b[i])|uint16(b[i+1])<<8)
	}
	return string(utf16.Decode(u))
}

func unzipOne(t *testing.T, blob, name string) string {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader([]byte(blob)), int64(len(blob)))
	if err != nil {
		t.Fatalf("not a zip: %v", err)
	}
	for _, f := range zr.File {
		if f.Name == name {
			rc, err := f.Open()
			if err != nil {
				t.Fatal(err)
			}
			defer rc.Close()
			b, err := io.ReadAll(rc)
			if err != nil {
				t.Fatal(err)
			}
			return string(b)
		}
	}
	t.Fatalf("no %s in the zip", name)
	return ""
}

// The variants are about where git holds a value, not only what the file looks like.
func TestHistoryVariantsAreReachableOnlyWhereTheyShouldBe(t *testing.T) {
	c := sharedCorpus(t)
	seen := map[string]int{}
	for _, p := range c.Truth.Plants {
		if !p.Positive {
			continue
		}
		seen[p.Variant]++
		loc := p.Location
		holders := strings.Fields(gitOut(t, c.Repo, "for-each-ref", "--contains", loc.Commit, "--format=%(refname)"))
		sort.Strings(holders)
		switch p.Variant {
		case vBranch:
			if len(holders) != 1 || !strings.HasPrefix(holders[0], "refs/heads/feature/") {
				t.Errorf("%s: held by %v, want only its unmerged feature branch", p.ID, holders)
			}
			if gitOK(c.Repo, "merge-base", "--is-ancestor", loc.Commit, "main") {
				t.Errorf("%s: reachable from main", p.ID)
			}
		case vTag:
			if len(holders) != 1 || !strings.HasPrefix(holders[0], "refs/tags/") {
				t.Errorf("%s: held by %v, want only a tag", p.ID, holders)
			}
		case vPull:
			if len(holders) != 1 || !strings.HasPrefix(holders[0], "refs/pull/") || !strings.HasSuffix(holders[0], "/head") {
				t.Errorf("%s: held by %v, want only refs/pull/N/head", p.ID, holders)
			}
		case vDeleted:
			if p.RemovedIn == "" {
				t.Errorf("%s: no removed_in", p.ID)
				continue
			}
			if !gitOK(c.Repo, "merge-base", "--is-ancestor", loc.Commit, p.RemovedIn) || loc.Commit == p.RemovedIn {
				t.Errorf("%s: removal %s does not follow the add %s", p.ID, p.RemovedIn[:8], loc.Commit[:8])
			}
			rec := recOf(c, p.ID)
			now, err := git(c.Repo, nil, "show", "main:"+loc.Path)
			if err == nil && strings.Contains(now, rec.fake.Value) {
				t.Errorf("%s: value is still at main's tip", p.ID)
			}
		case vBigfile:
			sz := gitOut(t, c.Repo, "cat-file", "-s", loc.Commit+":"+loc.Path)
			if n := strings.TrimSpace(sz); len(n) < 7 {
				t.Errorf("%s: file is %s bytes, want over 1 MB", p.ID, n)
			}
		case vCommitMsg:
			if len(holders) == 0 || !gitOK(c.Repo, "merge-base", "--is-ancestor", loc.Commit, "main") {
				t.Errorf("%s: the commit with the message is not on main (held by %v)", p.ID, holders)
			}
		case vTagMsg:
			if len(holders) != 1 || !strings.HasPrefix(holders[0], "refs/tags/") {
				t.Errorf("%s: held by %v, want only the annotated tag", p.ID, holders)
			}
			if kind := strings.TrimSpace(gitOut(t, c.Repo, "cat-file", "-t", loc.Ref)); kind != "tag" {
				t.Errorf("%s: %s is a %s object, want an annotated tag", p.ID, loc.Ref, kind)
			}
		case vBranchName:
			real := recOf(c, p.ID).file.ref
			if len(holders) != 1 || holders[0] != real {
				t.Errorf("%s: held by %v, want only the branch named for the value", p.ID, holders)
			}
		case vRename:
			out := gitOut(t, c.Repo, "show", "-M", "--name-status", "--format=", loc.Commit)
			if !strings.HasPrefix(out, "R") || !strings.Contains(out, loc.Path) {
				t.Errorf("%s: the commit is not a rename into %s: %q", p.ID, loc.Path, out)
			}
		}
		switch p.Variant {
		case vDeleted, vBranch, vTag, vPull, vCommitMsg, vTagMsg, vBranchName, vRename:
		case vZip, vJAR, vTGZ, vUTF16, vCastTyped:
			// the file is not the text: the blob must be there, and TestPlantsAreWhereTruthSays reads it
			if _, err := git(c.Repo, nil, "cat-file", "-e", "main:"+loc.Path); err != nil {
				t.Errorf("%s: %s is gone from main", p.ID, loc.Path)
			}
		default:
			rec := recOf(c, p.ID)
			now, err := git(c.Repo, nil, "show", "main:"+loc.Path)
			if err != nil {
				t.Errorf("%s: %s is gone from main", p.ID, loc.Path)
			} else if !strings.Contains(now, rec.file.rend.esc(rec.fake.Value)) {
				t.Errorf("%s: value missing from main's tip", p.ID)
			}
		}
	}
	for _, v := range variantOrder() {
		if seen[v] < 4 {
			t.Errorf("variant %s has %d positive plants, want at least 4", v, seen[v])
		}
	}
	if gitOut(t, c.Repo, "for-each-ref", "refs/pull/1/head") == "" {
		t.Error("refs/pull/1/head does not exist")
	}
}

func TestTruthCoversThePlan(t *testing.T) {
	c := sharedCorpus(t)
	if n := len(Providers); n < 40 {
		t.Errorf("%d provider formats, want at least 40", n)
	}
	types := map[string]bool{}
	for _, p := range Providers {
		types[p.Type] = true
	}
	for _, want := range strings.Fields(`anthropic openai github aws stripe slack discord telegram google gcp firebase supabase
		vercel cloudflare fal replicate huggingface groq xai openrouter elevenlabs twilio sendgrid mailgun shopify npm pypi
		dockerhub digitalocean linear notion airtable zoom calcom zerobounce postgres mongodb redis private-key generic card`) {
		if !types[want] {
			t.Errorf("PLAN format %q is not planted", want)
		}
	}
	ids := map[string]bool{}
	for _, p := range Providers {
		ids[p.ID] = true
	}
	for _, want := range strings.Fields(`github-classic github-oauth github-fine-grained aws rsa-key ec-key openssh-key
		supabase-service-role gcp-service-account firebase-admin slack-bot slack-webhook discord-bot discord-webhook`) {
		if !ids[want] {
			t.Errorf("provider %s missing", want)
		}
	}
	anon := false
	for _, p := range PublicProviders {
		anon = anon || p.ID == "supabase-anon"
	}
	if !anon {
		t.Error("the supabase anon JWT is not planted as public by design")
	}

	variants := map[string]bool{}
	kinds := map[string]bool{}
	paths := map[string]bool{}
	for _, p := range c.Truth.Plants {
		if p.Positive {
			variants[p.Variant] = true
		} else {
			kinds[p.Kind] = true
			paths[p.Location.Path] = true
		}
	}
	for _, v := range variantOrder() {
		if !variants[v] {
			t.Errorf("variant %s is not planted", v)
		}
	}
	for _, k := range strings.Fields("placeholder aws-example integrity-hash checksum commit-hash image-digest uuid base64-image public-key certificate jwt-sample public-by-design code-ref") {
		if !kinds[k] {
			t.Errorf("negative kind %s is not planted", k)
		}
	}
	for _, p := range []string{".env.example", "package-lock.json", "yarn.lock", "Cargo.lock", "go.sum"} {
		if !paths[p] {
			t.Errorf("negative file %s missing", p)
		}
	}
	st := c.Truth.Stats
	if st.Positives < 250 || st.Negatives < 100 || st.Detectable < 200 {
		t.Errorf("small corpus: %d positives, %d negatives, %d detectable", st.Positives, st.Negatives, st.Detectable)
	}
}

func TestTruthJSONHasTheSpecFields(t *testing.T) {
	c := sharedCorpus(t)
	var raw struct {
		Plants []map[string]json.RawMessage `json:"plants"`
	}
	if err := json.Unmarshal(readFile(t, filepath.Join(c.Dir, "truth.json")), &raw); err != nil {
		t.Fatal(err)
	}
	for _, p := range raw.Plants {
		for _, k := range []string{"id", "type", "variant", "location", "positive", "fp", "detectable_by_design", "note"} {
			if _, ok := p[k]; !ok {
				t.Fatalf("plant %s lacks %q", p["id"], k)
			}
		}
		var loc map[string]json.RawMessage
		if err := json.Unmarshal(p["location"], &loc); err != nil {
			t.Fatal(err)
		}
		for _, k := range []string{"ref", "path", "line"} {
			if _, ok := loc[k]; !ok {
				t.Fatalf("plant %s location lacks %q", p["id"], k)
			}
		}
	}
}

func TestFingerprintsDoNotCollide(t *testing.T) {
	c := sharedCorpus(t)
	owner := map[string]string{}
	for _, p := range c.Truth.Plants {
		if !p.Positive {
			continue
		}
		for _, f := range append([]string{p.FP}, p.AltFPs...) {
			if o, dup := owner[f]; dup && o != p.ID {
				t.Errorf("fingerprint shared by positive plants %s and %s", o, p.ID)
			}
			owner[f] = p.ID
		}
	}
	for _, p := range c.Truth.Plants {
		if p.Positive {
			continue
		}
		for _, f := range append([]string{p.FP}, p.AltFPs...) {
			if o, hit := owner[f]; hit && f != "" {
				t.Errorf("negative %s shares a fingerprint with positive %s", p.ID, o)
			}
		}
	}
}

func TestGenerateRefusesANonEmptyDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "keep"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Generate(dir, Options{Seed: 1}); err == nil {
		t.Fatal("Generate overwrote a non-empty directory")
	}
}

func TestGenerateRefusesAGitWorkTree(t *testing.T) {
	repo := t.TempDir()
	if out, err := exec.Command("git", "-C", repo, "init", "-q").CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	target := filepath.Join(repo, "deep", "corpus")
	if _, err := Generate(target, Options{Seed: 1}); err == nil {
		t.Fatal("Generate planted fake secrets inside a git work tree")
	}
	if _, err := os.Stat(filepath.Join(repo, "deep")); err == nil {
		t.Error("Generate created directories inside the work tree before refusing")
	}
}

func TestScaleGrowsTheFiller(t *testing.T) {
	small := sharedCorpus(t)
	big, err := Generate(filepath.Join(t.TempDir(), "big"), Options{Seed: 1, Scale: 2})
	if err != nil {
		t.Fatal(err)
	}
	// scale adds 400 filler commits per step; the plants and their history are the same at any scale
	if big.Truth.Stats.Commits < small.Truth.Stats.Commits+350 || big.Truth.Stats.Files < small.Truth.Stats.Files+120 {
		t.Errorf("scale 2: %d commits %d files, from %d and %d", big.Truth.Stats.Commits, big.Truth.Stats.Files, small.Truth.Stats.Commits, small.Truth.Stats.Files)
	}
	if big.Truth.Stats.Positives != small.Truth.Stats.Positives {
		t.Errorf("scale changed the plant count: %d vs %d", big.Truth.Stats.Positives, small.Truth.Stats.Positives)
	}
}

// The generator must not run the developer's hooks or read their git config: a reference-
// transaction hook installed globally (as keyguard does) would otherwise fire on every
// update-ref the generator makes.
func TestGeneratorIgnoresGlobalGitConfig(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "hook-ran")
	cfg := filepath.Join(t.TempDir(), "gitconfig")
	body := fmt.Sprintf("[hook \"probe\"]\n\tevent = reference-transaction\n\tcommand = touch %s\n", marker)
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_CONFIG_GLOBAL", cfg)

	// prove the probe fires when git is not isolated, or this test could pass vacuously
	probe := t.TempDir()
	for _, args := range [][]string{{"init", "-q", "-b", "main"}, {"-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "--allow-empty", "-m", "x"}} {
		cmd := exec.Command("git", append([]string{"-C", probe}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("the probe hook never fired under this git (%v): the test could not detect a leak", err)
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}

	if _, err := Generate(filepath.Join(t.TempDir(), "iso"), Options{Seed: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("the generator ran a global git hook")
	}
}

func TestGeneratorLeavesKeyguardHomeAlone(t *testing.T) {
	sharedCorpus(t)
	if ents, err := os.ReadDir(os.Getenv("KEYGUARD_HOME")); err == nil && len(ents) > 0 {
		t.Errorf("KEYGUARD_HOME was written to: %d entries", len(ents))
	}
}

func TestHelpers(t *testing.T) {
	// a Luhn-valid PAN stays valid
	g := &Gen{r: newRand(3, "luhn")}
	for i := 0; i < 50; i++ {
		s := "400000" + g.str(digits, 9)
		s += string(luhn(s))
		if luhn(s[:len(s)-1]) != s[len(s)-1] {
			t.Fatalf("luhn check digit unstable for %s", s[:4])
		}
		sum := 0
		for j, ch := range []byte(s) {
			d := int(ch - '0')
			if (len(s)-j)%2 == 0 {
				d *= 2
				if d > 9 {
					d -= 9
				}
			}
			sum += d
		}
		if sum%10 != 0 {
			t.Fatalf("PAN %s... fails the Luhn test", s[:6])
		}
	}
	// GitHub-style token: 30 random characters then the base62 CRC32 of them
	tok := withChecksum(g.str(alnum, 30))
	if len(tok) != 36 || tok[30:] != base62(crc32.ChecksumIEEE([]byte(tok[:30])), 6) {
		t.Error("checksum suffix is not the base62 CRC32 of the entropy")
	}
	if got := percentDecode("a%40b%2Fc%zz%4"); got != "a@b/c%zz%4" {
		t.Errorf("percentDecode left %q", got)
	}
	// the jwt.io sample is rebuilt exactly (its signature is public documentation)
	j := jwtIO()
	if !strings.HasSuffix(j, "SflKxwRJSMeKKF2QT4fwpMeJf3"+"6POk6yJV_adQssw5c") {
		t.Error("jwtIO() does not rebuild the jwt.io sample token")
	}
}
