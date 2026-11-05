package sweep

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"keyguard/internal/core"
	"keyguard/internal/fp"
)

type knownEnv struct {
	t     *testing.T
	repo  *repo
	known *fakeKnown
	kr    *fp.Keyring
	g     GitKnown
}

func newKnownEnv(t *testing.T) *knownEnv {
	isolate(t)
	kr := fp.NewEphemeral()
	return &knownEnv{t: t, repo: newRepo(t, filepath.Join(t.TempDir(), "r")), known: &fakeKnown{kr: kr}, kr: kr}
}

var testLoc = core.Location{Source: "github.com/o/r", Kind: "repo", Visibility: core.Private}

func (e *knownEnv) scan(r core.Range) ([]core.Hit, BlobStats) {
	e.t.Helper()
	var mu sync.Mutex
	var hits []core.Hit
	st, err := e.g.ScanBlobs(context.Background(), e.repo.dir, r, e.known, testLoc, func(h core.Hit) { mu.Lock(); hits = append(hits, h); mu.Unlock() })
	if err != nil {
		e.t.Fatal(err)
	}
	slices.SortFunc(hits, func(a, b core.Hit) int {
		return strings.Compare(a.Loc.Commit+a.Loc.Path, b.Loc.Commit+b.Loc.Path)
	})
	return hits, st
}

func TestGitKnownReportsTheAddingCommitPathAndLine(t *testing.T) {
	e := newKnownEnv(t)
	raw := fakeKey(t, "sk-", 48)
	e.known.add(raw, "OPENAI_API_KEY")
	e.repo.commit("readme", map[string]string{"README.md": "hello\n"})
	c2 := e.repo.commit("env", map[string]string{"cfg/.env": "A=1\nB=2\nOPENAI_API_KEY=" + raw + "\nC=3\n"})
	hits, st := e.scan(core.Range{All: true})
	if len(hits) != 1 {
		t.Fatalf("%d hits", len(hits))
	}
	h := hits[0]
	if h.Engine != "known" || h.Rule != "known-secret" || h.Type != "openai" || h.FP != e.kr.FP(raw) || h.Shape != fp.Shape(raw) ||
		h.Len != len(raw) || h.Verified != core.Unverified || !strings.HasSuffix(h.Known, " OPENAI_API_KEY") || h.Known[:2] != "kg" {
		t.Fatalf("hit: %+v", h)
	}
	if l := h.Loc; l.Commit != c2 || l.Path != "cfg/.env" || l.Line != 3 || l.Source != "github.com/o/r" || l.Visibility != core.Private ||
		l.Author != "Test" || l.Date == "" {
		t.Fatalf("location: %+v", l)
	}
	if strings.Contains(h.Context, raw[3:]) {
		t.Fatal("the context carries the raw value")
	}
	if !strings.Contains(h.Context, "OPENAI_API_KEY=«"+fp.Shape(raw)+"»") {
		t.Fatalf("the context (%d runes) lacks the masked assignment", len([]rune(h.Context)))
	}
	if h.Entropy < 4 {
		t.Fatalf("entropy %v", h.Entropy)
	}
	if st.Blobs < 2 || st.Skipped != 0 || st.Bytes == 0 {
		t.Fatalf("stats %+v", st)
	}
}

func TestGitKnownCountsASecretOnlyWhereItWasAdded(t *testing.T) {
	e := newKnownEnv(t)
	raw := fakeKey(t, "sk-", 48)
	e.known.add(raw, "OPENAI_API_KEY")
	c1 := e.repo.commit("add", map[string]string{".env": "K=" + raw + "\nX=1\n"})
	e.repo.commit("unrelated edit", map[string]string{".env": "K=" + raw + "\nX=2\n"})
	e.repo.commit("another edit", map[string]string{".env": "K=" + raw + "\nX=3\nY=4\n"})
	c4 := e.repo.commit("remove", map[string]string{".env": ""})
	c5 := e.repo.commit("add back", map[string]string{".env": "K=" + raw + "\nX=1\n"}) // the same bytes as c1
	hits, _ := e.scan(core.Range{All: true})
	var got []string
	for _, h := range hits {
		got = append(got, h.Loc.Commit)
	}
	slices.Sort(got)
	want := []string{c1, c5}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("commits %v, want only the two that added it (%s, %s); removal %s must not count", shortAll(got), c1[:7], c5[:7], c4[:7])
	}
}

func TestGitKnownIncrementalRangeUsesTheOldBlobToTellNewFromContinuing(t *testing.T) {
	e := newKnownEnv(t)
	raw1, raw2 := fakeKey(t, "sk-", 48), fakeKey(t, "ghp_", 36)
	e.known.add(raw1, "OPENAI_API_KEY")
	e.known.add(raw2, "GITHUB_TOKEN")
	e.repo.commit("add", map[string]string{".env": "K=" + raw1 + "\n"})
	c2 := e.repo.commit("unrelated edit", map[string]string{".env": "K=" + raw1 + "\nX=1\n"})
	c3 := e.repo.commit("second key", map[string]string{".env": "K=" + raw1 + "\nX=1\nG=" + raw2 + "\n"})

	// Only c3 is in range. Its blob holds both keys, but the old blob (c2's, out of range)
	// already held raw1, so only raw2 is new.
	hits, _ := e.scan(core.Range{Revs: []string{"--all", "--not", c2}})
	if len(hits) != 1 || hits[0].FP != e.kr.FP(raw2) || hits[0].Loc.Commit != c3 || hits[0].Loc.Line != 3 || hits[0].Type != "github" {
		t.Fatalf("hits: %+v", hits)
	}
}

func TestGitKnownFindsBlobsNoCommitDiffShows(t *testing.T) {
	e := newKnownEnv(t)
	raw := fakeKey(t, "sk-", 48)
	e.known.add(raw, "OPENAI_API_KEY")
	e.repo.commit("base", map[string]string{"README": "x\n"})

	// A blob a tag points at directly: no tree holds it, so no diff ever shows it.
	f := filepath.Join(t.TempDir(), "blob.txt")
	if err := os.WriteFile(f, []byte("loose key "+raw+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sha := e.repo.git("hash-object", "-w", f)
	e.repo.git("tag", "keyblob", sha)

	// A commit only a pull-request ref reaches.
	e.repo.git("checkout", "-q", "-b", "tmp")
	c := e.repo.commit("pr work", map[string]string{"pr.txt": "pr " + raw + "\n"})
	e.repo.git("update-ref", "refs/pull/1/head", c)
	e.repo.git("checkout", "-q", "main")
	e.repo.git("branch", "-q", "-D", "tmp")

	hits, _ := e.scan(core.Range{All: true})
	if len(hits) != 2 {
		t.Fatalf("%d hits, want the tagged blob and the pull-request file: %+v", len(hits), hits)
	}
	var tagged, pr *core.Hit
	for i := range hits {
		if hits[i].Loc.Commit == "" {
			tagged = &hits[i]
		} else {
			pr = &hits[i]
		}
	}
	if tagged == nil || pr == nil || tagged.Loc.Line != 1 || pr.Loc.Commit != c || pr.Loc.Path != "pr.txt" {
		t.Fatalf("tagged=%+v pr=%+v", tagged, pr)
	}
}

func TestGitKnownReadsBinaryFilesAndOddPaths(t *testing.T) {
	e := newKnownEnv(t)
	raw := fakeKey(t, "sk-", 48)
	e.known.add(raw, "SERVICE_TOKEN")
	bin := slices.Concat([]byte{0, 1, 2, 0xff, 0xfe, 0}, []byte(raw), []byte{0, 0xc3, 0x28, 0, 9})
	c := e.repo.commit("binary", map[string]string{"dir with space/ü.bin": string(bin), "plain.txt": "no key here\n"})
	hits, _ := e.scan(core.Range{All: true})
	if len(hits) != 1 {
		t.Fatalf("%d hits", len(hits))
	}
	h := hits[0]
	if h.Loc.Path != "dir with space/ü.bin" || h.Loc.Commit != c || h.Loc.Line != 1 {
		t.Fatalf("%+v", h.Loc)
	}
	if h.Type != "generic" {
		t.Fatalf("a name that is not a provider is generic, got %s", h.Type)
	}
	if strings.Contains(h.Context, raw[3:]) {
		t.Fatal("the context carries the raw value")
	}
	if !strings.Contains(h.Context, "«"+fp.Shape(raw)+"»") {
		t.Fatalf("the context (%d runes) lacks the masked value", len([]rune(h.Context)))
	}
	if !isValidUTF8(h.Context) {
		t.Fatal("a context built from binary must still be text")
	}
}

func isValidUTF8(s string) bool { return strings.ToValidUTF8(s, "\x00") == s }

func TestGitKnownMasksEveryLearnedValueInTheContext(t *testing.T) {
	e := newKnownEnv(t)
	k1, k2 := fakeKey(t, "sk-", 48), randStr(t, alnum, 14) // 14 characters: too short for fp.Scrub to mask on its own
	e.known.add(k1, "OPENAI_API_KEY")
	e.known.add(k2, "DB_PASS")
	e.repo.commit("one line", map[string]string{"app.js": "const a = '" + k1 + "', b = '" + k2 + "', again = '" + k2 + "';\n"})
	hits, _ := e.scan(core.Range{All: true})
	if len(hits) != 3 {
		t.Fatalf("%d hits: one for k1, two for k2's two copies", len(hits))
	}
	for _, h := range hits {
		if strings.Contains(h.Context, k2) || strings.Contains(h.Context, k1[3:]) {
			t.Fatal("a learned value is visible in a context")
		}
		if got := strings.Count(h.Context, "«"); got != 3 {
			t.Fatalf("all three values on the line should be masked, found %d marks", got)
		}
	}
}

func TestGitKnownLongLinesAreClippedAtTokenBoundaries(t *testing.T) {
	e := newKnownEnv(t)
	raw := fakeKey(t, "sk-", 48)
	e.known.add(raw, "OPENAI_API_KEY")
	pad := strings.Repeat("abcdefghij", 120)
	e.repo.commit("minified", map[string]string{"bundle.min.js": pad + ";k=" + raw + ";" + pad + "\n"})
	hits, _ := e.scan(core.Range{All: true})
	if len(hits) != 1 {
		t.Fatalf("%d hits", len(hits))
	}
	ctx := hits[0].Context
	if n := len([]rune(ctx)); n > 200 {
		t.Fatalf("context is %d runes", n)
	}
	if strings.Contains(ctx, raw[3:]) {
		t.Fatal("the context carries the raw value")
	}
	if !strings.Contains(ctx, "«") {
		t.Fatal("the match was not masked in the context")
	}
}

func TestGitKnownCountsWhatItSkipsAndCapsMatchesPerBlob(t *testing.T) {
	e := newKnownEnv(t)
	e.g = GitKnown{MaxBlob: 300}
	raw := fakeKey(t, "sk-", 48)
	e.known.add(raw, "OPENAI_API_KEY")
	big := raw + strings.Repeat("\npadding line that makes this blob larger than the limit", 20)
	e.repo.commit("big and small", map[string]string{"big.txt": big, "small.txt": "k=" + raw + "\n"})
	hits, st := e.scan(core.Range{All: true})
	if st.Skipped != 1 || st.SkippedBytes < 300 || st.Limit != 300 || !slices.Equal(st.SkippedPaths, []string{"big.txt"}) {
		t.Fatalf("a blob over the limit must be counted and named: %+v", st)
	}
	if len(hits) != 1 || hits[0].Loc.Path != "small.txt" {
		t.Fatalf("only the small file can be scanned: %+v", hits)
	}

	e2 := newKnownEnv(t)
	e2.known.add(raw, "OPENAI_API_KEY")
	var lines []string
	for i := 0; i < maxMatchesPerBlob+50; i++ {
		lines = append(lines, "k="+raw)
	}
	e2.repo.commit("repeated", map[string]string{"dump.txt": strings.Join(lines, "\n") + "\n"})
	hits, st = e2.scan(core.Range{All: true})
	if st.Truncated != 1 || len(hits) != maxMatchesPerBlob {
		t.Fatalf("%d hits, truncated=%d", len(hits), st.Truncated)
	}
	if hits[len(hits)-1].Loc.Line != maxMatchesPerBlob && hits[0].Loc.Line != 1 {
		t.Fatalf("lines should count from 1: first %d", hits[0].Loc.Line)
	}
}

func TestGitKnownHandlesMergesAndEmptyCommits(t *testing.T) {
	e := newKnownEnv(t)
	raw := fakeKey(t, "sk-", 48)
	e.known.add(raw, "OPENAI_API_KEY")
	e.repo.commit("base", map[string]string{"a": "1\n"})
	e.repo.git("checkout", "-q", "-b", "side")
	c2 := e.repo.commit("side work", map[string]string{"side.env": "K=" + raw + "\n"})
	e.repo.git("checkout", "-q", "main")
	e.repo.commit("main work", map[string]string{"b": "2\n"})
	e.repo.git("merge", "-q", "--no-ff", "-m", "merge side", "side")
	e.repo.commit("nothing changes", nil)
	hits, _ := e.scan(core.Range{All: true})
	if len(hits) != 1 || hits[0].Loc.Commit != c2 {
		t.Fatalf("the secret was added by the side commit, not the merge: %+v", hits)
	}
}

func TestGitKnownRejectsBadRanges(t *testing.T) {
	e := newKnownEnv(t)
	e.repo.commit("base", map[string]string{"a": "1\n"})
	for name, r := range map[string]core.Range{
		"empty":                {},
		"since only":           {Since: map[string]string{"refs/heads/main": strings.Repeat("a", 40)}},
		"option injection":     {Revs: []string{"--output=/tmp/x"}},
		"whitespace":           {Revs: []string{"main branch"}},
		"all with a bad rev":   {All: true, Revs: []string{"-p"}},
		"not an object in git": {Revs: []string{"nosuchref"}},
	} {
		if _, err := e.g.ScanBlobs(context.Background(), e.repo.dir, r, e.known, testLoc, func(core.Hit) {}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := e.g.ScanBlobs(context.Background(), filepath.Join(t.TempDir(), "missing"), core.Range{All: true}, e.known, testLoc, func(core.Hit) {}); err == nil {
		t.Error("a missing repo should be an error")
	}
}

func TestGitKnownStopsWhenCancelled(t *testing.T) {
	e := newKnownEnv(t)
	raw := fakeKey(t, "sk-", 48)
	e.known.add(raw, "OPENAI_API_KEY")
	e.repo.commit("one", map[string]string{"a": raw + "\n"})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := e.g.ScanBlobs(ctx, e.repo.dir, core.Range{All: true}, e.known, testLoc, func(core.Hit) {}); err == nil {
		t.Fatal("a cancelled scan reported success")
	}
}

func TestGitKnownScansManyBlobsWithoutDeadlock(t *testing.T) {
	e := newKnownEnv(t)
	raw := fakeKey(t, "sk-", 48)
	e.known.add(raw, "OPENAI_API_KEY")
	files := map[string]string{}
	for i := 0; i < 400; i++ {
		files[filepath.Join("d", string(rune('a'+i%26)), "f"+randStr(t, "0123456789", 6)+".txt")] = strings.Repeat("filler line number ten\n", 200+i)
	}
	files["d/z/needle.txt"] = "x\n" + raw + "\n"
	e.repo.commit("lots", files)
	hits, st := e.scan(core.Range{All: true})
	if len(hits) != 1 || hits[0].Loc.Path != "d/z/needle.txt" || hits[0].Loc.Line != 2 {
		t.Fatalf("%+v", hits)
	}
	if st.Blobs < 400 {
		t.Fatalf("only %d blobs read", st.Blobs)
	}
}

func TestTypeFromName(t *testing.T) {
	for name, want := range map[string]string{
		"OPENAI_API_KEY": "openai", "GITHUB_TOKEN": "github", "AWS_SECRET_ACCESS_KEY": "aws", "ANTHROPIC_API_KEY": "anthropic",
		"HF_TOKEN": "huggingface", "DATABASE_URL": "generic", "SECRET_KEY": "generic", "MY_APP_TOKEN": "generic",
		"OPENAI": "generic", "": "generic", "stripe_secret": "stripe",
	} {
		if got := typeFromName(name); got != want {
			t.Errorf("typeFromName(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestParseHeaderAndReadBatch(t *testing.T) {
	h, ok := parseHeader("abc123 blob 15 dir with space/u.txt\n")
	if !ok || h.sha != "abc123" || h.typ != "blob" || h.size != 15 || h.rest != "dir with space/u.txt" {
		t.Fatalf("%+v %v", h, ok)
	}
	if h, ok := parseHeader("abc123 blob 0 \n"); !ok || h.rest != "" || h.size != 0 {
		t.Fatalf("%+v %v", h, ok)
	}
	for _, bad := range []string{"", "nospaces", "a b", "a b c", "a b -3 x"} {
		if _, ok := parseHeader(bad); ok {
			t.Errorf("parsed %q", bad)
		}
	}
	// Two blobs, one over the limit, one missing object between them.
	in := "aaa blob 3 one.txt\nxyz\nbbb blob 6 two.txt\nabcdef\nccc missing\nddd blob 2 \nhi\n"
	var got []string
	err := readBatch(strings.NewReader(in), 5, func(h batchHeader, data []byte) error {
		got = append(got, h.sha+":"+string(data)+":"+h.rest)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"aaa:xyz:one.txt", "bbb::two.txt", "ddd:hi:"}; !slices.Equal(got, want) {
		t.Fatalf("%v, want %v", got, want)
	}
	if err := readBatch(strings.NewReader("aaa blob 9 x\nshort"), 100, func(batchHeader, []byte) error { return nil }); err == nil {
		t.Fatal("a truncated stream must be an error")
	}
	if err := readBatch(bytes.NewReader([]byte("garbage line\n")), 100, func(batchHeader, []byte) error { return nil }); err == nil {
		t.Fatal("a line that is not a header must be an error")
	}
}

func TestHumanBytes(t *testing.T) {
	for n, want := range map[int64]string{0: "0 B", 100: "100 B", 1023: "1023 B", 1024: "1 KiB", 3 << 10: "3 KiB", 50 << 20: "50 MiB", 2 << 30: "2 GiB"} {
		if got := humanBytes(n); got != want {
			t.Errorf("humanBytes(%d) = %q, want %q", n, got, want)
		}
	}
}
