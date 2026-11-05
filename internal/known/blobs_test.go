package known

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

// catFile runs git cat-file in batch mode over a real repository and returns the stream.
func catFile(t *testing.T, dir string, args ...string) *bytes.Buffer {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir, "cat-file"}, args...)...)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git cat-file %v: %v", args, err)
	}
	return bytes.NewBuffer(out)
}

func TestMatchBlobsRealRepo(t *testing.T) {
	testEnv(t)
	r := newRNG(t)
	s1 := "sk-proj-" + randFrom(r, alnum, 40)
	s2 := "ghp_" + randFrom(r, alnum, 36)
	s3 := randFrom(r, alnum, 32)
	s4 := randFrom(r, alnum, 32)
	m, _ := matcherFor(t, map[string]string{"S1": s1, "S2": s2, "S3": s3, "S4": s4})

	dir := newRepo(t)
	bin := noise(r, 200_000, false)
	copy(bin[123_456:], s1)
	writeFile(t, dir, "plain.txt", "nothing to see\n")
	writeFile(t, dir, "has.env", "KEY="+s1+"\nOTHER="+b64(s2)+"\n")
	writeFile(t, dir, "bin.dat", string(bin))
	huge := noise(r, 3<<20, true) // over the 1 MiB cap used below
	copy(huge[1<<20:], s1)
	writeFile(t, dir, "huge.log", string(huge))
	writeFile(t, dir, "deleted-later.txt", "was here "+s2+"\n")
	commit(t, dir, "files with secrets")
	git(t, dir, "rm", "-q", "deleted-later.txt")
	writeFile(t, dir, "empty.txt", "")
	// A secret in a commit message, and one in an annotated tag's.
	git(t, dir, "add", "-A")
	git(t, dir, "commit", "-q", "-m", "oops pasted "+s3)
	git(t, dir, "tag", "-a", "v1", "-m", "release with "+s4)

	shaOf := func(rel string) string { return strings.TrimSpace(git(t, dir, "hash-object", rel)) }
	hasEnv, binDat, plain := shaOf("has.env"), shaOf("bin.dat"), shaOf("plain.txt")
	deleted := strings.TrimSpace(git(t, dir, "rev-parse", "HEAD~1:deleted-later.txt"))
	commitSHA := strings.TrimSpace(git(t, dir, "rev-parse", "HEAD"))
	tagSHA := strings.TrimSpace(git(t, dir, "rev-parse", "v1"))

	got := map[string]BlobHit{}
	stream := catFile(t, dir, "--batch-all-objects", "--batch")
	total := strings.Count(catFile(t, dir, "--batch-all-objects", "--batch-check").String(), "\n")
	st, err := m.MatchBlobsMax(stream, 1<<20, func(h BlobHit) { got[h.SHA] = h })
	if err != nil {
		t.Fatal(err)
	}

	check := func(sha, typ, name string, wantNames ...string) {
		t.Helper()
		h, ok := got[sha]
		if !ok {
			t.Errorf("%s (%s) not reported", name, typ)
			return
		}
		if h.Type != typ {
			t.Errorf("%s: type %s want %s", name, h.Type, typ)
		}
		var names []string
		for _, m := range h.Matches {
			names = append(names, m.Name)
		}
		if strings.Join(names, ",") != strings.Join(wantNames, ",") {
			t.Errorf("%s: matched %v want %v", name, names, wantNames)
		}
	}
	check(hasEnv, "blob", "has.env", "S1", "S2")
	check(binDat, "blob", "bin.dat", "S1")
	if h := got[binDat]; len(h.Matches) == 1 && h.Matches[0].Offset != 123_456 {
		t.Errorf("binary blob offset %d, want 123456", h.Matches[0].Offset)
	}
	check(deleted, "blob", "a blob only history holds", "S2")
	check(commitSHA, "commit", "commit message", "S3")
	check(tagSHA, "tag", "tag message", "S4")
	if _, ok := got[plain]; ok {
		t.Error("a clean blob was reported")
	}

	// Every object is accounted for: scanned, skipped over the cap, or a tree.
	if st.Objects != total || st.Objects != st.Scanned+st.Skipped+st.Trees+st.Missing {
		t.Errorf("stats do not add up: %+v (git lists %d objects)", st, total)
	}
	if st.Skipped != 1 || st.SkippedBytes != int64(len(huge)) || st.Trees == 0 || st.Hits != len(got) {
		t.Errorf("stats: %+v", st)
	}
	if st.Bytes == 0 {
		t.Error("no bytes counted")
	}

	// With the default cap the 3 MiB blob is searched and its secret found.
	got = map[string]BlobHit{}
	st, err = m.MatchBlobs(catFile(t, dir, "--batch-all-objects", "--batch"), func(h BlobHit) { got[h.SHA] = h })
	if err != nil || st.Skipped != 0 {
		t.Fatalf("default cap: %+v %v", st, err)
	}
	check(shaOf("huge.log"), "blob", "huge.log", "S1")
	if h := got[shaOf("huge.log")]; len(h.Matches) == 1 && h.Matches[0].Offset != 1<<20 {
		t.Errorf("offset %d", h.Matches[0].Offset)
	}
}

func TestMatchBlobsMissingAndMalformedStreams(t *testing.T) {
	testEnv(t)
	r := newRNG(t)
	s1 := "sk-proj-" + randFrom(r, alnum, 40)
	m, _ := matcherFor(t, map[string]string{"S1": s1})
	dir := newRepo(t)
	writeFile(t, dir, "a.txt", "a "+s1+"\n")
	commit(t, dir, "c")
	sha := strings.TrimSpace(git(t, dir, "hash-object", "a.txt"))

	// Ask git for an object it does not have: the stream says "missing" and goes on.
	cmd := exec.Command("git", "-C", dir, "cat-file", "--batch")
	cmd.Stdin = strings.NewReader(strings.Repeat("0", 40) + "\n" + sha + "\n")
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	var hits int
	st, err := m.MatchBlobs(bytes.NewReader(out), func(BlobHit) { hits++ })
	if err != nil || st.Missing != 1 || hits != 1 || st.Objects != 2 {
		t.Fatalf("missing: %+v hits %d err %v", st, hits, err)
	}

	good := fmt.Sprintf("%s blob 4\nabcd\n", sha)
	for name, stream := range map[string]string{
		"truncated content":    fmt.Sprintf("%s blob 40\nabcd\n", sha),
		"no trailing newline":  fmt.Sprintf("%s blob 4\nabcdX", sha),
		"garbage header":       "this is not a header\n",
		"bad size":             fmt.Sprintf("%s blob lots\n", sha),
		"negative size":        fmt.Sprintf("%s blob -3\n", sha),
		"unknown type":         fmt.Sprintf("%s widget 4\nabcd\n", sha),
		"truncated header":     sha + " blob",
		"skipped then cut off": fmt.Sprintf("%s blob 100\nabc", sha),
	} {
		_, err := m.MatchBlobsMax(strings.NewReader(good+stream), 50, func(BlobHit) {})
		if err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	// An empty stream is fine.
	if st, err := m.MatchBlobs(strings.NewReader(""), func(BlobHit) {}); err != nil || st.Objects != 0 {
		t.Errorf("empty stream: %+v %v", st, err)
	}
}

// A full scan walks every object; it must not allocate per clean object beyond the buffer.
func TestMatchBlobsAllocatesLittleOnCleanObjects(t *testing.T) {
	r := newRNG(t)
	m, _ := matcherFor(t, map[string]string{"S1": "sk-proj-" + randFrom(r, alnum, 40)})
	var sb strings.Builder
	for i := 0; i < 2000; i++ {
		body := randFrom(r, alnum, 100+i%200)
		fmt.Fprintf(&sb, "%s blob %d\n%s\n", randFrom(r, hexchars, 40), len(body), body)
	}
	stream := sb.String()
	allocs := testing.AllocsPerRun(5, func() {
		if _, err := m.MatchBlobs(strings.NewReader(stream), func(BlobHit) { t.Fatal("hit") }); err != nil {
			t.Fatal(err)
		}
	})
	if allocs > 30 { // the reader, the buffer growth: a handful, not one per object
		t.Errorf("%.0f allocations for 2000 clean objects", allocs)
	}
}
