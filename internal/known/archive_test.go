package known

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"os/exec"
	"strings"
	"testing"
)

type member struct {
	name, body string
	store      bool // zip: store rather than deflate
}

func mkZip(t *testing.T, ms ...member) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, m := range ms {
		method := zip.Deflate
		if m.store {
			method = zip.Store
		}
		w, err := zw.CreateHeader(&zip.FileHeader{Name: m.name, Method: method})
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(m.body))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func mkTar(t *testing.T, ms ...member) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, m := range ms {
		if err := tw.WriteHeader(&tar.Header{Name: m.name, Mode: 0o644, Size: int64(len(m.body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		tw.Write([]byte(m.body))
	}
	tw.Close()
	return buf.Bytes()
}

func mkGzip(b []byte) []byte {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	w.Write(b)
	w.Close()
	return buf.Bytes()
}

func mkZlib(b []byte) []byte {
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	w.Write(b)
	w.Close()
	return buf.Bytes()
}

func mkBzip2(t *testing.T, b []byte) []byte {
	t.Helper()
	cmd := exec.Command("bzip2", "-c")
	cmd.Stdin = bytes.NewReader(b)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("bzip2: %v", err)
	}
	return out
}

func TestMatchBlobsOpensArchives(t *testing.T) {
	testEnv(t)
	r := newRNG(t)
	s1 := "sk-proj-" + randFrom(r, alnum, 40)
	s2 := "ghp_" + randFrom(r, alnum, 36)
	s3 := randFrom(r, alnum, 32)
	s4 := randFrom(r, alnum, 32)
	m, _ := matcherFor(t, map[string]string{"S1": s1, "S2": s2, "S3": s3, "S4": s4})

	dir := newRepo(t)
	put := func(name string, b []byte) string {
		writeFile(t, dir, name, string(b))
		return strings.TrimSpace(git(t, dir, "hash-object", name))
	}
	// A secret in a deflated member, a stored member in base64, and a clean one.
	plainZip := put("plain.zip", mkZip(t,
		member{name: "src/a.txt", body: "token = " + s1 + "\n"},
		member{name: "stored.txt", body: b64(s2), store: true},
		member{name: "clean.txt", body: "nothing here\n"}))
	// zip -> tar.gz -> tar -> member
	tgz := mkGzip(mkTar(t, member{name: "deep/x.env", body: "K=" + s3 + "\n"}, member{name: "deep/clean", body: "x"}))
	nested := put("nested.zip", mkZip(t, member{name: "inner.tar.gz", body: string(tgz)}))
	// four containers deep: past the limit, counted
	tooDeep := put("toodeep.zip", mkZip(t, member{name: "l1.zip", body: string(mkZip(t,
		member{name: "l2.zip", body: string(mkZip(t,
			member{name: "l3.zip", body: string(mkZip(t, member{name: "x.txt", body: s1}))}))}))}))
	gzBlob := put("data.gz", mkGzip([]byte("password: "+s4+"\n")))
	bzBlob := put("data.bz2", mkBzip2(t, []byte("password: "+s4+"\n")))
	zlBlob := put("data.zz", mkZlib([]byte("password: "+s4+"\n")))
	tarBlob := put("plain.tar", mkTar(t, member{name: "a/b.txt", body: s1}))
	// A secret in a member NAME must not reach the label unmasked.
	named := put("named.zip", mkZip(t, member{name: randFrom(r, alnum, 30) + "-" + s2 + "/x.txt", body: s1}))
	// A bomb: 70 MB of zeros is 70 KB deflated and bigger than one member may be.
	bomb := put("bomb.zip", mkZip(t, member{name: "zeros", body: string(make([]byte, 70<<20))}))
	// Recognised but unopenable, and garbage that merely starts like a zip.
	unsup := put("x.7z", append([]byte("7z\xbc\xaf\x27\x1c"), noise(r, 100, false)...))
	fake := put("fake.zip", append([]byte("PK\x03\x04"), noise(r, 300, false)...))
	clean := put("clean.zip", mkZip(t, member{name: "ok.txt", body: "ok"}))
	git(t, dir, "add", "-A")
	git(t, dir, "commit", "-q", "-m", "archives")

	got := map[string]BlobHit{}
	st, err := m.MatchBlobs(catFile(t, dir, "--batch-all-objects", "--batch"), func(h BlobHit) { got[h.SHA] = h })
	if err != nil {
		t.Fatal(err)
	}
	members := func(sha string) map[string][]string {
		out := map[string][]string{}
		for _, in := range got[sha].Inside {
			for _, m := range in.Matches {
				out[in.Member] = append(out[in.Member], m.Name)
			}
		}
		return out
	}
	eq := func(name string, got map[string][]string, want map[string][]string) {
		t.Helper()
		if len(got) != len(want) {
			t.Errorf("%s: %v, want %v", name, got, want)
			return
		}
		for k, v := range want {
			if strings.Join(got[k], ",") != strings.Join(v, ",") {
				t.Errorf("%s: member %s matched %v, want %v", name, k, got[k], v)
			}
		}
	}
	eq("plain.zip", members(plainZip), map[string][]string{"src/a.txt": {"S1"}, "stored.txt": {"S2"}})
	eq("nested", members(nested), map[string][]string{"inner.tar.gz!gz!/deep/x.env": {"S3"}})
	eq("data.gz", members(gzBlob), map[string][]string{"!gz": {"S4"}})
	eq("data.bz2", members(bzBlob), map[string][]string{"!bz2": {"S4"}})
	eq("data.zz", members(zlBlob), map[string][]string{"!zlib": {"S4"}})
	eq("plain.tar", members(tarBlob), map[string][]string{"a/b.txt": {"S1"}})
	for _, sha := range []string{tooDeep, bomb, unsup, fake, clean} {
		if _, ok := got[sha]; ok {
			t.Errorf("blob %s unexpectedly reported: %v", sha[:8], members(sha))
		}
	}
	for member := range members(named) {
		if strings.Contains(member, s2[:20]) || len(member) == 0 {
			t.Errorf("a secret in an archive member name reached the label")
		}
	}
	if len(members(named)) != 1 {
		t.Errorf("named.zip: %v", members(named))
	}
	// Compressed members have no raw hits; a stored zip member and a tar's text do, and are
	// reported both ways.
	for _, sha := range []string{nested, gzBlob, bzBlob, zlBlob} { // (named.zip spells its secret in the clear in the file name, so it has raw hits)
		if n := len(got[sha].Matches); n != 0 {
			t.Errorf("blob %s has %d raw matches; its secrets are all compressed", sha[:8], n)
		}
	}
	if len(got[plainZip].Matches) == 0 || len(got[tarBlob].Matches) == 0 {
		t.Error("a stored zip member and an uncompressed tar should also match in the clear")
	}
	// The things that were not searched are counted, not hidden.
	if st.ArchivesUnsupported != 1 {
		t.Errorf("unsupported archives counted %d, want 1", st.ArchivesUnsupported)
	}
	if st.ArchiveSkips < 3 { // the too-deep zip, the bomb, the fake zip
		t.Errorf("archive skips %d, want at least 3: %+v", st.ArchiveSkips, st)
	}
	if st.Archives < 9 || st.ArchiveBytes == 0 {
		t.Errorf("stats: %+v", st)
	}
}

func TestArchiveKindIsCheapAndStrict(t *testing.T) {
	r := newRNG(t)
	for i := 0; i < 5000; i++ {
		b := noise(r, 300, i%2 == 0)
		if k := archiveKindOf(b); k != notArchive && k != kindZlib {
			t.Fatalf("random bytes read as archive kind %d", k)
		}
	}
	if archiveKindOf([]byte("PK")) != notArchive || archiveKindOf(nil) != notArchive {
		t.Fatal("short input read as an archive")
	}
	if archiveKindOf(mkGzip([]byte("x"))) != kindGzip || archiveKindOf(mkZlib([]byte("x"))) != kindZlib {
		t.Fatal("real streams not recognised")
	}
}
