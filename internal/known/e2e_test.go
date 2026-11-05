package known

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"keyguard/internal/core"
)

// The whole path a leak takes: learn from a fake home, load the store the way a hook does,
// then catch the value in a real repository in the shapes people actually leak it, through
// both the diff the hooks read and the objects the sweep reads.
func TestEndToEndLearnLoadThenCatchLeaks(t *testing.T) {
	f := newFixture(t)
	api := f.secret("sk-proj-", 48, "OPENAI_API_KEY")
	dbpw := f.secret("", 24, "DATABASE_URL (url password)")
	odd := "p@ss/w&rd\"" + randFrom(f.r, alnum, 14) // a password JSON and URLs both rewrite
	f.values = append(f.values, odd)
	f.want[odd] = "ADMIN_PASSWORD"
	dock := f.secret("", 26, "docker ghcr.io password")
	f.write("dev/app/.env", fmt.Sprintf("OPENAI_API_KEY=%s\nDATABASE_URL=postgres://app:%s@db:5432/app\nADMIN_PASSWORD='%s'\n", api, dbpw, odd))
	f.write(".docker/config.json", fmt.Sprintf(`{"auths":{"ghcr.io":{"auth":"%s"}}}`, b64("someone:"+dock)))
	sshText, sshLines := fakeOpenSSHKey(f.r)
	f.write(".ssh/id_ed25519", sshText)
	f.learn(Options{})
	f.check()

	m, err := LoadMatcher(core.KnownRoots())
	if err != nil || m.Len() == 0 {
		t.Fatalf("LoadMatcher: %d forms, %v", m.Len(), err)
	}

	dir := newRepo(t)
	writeFile(t, dir, "README.md", "# project\n")
	commit(t, dir, "base")
	jsonForm := strings.Trim(mustMarshal(t, odd), `"`)
	leaks := map[string]string{ // path -> content, each a way this value gets out
		"copy.env":        fmt.Sprintf("OPENAI_API_KEY=%s\n", api),
		"k8s/secret.yaml": fmt.Sprintf("data:\n  OPENAI_API_KEY: %s\n", b64(api)),
		"deploy.sh":       fmt.Sprintf("curl -H 'Authorization: Basic %s' https://x.example.org\n", b64("svc:"+dbpw)),
		"app/config.json": fmt.Sprintf("{\n  \"admin\": \"%s\"\n}\n", jsonForm),
		"link.txt":        fmt.Sprintf("postgres://app:%s@db:5432/app?x=1\nadmin=%s\n", url.QueryEscape(dbpw), url.QueryEscape(odd)),
		"docker.json":     fmt.Sprintf(`{"auths":{"ghcr.io":{"auth":"%s"}}}`, b64("someone:"+dock)),
		"id_copy":         sshText,
		"notes.txt":       "nothing to see here\n",
	}
	for p, c := range leaks {
		writeFile(t, dir, p, c)
	}
	// The same copy of .env, but inside a tarball, which no diff shows and no blob search sees.
	writeFile(t, dir, "backup.tar.gz", string(mkGzip(mkTar(t, member{name: "app/.env", body: "OPENAI_API_KEY=" + api + "\n"}))))
	git(t, dir, "add", "-A")

	// What the pre-commit and reference-transaction hooks see.
	got := map[string][]string{}
	for _, lm := range m.MatchDiff([]byte(git(t, dir, "diff", "--cached", "-U0", "--no-color", "--no-ext-diff"))) {
		got[lm.Path] = append(got[lm.Path], lm.Name)
	}
	for path, want := range map[string]string{
		"copy.env": "OPENAI_API_KEY", "k8s/secret.yaml": "OPENAI_API_KEY", "deploy.sh": "DATABASE_URL (url password)",
		"app/config.json": "ADMIN_PASSWORD", "link.txt": "ADMIN_PASSWORD", "docker.json": "docker ghcr.io password",
		"id_copy": "id_ed25519 line",
	} {
		ok := false
		for _, n := range got[path] {
			if strings.Contains(n, want) {
				ok = true
			}
		}
		if !ok {
			t.Errorf("diff scan missed the leak in %s (found %v)", path, got[path])
		}
	}
	if len(got["notes.txt"]) != 0 || len(got["README.md"]) != 0 {
		t.Errorf("clean files matched: %v", got)
	}
	// link.txt carries both the password and the URL-encoded DB password.
	if len(got["link.txt"]) < 2 {
		t.Errorf("link.txt: %v", got["link.txt"])
	}

	// What the sweep sees: every object, archives included.
	commit(t, dir, "leaks")
	blobs := map[string]BlobHit{}
	if _, err := m.MatchBlobs(catFile(t, dir, "--batch-all-objects", "--batch"), func(h BlobHit) { blobs[h.SHA] = h }); err != nil {
		t.Fatal(err)
	}
	tarSHA := strings.TrimSpace(git(t, dir, "hash-object", "backup.tar.gz"))
	if h, ok := blobs[tarSHA]; !ok || len(h.Inside) != 1 || h.Inside[0].Member != "!gz!/app/.env" && !strings.HasSuffix(h.Inside[0].Member, "app/.env") {
		t.Errorf("the tarball's secret was not found: %+v", blobs[tarSHA].Inside)
	}
	for p := range leaks {
		sha := strings.TrimSpace(git(t, dir, "hash-object", p))
		if _, ok := blobs[sha]; ok != (p != "notes.txt") {
			t.Errorf("blob scan: %s found=%v", p, ok)
		}
	}

	// And nothing it printed holds a usable part of any value.
	var report strings.Builder
	for _, lm := range m.MatchDiff([]byte(git(t, dir, "show", "-U0", "--no-color", "HEAD"))) {
		fmt.Fprintf(&report, "%s %s %d %s %s\n", lm.Commit, lm.Path, lm.Line, lm.Name, lm.Context)
	}
	for _, h := range blobs {
		fmt.Fprintf(&report, "%+v\n", h)
	}
	assertNoValue(t, append([]string{api, dbpw, odd, dock}, sshLines[2:]...), map[string][]byte{"report": []byte(report.String())})
}

func mustMarshal(t *testing.T, s string) string {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
