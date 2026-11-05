package engines

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"keyguard/internal/core"
)

// ----- P0-06: titus keeps no datastore and phones nobody -----

// Titus's datastore is a SQLite file holding every match in the clear (20 of 20 planted keys,
// measured). The engine must leave no datastore.db or *.ds anywhere it can write: its working
// directory, the keyguard data root, the temp dir. Its compiled-rules cache (no secrets in it,
// 2.7 s to build and 30 ms to read) belongs under the data root, where install can warm it
// and doctor can see it, and not wherever titus decides.
func TestTitusLeavesNoDatastoreAndCachesUnderKeyguard(t *testing.T) {
	f := getFixture(t)
	e := newEngine(t, "titus", f.kr)
	resetAudit()
	root := os.Getenv("KEYGUARD_HOME")
	hits := scanGit(t, e, f.mirror, core.Range{All: true}, testOpts())
	if len(hits) == 0 {
		t.Fatal("titus found nothing in the fixture")
	}
	dir, _ := dirTree(t)
	if err := e.ScanDir(context.Background(), dir, testOpts(), func(core.Hit) {}); err != nil {
		t.Fatal(err)
	}
	for _, where := range []string{root, os.Getenv("TMPDIR"), dir, f.mirror} {
		filepath.WalkDir(where, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if n := d.Name(); n == "datastore.db" || strings.HasSuffix(n, ".ds") || n == "titus.ds" {
				t.Errorf("titus left a datastore: %s", strings.TrimPrefix(p, where))
			}
			return nil
		})
	}
	cache := filepath.Join(root, "cache", "titus")
	n := 0
	filepath.WalkDir(cache, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			n++
		}
		return nil
	})
	if n == 0 {
		t.Errorf("titus built its rule cache somewhere other than %s", cache)
	}
}

// --accessibility auto, titus's default, looks the repository up on GitHub to decide how to
// score what it found. A scan of a mirror whose origin is on github.com must not call out.
func TestTitusDoesNotPhoneHome(t *testing.T) {
	f := getFixture(t)
	e := newEngine(t, "titus", f.kr)
	l := newListener(t)
	for _, k := range []string{"HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy", "ALL_PROXY"} {
		t.Setenv(k, "http://"+l.addr)
	}
	t.Setenv("NO_PROXY", "")
	repo := worktree(t)
	gitIn(repo, nil, "remote", "add", "origin", "https://github.com/someowner/somerepo.git")
	writeLines(t, repo, "prod.env", "STRIPE="+fake("stripe"))
	gitIn(repo, nil, "add", "-A")
	gitIn(repo, nil, "commit", "-q", "-m", "key")
	resetAudit()
	if hits := scanGit(t, e, repo, core.Range{All: true}, testOpts()); len(hits) == 0 {
		t.Fatal("titus found nothing")
	}
	if n := l.count(); n != 0 {
		t.Errorf("titus opened %d connection(s) while scanning a repository with a GitHub remote", n)
	}
}
