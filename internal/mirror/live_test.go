//go:build live

// Live smoke against real GitHub. Read-only (clone and fetch, nothing is pushed or changed),
// into a temp directory, and kept out of the default test run by its build tag:
// go test -tags live -run TestLive -v ./internal/mirror
package mirror

import (
	"context"
	"errors"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"testing"
	"time"

	"keyguard/internal/core"
)

func dirSize(t *testing.T, root string) int64 {
	t.Helper()
	var n int64
	err := filepath.WalkDir(root, func(_ string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if fi, ierr := d.Info(); ierr == nil {
				n += fi.Size()
			}
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestLiveSyncPublicRepoThenNoOpThenAbsentWikiAndMissingRepo(t *testing.T) {
	tmp := t.TempDir()
	// Isolate git's config; leave HOME alone, because gh finds its accounts through it.
	cfgFile := filepath.Join(tmp, "gitconfig")
	if err := os.WriteFile(cfgFile, []byte("[init]\n\tdefaultBranch = main\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_CONFIG_GLOBAL", cfgFile)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("KEYGUARD_HOME", filepath.Join(tmp, "kg"))

	m, err := New(Config{Root: filepath.Join(tmp, "mirrors")})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()

	headroom := core.Source{
		ID: "github.com/hangryclaude/headroom", Kind: "repo", Owner: "hangryclaude", Name: "headroom", Account: "hangryclaude",
		CloneURL: "https://github.com/hangryclaude/headroom.git", Visibility: core.Public,
	}
	first, err := m.SyncResult(ctx, headroom)
	if err != nil {
		t.Fatalf("clone: %v", err)
	}
	t.Logf("clone: %s, %d refs, %.1f MB on disk", first.Elapsed.Round(time.Millisecond), len(first.After), float64(dirSize(t, m.Path(headroom)))/1e6)
	if !first.Cloned || len(first.After) == 0 || len(first.Before) != 0 {
		t.Fatalf("clone result = cloned %v, %d before, %d after", first.Cloned, len(first.Before), len(first.After))
	}

	second, err := m.SyncResult(ctx, headroom)
	if err != nil {
		t.Fatalf("no-op fetch: %v", err)
	}
	t.Logf("no-op fetch: %s", second.Elapsed.Round(time.Millisecond))
	if second.Cloned || !maps.Equal(second.Before, second.After) || !maps.Equal(second.After, first.After) {
		t.Fatalf("no-op fetch changed something: cloned=%v moved=%v", second.Cloned, second.Moved())
	}

	third, err := m.SyncResult(ctx, headroom)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("second no-op fetch: %s", third.Elapsed.Round(time.Millisecond))

	// Real GitHub's wording for a wiki with no pages (hasWikiEnabled is true on this org repo).
	wiki := core.Source{
		ID: "github.com/acme-apps/mailflare.wiki", Kind: "wiki", Owner: "acme-apps", Name: "mailflare.wiki", Account: "hangryclaude",
		CloneURL: "https://github.com/acme-apps/mailflare.wiki.git", Visibility: core.Public,
	}
	w, err := m.SyncResult(ctx, wiki)
	if err != nil {
		t.Fatalf("wiki: %v", err)
	}
	t.Logf("wiki of an org repo with the wiki switched on: absent=%v cloned=%v refs=%d in %s", w.Absent, w.Cloned, len(w.After), w.Elapsed.Round(time.Millisecond))

	// And for a repo that is not there: a typed error, not an absent wiki.
	ghost := core.Source{
		ID: "github.com/hangryclaude/kg-smoke-no-such-repo", Kind: "repo", Owner: "hangryclaude", Name: "kg-smoke-no-such-repo", Account: "hangryclaude",
		CloneURL: "https://github.com/hangryclaude/kg-smoke-no-such-repo.git",
	}
	_, err = m.SyncResult(ctx, ghost)
	t.Logf("missing repo: %v", err)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("missing repo error = %v, want ErrNotFound", err)
	}
	if _, serr := os.Stat(m.Path(ghost)); serr == nil {
		t.Error("a directory exists for a repo that does not")
	}
}
