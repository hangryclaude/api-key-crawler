package install

import (
	"os"
	"path/filepath"
	"testing"

	"keyguard/internal/engines"
	"keyguard/internal/testkit"
)

// realEnginesOnPath puts the four real engines on PATH, as links in a directory of their own,
// wherever the test kit finds them: the installer looks on PATH and under the machine's fake HOME,
// and a CI run has a narrow PATH. A missing engine skips the test, or fails it under
// KEYGUARD_TEST_REQUIRE_ENGINES=1. Nothing is written through a link.
func realEnginesOnPath(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	for _, name := range engines.Names {
		if err := os.Symlink(testkit.EnginePath(t, name), filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// The installer pins the engines it discovers into config.json; the tests run the ones testkit
// discovers. If the two ever searched differently, the suite would exercise engines other than
// the ones the hooks run. Each is the other's independent check: neither calls the other.
func TestTestkitFindsTheEnginesTheInstallerDoes(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	found := DiscoverEngines(home)
	if len(found) == 0 {
		if os.Getenv(testkit.RequireEnv) == "1" {
			t.Fatalf("no engine is installed, and %s=1 makes that a failure and not a skip", testkit.RequireEnv)
		}
		t.Skip("no engine installed here, so there is nothing for the two searches to disagree about")
	}
	for _, name := range engines.Names {
		if os.Getenv(testkit.OverrideEnv(name)) != "" {
			continue // pinned on purpose, and the installer knows nothing of pins
		}
		want, installed := found[name]
		got, err := testkit.LookupEngine(name)
		if installed != (err == nil) {
			t.Errorf("%s: the installer found it = %v, testkit found it = %v (%v)", name, installed, err == nil, err)
			continue
		}
		if !installed {
			continue
		}
		// Same file, even if one search reached it through a symlink the other did not follow.
		a, errA := filepath.EvalSymlinks(want)
		b, errB := filepath.EvalSymlinks(got)
		if errA != nil || errB != nil || a != b {
			t.Errorf("%s: the installer would pin %s, testkit runs %s", name, want, got)
		}
	}
}
