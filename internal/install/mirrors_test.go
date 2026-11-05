package install

import (
	"path/filepath"
	"strings"
	"testing"

	"keyguard/internal/core"
)

func TestMirrorRootIsTheCacheUnlessConfigNamesAnother(t *testing.T) {
	w := newWorld(t)
	cfg, err := LoadConfig(w.paths, w.home)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := cfg.MirrorRoot(w.paths), filepath.Join(w.paths.Root, "cache", "mirrors"); got != want {
		t.Errorf("the default mirror root is %s, want %s", got, want)
	}

	other := filepath.Join(t.TempDir(), "mirrors")
	named := DefaultConfig(w.paths, w.home)
	named.Accounts = []string{"hangryclaude"}
	named.Mirrors = other
	if err := named.Save(w.paths); err != nil {
		t.Fatal(err)
	}
	cfg, err = LoadConfig(w.paths, w.home)
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.MirrorRoot(w.paths); got != other {
		t.Errorf("config.json names %s as the mirrors, MirrorRoot says %s", other, got)
	}
	if p := cfg.Problems(); len(p) != 0 {
		t.Errorf("a config with an absolute mirrors path has problems: %v", p)
	}
	// Left out of the file when unset, so an ordinary config.json does not grow a key.
	b, err := (Config{}).marshal()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "mirrors") {
		t.Errorf("an unset mirrors root is written out:\n%s", b)
	}
}

func TestRelativeMirrorsPathIsAProblem(t *testing.T) {
	cfg := DefaultConfig(core.PathsAt("/tmp/x/.keyguard"), "/tmp/x")
	cfg.Mirrors = "cache/mirrors"
	found := false
	for _, p := range cfg.Problems() {
		found = found || strings.Contains(p, "mirrors") && strings.Contains(p, "absolute")
	}
	if !found {
		t.Errorf("a relative mirrors path would resolve against whatever directory a command runs in: %v", cfg.Problems())
	}
}
