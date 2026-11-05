package install

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"keyguard/internal/core"
	"keyguard/internal/inventory"
)

func TestDefaultConfigIsWhatPlanSays(t *testing.T) {
	w := newWorld(t)
	c := DefaultConfig(w.paths, w.home)
	if c.Jobs != 8 {
		t.Errorf("-j default is %d, want 8", c.Jobs)
	}
	if c.Notify.IMessageTo != "" {
		t.Errorf("notify targets must be empty until set, got %q", c.Notify.IMessageTo)
	}
	if len(c.Accounts) != 0 || len(c.Orgs) != 0 {
		t.Errorf("accounts come from gh at the first install, not from the defaults: %v %v", c.Accounts, c.Orgs)
	}
	if c.Rules != filepath.Join(w.paths.Root, "rules", "keyguard.toml") {
		t.Errorf("rules: %s", c.Rules)
	}
	// Engines are looked for on this Mac and are absolute.
	for name, p := range c.Engines {
		if !filepath.IsAbs(p) || !isExecutable(p) {
			t.Errorf("engine %s -> %q is not an executable absolute path", name, p)
		}
	}
	if c.Engines["betterleaks"] == "" {
		t.Error("betterleaks should be found on this Mac")
	}
	if got := c.Tier(TierPreCommit); !slices.Equal(got, []string{"betterleaks", "gitleaks"}) {
		t.Errorf("precommit tier: %v", got)
	}
	if got := c.Tier(TierPoll); !slices.Equal(got, []string{"betterleaks", "gitleaks", "trufflehog"}) { // titus stays out until the bench says it pays
		t.Errorf("poll tier: %v", got)
	}
	if p := c.Problems(); !slices.Equal(p, []string{"accounts: nothing to watch"}) {
		t.Errorf("the default config's one problem is that it watches nobody yet: %v", p)
	}
}

func TestFirstInstallTakesTheAccountsFromGH(t *testing.T) {
	w := newWorld(t)
	if res := w.install(); len(res.Warnings) != 0 {
		t.Errorf("a first install with gh logged in warns: %v", res.Warnings)
	}
	c, err := LoadConfig(w.paths, w.home)
	if err != nil {
		t.Fatal(err)
	}
	want := []inventory.Org{{Login: "Loony-Labs-Video", Via: "hangryclaude"}, {Login: "acme-apps", Via: "hangryclaude"}}
	if !slices.Equal(c.Accounts, []string{"hangryclaude", "alt-builds"}) || !slices.Equal(c.Orgs, want) {
		t.Errorf("accounts %v, orgs %v", c.Accounts, c.Orgs)
	}
	// From then on config.json is the user's: install never asks gh again.
	c.Accounts, c.Orgs = []string{"someone"}, nil
	if err := c.Save(w.paths); err != nil {
		t.Fatal(err)
	}
	w.install()
	if c, _ = LoadConfig(w.paths, w.home); !slices.Equal(c.Accounts, []string{"someone"}) || len(c.Orgs) != 0 {
		t.Errorf("a second install replaced the user's accounts: %v %v", c.Accounts, c.Orgs)
	}
}

func TestFirstInstallWithoutAGHLoginSaysWhereTheAccountsGo(t *testing.T) {
	w := newWorld(t)
	w.run.loggedOut = true
	res := w.install()
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "gh auth login") || !strings.Contains(res.Warnings[0], w.paths.Config) {
		t.Errorf("warnings: %v", res.Warnings)
	}
	if c, _ := LoadConfig(w.paths, w.home); len(c.Accounts) != 0 || len(c.Orgs) != 0 {
		t.Errorf("accounts %v, orgs %v", c.Accounts, c.Orgs)
	}
}

func TestLoadConfigOverlaysTheFileOnTheDefaults(t *testing.T) {
	w := newWorld(t)
	// No file: defaults, no error, nothing written.
	c, err := LoadConfig(w.paths, w.home)
	if err != nil || c.Jobs != 8 {
		t.Fatalf("missing file: %+v %v", c, err)
	}
	if _, err := os.Stat(w.paths.Config); err == nil {
		t.Fatal("LoadConfig created a file")
	}

	// A partial file: what it names wins, the rest stays default, tiers are replaced whole.
	body := `{"accounts":["someone"],"jobs":3,"tiers":{"precommit":["gitleaks"]},"notify":{"imessage_to":"+15555550100"},"engines":{"betterleaks":"/custom/betterleaks"}}`
	if err := os.MkdirAll(filepath.Dir(w.paths.Config), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(w.paths.Config, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err = LoadConfig(w.paths, w.home)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(c.Accounts, []string{"someone"}) || c.Jobs != 3 || c.Notify.IMessageTo != "+15555550100" {
		t.Errorf("file values lost: %+v", c)
	}
	if got := c.Tier(TierPreCommit); !slices.Equal(got, []string{"gitleaks"}) {
		t.Errorf("a tier the file shortened must stay short, got %v", got)
	}
	if got := c.Tier(TierPoll); !slices.Equal(got, DefaultTiers()[TierPoll]) {
		t.Errorf("a tier the file does not mention keeps its default, got %v", got)
	}
	if c.Engines["betterleaks"] != "/custom/betterleaks" {
		t.Errorf("the file's engine path lost: %v", c.Engines)
	}
	if c.Engines["trufflehog"] == "" {
		t.Error("an engine the file does not name should still be looked for")
	}
	// The defaults handed out afterwards are untouched by the overlay.
	if d := DefaultConfig(w.paths, w.home); len(d.Accounts) != 0 {
		t.Errorf("LoadConfig wrote through shared defaults: %v", d.Accounts)
	}
}

func TestLoadConfigBadFileFallsBackToDefaultsAndSaysSo(t *testing.T) {
	w := newWorld(t)
	secretish := "+15555550100"
	for name, body := range map[string]string{
		"syntax": `{"notify":{"imessage_to":"` + secretish + `"` + "\n",
		"type":   `{"jobs":"eight","notify":{"imessage_to":"` + secretish + `"}}`,
	} {
		if err := os.MkdirAll(filepath.Dir(w.paths.Config), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(w.paths.Config, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		c, err := LoadConfig(w.paths, w.home)
		if err == nil {
			t.Errorf("%s: a file that does not parse must be an error", name)
		}
		if c.Jobs != 8 || len(c.Tier(TierPreCommit)) == 0 {
			t.Errorf("%s: the returned config must still be usable: %+v", name, c)
		}
		if err != nil && strings.Contains(err.Error(), secretish) {
			t.Errorf("%s: the error quotes the file's content: %v", name, err)
		}
	}
}

func TestConfigSaveRoundTripAndPermissions(t *testing.T) {
	w := newWorld(t)
	c := DefaultConfig(w.paths, w.home)
	c.Jobs = 5
	c.Pins = map[string]Pin{"betterleaks": {Version: "1.9.0", SHA256: "abc"}}
	if err := c.Save(w.paths); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(w.paths.Config)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("config.json: %v %v", fi, err)
	}
	back, err := LoadConfig(w.paths, w.home)
	if err != nil || back.Jobs != 5 || back.Pins["betterleaks"].Version != "1.9.0" || back.Version != ConfigVersion {
		t.Errorf("round trip: %+v %v", back, err)
	}
}

func TestProblemsNamesWhatIsWrong(t *testing.T) {
	c := DefaultConfig(core.PathsAt(t.TempDir()), t.TempDir())
	c.Engines["betterleaks"] = "betterleaks" // a relative path would resolve against whatever repo a hook runs in
	c.Engines["nonsense"] = "/bin/true"
	c.Tiers["poll"] = []string{"betterleaks", "mystery"}
	c.Jobs = 0
	c.Rules = "rules.toml"
	got := strings.Join(c.Problems(), "\n")
	for _, want := range []string{"engines.betterleaks", "not an engine keyguard has", "tiers.poll", "jobs: 0", "rules:"} {
		if !strings.Contains(got, want) {
			t.Errorf("Problems() does not mention %q:\n%s", want, got)
		}
	}
	// The relative path is never handed to the engines.
	if _, ok := c.EnginePaths()["betterleaks"]; ok {
		t.Error("EnginePaths passed a relative path through")
	}
	// Unknown engine names in a tier are dropped from what runs.
	if got := c.Tier("poll"); !slices.Equal(got, []string{"betterleaks"}) {
		t.Errorf("Tier(poll) = %v", got)
	}
}

func TestInventoryConfigSkipsDefaultBranches(t *testing.T) {
	w := newWorld(t)
	c := DefaultConfig(w.paths, w.home)
	c.Accounts = []string{"hangryclaude", "alt-builds"}
	ic := c.InventoryConfig(w.paths)
	if !ic.NoDefaultBranch || ic.StateDir != w.paths.State || len(ic.Accounts) != 2 {
		t.Errorf("%+v", ic)
	}
}

func TestUnreachableTarget(t *testing.T) {
	for target, want := range map[string]bool{ // true: the doctor warns
		"+15555550100":          false,
		"+1 (555) 555-0100":     false,
		"+44 20 7946 0958":      false,
		"someone@example.com":   false,
		"a.b_c-d@x.co":          false,
		"5555550100":            true, // no country code
		"(555) 555-0100":        true,
		"+1555":                 true, // too few digits
		"+1234567890123456":     true, // too many for E.164
		"+1555abc5550100":       true,
		"call me":               true,
		"someone@nowhere":       true,
		"two words@example.com": true,
	} {
		if got := unreachableTarget(target) != ""; got != want {
			t.Errorf("unreachableTarget(%q) warns=%v, want %v", target, got, want)
		}
	}
}
