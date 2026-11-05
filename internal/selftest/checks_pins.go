package selftest

import (
	"fmt"
	"os"
	"strings"

	"keyguard/internal/core"
	"keyguard/internal/fp"
	"keyguard/internal/install"
)

// checkFailOpenPins is STEAL P0-01 where a person would meet it: an engine whose binary is not the
// one that was pinned does not run. The hook says so, once, and takes the next engine of its tier;
// only when every engine of the tier is refused does it fall back to the learned-secret matcher
// alone, loudly, which still stops a learned key. The machine's config is replaced for the length
// of the check and put back after.
func checkFailOpenPins(s *suite) (string, error) {
	cfgPath := core.PathsAt(s.root).Config
	orig, err := os.ReadFile(cfgPath)
	if err != nil {
		return "", fmt.Errorf("setup: reading the machine's config: %w", err)
	}
	defer os.WriteFile(cfgPath, orig, 0o600) // the next check reads this file

	paths := core.PathsAt(s.root)
	cfg, err := install.LoadConfig(paths, s.realHome)
	if err != nil {
		return "", fmt.Errorf("setup: %w", err)
	}
	wrong := func(name string) install.Pin {
		return install.Pin{Version: cfg.Pins[name].Version, SHA256: strings.Repeat("0", 64)}
	}
	save := func() error { return cfg.Save(paths) }

	c := s.scene("failopen-pins")
	r := c.seeded("r")
	warn := runOpts{tolerate: true}
	before := r.head()
	haveNext := s.regex == "betterleaks" && s.engine["gitleaks"] != ""

	// The first engine of the tier is not the binary that was pinned.
	cfg.Pins[s.regex] = wrong(s.regex)
	if err := save(); err != nil {
		return "", err
	}
	u := s.fake("ghp_", 36)
	r.write("config.py", "TOKEN = \""+u+"\"\n")
	r.stage("config.py")
	res := r.gitWith(warn, "commit", "-q", "-m", "x")
	if haveNext {
		c.blocked("a token with the first engine refused for its pin", res, commitTitle, fp.Shape(u))
		c.stays("that commit", r, before)
		r.tidy()
	} else {
		c.passed("a commit with the only engine refused for its pin", res)
		r.tidy()
	}
	if c.err == nil && !strings.Contains(res.out, s.regex+" is not the binary that was pinned") {
		c.failf("the refusal was not said: the engine was skipped and nobody was told")
	}
	if c.err == nil && strings.Count(res.out, "is not the binary that was pinned") != 1 {
		c.failf("the refusal was said %d times in one hook, want once", strings.Count(res.out, "is not the binary that was pinned"))
	}

	// Every engine of the tier is refused: the scan is lost, the hook says so, and the learned key
	// is still stopped by the matcher, which needs no engine.
	for name := range s.engine {
		cfg.Pins[name] = wrong(name)
	}
	if err := save(); err != nil {
		return "", err
	}
	r.write("fine.txt", "nothing to see\n")
	r.stage("fine.txt")
	res = r.gitWith(warn, "commit", "-q", "-m", "fine")
	c.passed("a clean commit with every engine refused", res)
	if c.err == nil && !strings.Contains(res.out, "keyguard: warning:") {
		c.failf("a hook with no engine it may run said nothing")
	}
	c.moves("that commit", r, before)

	before = r.head()
	r.write("notes.txt", "key = "+s.k+"\n")
	r.stage("notes.txt")
	c.blocked("a learned key with every engine refused", r.gitWith(warn, "commit", "-q", "-m", "x"), commitTitle, "your learned key")
	c.stays("that commit", r, before)
	r.tidy()
	if haveNext {
		return "a changed betterleaks was skipped with one line and gitleaks still refused the token; with every engine refused a clean commit passed with a warning and a learned key was still refused", c.err
	}
	return "a changed engine was refused with one line; with every engine refused a clean commit passed with a warning and a learned key was still refused", c.err
}
