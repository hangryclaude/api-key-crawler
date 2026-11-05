package selftest

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"keyguard/internal/core"
	"keyguard/internal/fp"
)

// checkFailOpen is invariant 5 end to end: a hook that cannot do part of its job says so and
// does the rest. A keyguard bug must never break git on this Mac, and a finding must still
// block. The machine's config is replaced for the length of the check and put back after.
func checkFailOpen(s *suite) (string, error) {
	cfg := core.PathsAt(s.root).Config
	orig, err := os.ReadFile(cfg)
	if err != nil {
		return "", fmt.Errorf("setup: reading the machine's config: %w", err)
	}
	defer os.WriteFile(cfg, orig, 0o600) // the next check reads this file

	c := s.scene("failopen")
	r := c.seeded("r")
	warn := runOpts{tolerate: true}
	before := r.head()

	// A config that does not parse falls back to the defaults, which find the engines on the
	// PATH and in the usual places: nothing is lost but the file.
	if err := os.WriteFile(cfg, []byte("{this is not json"), 0o600); err != nil {
		return "", err
	}
	u := s.fake("ghp_", 36)
	r.write("config.py", "TOKEN = \""+u+"\"\n")
	r.stage("config.py")
	res := r.gitWith(warn, "commit", "-q", "-m", "x")
	c.blocked("a token with an unreadable config.json", res, commitTitle, fp.Shape(u))
	if c.err == nil && !strings.Contains(res.out, "using the defaults") {
		c.failf("the unreadable config.json was not mentioned: it may not have been read at all")
	}
	c.stays("that commit", r, before)
	r.tidy()

	// An engine that will not start costs the scan, not the commit. The learned-secret
	// matcher needs no engine, so the keys that matter most are still stopped, at the ref.
	missing := filepath.Join(c.dir, "no-such-engine")
	if err := os.WriteFile(cfg, []byte(fmt.Sprintf(`{"engines": {"betterleaks": %q, "gitleaks": %q}}`, missing, missing)), 0o600); err != nil {
		return "", err
	}
	r.write("fine.txt", "nothing to see\n")
	r.stage("fine.txt")
	res = r.gitWith(warn, "commit", "-q", "-m", "fine")
	c.passed("a clean commit with no engine to read it", res)
	if c.err == nil && !strings.Contains(res.out, "regex engine") {
		c.failf("the missing engine was not mentioned: staged files went unread and nobody was told")
	}
	c.moves("that commit", r, before)

	before = r.head()
	r.write("notes.txt", "key = "+s.k+"\n")
	r.stage("notes.txt")
	c.blocked("a learned key with no engine", r.gitWith(warn, "commit", "-q", "-m", "x"), commitTitle, "your learned key")
	c.stays("that commit", r, before)
	r.tidy()
	return "bad config.json: defaults, token still refused; no engine: clean commit passes with a warning, key still refused", c.err
}
