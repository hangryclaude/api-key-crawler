package selftest

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"keyguard/internal/fp"
)

const commitTitle = "commit blocked"

func checkPrecommitKnown(s *suite) (string, error) {
	c := s.scene("pc-known")
	r := c.seeded("r")
	std := base64.StdEncoding.EncodeToString([]byte(s.k))
	url := base64.RawURLEncoding.EncodeToString([]byte(s.k))
	r.write("deploy.sh", "#!/bin/sh\nexport SERVICE_KEY="+s.k+"\n")
	r.write("ci.yml", "env:\n  auth: "+std+"\n")
	r.write("token.txt", url+"\n")
	r.stage("deploy.sh", "ci.yml", "token.txt")
	before := r.head()
	res := r.git("commit", "-q", "-m", "oops")
	c.blocked("a commit holding a learned key three ways", res, commitTitle,
		"your learned key", "deploy.sh", "ci.yml", "token.txt", fp.Shape(s.k))
	c.stays("that commit", r, before)
	return fmt.Sprintf("refused %s raw, in base64 and in base64url (3 files); nothing committed", fp.Shape(s.k)), c.err
}

func checkPrecommitScanner(s *suite) (string, error) {
	c := s.scene("pc-scanner")
	r := c.seeded("r")
	u := s.fake("ghp_", 36)
	r.write("config.py", "GITHUB_TOKEN = \""+u+"\"\n")
	r.stage("config.py")
	before := r.head()
	res := r.git("commit", "-q", "-m", "oops")
	c.blocked("a commit with a token the store does not know", res, commitTitle, fp.Shape(u), "config.py")
	c.stays("that commit", r, before)
	return fmt.Sprintf("refused %s in config.py, found by %s", fp.Shape(u), s.regex), c.err
}

// checkPrecommitMessage holds the block message to PLAN.md: a table, the secret as a shape
// and never more, what to do about it, and how to say it was a false alarm.
func checkPrecommitMessage(s *suite) (string, error) {
	c := s.scene("pc-message")
	r := c.seeded("r")
	u := s.fake("ghp_", 36)
	r.write("config.py", "GITHUB_TOKEN = \""+u+"\"\n")
	r.stage("config.py")
	res := r.git("commit", "-q", "-m", "oops")
	c.blocked("a commit with a token", res, commitTitle, fp.Shape(u))
	if c.err == nil {
		switch {
		case !strings.HasPrefix(strings.TrimSpace(res.out), "keyguard: "+commitTitle+": "):
			c.failf("the message does not open with what happened: %s", s.line(res.out))
		case !headerRE.MatchString(res.out):
			c.failf("the message has no FILE / LINE / TYPE / SECRET / WHY table: %s", s.line(res.out))
		case !strings.Contains(res.out, "fix: move the value to a gitignored .env"):
			c.failf("the message does not say how to fix it")
		case !strings.Contains(res.out, "do not bypass with --no-verify"):
			c.failf("the message does not warn off --no-verify")
		case firstGroup(allowRE, res.out) == "":
			c.failf("the message does not say how to allow a false positive (keyguard allow kg......)")
		}
	}
	return "count, FILE LINE TYPE SECRET WHY table, shape " + fp.Shape(u) + ", fix, --no-verify warning, allow command", c.err
}

// checkPrecommitNames is the filename rules of PLAN.md. All the key files go in one commit
// and all the look-alikes in another, so the block message has to list every one.
func checkPrecommitNames(s *suite) (string, error) {
	c := s.scene("pc-names")
	r := c.seeded("r")
	type file struct{ path, body string }
	blocked := []file{
		{".env", "MODE=development\n"},
		{".env.local", "MODE=development\n"},
		{"config/.env.production", "MODE=production\n"},
		{"id_ed25519", "placeholder\n"},
		{"keys/id_rsa", "placeholder\n"},
		{"server.pem", s.fakePEM()},
		{"release.keystore", "placeholder\n"},
		{"cert.p12", "placeholder\n"},
		{".git-credentials", "placeholder\n"},
		{".netrc", "placeholder\n"},
		{".npmrc", "//registry.npmjs.org/:_authToken=" + s.fake("npm_", 36) + "\n"},
		{".pypirc", "[pypi]\nusername = __token__\npassword = " + s.fake("pypi-", 60) + "\n"},
		{"infra/terraform.tfstate", "{}\n"},
		{"credentials.json", "{\"private_key\": \"placeholder\"}\n"},
		{"deploy-service-account.json", "{\"private_key\": \"placeholder\"}\n"},
	}
	allowed := []file{
		{".env.example", "OPENAI_API_KEY=\n"},
		{".env.sample", "OPENAI_API_KEY=\n"},
		{".env.template", "OPENAI_API_KEY=\n"},
		{"id_rsa.pub", "ssh-ed25519 placeholder selftest@example.invalid\n"},
		{"cert.pem", "a certificate goes here\n"},
		{"docs/.npmrc", "//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n"},
		{"docs/credentials.json", "{\"type\": \"placeholder\"}\n"},
	}

	var paths, wants []string
	for _, f := range blocked {
		r.write(f.path, f.body)
		paths = append(paths, f.path)
		wants = append(wants, f.path)
	}
	r.stage(paths...)
	before := r.head()
	res := r.git("commit", "-q", "-m", "keys")
	c.blocked("a commit of key files", res, commitTitle, wants...)
	c.stays("that commit", r, before)
	r.tidy()

	paths = nil
	for _, f := range allowed {
		r.write(f.path, f.body)
		paths = append(paths, f.path)
	}
	r.stage(paths...)
	res = r.git("commit", "-q", "-m", "look-alikes")
	c.silent("a commit of look-alike file names", res)
	c.moves("that commit", r, before)
	return fmt.Sprintf("blocked %d key files by name, each listed; passed %d look-alikes (templates, public key, ${VAR})", len(blocked), len(allowed)), c.err
}

// checkPrecommitClean is the other half of accuracy: ordinary code, and the things that look
// like keys without being one (a UUID, a checksum), go through and nothing is said.
func checkPrecommitClean(s *suite) (string, error) {
	c := s.scene("pc-clean")
	r := c.repo("r")
	r.write("main.go", goSource("demo", 0, 60))
	r.write("README.md", "# demo\n\nbuild id: "+randomUUID()+"\n")
	r.write("SHA256SUMS", randomChecksum()+"  demo.tar.gz\n")
	r.stage("main.go", "README.md", "SHA256SUMS")
	res := r.git("commit", "-q", "-m", "first")
	c.silent("a clean first commit", res)
	c.moves("that commit", r, "")
	return "ordinary code, a UUID and a checksum committed without a word", c.err
}

// checkPrecommitForms: git builds the index to judge differently for `commit -a` and for
// `commit <path>`, and the hook has to see the same thing git is about to commit.
func checkPrecommitForms(s *suite) (string, error) {
	c := s.scene("pc-forms")
	r := c.seeded("r")
	r.commitFile("app", "app.py", "KEY = None\n")
	before := r.head()

	r.write("app.py", "KEY = \""+s.k+"\"\n") // tracked, changed, not staged
	c.blocked("commit -a with a learned key", r.git("commit", "-q", "-a", "-m", "x"), commitTitle, "your learned key", "app.py")
	c.blocked("commit -- app.py with a learned key", r.git("commit", "-q", "-m", "x", "--", "app.py"), commitTitle, "your learned key", "app.py")
	c.stays("those commits", r, before)
	r.tidy()

	u := s.fake("ghp_", 36)
	r.write("app.py", "KEY = \""+u+"\"\n")
	c.blocked("commit -a with a token", r.git("commit", "-q", "-a", "-m", "x"), commitTitle, fp.Shape(u), "app.py")
	c.stays("that commit", r, before)
	r.tidy()
	return "refused a learned key under `commit -a` and `commit -- path`, and a token under `commit -a`", c.err
}

// checkPrecommitAllow: the two ways to say "this is not a secret", and the one thing they
// cannot say it about.
func checkPrecommitAllow(s *suite) (string, error) {
	c := s.scene("pc-allow")
	r := c.seeded("r")
	u1, u2, u3 := s.fake("ghp_", 36), s.fake("ghp_", 36), s.fake("ghp_", 36)

	r.write("a.py", "TOKEN = \""+u1+"\"\n")
	r.stage("a.py")
	res := r.git("commit", "-q", "-m", "a")
	c.blocked("a commit with a token", res, commitTitle, "keyguard allow kg")
	if id := firstGroup(allowRE, res.out); c.err == nil && id != "" {
		c.passed("keyguard allow", s.run(runOpts{dir: s.dir}, s.bin, "allow", id, "--reason", "selftest"))
	} else if c.err == nil {
		c.failf("the block message names no id to allow")
	}
	before := r.head()
	c.silent("the same commit after `keyguard allow`", r.git("commit", "-q", "-m", "a"))
	c.moves("that commit", r, before)

	// An allow is for one secret, not for the repo.
	r.write("b.py", "TOKEN = \""+u2+"\"\n")
	r.stage("b.py")
	before = r.head()
	c.blocked("a second token after the first was allowed", r.git("commit", "-q", "-m", "b"), commitTitle, fp.Shape(u2))
	c.stays("that commit", r, before)
	r.tidy()

	// A comment on the line is nobody's say-so but the committer's, and a blocked agent can write
	// it as easily as a person: it allows nothing, for what an engine found or for a learned key
	// (STEAL P0-12). Only the id the message printed does.
	r.write("docs.md", "example token: "+u3+" # betterleaks:allow\n")
	r.stage("docs.md")
	c.blocked("a token marked betterleaks:allow", r.git("commit", "-q", "-m", "docs"), commitTitle, fp.Shape(u3))
	c.stays("that commit", r, before)
	r.tidy()

	r.write("deploy.sh", "export T="+s.k+" # betterleaks:allow\n")
	r.stage("deploy.sh")
	c.blocked("a learned key marked betterleaks:allow", r.git("commit", "-q", "-m", "deploy"), commitTitle, "your learned key")
	c.stays("that commit", r, before)
	r.tidy()
	return "allow by id passes a false positive; a comment on the line allows nothing; a second token and a learned key still stop", c.err
}

// checkPrecommitHusky: the global hooks are added to a repo's own, never in place of them.
func checkPrecommitHusky(s *suite) (string, error) {
	c := s.scene("pc-husky")
	r := c.seeded("r")
	marker := filepath.Join(c.dir, "husky-ran")
	r.writeMode(".husky/pre-commit", "#!/bin/sh\necho ran >> "+shq(marker)+"\n", 0o755)
	r.must(r.git("config", "core.hooksPath", ".husky"), "git config core.hooksPath")

	r.commitFile("clean", "notes.txt", "fine\n")
	if b, err := os.ReadFile(marker); c.err == nil && (err != nil || len(nonEmpty(string(b))) != 1) {
		c.failf("the repo's own pre-commit hook did not run exactly once beside keyguard's")
	}

	r.write("deploy.sh", "export SERVICE_KEY="+s.k+"\n")
	r.stage("deploy.sh")
	before := r.head()
	c.blocked("a learned key in a repo with core.hooksPath", r.git("commit", "-q", "-m", "x"), commitTitle, "your learned key")
	c.stays("that commit", r, before)
	r.tidy()
	return "core.hooksPath=.husky: the repo's hook ran on a clean commit, and keyguard still refused a learned key", c.err
}

// checkPrecommitWorktree: a linked worktree has an index of its own and a .git that is a file,
// and a bare repo with worktrees checked out beside it has no work tree of its own at all.
// Both read the shared config, so the global hooks must run there; a hook that looked for the
// git dir the wrong way would wave everything through or refuse everything, and the bare
// layout must not be mistaken for a mirror in the cache.
func checkPrecommitWorktree(s *suite) (string, error) {
	c := s.scene("pc-worktree")
	r := c.seeded("r")
	linked := &repo{c: c, dir: filepath.Join(c.dir, "linked")}
	r.must(r.git("worktree", "add", "-q", "-b", "side", linked.dir), "git worktree add")
	linked.commitFile("clean", "notes.txt", "fine\n")

	h := c.history("origin")
	hub := filepath.Join(c.dir, "hub.git")
	c.passed("git clone --bare", s.run(runOpts{dir: c.dir}, "git", "clone", "-q", "--bare", h.origin, hub))
	beside := &repo{c: c, dir: filepath.Join(c.dir, "hub-main")}
	c.must(s.run(runOpts{dir: hub}, "git", "worktree", "add", "-q", beside.dir, "main"), "git worktree add")

	for _, w := range []struct {
		where string
		r     *repo
	}{{"a linked worktree", linked}, {"a worktree of a bare repo", beside}} {
		before := w.r.head()
		w.r.write("deploy.sh", "export SERVICE_KEY="+s.k+"\n")
		w.r.stage("deploy.sh")
		c.blocked("a learned key committed in "+w.where, w.r.git("commit", "-q", "-m", "x"), commitTitle, "your learned key", "deploy.sh")
		c.stays("that commit", w.r, before)
		w.r.tidy()

		u := s.fake("ghp_", 36)
		w.r.write("config.py", "TOKEN = \""+u+"\"\n")
		w.r.stage("config.py")
		c.blocked("a token committed in "+w.where, w.r.git("commit", "-q", "-m", "x"), commitTitle, fp.Shape(u), "config.py")
		c.stays("that commit", w.r, before)
		w.r.tidy()

		w.r.write("notes.txt", "key = "+s.k+"\n")
		w.r.stage("notes.txt")
		c.blocked("a --no-verify commit of a learned key in "+w.where, w.r.git("commit", "-q", "--no-verify", "-m", "x"), refTitle, "your learned key")
		c.stays("that commit", w.r, before)
		w.r.tidy()

		w.r.write("fine.txt", "nothing to see\n")
		w.r.stage("fine.txt")
		c.silent("a clean commit in "+w.where, w.r.git("commit", "-q", "-m", "fine"))
		c.moves("that commit", w.r, before)
	}
	return "in a linked worktree and in a worktree of a bare repo: a learned key and a token refused at commit, a --no-verify key refused at the ref update, a clean commit passed", c.err
}
