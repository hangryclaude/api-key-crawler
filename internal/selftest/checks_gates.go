package selftest

import (
	"fmt"
	"path/filepath"
	"strings"

	"keyguard/internal/fp"
)

const (
	refTitle  = "ref update blocked"
	pushTitle = "push blocked"
)

// checkRefNoVerify is the gate `git commit --no-verify` cannot skip: it is a hook on the ref
// update, which git runs whatever the committer says.
func checkRefNoVerify(s *suite) (string, error) {
	c := s.scene("ref-noverify")
	r := c.seeded("r")
	before := r.head()
	r.write("notes.txt", "key = "+s.k+"\n")
	r.stage("notes.txt")
	res := r.git("commit", "-q", "--no-verify", "-m", "sneaky")
	c.blocked("a --no-verify commit of a learned key", res, refTitle, "your learned key", fp.Shape(s.k))
	c.stays("the --no-verify commit", r, before)
	if c.err == nil && !strings.Contains(r.git("diff", "--cached", "--name-only").out, "notes.txt") {
		c.failf("the refused commit took the staged file away; the work should be where it was")
	}
	r.tidy()

	// A gate that refuses everything proves nothing.
	r.write("fine.txt", "nothing to see\n")
	r.stage("fine.txt")
	c.silent("a clean --no-verify commit", r.git("commit", "-q", "--no-verify", "-m", "fine"))
	c.moves("that commit", r, before)
	return "--no-verify commit of " + fp.Shape(s.k) + " aborted at the ref update, branch unmoved; a clean one went through", c.err
}

// checkRefWays tries the ways round the ref gate that are within reach of a person or an
// agent at a terminal. The one that is not here, -c hook.keyguard-reftx.enabled=false, is the
// agent guard's to refuse; push-known shows the push gate catches what it lets through.
func checkRefWays(s *suite) (string, error) {
	c := s.scene("ref-ways")
	r := c.seeded("r")
	base := r.head()
	r.write("notes.txt", "key = "+s.k+"\n")
	r.stage("notes.txt")
	tried := 0
	try := func(way string, res result) {
		tried++
		c.blocked(way, res, refTitle, "your learned key")
		c.stays(way, r, base)
	}

	try("a core.hooksPath override", r.git("-c", "core.hooksPath=/dev/null", "commit", "-q", "--no-verify", "-m", "x"))
	// The environment is the caller's to set, so the gate must not take its word for anything.
	try("GIT_REFLOG_ACTION=fetch", r.gitEnv([]string{"GIT_REFLOG_ACTION=fetch"}, "commit", "-q", "--no-verify", "-m", "x"))
	try("an amended commit", r.git("commit", "-q", "--amend", "--no-verify", "-C", "HEAD"))

	// Plumbing never runs a commit hook; only the ref transaction is left to stop it.
	tree := strings.TrimSpace(r.git("write-tree").out)
	commit := strings.TrimSpace(r.git("commit-tree", tree, "-p", "HEAD", "-m", "x").out)
	if c.err == nil && (tree == "" || commit == "") {
		c.failf("setup: could not build a commit with plumbing")
	}
	try("commit-tree and update-ref", r.git("update-ref", "refs/heads/main", commit))
	try("a new branch at that commit", r.git("branch", "other", commit))
	try("a tag at that commit", r.git("tag", "v1", commit))
	for _, ref := range []string{"refs/heads/other", "refs/tags/v1"} {
		if c.err == nil && r.rev(ref) != "" {
			c.failf("%s exists although the update was refused", ref)
		}
	}
	r.tidy()

	// A commit made where keyguard is not (hooks off), brought here by cherry-pick. Main moves
	// on first: a pick onto the commit's own parent would rebuild the very same commit, which
	// is already on a ref, and the ref gate leaves commits already on a ref to the push gate.
	r.must(r.off("checkout", "-q", "-b", "donor"), "git checkout -b donor")
	r.commitOff("carry the key", "carried.txt", "key = "+s.k+"\n")
	r.must(r.off("checkout", "-q", "main"), "git checkout main")
	r.commitFile("move on", "m2.txt", "clean\n")
	base = r.head()
	try("a cherry-pick of it", r.git("cherry-pick", "donor"))
	r.off("cherry-pick", "--abort")
	r.tidy()
	return fmt.Sprintf("%d ways round it, all refused: hooksPath, GIT_REFLOG_ACTION, amend, update-ref, branch, tag, cherry-pick", tried), c.err
}

// pushWorld is a clean repo whose first commit is already on a bare remote at a local path,
// which counts as private: the push gate runs without the verifying pass and without a network.
func (c *scene) pushWorld() (r *repo, remote string) {
	remote = filepath.Join(c.dir, "remote.git")
	c.must(c.s.run(runOpts{dir: c.dir}, "git", "init", "-q", "--bare", "-b", "main", remote), "git init --bare")
	r = c.seeded("r")
	r.must(r.git("remote", "add", "origin", remote), "git remote add")
	c.silent("the first push", r.git("push", "-q", "-u", "origin", "main"))
	return r, remote
}

// remoteRef is where a ref of the remote stands, "" if it is not there.
func (c *scene) remoteRef(remote, ref string) string {
	if c.err != nil {
		return ""
	}
	res := c.s.run(runOpts{dir: c.dir, quiet: true}, "git", "--git-dir="+remote, "rev-parse", "-q", "--verify", ref)
	return strings.TrimSpace(res.out)
}

func checkPushClean(s *suite) (string, error) {
	c := s.scene("push-clean")
	r, remote := c.pushWorld()
	r.commitFile("second", "b.txt", "more\n")
	c.silent("a clean push", r.git("push", "-q", "origin", "main"))
	if c.err == nil && c.remoteRef(remote, "main") != r.head() {
		c.failf("the clean push did not arrive")
	}
	r.must(r.git("tag", "v1"), "git tag")
	c.silent("a tag push", r.git("push", "-q", "origin", "v1"))
	r.must(r.git("branch", "topic"), "git branch")
	c.silent("a branch push with nothing new", r.git("push", "-q", "origin", "topic"))
	c.silent("a branch delete", r.git("push", "-q", "origin", ":topic"))
	if c.err == nil && c.remoteRef(remote, "refs/heads/topic") != "" {
		c.failf("the branch delete did not arrive")
	}
	return "a clean push, a tag, a branch with nothing new and a branch delete all arrived", c.err
}

func checkPushUnknown(s *suite) (string, error) {
	c := s.scene("push-unknown")
	r, remote := c.pushWorld()
	u := s.fake("ghp_", 36)
	r.write("settings.py", "API_TOKEN = \""+u+"\"\n")
	r.stage("settings.py")
	// Nothing has learned this token, so only the scanner can know it, and --no-verify has
	// already skipped the scanner at commit time. The ref gate lets it by; the push gate is
	// the one left.
	r.must(r.git("commit", "-q", "--no-verify", "-m", "sneaky"), "a --no-verify commit of a token nobody has learned")
	tip := c.remoteRef(remote, "main")
	res := r.git("push", "origin", "main")
	c.blocked("a push of a token", res, pushTitle, fp.Shape(u), "settings.py")
	if c.err == nil && c.remoteRef(remote, "main") != tip {
		c.failf("the push was refused but the remote moved")
	}
	return "refused " + fp.Shape(u) + " pushed to a local bare remote; the remote stayed where it was", c.err
}

// checkPushRewrites: pre-commit does not run on a cherry-pick or a rebase, so a token that
// travels that way meets the push gate and nothing else.
func checkPushRewrites(s *suite) (string, error) {
	c := s.scene("push-rewrites")
	r, remote := c.pushWorld()
	u := s.fake("ghp_", 36)
	r.must(r.git("checkout", "-q", "-b", "donor"), "git checkout -b donor")
	r.write("t.py", "TOKEN = \""+u+"\"\n")
	r.stage("t.py")
	r.must(r.git("commit", "-q", "--no-verify", "-m", "carry"), "a --no-verify commit of a token")
	r.must(r.git("checkout", "-q", "main"), "git checkout main")
	r.commitFile("move on", "m2.txt", "clean\n")
	c.silent("a clean push of main", r.git("push", "-q", "origin", "main"))

	r.must(r.git("checkout", "-q", "-b", "pick"), "git checkout -b pick")
	r.must(r.git("cherry-pick", "donor"), "a cherry-pick of the token")
	c.blocked("a push after a cherry-pick", r.git("push", "origin", "pick"), pushTitle, fp.Shape(u))
	if c.err == nil && c.remoteRef(remote, "refs/heads/pick") != "" {
		c.failf("the cherry-picked branch arrived although the push was refused")
	}

	r.must(r.git("checkout", "-q", "donor"), "git checkout donor")
	r.must(r.git("rebase", "-q", "main"), "a rebase of the token")
	c.blocked("a push after a rebase", r.git("push", "origin", "donor"), pushTitle, fp.Shape(u))
	if c.err == nil && c.remoteRef(remote, "refs/heads/donor") != "" {
		c.failf("the rebased branch arrived although the push was refused")
	}
	return "refused " + fp.Shape(u) + " after a cherry-pick and after a rebase, where no commit hook ran", c.err
}

// checkPushKnown: a learned key committed where no gate stood (another machine, a fresh
// clone, a commit with the hooks switched off) is still caught on its way out.
func checkPushKnown(s *suite) (string, error) {
	c := s.scene("push-known")
	r, remote := c.pushWorld()
	r.commitOff("from somewhere else", "keys.txt", "key = "+s.k+"\n")
	tip := c.remoteRef(remote, "main")
	res := r.git("push", "origin", "main")
	c.blocked("a push of a learned key", res, pushTitle, "your learned key", fp.Shape(s.k))
	if c.err == nil && c.remoteRef(remote, "main") != tip {
		c.failf("the push was refused but the remote moved")
	}
	return "refused " + fp.Shape(s.k) + " committed with every hook off; the remote stayed where it was", c.err
}
