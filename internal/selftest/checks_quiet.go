package selftest

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"keyguard/internal/fp"
)

// The checks in this file are the other half of the gates: a key that reached this Mac's
// history by being fetched, cloned or pulled was not authored here, and blocking it would
// break git everywhere without stopping a single leak. Each one ends with armed(), because a
// hook that is not wired at all would pass every one of them.

func checkQuietClone(s *suite) (string, error) {
	c := s.scene("quiet-clone")
	h := c.history("origin")
	clone := h.clone("clone")
	if c.err == nil && strings.TrimSpace(clone.git("rev-list", "--count", "HEAD").out) != "2" {
		c.failf("the clone does not hold the history with the key in it")
	}
	c.passed("a bare clone", s.run(runOpts{dir: c.dir}, "git", "clone", "-q", "--bare", h.origin, filepath.Join(c.dir, "plain.git")))
	clone.armed("after cloning")
	return "git clone and git clone --bare of a repo whose history holds " + fp.Shape(s.k) + " were not blocked", c.err
}

func checkQuietFetch(s *suite) (string, error) {
	c := s.scene("quiet-fetch")
	h := c.history("origin")
	clone := h.clone("clone")

	h.leakAgain()
	c.silent("git fetch", clone.git("fetch", "-q", "origin"))

	// The ref gate looks at branches and tags. A fetch moves a tag to a commit no branch has,
	// and that commit carries the key: the gate has to see that it arrived by fetch.
	h.seed.must(h.seed.off("checkout", "-q", "--detach"), "git checkout --detach")
	h.seed.commitOff("a commit no branch has", "lone.txt", "key = "+s.k+"\n")
	h.seed.must(h.seed.off("tag", "lone"), "git tag")
	h.seed.must(h.seed.off("push", "-q", "origin", "lone"), "git push lone")
	c.passed("git fetch --tags with a tag on a commit no branch has", clone.git("fetch", "-q", "--tags", "origin"))
	if c.err == nil && clone.rev("refs/tags/lone") == "" {
		c.failf("the tag did not arrive")
	}

	h.seed.must(h.seed.off("checkout", "-q", "main"), "git checkout main")
	h.leakAgain()
	c.passed("git fetch into a local branch", clone.git("fetch", "-q", "origin", "main:fetched"))
	if c.err == nil && clone.rev("refs/heads/fetched") == "" {
		c.failf("the branch did not arrive")
	}
	clone.armed("after fetching")
	return "fetch, fetch --tags (tag on a commit no branch has), fetch into a branch: key arrived, nothing blocked", c.err
}

func checkQuietPull(s *suite) (string, error) {
	c := s.scene("quiet-pull")
	h := c.history("origin")
	clone := h.clone("clone")

	h.leakAgain()
	c.passed("git pull --ff-only", clone.git("pull", "-q", "--ff-only"))
	if c.err == nil && clone.rev("HEAD") != clone.rev("origin/main") {
		c.failf("the fast-forward pull did not reach origin's main")
	}

	clone.commitFile("local work", "local.txt", "mine\n")
	h.leakAgain()
	c.passed("git pull --rebase", clone.git("pull", "-q", "--rebase"))

	clone.commitFile("more local work", "local2.txt", "mine too\n")
	h.leakAgain()
	c.passed("git pull (a merge)", clone.git("pull", "-q", "--no-rebase", "--no-edit"))
	if c.err == nil && !strings.Contains(clone.git("rev-list", "--merges", "-n", "1", "HEAD").out, strings.TrimSpace(clone.rev("HEAD"))) {
		c.failf("the third pull was meant to make a merge commit and did not")
	}
	clone.armed("after pulling")
	return "pull --ff-only, --rebase and a merge pull, each bringing the key in: nothing blocked", c.err
}

func checkQuietRebase(s *suite) (string, error) {
	c := s.scene("quiet-rebase")
	h := c.history("origin")
	clone := h.clone("clone")
	clone.must(clone.git("checkout", "-q", "-b", "topic"), "git checkout -b topic")
	clone.commitFile("topic work", "topic.txt", "clean\n")
	h.leakAgain()
	clone.must(clone.git("fetch", "-q", "origin"), "git fetch")
	c.passed("git rebase onto leaked history", clone.git("rebase", "-q", "origin/main"))
	if c.err == nil && clone.git("merge-base", "--is-ancestor", "origin/main", "topic").code != 0 {
		c.failf("the rebase did not move the branch onto origin's main")
	}
	clone.armed("after rebasing")
	return "a clean branch rebased onto history that holds " + fp.Shape(s.k) + " was not blocked", c.err
}

func checkQuietStash(s *suite) (string, error) {
	c := s.scene("quiet-stash")
	h := c.history("origin")
	clone := h.clone("clone")
	// refs/stash is not a branch or a tag: a work tree with the key in it can be put aside.
	clone.write("config.txt", "export SERVICE_KEY="+s.k+"\nexport EXTRA="+s.k+"\n")
	c.passed("git stash", clone.git("stash", "push", "-q"))
	c.passed("git stash pop", clone.git("stash", "pop", "-q"))
	clone.write("scratch.txt", "key = "+s.k+"\n")
	c.passed("git stash -u", clone.git("stash", "push", "-q", "-u"))
	c.passed("git stash pop", clone.git("stash", "pop", "-q"))
	clone.tidy()
	clone.armed("after stashing")
	return "stash and pop, tracked and untracked, with the key in the work tree were not blocked", c.err
}

func checkQuietBranch(s *suite) (string, error) {
	c := s.scene("quiet-branch")
	h := c.history("origin")
	clone := h.clone("clone")
	c.passed("git branch at leaked history", clone.git("branch", "topic", "origin/main"))
	c.passed("pushing that branch", clone.git("push", "-q", "origin", "topic"))
	c.passed("deleting it on the remote", clone.git("push", "-q", "origin", ":topic"))
	c.passed("git branch -D", clone.git("branch", "-D", "topic"))
	c.passed("git tag at leaked history", clone.git("tag", "v1", "origin/main"))
	c.passed("git tag -d", clone.git("tag", "-d", "v1"))
	clone.armed("after branches and tags")
	return "making, pushing and deleting a branch and a tag at leaked history were not blocked", c.err
}

func checkQuietRemove(s *suite) (string, error) {
	c := s.scene("quiet-remove")
	h := c.history("origin")
	clone := h.clone("clone")
	// Taking the key out is the fix. A gate that read removed lines as new ones would punish it.
	clone.write("config.txt", "# the key now comes from the environment\n")
	c.silent("a commit that removes the key", clone.git("commit", "-q", "-a", "-m", "move the key to the environment"))
	c.silent("pushing it", clone.git("push", "-q", "origin", "main"))

	h2 := c.history("origin2")
	rv := h2.clone("reverted")
	c.passed("git revert of the commit that added the key", rv.git("revert", "--no-edit", "HEAD"))
	rv.armed("after reverting")
	return "a commit that removes the key, its push, and a revert of the commit that added it were not blocked", c.err
}

// checkMirror is invariant 6 from the gate's side. The sweep switches the hooks off when it
// fetches; the cache has to be safe even when someone runs plain git in it, or the day a
// fetch brings in a leaked key the mirror would refuse it and the sweep would never see it.
func checkMirror(s *suite) (string, error) {
	c := s.scene("mirror")
	h := c.history("origin")
	mirror := filepath.Join(s.root, "cache", "mirrors", "github.com", "selftest", "leaky.git")
	if err := os.MkdirAll(filepath.Dir(mirror), 0o700); err != nil {
		return "", err
	}
	c.passed("git clone --mirror into the cache", s.run(runOpts{dir: c.dir}, "git", "clone", "-q", "--mirror", h.origin, mirror))
	h.leakAgain()
	c.passed("git fetch into the mirror", s.run(runOpts{dir: c.dir}, "git", "--git-dir="+mirror, "fetch", "-q", "--prune", "origin"))
	if c.err == nil && c.tips(mirror) != c.tips(h.origin) {
		c.failf("the mirror does not hold what origin holds: the leak never arrived")
	}
	// Not a free pass for everything: a working clone beside it is still guarded.
	h.clone("clone").armed("beside the mirror")
	return "clone --mirror and fetch into the cache took in " + fp.Shape(s.k) + " unblocked; same refs as origin", c.err
}

// ----- data roots -----

// keepRoot makes a throwaway data root outside the machine's own, for $KEYGUARD_HOME to point at.
func (s *suite) keepRoot(c *scene, name string) string {
	dir := filepath.Join(c.dir, name)
	s.roots = append(s.roots, dir)
	return dir
}

// checkRootsAdd: $KEYGUARD_HOME names a second store, and the hooks read it as well as the
// real one. The environment can add protection.
func checkRootsAdd(s *suite) (string, error) {
	c := s.scene("roots-add")
	extra := s.keepRoot(c, "extra-root")
	k2 := s.fake("xai-", 60)
	if _, err := s.learn(extra, filepath.Join(c.dir, "extra-learn"), [][2]string{{"EXTRA_API_KEY", k2}}); err != nil {
		return "", fmt.Errorf("setup: learning into the second store: %w", err)
	}
	r := c.seeded("r")
	before := r.head()
	r.write("notes.txt", "key = "+k2+"\n")
	r.stage("notes.txt")
	res := r.gitEnv([]string{"KEYGUARD_HOME=" + extra}, "commit", "-q", "--no-verify", "-m", "x")
	c.blocked("a --no-verify commit of a key learned only in $KEYGUARD_HOME", res, refTitle, "your learned key", fp.Shape(k2))
	c.stays("that commit", r, before)
	// With the variable gone nothing knows that key, so the same commit goes through: the
	// block above was the second store's doing and nothing else's.
	c.silent("the same commit without the second store", r.git("commit", "-q", "--no-verify", "-m", "x"))
	c.moves("that commit", r, before)
	return "a key learned only in $KEYGUARD_HOME was refused with it set and passed without it", c.err
}

// checkRootsKeep: and the environment cannot take protection away. Whatever $KEYGUARD_HOME
// says, the real store is still read.
func checkRootsKeep(s *suite) (string, error) {
	c := s.scene("roots-keep")
	r := c.seeded("r")
	before := r.head()
	empty := s.keepRoot(c, "empty-root")
	if err := os.MkdirAll(empty, 0o700); err != nil {
		return "", err
	}
	for _, v := range []struct{ what, env string }{
		{"$KEYGUARD_HOME at an empty directory", empty},
		{"$KEYGUARD_HOME at a path that is not there", filepath.Join(c.dir, "not-there")},
		{"$KEYGUARD_HOME empty", ""},
	} {
		r.write("notes.txt", "key = "+s.k+"\n")
		r.stage("notes.txt")
		res := r.gitEnv([]string{"KEYGUARD_HOME=" + v.env}, "commit", "-q", "--no-verify", "-m", "x")
		c.blocked("a learned key with "+v.what, res, refTitle, "your learned key")
		c.stays("that commit", r, before)
		r.tidy()
	}
	return "a learned key was refused with $KEYGUARD_HOME at an empty directory, at nothing, and unset", c.err
}

// checkRootsBroken: a second store that does not parse must neither switch the first off
// (that would let the environment remove protection) nor stop git (that would break it
// everywhere). It says so, keeps matching with what loaded, and still blocks the scanner's finds.
func checkRootsBroken(s *suite) (string, error) {
	c := s.scene("roots-broken")
	broken := s.keepRoot(c, "broken-root")
	if err := os.MkdirAll(filepath.Join(broken, "state", "known"), 0o700); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(broken, "state", "known", "known.json"), []byte("{this is not json"), 0o600); err != nil {
		return "", err
	}
	env := runOpts{env: []string{"KEYGUARD_HOME=" + broken}, tolerate: true}
	r := c.seeded("r")
	before := r.head()

	r.write("notes.txt", "key = "+s.k+"\n")
	r.stage("notes.txt")
	res := r.gitWith(env, "commit", "-q", "--no-verify", "-m", "x")
	c.blocked("a learned key with a broken second store", res, refTitle, "your learned key")
	if c.err == nil && !strings.Contains(res.out, "learned-secret store") {
		c.failf("the broken store was not mentioned: it may not have been read at all")
	}
	c.stays("that commit", r, before)
	r.tidy()

	u := s.fake("ghp_", 36)
	r.write("config.py", "TOKEN = \""+u+"\"\n")
	r.stage("config.py")
	c.blocked("a token with a broken second store", r.gitWith(env, "commit", "-q", "-m", "x"), commitTitle, fp.Shape(u))
	c.stays("that commit", r, before)
	r.tidy()

	r.write("fine.txt", "nothing to see\n")
	r.stage("fine.txt")
	c.passed("a clean commit with a broken second store", r.gitWith(env, "commit", "-q", "-m", "fine"))
	c.moves("that commit", r, before)
	return "broken second store: key and token still refused, clean commit allowed, store named in a warning", c.err
}
