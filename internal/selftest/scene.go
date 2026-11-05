package selftest

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// scene is one scenario's directory and the first thing that went wrong in it. Every method
// does nothing once something has failed, so a check reads as the steps it takes and ends in
// `return detail, c.err`.
type scene struct {
	s    *suite
	name string
	dir  string
	err  error
}

func (s *suite) scene(name string) *scene {
	s.n++
	c := &scene{s: s, name: name, dir: filepath.Join(s.work, fmt.Sprintf("%02d-%s", s.n, name))}
	if err := os.MkdirAll(c.dir, 0o755); err != nil {
		c.err = err
	}
	return c
}

func (c *scene) failf(format string, a ...any) {
	if c.err == nil {
		c.err = fmt.Errorf(format, a...)
	}
}

// repo is a working repository inside a scene.
type repo struct {
	c   *scene
	dir string
}

// repo makes an empty repository, on a branch called main, with the hooks wired.
func (c *scene) repo(sub string) *repo {
	r := &repo{c: c, dir: filepath.Join(c.dir, sub)}
	if c.err != nil {
		return r
	}
	if err := os.MkdirAll(r.dir, 0o755); err != nil {
		c.err = err
		return r
	}
	r.must(r.git("init", "-q", "-b", "main"), "git init")
	return r
}

// seeded is a repo with one clean commit, made the ordinary way (through the hooks).
func (c *scene) seeded(sub string) *repo {
	r := c.repo(sub)
	r.commitFile("init", "README.md", "a small project\n")
	return r
}

// git runs git in the repo with the hooks on, as a person would.
func (r *repo) git(args ...string) result {
	if r.c.err != nil {
		return result{}
	}
	return r.c.s.run(runOpts{dir: r.dir}, "git", args...)
}

// gitWith is git with run options: extra environment, or warnings the check expects.
func (r *repo) gitWith(o runOpts, args ...string) result {
	if r.c.err != nil {
		return result{}
	}
	o.dir = r.dir
	return r.c.s.run(o, "git", args...)
}

// gitEnv is git with extra environment: the spoofing a check tries.
func (r *repo) gitEnv(env []string, args ...string) result {
	return r.gitWith(runOpts{env: env}, args...)
}

// off is git with keyguard's three hooks switched off: a commit made on a machine keyguard
// does not guard, or by a sweep fetching a leak into a mirror.
func (r *repo) off(args ...string) result {
	if r.c.err != nil {
		return result{}
	}
	return r.c.s.run(runOpts{dir: r.dir}, "git", append(append([]string(nil), hooksOff...), args...)...)
}

// must fails the scene when a step that has to work did not.
func (r *repo) must(res result, what string) {
	r.c.must(res, what)
}

func (c *scene) must(res result, what string) {
	if c.err == nil && res.code != 0 {
		c.failf("setup: %s failed (exit %d): %s", what, res.code, c.s.line(res.out))
	}
}

func (r *repo) write(rel, body string) { r.writeMode(rel, body, 0o644) }

func (r *repo) writeMode(rel, body string, mode os.FileMode) {
	if r.c.err != nil {
		return
	}
	p := filepath.Join(r.dir, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		r.c.err = err
		return
	}
	if err := os.WriteFile(p, []byte(body), mode); err != nil {
		r.c.err = err
	}
}

// commitFile writes a file and commits it through the hooks. It is for content that is
// clean; a hook that refuses it fails the scene, which is the right answer.
func (r *repo) commitFile(msg, rel, body string) {
	r.write(rel, body)
	r.must(r.git("add", "--", rel), "git add")
	r.must(r.git("commit", "-q", "-m", msg), "a clean commit")
}

// commitOff is commitFile with the hooks off.
func (r *repo) commitOff(msg, rel, body string) {
	r.write(rel, body)
	r.must(r.off("add", "--", rel), "git add")
	r.must(r.off("commit", "-q", "-m", msg), "a commit made without the hooks")
}

// drop removes a file the check wrote into the work tree and did not stage.
func (r *repo) drop(rel string) {
	if r.c.err != nil {
		return
	}
	_ = os.Remove(filepath.Join(r.dir, rel))
}

func (r *repo) stage(paths ...string) {
	r.must(r.git(append([]string{"add", "-f", "--"}, paths...)...), "git add")
}

// head is where HEAD is, or "" before the first commit.
func (r *repo) head() string {
	if r.c.err != nil {
		return ""
	}
	res := r.c.s.run(runOpts{dir: r.dir, quiet: true}, "git", "rev-parse", "-q", "--verify", "HEAD")
	return strings.TrimSpace(res.out)
}

// rev resolves any revision, quietly.
func (r *repo) rev(spec string) string {
	if r.c.err != nil {
		return ""
	}
	res := r.c.s.run(runOpts{dir: r.dir, quiet: true}, "git", "rev-parse", "-q", "--verify", spec)
	return strings.TrimSpace(res.out)
}

// tidy puts the index and the working tree back to HEAD after a refused commit. It ignores
// what git says: in a repo with no commits yet some of it has nothing to do.
func (r *repo) tidy() {
	if r.c.err != nil {
		return
	}
	for _, args := range [][]string{{"reset", "-q"}, {"checkout", "-q", "--", "."}, {"clean", "-fdq"}} {
		r.c.s.run(runOpts{dir: r.dir, quiet: true}, "git", args...)
	}
}

// ----- what a check expects -----

// blocked says git refused, keyguard's own gate (named by title) said so, the message holds
// what the caller wants in it, and none of it is a planted secret.
func (c *scene) blocked(what string, res result, title string, wants ...string) {
	if c.err != nil {
		return
	}
	switch {
	case res.code == 0:
		c.failf("%s was not blocked", what)
	case c.s.leaks(res.out) > 0:
		c.failf("%s was refused, but its message printed a planted secret", what)
	case !strings.Contains(res.out, "keyguard: "+title):
		c.failf("%s was refused, but not by keyguard's %q gate: %s", what, title, c.s.line(res.out))
	default:
		for _, w := range wants {
			if !strings.Contains(res.out, w) {
				c.failf("%s was refused, but the message lacks %q: %s", what, w, c.s.line(res.out))
				return
			}
		}
	}
}

// passed says the command worked and printed no secret, and that no gate called it blocked.
func (c *scene) passed(what string, res result) {
	if c.err != nil {
		return
	}
	switch {
	case res.code != 0:
		c.failf("%s was refused (exit %d): %s", what, res.code, c.s.line(res.out))
	case c.s.leaks(res.out) > 0:
		c.failf("%s printed a planted secret", what)
	case strings.Contains(res.out, "blocked"):
		c.failf("%s went through but keyguard called it blocked: %s", what, c.s.line(res.out))
	}
}

// silent is passed for a command that has nothing to say: a clean commit does not talk.
func (c *scene) silent(what string, res result) {
	c.passed(what, res)
	if c.err == nil && strings.TrimSpace(res.out) != "" {
		c.failf("%s went through but printed something: %s", what, c.s.line(res.out))
	}
}

// stays says HEAD did not move: a refused commit leaves no commit behind.
func (c *scene) stays(what string, r *repo, before string) {
	if c.err == nil && r.head() != before {
		c.failf("%s moved the branch although it was refused", what)
	}
}

func (c *scene) moves(what string, r *repo, before string) {
	if c.err == nil && r.head() == before {
		c.failf("%s did not move the branch", what)
	}
}

// armed is the control that makes a "nothing was blocked" claim mean something: the same
// repo, a moment later, still refuses a learned key committed with --no-verify. Without it a
// hook that is not wired at all would pass every quiet check.
func (r *repo) armed(why string) {
	if r.c.err != nil {
		return
	}
	before := r.head()
	r.write("armed-control.txt", "key = "+r.c.s.k+"\n")
	r.stage("armed-control.txt")
	res := r.git("commit", "-q", "--no-verify", "-m", "control")
	r.c.blocked("the control commit ("+why+")", res, "ref update blocked")
	r.c.stays("the control commit", r, before)
	r.tidy()
}

// ----- history from elsewhere -----

// history is a remote whose past holds a learned key, made by someone else before keyguard
// stood guard: the origin of every "nothing to block here" check. The key sits in a commit
// from before, and the seed repo that built it can add more.
type history struct {
	c      *scene
	origin string // a bare repo
	seed   *repo  // the working repo that feeds it, with the hooks off
	n      int
}

// history makes one; a scene that needs two gives them different names.
func (c *scene) history(name string) *history {
	h := &history{c: c, origin: filepath.Join(c.dir, name+".git")}
	if c.err != nil {
		return h
	}
	c.must(c.s.run(runOpts{dir: c.dir}, "git", "init", "-q", "--bare", "-b", "main", h.origin), "git init --bare")
	h.seed = c.repo(name + "-seed")
	h.seed.must(h.seed.off("remote", "add", "origin", h.origin), "git remote add")
	h.seed.commitOff("init", "README.md", "a small project\n")
	h.seed.commitOff("add the service key", "config.txt", "export SERVICE_KEY="+c.s.k+"\n")
	h.seed.must(h.seed.off("checkout", "-q", "-b", "feature"), "git checkout")
	h.seed.commitOff("a side branch", "feature.txt", "work in progress\n")
	h.seed.must(h.seed.off("checkout", "-q", "main"), "git checkout")
	h.seed.must(h.seed.off("push", "-q", "origin", "main", "feature"), "git push")
	return h
}

// leakAgain pushes one more commit carrying the learned key to origin's main.
func (h *history) leakAgain() {
	h.n++
	h.seed.commitOff("another leak", fmt.Sprintf("more-%d.txt", h.n), "key = "+h.c.s.k+"\n")
	h.seed.must(h.seed.off("push", "-q", "origin", "main"), "git push")
}

// cleanAgain pushes one commit with nothing in it to origin's main.
func (h *history) cleanAgain() {
	h.n++
	h.seed.commitOff("housekeeping", fmt.Sprintf("notes-%d.txt", h.n), "nothing to see\n")
	h.seed.must(h.seed.off("push", "-q", "origin", "main"), "git push")
}

// clone clones origin the way a person does, hooks on, and expects it to work.
func (h *history) clone(name string) *repo {
	r := &repo{c: h.c, dir: filepath.Join(h.c.dir, name)}
	if h.c.err != nil {
		return r
	}
	res := h.c.s.run(runOpts{dir: h.c.dir}, "git", "clone", "-q", h.origin, r.dir)
	h.c.passed("cloning a repo whose history holds a learned key", res)
	return r
}

// tips lists every ref of a repo with its tip, for comparing two repos.
func (c *scene) tips(gitDir string) string {
	if c.err != nil {
		return ""
	}
	res := c.s.run(runOpts{dir: c.dir, quiet: true}, "git", "--git-dir="+gitDir, "for-each-ref", "--format=%(objectname) %(refname)")
	c.must(res, "git for-each-ref")
	return res.out
}
