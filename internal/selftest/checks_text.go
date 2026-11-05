package selftest

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"

	"keyguard/internal/fp"
)

// Keys in the text git keeps (STEAL P0-13): a commit message, a tag annotation, a branch or tag
// name. No engine reads any of them, so a key typed there goes straight to GitHub unless the
// learned-secret matcher catches it, at the commit-msg hook when the committer lets it run and at
// the reference transaction and the push when they do not.

const commitMsgTitle = "commit message blocked"

func checkTextMessage(s *suite) (string, error) {
	c := s.scene("text-message")
	r := c.seeded("r")
	before := r.head()

	r.write("notes.txt", "nothing secret here\n")
	r.stage("notes.txt")
	res := r.git("commit", "-q", "-m", "wire up the service, key "+s.k)
	c.blocked("a commit message holding a learned key", res, commitMsgTitle, "(commit message)", fp.Shape(s.k))
	c.stays("that commit", r, before)

	// The second paragraph is part of the message, and the table says which line it is on.
	res = r.git("commit", "-q", "-m", "wire up the service", "-m", "the key is "+s.k)
	c.blocked("a second paragraph holding a learned key", res, commitMsgTitle, "(commit message)")
	c.stays("that commit", r, before)

	// --no-verify skips commit-msg, as it skips pre-commit; the reference transaction has no
	// such switch and reads the message of every commit a ref is about to take.
	res = r.git("commit", "-q", "--no-verify", "-m", "subject\n\nthe key is "+s.k)
	c.blocked("a --no-verify commit whose message holds a learned key", res, refTitle, "(commit message)")
	c.stays("that commit", r, before)
	r.tidy()

	// The author line is text git keeps too.
	r.write("notes.txt", "nothing secret here\n")
	r.stage("notes.txt")
	res = r.git("-c", "user.name="+s.k, "commit", "-q", "--no-verify", "-m", "a clean message")
	c.blocked("a commit whose author name is a learned key", res, refTitle, "(author name)")
	c.stays("that commit", r, before)
	r.tidy()

	// And a message with no secret in it goes through without a word.
	r.write("fine.txt", "nothing to see\n")
	r.stage("fine.txt")
	c.silent("a clean message", r.git("commit", "-q", "-m", "a message with no secret in it"))
	c.moves("that commit", r, before)
	return "a learned key in a message, in a second paragraph and in the author name was refused at commit-msg or, past --no-verify, at the ref update; a clean message passed", c.err
}

func checkTextTag(s *suite) (string, error) {
	c := s.scene("text-tag")
	r := c.seeded("r")
	res := r.git("tag", "-a", "v1", "-m", "release notes, key "+s.k)
	c.blocked("an annotated tag whose message holds a learned key", res, refTitle, "(tag annotation)", fp.Shape(s.k))
	if c.err == nil && r.rev("refs/tags/v1") != "" {
		c.failf("the tag exists although the update was refused")
	}
	c.silent("an annotated tag with a clean message", r.git("tag", "-a", "v2", "-m", "release notes"))
	if c.err == nil && r.rev("refs/tags/v2") == "" {
		c.failf("the clean annotated tag was not made")
	}
	return "an annotated tag whose message holds " + fp.Shape(s.k) + " was refused and not created; a clean one was made", c.err
}

// A key used as a branch or tag name is a ref name, which no content scan reads. The name is the
// key, so the message must say where it is and never repeat it.
func checkTextRefName(s *suite) (string, error) {
	c := s.scene("text-refname")
	r := c.seeded("r")
	before := r.head()
	for _, way := range []struct {
		what string
		args []string
		ref  string
	}{
		{"a branch named after a learned key", []string{"branch", s.k}, "refs/heads/" + s.k},
		{"a checkout -b named after a learned key", []string{"checkout", "-q", "-b", s.k}, "refs/heads/" + s.k},
		{"a tag named after a learned key", []string{"tag", s.k}, "refs/tags/" + s.k},
	} {
		res := r.git(way.args...)
		c.blocked(way.what, res, refTitle, "(ref name)")
		if c.err == nil && r.rev(way.ref) != "" {
			c.failf("%s exists although the update was refused", way.what)
		}
		c.stays(way.what, r, before)
	}
	c.silent("a branch with an ordinary name", r.git("branch", "feature/login"))
	return "a branch, a checkout -b and a tag named after " + fp.Shape(s.k) + " were refused and not created, and the name was never printed; an ordinary branch was made", c.err
}

// Past the commit and the ref update (another machine, a fresh clone, every hook off) the push is
// the last gate, and it reads the same text.
func checkTextPush(s *suite) (string, error) {
	c := s.scene("text-push")
	r, remote := c.pushWorld()
	r.commitOff("the key is "+s.k, "docs.txt", "plain\n")
	tip := c.remoteRef(remote, "main")
	c.blocked("a push of a commit whose message holds a learned key", r.git("push", "origin", "main"), pushTitle, "(commit message)", fp.Shape(s.k))
	if c.err == nil && c.remoteRef(remote, "main") != tip {
		c.failf("the push was refused but the remote moved")
	}
	r.must(r.off("reset", "-q", "--hard", "HEAD~1"), "git reset")

	// A tag on a commit the remote does not have yet. (A tag on a commit it already holds adds no
	// commit to scan, and pre-push stops there without reading the annotation; the reference
	// transaction, which reads it when the tag is made, is what catches that one.)
	r.commitOff("housekeeping", "notes.txt", "nothing to see\n")
	r.must(r.off("tag", "-a", "v9", "-m", "notes, key "+s.k), "git tag")
	c.blocked("a push of a tag whose annotation holds a learned key", r.git("push", "origin", "v9"), pushTitle, "(tag annotation)")
	if c.err == nil && c.remoteRef(remote, "refs/tags/v9") != "" {
		c.failf("the tag arrived although the push was refused")
	}
	return "a push of a commit message and of a tag annotation holding " + fp.Shape(s.k) + " was refused; the remote stayed where it was", c.err
}

// ----- repo files cannot blind the pre-commit scan -----

// engineFingerprint asks the regex engine what it calls the one finding in dir's index, straight
// from the binary, so that an ignore file can be written for exactly that finding.
func (s *suite) engineFingerprint(dir string) (string, error) {
	cmd := exec.CommandContext(s.ctx, s.engine[s.regex], "git", "--pre-commit", "--staged", "--no-banner", "--no-color",
		"-l", "error", "-f", "json", "-r", "-", "--exit-code", "0", dir)
	cmd.Dir, cmd.Env = dir, s.env
	out, err := cmd.Output() // the report goes to this pipe only; it is decoded for one field and dropped
	if err != nil {
		return "", fmt.Errorf("%s did not run for the control: %w", s.regex, err)
	}
	var found []struct{ Fingerprint string }
	if err := json.Unmarshal(out, &found); err != nil || len(found) != 1 || found[0].Fingerprint == "" {
		return "", fmt.Errorf("%s found %d things to ignore in the control, want 1", s.regex, len(found))
	}
	return found[0].Fingerprint, nil
}

// markers are the comments an engine reads as "this line is allowed". A blocked agent can write
// any of them, so none may silence anything.
var markers = []string{"betterleaks:allow", "gitleaks:allow", "trufflehog:ignore", "pragma: allowlist secret"}

// checkPrecommitBlind is STEAL P0-05 and P0-12 where a person would see them. Every one of these
// hid a staged token from the real engine when it was run the plain way (reproduced on betterleaks
// 1.9.0 and gitleaks 8.30.1): an ignore file holding the finding's fingerprint, an allowlist
// config, a .gitattributes that makes git print "Binary files differ", the engine's own allow
// comment. Files that sit in the working tree, untracked, are enough, so that is where they are
// put; each attack is tried against the same token the control commit was refused for.
func checkPrecommitBlind(s *suite) (string, error) {
	c := s.scene("pc-blind")
	r := c.seeded("r")
	token := s.fake("ghp_", 36)
	before := r.head()

	// The control: no attack, refused, and the engine's fingerprint of what it refused.
	r.write("b.env", "GITHUB_TOKEN="+token+"\n")
	r.stage("b.env")
	c.blocked("the control commit", r.git("commit", "-q", "-m", "control"), commitTitle, fp.Shape(token))
	c.stays("the control commit", r, before)
	fpr := ""
	if c.err == nil {
		var err error
		if fpr, err = s.engineFingerprint(r.dir); err != nil {
			c.failf("%s", s.line(err.Error()))
		}
	}

	attacks := []struct {
		what  string
		files map[string]string
	}{
		{"an ignore file holding its fingerprint", map[string]string{".betterleaksignore": fpr + "\n", ".gitleaksignore": fpr + "\n"}},
		{"an allowlist config", map[string]string{
			".betterleaks.toml": "[extend]\nuseDefault = true\n[allowlist]\nregexes = [\".*\"]\n",
			".gitleaks.toml":    "[extend]\nuseDefault = true\n[allowlist]\nregexes = [\".*\"]\n"}},
		{"a .gitattributes marking the file -diff", map[string]string{".gitattributes": "*.env -diff\n"}},
		{"a .gitattributes marking the file binary", map[string]string{".gitattributes": "*.env binary\n"}},
		{"all of them at once", map[string]string{
			".betterleaksignore": fpr + "\n", ".gitleaksignore": fpr + "\n", ".gitattributes": "*.env -diff\n",
			".betterleaks.toml": "[extend]\nuseDefault = true\n[allowlist]\nregexes = [\".*\"]\n"}},
	}
	for _, a := range attacks {
		for p, body := range a.files {
			r.write(p, body)
		}
		c.blocked("a token beside "+a.what, r.git("commit", "-q", "-m", "attack"), commitTitle, fp.Shape(token))
		c.stays("that commit", r, before)
		// Only the attack goes: the token file stays staged for the next one.
		for p := range a.files {
			r.drop(p)
		}
	}

	// A learned key in a file the same .gitattributes line hides from git diff.
	r.tidy()
	r.write(".gitattributes", "*.env -diff\n")
	r.write("k.env", "SERVICE_KEY="+s.k+"\n")
	r.stage("k.env")
	c.blocked("a learned key in a file marked -diff", r.git("commit", "-q", "-m", "attack"), commitTitle, "your learned key")
	c.stays("that commit", r, before)
	r.tidy()

	// The comment on the line, in every dialect: it is the committer's own say-so, and a blocked
	// agent can write it as easily as a person.
	for _, m := range markers {
		u := s.fake("ghp_", 36)
		r.write("docs.md", "example token: "+u+" # "+m+"\n")
		r.stage("docs.md")
		c.blocked("a token marked "+m, r.git("commit", "-q", "-m", "attack"), commitTitle, fp.Shape(u))
		c.stays("that commit", r, before)
		r.tidy()
	}
	return fmt.Sprintf("%d attacks on a refused token (ignore file, allowlist config, -diff, binary, all four together) and %d allow comments all failed; a learned key marked -diff was still found", len(attacks), len(markers)), c.err
}

// ----- pins -----

// checkEnginesClean is STEAL P0-01 and P0-06 for the whole run. Over every check above, the
// engines the hooks start have been started hundreds of times: none of them may have replaced
// itself, left its updates lock beside it, written a titus datastore (which keeps findings in the
// clear) or left its scratch directory in the data root.
func checkEnginesClean(s *suite) (string, error) {
	var changed []string
	for name, was := range s.engineSums {
		path := s.engine[name]
		if now, err := fileSum(path); err != nil || now != was {
			changed = append(changed, name)
		}
		if lock := filepath.Join(filepath.Dir(path), name+"-updates.lock"); exists(lock) && !s.hadLock[name] {
			return "", fmt.Errorf("%s left %s-updates.lock beside it: it tried to update itself", name, name)
		}
	}
	if len(changed) > 0 {
		return "", fmt.Errorf("%d engine binaries are not what they were when the run began: %v", len(changed), changed)
	}
	if stores := s.datastores(); len(stores) > 0 {
		return "", fmt.Errorf("a titus datastore, which keeps findings in the clear, was left at %s", s.line(stores[0]))
	}
	if left := s.scratchLeft(); left > 0 {
		return "", fmt.Errorf("%d engine scratch director(ies) were left in the data root's tmp", left)
	}
	return fmt.Sprintf("%d engine binaries unchanged and un-updated, no datastore anywhere, no scratch directory left behind", len(s.engineSums)), nil
}
