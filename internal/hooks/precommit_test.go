package hooks

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"keyguard/internal/core"
)

func TestPreCommitBlocksStagedKey(t *testing.T) {
	t.Parallel()
	e := newTenv(t)
	repo := e.initRepo("r")
	key := fakeGitHub()
	e.write(repo, "app/api.py", "import os\n\nTOKEN = \""+key+"\"\n")
	e.must(repo, "add", "app/api.py")

	r := e.git(repo, "commit", "-m", "add api")
	if r.code == 0 {
		t.Fatalf("commit with a staged key went through:\n%s", r)
	}
	for _, want := range []string{"commit blocked", "app/api.py", "github-pat", "ghp_…", "FILE", "LINE", "TYPE", "SECRET", "WHY",
		"gitignored .env", "--no-verify", "keyguard allow kg"} {
		if !strings.Contains(r.err, want) {
			t.Errorf("block message lacks %q:\n%s", want, r.err)
		}
	}
	assertNoLeak(t, "stderr", r.err, key)
	assertNoLeak(t, "stdout", r.out, key)
	if head := e.git(repo, "rev-parse", "--verify", "-q", "HEAD"); head.code == 0 {
		t.Errorf("a commit was created despite the block")
	}
}

func TestPreCommitBlocksLearnedKey(t *testing.T) {
	t.Parallel()
	e := newTenv(t)
	repo := e.initRepo("r")
	key := fakeGitHub()
	e.setKnown(map[string]string{"GITHUB_TOKEN": key})
	e.write(repo, "deploy.sh", "#!/bin/sh\n# betterleaks:allow\nexport T="+key+"\n")
	e.must(repo, "add", "deploy.sh")

	r := e.git(repo, "commit", "-m", "x")
	if r.code == 0 {
		t.Fatalf("learned key went through:\n%s", r)
	}
	for _, want := range []string{"deploy.sh", "learned key GITHUB_TOKEN", "ghp_…"} {
		if !strings.Contains(r.err, want) {
			t.Errorf("message lacks %q:\n%s", want, r.err)
		}
	}
	// The key is also on a line a human could have marked allowed; learned keys ignore that.
	if !strings.Contains(r.err, "  3  ") && !strings.Contains(r.err, " 3 ") {
		t.Errorf("message should point at line 3:\n%s", r.err)
	}
	assertNoLeak(t, "stderr", r.err, key)
}

// No inline allow marker is honored, by any scanner (STEAL P0-12, K9). A blocked agent could
// otherwise add the comment itself; the one allowlist is ignore.json, written by
// `keyguard allow`, which the agent guard keeps from it. The engine stand-in in helperDeps
// passes the flag production passes, so this proves the contract between the hook and the
// engine behind it: a marker on the line changes nothing.
func TestPreCommitIgnoresInlineAllowMarkers(t *testing.T) {
	t.Parallel()
	e := newTenv(t)
	for _, marker := range []string{"betterleaks:allow", "gitleaks:allow"} {
		repo := e.initRepo("r-" + strings.ReplaceAll(marker, ":", "-"))
		unknown := fakeGitHub()
		e.write(repo, "docs.md", "example token: "+unknown+" # "+marker+"\n")
		e.must(repo, "add", "docs.md")
		r := e.git(repo, "commit", "-m", "doc")
		if r.code == 0 {
			t.Errorf("an engine hit marked %s went through:\n%s", marker, r)
			continue
		}
		if !strings.Contains(r.err, "github-pat") || !strings.Contains(r.err, "docs.md") {
			t.Errorf("%s: the block does not name the finding:\n%s", marker, r.err)
		}
		assertNoLeak(t, marker, r.err, unknown)
	}
}

// A repo file the committer controls must not be able to blind the check (STEAL P0-05). With
// `.gitattributes` saying `-diff`, git prints "Binary files differ" for the path and a
// scanner that reads the diff sees nothing. The hook reads the diff with --text, so the
// staged key is still found, in pre-commit and, past --no-verify, in reference-transaction.
func TestAGitattributesLineCannotHideAKeyFromTheHooks(t *testing.T) {
	t.Parallel()
	e := newTenv(t)
	repo := e.initRepo("r")
	key := fakeGitHub()
	e.setKnown(map[string]string{"GITHUB_TOKEN": key})
	e.commitFile(repo, ".gitattributes", "*.cfg -diff\n*.dat binary\n", "attributes")
	for _, path := range []string{"app.cfg", "blob.dat"} {
		e.write(repo, path, "token = "+key+"\n")
		e.must(repo, "add", path)
		r := e.git(repo, "commit", "-m", "x")
		if r.code == 0 {
			t.Errorf("%s: a key hidden by .gitattributes went through pre-commit:\n%s", path, r)
			continue
		}
		assertNoLeak(t, path, r.err, key)
		if !strings.Contains(r.err, path) || !strings.Contains(r.err, "learned key GITHUB_TOKEN") {
			t.Errorf("%s: the block does not name it:\n%s", path, r.err)
		}
		if r := e.git(repo, "commit", "--no-verify", "-m", "x"); r.code == 0 {
			t.Errorf("%s: --no-verify got a hidden key past reference-transaction:\n%s", path, r)
		}
		e.must(repo, "reset", "-q")
		os.Remove(filepath.Join(repo, path))
	}
	// The attribute that sends a diff through a converter is no better.
	e.commitFile(repo, ".gitattributes", "*.cfg -diff\n*.dat binary\n*.conv diff=conv\n", "more attributes")
	e.must(repo, "config", "diff.conv.textconv", "true")
	e.write(repo, "x.conv", "token = "+key+"\n")
	e.must(repo, "add", "x.conv")
	if r := e.git(repo, "commit", "-m", "x"); r.code == 0 {
		t.Errorf("a textconv driver hid the key:\n%s", r)
	}
}

func TestPreCommitFilenameRules(t *testing.T) {
	t.Parallel()
	e := newTenv(t)
	for _, c := range []struct {
		path    string
		content string
		blocked bool
	}{
		{".env", "PORT=3000\n", true},
		{"deploy/.env.production", "MODE=prod\n", true},
		{"app/.ENV", "A=1\n", true},
		{".env.local", "A=1\n", true},
		{".env.example", "OPENAI_API_KEY=your-key-here\nDATABASE_URL=<your database url>\n", false},
		{".env.sample", "A=changeme\n", false},
		{".env.template", "A=\n", false},
		{".env.dist", "A=\n", false},
		{".env.defaults", "PORT=3000\n", false},
		{"id_rsa", "not really a key\n", true},
		{"ssh/id_ed25519", "x\n", true},
		{"id_rsa.pub", "ssh-rsa AAAA user@host\n", false},
		{"certs/server.pem", fakePEM(), true},
		{"certs/server.key", fakePEM(), true},
		{"certs/ca.pem", "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n", false},
		{"store.p12", "x", true},
		{"store.pfx", "x", true},
		{"release.jks", "x", true},
		{"android.keystore", "x", true},
		{".git-credentials", "https://user@example.com\n", true},
		{".netrc", "machine example.com\n", true},
		{"infra/terraform.tfstate", "{}\n", true},
		{".npmrc", "//registry.npmjs.org/:_authToken=${NPM_TOKEN}\nregistry=https://registry.npmjs.org/\n", false},
		{".npmrc", "//registry.npmjs.org/:_authToken=npm_" + randString(36, alnum) + "\n", true},
		{".pypirc", "[pypi]\nusername = __token__\npassword = ${PYPI_TOKEN}\n", false},
		{".pypirc", "[pypi]\nusername = __token__\npassword = pypi-" + randString(40, alnum) + "\n", true},
		{"credentials.json", `{"client_id": "abc"}` + "\n", false},
		{"credentials.json", `{"type":"service_account","private_key":"` + randString(30, alnum) + `"}` + "\n", true},
		{"gcp/my-service-account.json", `{"private_key":"` + randString(30, alnum) + `"}` + "\n", true},
		{"fb/proj-firebase-adminsdk-abc12.json", `{"private_key":"` + randString(30, alnum) + `"}` + "\n", true},
		{"README.md", "# hello\n", false},
	} {
		repo := e.initRepo(strings.NewReplacer("/", "_", ".", "_").Replace(c.path) + randString(4, alnum))
		e.write(repo, c.path, c.content)
		e.must(repo, "add", "-f", "--", c.path)
		r := e.git(repo, "commit", "-m", "x")
		if c.blocked && r.code == 0 {
			t.Errorf("%s should be blocked", c.path)
		} else if !c.blocked && r.code != 0 {
			t.Errorf("%s should pass:\n%s", c.path, r)
		}
		if c.blocked && !strings.Contains(r.err, filepath.Base(c.path)) {
			t.Errorf("%s: message does not name the file:\n%s", c.path, r.err)
		}
		assertNoLeak(t, c.path, r.err, secretsIn(c.content)...)
	}
}

// secretsIn returns the long random-looking tokens of a test file, the parts that must
// never appear in output (the public PEM header is not one).
func secretsIn(content string) []string {
	var out []string
	for _, tok := range strings.FieldsFunc(content, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-')
	}) {
		if len(tok) >= 30 {
			out = append(out, tok)
		}
	}
	return out
}

func TestPreCommitCleanCommitPasses(t *testing.T) {
	t.Parallel()
	e := newTenv(t)
	repo := e.initRepo("r")
	e.setKnown(map[string]string{"OTHER": fakeGitHub()})
	e.write(repo, "main.go", "package main\n\nfunc main() { println(\"hi\") }\n")
	e.write(repo, "README.md", "# demo\n")
	e.must(repo, "add", "-A")
	if r := e.git(repo, "commit", "-m", "init"); r.code != 0 {
		t.Fatalf("clean commit blocked:\n%s", r)
	}
	// An empty commit has nothing staged and nothing to scan.
	if r := e.git(repo, "commit", "--allow-empty", "-m", "empty"); r.code != 0 {
		t.Fatalf("empty commit blocked:\n%s", r)
	}
	// So does a commit that only deletes: removing a leaked file must never be refused.
	e.must(repo, "rm", "-q", "README.md")
	if r := e.git(repo, "commit", "-m", "delete"); r.code != 0 {
		t.Fatalf("delete-only commit blocked:\n%s", r)
	}
	// Deleting a .env that was committed earlier is the fix, not a new leak.
	e.write(repo, ".env", "A=1\n")
	e.must(repo, "add", "-f", ".env")
	e.mustQuiet(repo, "commit", "-q", "-m", "oops, committed a .env")
	e.must(repo, "rm", "-q", ".env")
	if r := e.git(repo, "commit", "-m", "remove .env"); r.code != 0 {
		t.Fatalf("removing a committed .env was refused:\n%s", r)
	}
}

// `git commit -a` and `git commit <path>` give the hook a temporary index (GIT_INDEX_FILE);
// the scan has to read that one, not .git/index.
func TestPreCommitReadsTheCommitsOwnIndex(t *testing.T) {
	t.Parallel()
	e := newTenv(t)
	repo := e.initRepo("r")
	e.commitFile(repo, "a.txt", "one\n", "init")
	key := fakeGitHub()

	e.write(repo, "a.txt", "one\ntoken = "+key+"\n")
	if r := e.git(repo, "commit", "-a", "-m", "tracked change"); r.code == 0 {
		t.Errorf("commit -a with a key in a tracked file went through:\n%s", r)
	}
	if r := e.git(repo, "commit", "-m", "path form", "--", "a.txt"); r.code == 0 {
		t.Errorf("commit -- a.txt with a key went through:\n%s", r)
	}
	e.must(repo, "checkout", "--", "a.txt")
	e.write(repo, "a.txt", "one\ntwo\n")
	if r := e.git(repo, "commit", "-a", "-m", "clean change"); r.code != 0 {
		t.Errorf("clean commit -a blocked:\n%s", r)
	}
}

// A repo with its own hooks (husky sets core.hooksPath) still gets keyguard's: git runs
// config hooks in addition to the repo's.
func TestPreCommitRunsBesideHusky(t *testing.T) {
	t.Parallel()
	e := newTenv(t)
	repo := e.initRepo("r")
	marker := filepath.Join(e.root, "husky-ran")
	e.write(repo, ".husky/pre-commit", "#!/bin/sh\necho ran >> "+marker+"\n")
	if err := os.Chmod(filepath.Join(repo, ".husky/pre-commit"), 0o755); err != nil {
		t.Fatal(err)
	}
	e.must(repo, "config", "core.hooksPath", ".husky")

	e.write(repo, "ok.txt", "fine\n")
	e.must(repo, "add", "ok.txt")
	if r := e.git(repo, "commit", "-m", "clean"); r.code != 0 {
		t.Fatalf("clean commit failed:\n%s", r)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Errorf("the repo's own husky hook did not run: %v", err)
	}

	key := fakeGitHub()
	e.write(repo, "leak.txt", "k="+key+"\n")
	e.must(repo, "add", "leak.txt")
	r := e.git(repo, "commit", "-m", "leak")
	if r.code == 0 || !strings.Contains(r.err, "commit blocked") {
		t.Errorf("keyguard did not run beside husky:\n%s", r)
	}
	assertNoLeak(t, "stderr", r.err, key)
}

// While a merge waits to be committed, the staged diff against HEAD holds everything the
// other side brought. A key that came in unchanged from that side is not this commit's
// doing; a key typed into the conflict resolution is.
func TestPreCommitMergeJudgesOnlyWhatTheMergeAdds(t *testing.T) {
	t.Parallel()
	for _, learned := range []bool{true, false} { // learned: the matcher knows it; else only betterleaks can
		name := "engine only"
		if learned {
			name = "learned key"
		}
		t.Run(name, func(t *testing.T) {
			e := newTenv(t)
			origin := e.initBare("origin.git")
			repo := e.initRepo("r")
			e.mustQuiet(repo, "remote", "add", "origin", origin)
			inherited, typed := fakeGitHub(), fakeGitHub()
			if learned {
				e.setKnown(map[string]string{"INHERITED": inherited, "TYPED": typed})
			}

			e.quietCommit(repo, "f.txt", "a\nb\nc\n", "base")
			e.mustQuiet(repo, "push", "-q", "-u", "origin", "main")
			e.mustQuiet(repo, "checkout", "-q", "-b", "side")
			e.quietCommit(repo, "k.txt", "t = \""+inherited+"\"\n", "side holds a key")
			e.quietCommit(repo, "f.txt", "a\nSIDE\nc\n", "side edit")
			e.mustQuiet(repo, "push", "-q", "origin", "side")
			e.mustQuiet(repo, "checkout", "-q", "main")
			e.mustQuiet(repo, "branch", "-D", "side")
			e.quietCommit(repo, "f.txt", "a\nMAIN\nc\n", "main edit")
			e.mustQuiet(repo, "fetch", "-q", "origin")

			// 1. The key arrives with the other side; the resolution is clean.
			if e.git(repo, "merge", "origin/side").code == 0 {
				t.Fatal("expected a conflict")
			}
			e.write(repo, "f.txt", "a\nBOTH\nc\n")
			e.must(repo, "add", "f.txt")
			if r := e.git(repo, "commit", "-m", "merge"); r.code != 0 {
				t.Fatalf("a merge that only inherits a key was refused:\n%s", r)
			}

			// 2. The same merge, but the resolution itself carries a key.
			e.must(repo, "reset", "-q", "--hard", "HEAD~1")
			if e.git(repo, "merge", "origin/side").code == 0 {
				t.Fatal("expected a conflict")
			}
			e.write(repo, "f.txt", "a\nsecret = \""+typed+"\"\nc\n")
			e.must(repo, "add", "f.txt")
			r := e.git(repo, "commit", "-m", "merge with a typed key")
			if r.code == 0 {
				t.Fatalf("a key typed into a merge resolution went through")
			}
			if !strings.Contains(r.err, "f.txt") || strings.Contains(r.err, "k.txt") {
				t.Errorf("only the resolution should be named:\n%s", r.err)
			}
			assertNoLeak(t, "stderr", r.err, inherited, typed)
		})
	}
}

// In-process: the injected pieces, without the engine binary or a hook subprocess.
func TestPreCommitInjection(t *testing.T) {
	e := newTenv(t)
	e.activate()
	repo := e.initRepo("r")
	key := fakeGitHub()
	e.write(repo, "x.txt", "k="+key+"\n")
	e.must(repo, "add", "x.txt")
	fpKey := testKeyring.FP(key)
	engineHit := func(ctx context.Context, dir string, emit core.Emit) error {
		emit(core.Hit{Engine: "betterleaks", Rule: "test-rule", Type: "test", FP: fpKey, Shape: "ghp_…", Loc: core.Location{Path: "x.txt", Line: 1}})
		return nil
	}

	var stderr strings.Builder
	d := Deps{Dir: repo, ScanStaged: engineHit, Stderr: &stderr, FP: testKeyring}

	t.Run("an engine hit blocks", func(t *testing.T) {
		stderr.Reset()
		if code := PreCommit(context.Background(), d); code != 1 {
			t.Fatalf("code %d, want 1:\n%s", code, stderr.String())
		}
		if !strings.Contains(stderr.String(), "test-rule") {
			t.Errorf("message lacks the rule:\n%s", stderr.String())
		}
	})

	t.Run("an ignored fingerprint passes", func(t *testing.T) {
		stderr.Reset()
		dd := d
		dd.Ignored = func(fp string) bool { return fp == fpKey }
		if code := PreCommit(context.Background(), dd); code != 0 {
			t.Fatalf("code %d, want 0:\n%s", code, stderr.String())
		}
	})

	t.Run("record receives what blocked", func(t *testing.T) {
		stderr.Reset()
		var layer string
		var got []core.Hit
		dd := d
		dd.Record = func(l string, hits []core.Hit) { layer, got = l, hits }
		PreCommit(context.Background(), dd)
		if layer != "pre-commit" || len(got) != 1 || got[0].FP != fpKey || got[0].Loc.Kind != "staged" || !strings.HasPrefix(got[0].Loc.Source, "local:") {
			t.Errorf("record got layer %q hits %+v", layer, got)
		}
	})

	t.Run("an engine error fails open", func(t *testing.T) {
		stderr.Reset()
		dd := d
		dd.ScanStaged = func(context.Context, string, core.Emit) error { return errors.New("engine exploded") }
		if code := PreCommit(context.Background(), dd); code != 0 {
			t.Fatalf("code %d, want 0 (fail open):\n%s", code, stderr.String())
		}
		if !strings.Contains(stderr.String(), "warning") || !strings.Contains(stderr.String(), "engine exploded") {
			t.Errorf("no warning:\n%s", stderr.String())
		}
	})

	t.Run("an engine panic fails open", func(t *testing.T) {
		stderr.Reset()
		dd := d
		dd.ScanStaged = func(context.Context, string, core.Emit) error { panic("boom") }
		if code := Run(context.Background(), NamePreCommit, nil, strings.NewReader(""), dd); code != 0 {
			t.Fatalf("code %d, want 0:\n%s", code, stderr.String())
		}
	})

	t.Run("a learned key still blocks when the engine is down", func(t *testing.T) {
		stderr.Reset()
		dd := d
		dd.Known = newSubMatcher([]string{"K=" + key})
		dd.ScanStaged = func(context.Context, string, core.Emit) error { return errors.New("engine exploded") }
		if code := PreCommit(context.Background(), dd); code != 1 {
			t.Fatalf("code %d, want 1:\n%s", code, stderr.String())
		}
		assertNoLeak(t, "stderr", stderr.String(), key)
	})

	t.Run("lazy known store loads once and only when needed", func(t *testing.T) {
		stderr.Reset()
		calls := 0
		dd := d
		dd.ScanStaged = nil
		dd.LoadKnown = func() (core.KnownMatcher, error) { calls++; return newSubMatcher([]string{"K=" + key}), nil }
		if code := PreCommit(context.Background(), dd); code != 1 || calls != 1 {
			t.Fatalf("code %d, loads %d:\n%s", code, calls, stderr.String())
		}
	})

	t.Run("a store that will not load is one warning, not a failure", func(t *testing.T) {
		stderr.Reset()
		dd := d
		dd.ScanStaged = nil
		dd.LoadKnown = func() (core.KnownMatcher, error) { return nil, errors.New("known.json unreadable") }
		if code := PreCommit(context.Background(), dd); code != 0 {
			t.Fatalf("code %d, want 0:\n%s", code, stderr.String())
		}
		if n := strings.Count(stderr.String(), "warning"); n != 1 {
			t.Errorf("%d warnings, want 1:\n%s", n, stderr.String())
		}
	})

	t.Run("verified-dead keys do not block", func(t *testing.T) {
		stderr.Reset()
		dd := d
		dd.ScanStaged = func(ctx context.Context, dir string, emit core.Emit) error {
			emit(core.Hit{Engine: "x", Rule: "r", FP: "ab", Verified: core.Dead, Loc: core.Location{Path: "x.txt", Line: 1}})
			return nil
		}
		if code := PreCommit(context.Background(), dd); code != 0 {
			t.Fatalf("code %d, want 0:\n%s", code, stderr.String())
		}
	})
}
