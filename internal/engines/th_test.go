package engines

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"keyguard/internal/core"
)

// ----- P0-02: a bare mirror is scanned in place -----

// trufflehog on a bare repository with --bare alone clones it into TMPDIR first: a second copy
// of whatever leaked, and a failure when TMPDIR cannot be written (reproduced on 3.99.8: rc 1,
// "failed to clone"). The shim makes the engine's TMPDIR read-only for exactly as long as
// trufflehog runs, so only a scan that touches nothing there can succeed.
func TestTrufflehogOnABareMirrorWritesNothingIntoTmp(t *testing.T) {
	f := getFixture(t)
	real := needEngine(t, "trufflehog")
	e := shimEngine(t, "trufflehog", real, `chmod 500 "$TMPDIR"`, `chmod 700 "$TMPDIR"`, f.kr)
	resetAudit()
	hits := scanGit(t, e, f.mirror, core.Range{All: true}, testOpts())
	f.checkHits(t, "trufflehog", hits, f.fpIndex())
}

// ----- P0-03: no result is hidden -----

// Results whose body holds a dictionary word are dropped by default (0.5% of random keys;
// "password" and "business" always, measured). They come back with the filtered_unverified
// class of --results, and nothing else may be filtered.
func TestTrufflehogKeepsKeysThatContainAWord(t *testing.T) {
	f := getFixture(t)
	e := newEngine(t, "trufflehog", f.kr)
	for _, word := range []string{"password", "business"} {
		t.Run(word, func(t *testing.T) {
			resetAudit()
			wt := worktree(t)
			raw := register("sk_live_" + tok(alnumCS, 6) + word + tok(alnumCS, 10))
			writeLines(t, wt, "prod.env", "STRIPE="+raw)
			gitIn(wt, nil, "add", "-A")
			gitIn(wt, nil, "commit", "-q", "-m", "key")
			if got := fpSet(f.kr, scanGit(t, e, wt, core.Range{All: true}, testOpts()), map[string]string{"stripe": raw}); !slices.Equal(got, []string{"stripe"}) {
				t.Errorf("ScanGit dropped a key because its body spells %q", word)
			}
			var hits []core.Hit
			if err := e.ScanDir(context.Background(), wt, testOpts(), func(h core.Hit) { hits = append(hits, h) }); err != nil {
				t.Fatal(err)
			}
			assertSafe(t, "trufflehog", hits)
			if got := fpSet(f.kr, hits, map[string]string{"stripe": raw}); !slices.Equal(got, []string{"stripe"}) {
				t.Errorf("ScanDir dropped a key because its body spells %q", word)
			}
		})
	}
}

// ----- P0-10: verification stays on provider APIs -----

// TruffleHog's URI, JDBC, MongoDB, Redis and FTP detectors verify a credential by dialling the
// host written next to it in the scanned text: a stranger's server gets the password. With
// verification on and no allowlist it made 24 connections to a loopback port in one run.
func TestVerificationNeverDialsAHostFromTheScannedText(t *testing.T) {
	f := getFixture(t)
	e := newEngine(t, "trufflehog", f.kr)
	l := newListener(t)
	pw := func() string { return register(tok(alnumCS, 16)) }
	write := func(root string) {
		writeLines(t, root, "mongo.env", "MONGO="+uriOf("mongodb", "dbuser", pw(), l.addr+"/app"))
		writeLines(t, root, "redis.env", "REDIS="+uriOf("redis", "default", pw(), l.addr+"/0"))
		writeLines(t, root, "ftp.env", "FTP="+uriOf("ftp", "ftpuser", pw(), l.addr+"/"))
		writeLines(t, root, "jdbc.env", "JDBC="+"jdbc:postgresql:"+"//"+l.addr+"/app?user=dbuser&"+"password="+pw())
		writeLines(t, root, "pg.env", "DATABASE_URL="+uriOf("postgres", "dbuser", pw(), l.addr+"/app"))
	}
	for _, verify := range []bool{false, true} {
		t.Run("verify="+strconv.FormatBool(verify), func(t *testing.T) {
			resetAudit()
			o := testOpts()
			o.Verify = verify
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			before := l.count()

			dir := t.TempDir()
			write(dir)
			if err := e.ScanDir(ctx, dir, o, func(core.Hit) {}); err != nil {
				t.Fatal(err)
			}
			repo := worktree(t)
			write(repo)
			gitIn(repo, nil, "add", "-A")
			gitIn(repo, nil, "commit", "-q", "-m", "urls")
			if err := e.ScanGit(ctx, repo, core.Range{All: true}, o, func(core.Hit) {}); err != nil {
				t.Fatal(err)
			}
			assertScratchClean(t)
			if n := l.count() - before; n != 0 {
				t.Errorf("trufflehog dialled a host from the scanned text %d times (verify=%v)", n, verify)
			}
		})
	}
}

// The detectors a verifying run may use are the ones that talk to their provider's own API
// (STEAL Appendix C tiers A and B, minus SlackWebhook, which POSTs). Every other run is
// offline. The ids are protobuf enum numbers, so the installed binary is the authority on
// whether they exist: an id it does not know makes it exit 1.
func TestVerificationAllowlist(t *testing.T) {
	f := getFixture(t)
	// tier A and B of the appendix, minus 30 SlackWebhook
	want := []int{933, 201, 1040, 8, 988, 1023, 1057, 967, 926, 16, 994, 12, 100, 58, 13, 66, 2, 959, 915, 1041, 6,
		160, 144, 91, 65, 26, 1011}
	dialers := map[int]string{30: "SlackWebhook", 17: "URI", 10: "JDBC", 968: "Postgres", 895: "MongoDB", 900: "Redis",
		901: "LDAP", 899: "FTP", 904: "CustomRegex", 1039: "JWT", 15: "PrivateKey"}

	e, calls := recordingEngine(t, "trufflehog", f.kr, "", "", 0)
	root := t.TempDir()
	writeLines(t, root, "a.txt", "nothing here")
	for _, verify := range []bool{true, false} {
		o := testOpts()
		o.Verify = verify
		if err := e.ScanDir(context.Background(), root, o, func(core.Hit) {}); err != nil {
			t.Fatal(err)
		}
		if err := e.ScanGit(context.Background(), f.mirror, core.Range{All: true}, o, func(core.Hit) {}); err != nil {
			t.Fatal(err)
		}
	}
	cs := calls()
	if len(cs) != 4 {
		t.Fatalf("%d starts, want 4", len(cs))
	}
	for i, c := range cs {
		verifying := i < 2
		arg, has := argWithPrefix(c.args, "--include-detectors=")
		switch {
		case verifying && (!has || slices.Contains(c.args, "--no-verification")):
			t.Errorf("call %d verifies without an allowlist: %v", i, c.args)
		case !verifying && (has || !slices.Contains(c.args, "--no-verification")):
			t.Errorf("call %d is not offline: %v", i, c.args)
		}
		if !has {
			continue
		}
		var got []int
		for _, s := range strings.Split(strings.TrimPrefix(arg, "--include-detectors="), ",") {
			n, err := strconv.Atoi(s)
			if err != nil {
				t.Fatalf("allowlist entry %q is not a detector id", s)
			}
			got = append(got, n)
		}
		slices.Sort(got)
		w := slices.Clone(want)
		slices.Sort(w)
		if !slices.Equal(got, w) {
			t.Errorf("allowlist %v, want %v", got, w)
		}
		for _, n := range got {
			if name, bad := dialers[n]; bad {
				t.Errorf("allowlist holds %d %s, which dials hosts from the scanned text or sends a request of its own", n, name)
			}
		}
	}

	// The installed binary knows every id (TruffleHog exits 1 on one it does not).
	real := needEngine(t, "trufflehog")
	ids := make([]string, len(want))
	for i, n := range want {
		ids[i] = strconv.Itoa(n)
	}
	out, err := exec.Command(real, "--no-update", "filesystem", root, "--no-verification", "--log-level=-1",
		"--include-detectors="+strings.Join(ids, ",")).CombinedOutput()
	if err != nil {
		t.Errorf("the installed trufflehog rejects the allowlist: %v: %s", err, safeText(out))
	}
}

// ----- P0-01, P0-02, P0-03, P0-12: the flags every call carries -----

func TestTrufflehogFlagsOnEveryCall(t *testing.T) {
	f := getFixture(t)
	e, calls := recordingEngine(t, "trufflehog", f.kr, "", "", 0)
	root := t.TempDir()
	writeLines(t, root, "a.txt", "nothing here")
	for _, verify := range []bool{false, true} {
		o := testOpts()
		o.Verify = verify
		if err := e.ScanDir(context.Background(), root, o, func(core.Hit) {}); err != nil {
			t.Fatal(err)
		}
		for _, r := range []core.Range{{All: true}, {Revs: []string{f.c["c3"], "^" + f.c["c2"]}}, {All: true, Since: map[string]string{"refs/heads/main": f.c["c2"]}}} {
			if err := e.ScanGit(context.Background(), f.mirror, r, o, func(core.Hit) {}); err != nil {
				t.Fatal(err)
			}
		}
	}
	_ = e.Version()
	never := []string{"--filter-unverified", "--filter-entropy", "--allow-verification-overlap", "--skip-additional-refs",
		"--force-skip-archives", "--force-skip-binaries", "--fail"}
	cs := calls()
	if len(cs) < 9 {
		t.Fatalf("only %d starts recorded", len(cs))
	}
	for _, c := range cs {
		if !slices.Contains(c.args, "--no-update") {
			t.Errorf("trufflehog started without --no-update (it replaces its own binary): %v", c.args)
		}
		if slices.Contains(c.args, "--version") {
			continue
		}
		if !slices.Contains(c.args, "--no-ignore-tag") {
			t.Errorf("trufflehog honors trufflehog:ignore: %v", c.args)
		}
		if !slices.Contains(c.args, "--results=verified,unknown,unverified,filtered_unverified") {
			t.Errorf("trufflehog hides results by default: %v", c.args)
		}
		for _, bad := range never {
			if slices.Contains(c.args, bad) || func() bool { _, ok := argWithPrefix(c.args, bad+"="); return ok }() {
				t.Errorf("trufflehog started with %s: %v", bad, c.args)
			}
		}
		if slices.Contains(c.args, "git") {
			if !slices.Contains(c.args, "--bare") || !slices.Contains(c.args, "--trust-local-git-config") {
				t.Errorf("a git scan needs --bare and --trust-local-git-config or trufflehog clones the mirror: %v", c.args)
			}
		}
	}
}

// ----- P0-02: a scan that read nothing is not a clean scan -----

func TestTrufflehogZeroBytesOverNewContentIsAnEngineFailure(t *testing.T) {
	f := getFixture(t)
	const done = `{"level":"info-0","msg":"finished scanning","chunks":0,"bytes":0,"verified_secrets":0,"unverified_secrets":0}` + "\n"
	e := scriptEngine(t, "trufflehog", f.kr, "", done, 0)
	err := e.ScanGit(context.Background(), f.mirror, core.Range{All: true}, testOpts(), func(core.Hit) { t.Error("hit from a scan that read nothing") })
	if err == nil {
		t.Fatal("trufflehog reported 0 bytes scanned over a history full of text and that read as a clean scan")
	}
	assertNoRaw(t, "error", []byte(err.Error()))
}

// Not every range has text to read: a commit that only deletes files, adds an empty file or a
// binary has none, and trufflehog is right to report 0 bytes for it.
func TestTrufflehogZeroBytesOverNothingToReadIsFine(t *testing.T) {
	f := getFixture(t)
	const done = `{"level":"info-0","msg":"finished scanning","chunks":0,"bytes":0,"verified_secrets":0,"unverified_secrets":0}` + "\n"
	repo := t.TempDir()
	gitIn(repo, nil, "init", "-q", "-b", "main")
	writeLines(t, repo, "keep.txt", "text")
	writeLines(t, repo, "gone.txt", "more text")
	gitIn(repo, nil, "add", "-A")
	gitIn(repo, nil, "commit", "-q", "-m", "base")
	base := gitIn(repo, nil, "rev-parse", "HEAD")

	gitIn(repo, nil, "rm", "-q", "gone.txt")
	gitIn(repo, nil, "commit", "-q", "-m", "delete only")
	deleted := gitIn(repo, nil, "rev-parse", "HEAD")

	if err := os.WriteFile(filepath.Join(repo, "empty.txt"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "blob.bin"), []byte("\x00\x01\x02\x03binary\x00"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitIn(repo, nil, "add", "-A")
	gitIn(repo, nil, "commit", "-q", "-m", "empty and binary")
	added := gitIn(repo, nil, "rev-parse", "HEAD")

	e := scriptEngine(t, "trufflehog", f.kr, "", done, 0)
	for label, r := range map[string]core.Range{
		"only a deletion":       {Revs: []string{deleted, "^" + base}},
		"an empty and a binary": {Revs: []string{added, "^" + deleted}},
	} {
		if err := e.ScanGit(context.Background(), repo, r, testOpts(), func(core.Hit) {}); err != nil {
			t.Errorf("%s: 0 bytes was called a failure: %v", label, err)
		}
	}
	// A summary line that is missing proves nothing either way.
	silent := scriptEngine(t, "trufflehog", f.kr, "", "", 0)
	if err := silent.ScanGit(context.Background(), f.mirror, core.Range{All: true}, testOpts(), func(core.Hit) {}); err != nil {
		t.Errorf("no summary line, and that failed the scan: %v", err)
	}
}

// ----- P0-04: trufflehog's log is not for us -----

// With a log level that prints the summary line, trufflehog also logs other things. Only the
// lines we know are kept; the rest never reaches an error string.
func TestTrufflehogStderrKeepsOnlyTheLinesWeKnow(t *testing.T) {
	f := getFixture(t)
	leak := register(tok(alnumCS, 12)) // short enough that fp.Scrub would not mask it
	stderr := `{"level":"info-0","msg":"result","detector":"Stripe","detail":"` + leak + `"}` + "\n" +
		`{"level":"error","msg":"error running scan","error":"engine failed to finish execution: fatal: not a git repository"}` + "\n" +
		leak + " raw line\n"
	e := scriptEngine(t, "trufflehog", f.kr, "", stderr, 1)
	err := e.ScanDir(context.Background(), t.TempDir(), testOpts(), func(core.Hit) {})
	if err == nil || !strings.Contains(err.Error(), "not a git repository") {
		t.Fatalf("want the explanation of the failure, got %v", err)
	}
	assertNoRaw(t, "error", []byte(err.Error()))
}
