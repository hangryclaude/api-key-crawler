package engines

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"keyguard/internal/core"
)

// A directory scan is pointed at the directory it scans, so what that directory holds is the
// place a repo-planted file would be read from. Measured on betterleaks 1.9.0 and gitleaks
// 8.30.1: with -i and -c given and the engine run from elsewhere, none of these hides anything.
// This keeps it so.
func TestRepoFilesCannotBlindADirectoryScan(t *testing.T) {
	f := getFixture(t)
	for _, name := range []string{"betterleaks", "gitleaks"} {
		for _, b := range blinders() {
			if b.label == "-diff attribute" || b.label == "binary attribute" {
				continue // attributes only matter to git
			}
			t.Run(name+"/"+b.label, func(t *testing.T) {
				bin := needEngine(t, name)
				e := newEngine(t, name, f.kr)
				resetAudit()
				dir := worktree(t)
				token := fake("github")
				writeLines(t, dir, "b.env", "GITHUB_TOKEN="+token)
				gitIn(dir, nil, "add", "-A")
				b.apply(t, dir, name, bin, token)
				var hits []core.Hit
				if err := e.ScanDir(context.Background(), dir, stagedOpts(dir), func(h core.Hit) { hits = append(hits, h) }); err != nil {
					t.Fatal(err)
				}
				assertSafe(t, name, hits)
				if got := fpSet(f.kr, hits, map[string]string{"github": token}); len(got) != 1 {
					t.Errorf("%s: a %s in the scanned directory hid the token from the directory scan", name, b.label)
				}
			})
		}
	}
}

// Whatever the process that started keyguard had in its environment, an engine does not:
// not a config that would stand in for -c, not a token it has no use for, not a thread count,
// not a rule cache of someone else's choosing.
func TestEnginesDoNotInheritWhatTheyMustNot(t *testing.T) {
	token := register(fake("github"))
	for k, v := range map[string]string{
		"GITHUB_TOKEN": token, "GH_TOKEN": token, "BETTERLEAKS_CONFIG": "/nonexistent/evil.toml", "GITLEAKS_CONFIG": "/nonexistent/evil.toml",
		"BETTERLEAKS_CONFIG_TOML": "[allowlist]\nregexes=['.*']", "GITLEAKS_CONFIG_TOML": "[allowlist]\nregexes=['.*']",
		"GOMAXPROCS": "64", "TITUS_CACHE_DIR": "/nonexistent/cache",
	} {
		t.Setenv(k, v)
	}
	for _, name := range Names {
		t.Run(name, func(t *testing.T) {
			calls, _ := scanEverything(t, name, testOpts())
			for _, c := range calls {
				for _, k := range []string{"GITHUB_TOKEN", "GH_TOKEN", "BETTERLEAKS_CONFIG", "GITLEAKS_CONFIG", "BETTERLEAKS_CONFIG_TOML", "GITLEAKS_CONFIG_TOML"} {
					if _, ok := c.env[k]; ok {
						t.Errorf("%s reached the engine", k) // the value is a token: never printed
					}
				}
				if c.env["GOMAXPROCS"] != "2" {
					t.Errorf("an inherited GOMAXPROCS=64 beat the cap: %q", c.env["GOMAXPROCS"])
				}
				want := "" // only titus has a cache, and it is under the data root
				if name == "titus" {
					want = filepath.Join(os.Getenv("KEYGUARD_HOME"), "cache", "titus")
				}
				if got := c.env["TITUS_CACHE_DIR"]; got != want {
					t.Errorf("TITUS_CACHE_DIR=%q, want %q", got, want)
				}
			}
		})
	}
}

// ----- the regex engine at the gate follows the size of what is staged -----

func TestPreCommitRegexEngineFollowsStagedSize(t *testing.T) {
	f := getFixture(t)
	e, calls := recordingEngine(t, "betterleaks", f.kr, "[]", "", 0)
	small := worktree(t)
	writeLines(t, small, "a.txt", "one line")
	gitIn(small, nil, "add", "-A")
	if err := e.ScanStaged(context.Background(), small, stagedOpts(small), func(core.Hit) {}); err != nil {
		t.Fatal(err)
	}
	big := worktree(t)
	var lines []string
	for i := 0; i < stdlibLines+10; i++ {
		lines = append(lines, fmt.Sprintf("line %d", i))
	}
	writeLines(t, big, "big.txt", lines...)
	gitIn(big, nil, "add", "-A")
	if err := e.ScanStaged(context.Background(), big, stagedOpts(big), func(core.Hit) {}); err != nil {
		t.Fatal(err)
	}
	cs := calls()
	if len(cs) != 2 {
		t.Fatalf("%d starts", len(cs))
	}
	if !hasArgs(cs[0].args, "--regex-engine", "stdlib") {
		t.Errorf("a small staged change did not get the stdlib regex engine: %v", cs[0].args)
	}
	if !hasArgs(cs[1].args, "--regex-engine", "re2") {
		t.Errorf("a large staged change did not get re2: %v", cs[1].args)
	}
	if regexEngine(0) != "stdlib" || regexEngine(stdlibLines-1) != "stdlib" || regexEngine(stdlibLines) != "re2" {
		t.Error("the threshold moved")
	}
}

// Nothing staged starts no engine; a directory that is not a repository is an error and not a
// clean scan; a staged binary file counts as staged (its line counts are "-").
func TestScanStagedEdges(t *testing.T) {
	f := getFixture(t)
	e, calls := recordingEngine(t, "betterleaks", f.kr, "[]", "", 0)
	wt := worktree(t)
	if err := e.ScanStaged(context.Background(), wt, stagedOpts(wt), func(core.Hit) {}); err != nil {
		t.Fatal(err)
	}
	if n := len(calls()); n != 0 {
		t.Errorf("nothing staged started the engine %d times", n)
	}
	if err := e.ScanStaged(context.Background(), t.TempDir(), stagedOpts(wt), func(core.Hit) { t.Error("hit from a failed scan") }); err == nil {
		t.Error("a directory that is not a repository was scanned as if it were clean")
	}
	writeLines(t, wt, "blob.bin", "\x00\x01\x02binary\x00")
	gitIn(wt, nil, "add", "-A")
	if err := e.ScanStaged(context.Background(), wt, stagedOpts(wt), func(core.Hit) {}); err != nil {
		t.Fatal(err)
	}
	if n := len(calls()); n != 1 {
		t.Errorf("a staged binary started the engine %d times, want 1", n)
	}
}

// ----- the context line never shows the secret the engine did not say was the secret -----

// Titus's np.postgres.1 reports the user name first. For a rule whose groups are not named for
// a secret there is no telling which of several is, and the first is a guess; the line the
// hit shows must not carry the real one then (a password of 12 to 19 characters is too short for
// fp.Scrub to mask it).
func TestTitusHidesTheWholeMatchWhenItCannotTellTheSecret(t *testing.T) {
	f := getFixture(t)
	root := t.TempDir()
	pw := register(tok(alnumCS, 14))
	writeLines(t, root, "a.txt", "login appuser:"+pw+" now")
	blob, ok := gitBlobID(filepath.Join(root, "a.txt"))
	if !ok {
		t.Fatal("cannot hash the file")
	}
	b, _ := json.Marshal([]map[string]any{{
		"BlobID": blob, "RuleID": "np.unnamed.1", "Groups": [][]byte{[]byte("appuser"), []byte(pw)},
		"Location": map[string]any{"Source": map[string]any{"Start": map[string]any{"Line": 1}}},
		"Snippet":  map[string]any{"Before": []byte("login "), "Matching": []byte("appuser:" + pw), "After": []byte(" now")},
	}})
	e := scriptEngine(t, "titus", f.kr, string(b), "", 0)
	var hits []core.Hit
	if err := e.ScanDir(context.Background(), root, testOpts(), func(h core.Hit) { hits = append(hits, h) }); err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 {
		t.Fatalf("%d hits", len(hits))
	}
	assertSafe(t, "titus", hits) // the password is registered: it must be nowhere in the hit
	if !strings.HasPrefix(hits[0].Context, "login ") || !strings.HasSuffix(hits[0].Context, " now") {
		t.Errorf("context lost its surroundings: %q", hits[0].Context)
	}
}
