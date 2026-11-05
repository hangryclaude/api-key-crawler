package engines

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"keyguard/internal/core"
	"keyguard/internal/triage"
)

// ----- no silent caps (core.NoteTaker) -----

func TestEnginesAreNoteTakers(t *testing.T) {
	f := getFixture(t)
	for _, name := range Names {
		e, _ := New(name, "/bin/true", f.kr)
		if _, ok := e.(core.NoteTaker); !ok {
			t.Errorf("%s is not a core.NoteTaker", name)
		}
	}
}

func takeNotes(t *testing.T, e core.Engine) []string {
	t.Helper()
	nt, ok := e.(core.NoteTaker)
	if !ok {
		t.Fatalf("%s has no notes", e.Name())
	}
	return nt.TakeNotes()
}

func TestWidenedScanSaysSo(t *testing.T) {
	f := getFixture(t)
	for _, name := range Names {
		t.Run(name, func(t *testing.T) {
			e := newEngine(t, name, f.kr)
			if n := takeNotes(t, e); len(n) != 0 {
				t.Fatalf("notes before any scan: %v", n)
			}
			// A recorded tip the repository no longer has widens the scan instead of failing it.
			scanGit(t, e, f.mirror, core.Range{All: true, Since: map[string]string{"refs/heads/main": strings.Repeat("ab", 20), "refs/heads/feature": f.c["c3"]}}, testOpts())
			notes := takeNotes(t, e)
			if len(notes) != 1 || !strings.Contains(notes[0], "1 recorded tip") {
				t.Errorf("notes %v, want one naming the missing tip", notes)
			}
			if again := takeNotes(t, e); len(again) != 0 {
				t.Errorf("TakeNotes did not forget: %v", again)
			}
			// A range whose tips all exist says nothing.
			scanGit(t, e, f.mirror, core.Range{All: true, Since: map[string]string{"refs/heads/main": f.c["c2"]}}, testOpts())
			if n := takeNotes(t, e); len(n) != 0 {
				t.Errorf("a plain incremental scan left notes: %v", n)
			}
		})
	}
}

func TestTitusSaysWhatItDroppedAndCapped(t *testing.T) {
	f := getFixture(t)
	e := newEngine(t, "titus", f.kr)

	// A blob kept alive only by a tag is in no commit: a ranged scan reports what its commits
	// introduced, so the hit is dropped, and says so.
	repo := worktree(t)
	raw := fake("stripe")
	cmd := gitCmd(context.Background(), repo, nil, "hash-object", "-w", "--stdin")
	cmd.Stdin = strings.NewReader("KEY=" + raw + "\n")
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	gitIn(repo, nil, "tag", "-a", "-m", "keyblob", "keytag", strings.TrimSpace(string(out)))
	resetAudit()
	if hits := scanGit(t, e, repo, core.Range{Revs: []string{"main"}}, testOpts()); len(hits) != 0 {
		t.Fatalf("%d hits", len(hits))
	}
	notes := takeNotes(t, e)
	if len(notes) != 1 || !strings.Contains(notes[0], "1 hit(s) were on blobs that only a tag reaches") {
		t.Errorf("notes %v", notes)
	}
	assertNoRaw(t, "notes", []byte(strings.Join(notes, "\n")))

	// One blob at more than 32 paths reports 32.
	many := worktree(t)
	shared := fake("stripe")
	for i := 0; i < maxBlobLocs+8; i++ {
		writeLines(t, many, fmt.Sprintf("copies/c%02d.env", i), "S="+shared)
	}
	gitIn(many, nil, "add", "-A")
	gitIn(many, nil, "commit", "-q", "-m", "copies")
	resetAudit()
	n := 0
	for _, h := range scanGit(t, e, many, core.Range{All: true}, testOpts()) {
		if h.FP == f.kr.FP(shared) {
			n++
		}
	}
	if n != maxBlobLocs {
		t.Errorf("%d locations for a blob in %d files, want %d", n, maxBlobLocs+8, maxBlobLocs)
	}
	notes = takeNotes(t, e)
	if len(notes) != 1 || !strings.Contains(notes[0], "1 blob(s) are at more than 32 paths") {
		t.Errorf("notes %v", notes)
	}
}

func TestTrufflehogSaysWhenItScannedMoreThanTheRange(t *testing.T) {
	f := getFixture(t)
	e := newEngine(t, "trufflehog", f.kr)
	resetAudit()
	repo := t.TempDir()
	gitIn(repo, nil, "init", "-q", "-b", "main")
	writeLines(t, repo, "old.env", "S="+fake("stripe"))
	gitIn(repo, nil, "add", "-A")
	gitIn(repo, nil, "commit", "-q", "-m", "old")
	base := gitIn(repo, nil, "rev-parse", "HEAD")
	for i := range maxTrufflePasses + 2 {
		gitIn(repo, nil, "checkout", "-q", "-b", fmt.Sprintf("b%d", i), base)
		writeLines(t, repo, fmt.Sprintf("n%d.sh", i), "export NPM_TOKEN="+fake("npm"))
		gitIn(repo, nil, "add", "-A")
		gitIn(repo, nil, "commit", "-q", "-m", "new")
	}
	scanGit(t, e, repo, core.Range{Revs: []string{"--all", "--not", base}}, testOpts())
	notes := takeNotes(t, e)
	if len(notes) != 1 || !strings.Contains(notes[0], fmt.Sprintf("%d new heads", maxTrufflePasses+2)) {
		t.Errorf("notes %v", notes)
	}
}

// When the data root cannot be written the scan still runs, in the system temp dir, and says so.
func TestScratchFallsBackAndSaysSo(t *testing.T) {
	f := getFixture(t)
	blocker := t.TempDir()
	if err := os.WriteFile(blocker+"/kg", []byte("a file where the data root should be"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KEYGUARD_HOME", blocker+"/kg")
	e, _ := recordingEngine(t, "betterleaks", f.kr, "[]", "", 0)
	root := t.TempDir()
	writeLines(t, root, "a.txt", "x")
	if err := e.ScanDir(context.Background(), root, testOpts(), func(core.Hit) {}); err != nil {
		t.Fatalf("a data root that cannot be written stopped the scan: %v", err)
	}
	if n := takeNotes(t, e); len(n) != 1 || !strings.Contains(n[0], "system temp dir") {
		t.Errorf("notes %v", n)
	}
}

// ----- tags: the vocabulary is triage's -----

func TestTagsMatchTriage(t *testing.T) {
	for _, c := range [][2]string{
		{tagPlaceholder, triage.TagPlaceholder}, {tagJWTAnon, triage.TagJWTAnon},
		{tagJWTServiceRole, triage.TagJWTServiceRole}, {tagTestMode, triage.TagTestMode},
	} {
		if c[0] != c[1] {
			t.Errorf("engines tags %q, triage reads %q", c[0], c[1])
		}
	}
}
