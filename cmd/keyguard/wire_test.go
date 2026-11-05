package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"keyguard/internal/core"
	"keyguard/internal/engines"
	"keyguard/internal/install"
	"keyguard/internal/inventory/ghcli"
	"keyguard/internal/inventory/ghcli/ghclitest"
	"keyguard/internal/mirror"
	"keyguard/internal/sweep"
	"keyguard/internal/testkit"
	"keyguard/internal/upgrade"
)

// fakeEngines puts four tiny engines in front of the real ones on PATH, so that install finds,
// copies, pins and runs them like any engine and the test copies no 170 MB binary. They answer
// "version" and nothing else.
func fakeEngines(t *testing.T, dir string) string {
	t.Helper()
	bin := filepath.Join(dir, "fakebin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range engines.Names {
		script := "#!/bin/sh\necho '" + name + " version 9.9.9'\n"
		if err := os.WriteFile(filepath.Join(bin, name), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	return bin
}

func fileHash(t testing.TB, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// A small stand-in for the binary install copies: the test binary is 20 MB.
func fakeExe(t *testing.T, dir string) string {
	t.Helper()
	p := filepath.Join(dir, "keyguard-src")
	if err := os.WriteFile(p, []byte("#!/bin/sh\necho keyguard-test-binary\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestInstallCopiesEnginesAndEnginesCommandsManageThem(t *testing.T) {
	w := newWorld(t)
	src := fakeEngines(t, w.m.dir)
	w.seams.exe = fakeExe(t, w.m.dir)

	out := w.mustCLI("install", "--no-bootstrap", "--launchd-dir", w.m.launch)
	for _, want := range []string{"engine", "created", GuardMatcherForTest, "! f="} {
		if !strings.Contains(out, want) {
			t.Errorf("install output lacks %q:\n%s", want, out)
		}
	}
	cfg, err := install.LoadConfig(w.paths, w.m.home)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range engines.Names {
		want := install.EnginePath(w.paths, name, "9.9.9")
		if cfg.Engines[name] != want || cfg.Pins[name].SHA256 != fileHash(t, filepath.Join(src, name)) {
			t.Errorf("%s: engine %s pin %+v", name, cfg.Engines[name], cfg.Pins[name])
		}
	}

	list := w.mustCLI("engines", "list")
	for _, name := range engines.Names {
		if !strings.Contains(list, name) {
			t.Errorf("engines list lacks %s:\n%s", name, list)
		}
	}
	if strings.Count(list, "pinned") != 4 || strings.Contains(list, "CHANGED") {
		t.Errorf("four pinned engines:\n%s", list)
	}
	var rows []struct{ Engine, Version, State string }
	if err := json.Unmarshal([]byte(w.mustCLI("engines", "list", "--json")), &rows); err != nil || len(rows) != 4 || rows[0].Version != "9.9.9" {
		t.Errorf("engines list --json: %v %+v", err, rows)
	}

	// Somebody replaces a pinned copy. It no longer runs, and the list says so with an exit code.
	copyPath := cfg.Engines["gitleaks"]
	if err := os.WriteFile(copyPath, []byte("#!/bin/sh\necho 'gitleaks version 9.9.9'\n# changed\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	list, _, code := w.cli("engines", "list")
	if code != exitFound || !strings.Contains(list, "CHANGED since it was pinned") {
		t.Errorf("a changed copy: exit %d\n%s", code, list)
	}

	// Pinning on purpose takes the binary named and puts the changed copy aside, never over it.
	out = w.mustCLI("engines", "pin", "gitleaks", filepath.Join(src, "gitleaks"))
	if !strings.Contains(out, "pinned gitleaks 9.9.9") {
		t.Errorf("pin: %s", out)
	}
	if fileHash(t, copyPath) != fileHash(t, filepath.Join(src, "gitleaks")) {
		t.Error("the pinned copy is not the binary that was named")
	}
	aside, _ := filepath.Glob(filepath.Join(w.paths.Root, ".superseded", "*", "gitleaks-9.9.9"))
	if len(aside) != 1 {
		t.Errorf("the copy it replaced was not kept: %v", aside)
	}
	if list, _, code = w.cli("engines", "list"); code != exitOK || strings.Contains(list, "CHANGED") {
		t.Errorf("after pinning: exit %d\n%s", code, list)
	}
	if out = w.mustCLI("engines", "pin", "gitleaks", filepath.Join(src, "gitleaks")); !strings.Contains(out, "already pinned") {
		t.Errorf("pinning the same bytes again: %s", out)
	}

	for _, args := range [][]string{{"engines", "pin", "nonesuch"}, {"engines", "pin", "gitleaks", filepath.Join(w.m.dir, "no-such-file")}} {
		if _, errs, code := w.cli(args...); code != exitFailed || errs == "" {
			t.Errorf("%v: exit %d %q", args, code, errs)
		}
	}
	if _, _, code := w.cli("engines"); code != exitUsage {
		t.Errorf("engines with nothing: %d", code)
	}
	if _, errs, code := w.cli("engines", "frobnicate"); code != exitUsage || !strings.Contains(errs, "check-upgrade") {
		t.Errorf("an unknown engines command: %d %q", code, errs)
	}
}

// doctorReport is the quick doctor, run the way the CLI runs it.
func (w *world) doctorReport() install.Report {
	w.t.Helper()
	c := &cli{ctx: context.Background(), in: strings.NewReader(""), out: &strings.Builder{}, err: &strings.Builder{}, seams: w.seams}
	rep, err := install.Doctor(c.ctx, c.doctorOptions(w.paths, true))
	if err != nil {
		w.t.Fatal(err)
	}
	return rep
}

// GuardMatcherForTest is the matcher install prints, spelled out so a change to it is seen.
const GuardMatcherForTest = "Bash|Write|Edit|MultiEdit|NotebookEdit|mcp__.*"

// fakeReleases is GitHub's releases API for titus and the files behind it, on a local server.
func fakeReleases(t *testing.T, tags map[string]string) *httptest.Server {
	t.Helper()
	files := map[string][]byte{}
	var rels []map[string]any
	for tag, label := range tags {
		ver := strings.TrimPrefix(tag, "v")
		bin := []byte("#!/bin/sh\n# engine " + label + "\necho 'titus version " + ver + "'\n")
		sum := sha256.Sum256(bin)
		hexSum := hex.EncodeToString(sum[:])
		files["/dl/"+tag+"/titus-darwin-arm64"] = bin
		files["/dl/"+tag+"/checksums.txt"] = []byte(hexSum + "  titus-darwin-arm64\n")
		rels = append(rels, map[string]any{"tag_name": tag, "draft": false, "prerelease": false, "assets": []map[string]any{
			{"name": "titus-darwin-arm64", "browser_download_url": "@@" + "/dl/" + tag + "/titus-darwin-arm64", "size": len(bin), "digest": "sha256:" + hexSum},
			{"name": "checksums.txt", "browser_download_url": "@@" + "/dl/" + tag + "/checksums.txt", "size": 80},
		}})
	}
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if body, ok := files[r.URL.Path]; ok {
			rw.Write(body)
			return
		}
		if r.URL.Path == "/repos/praetorian-inc/titus/releases" {
			b, _ := json.Marshal(rels)
			rw.Write([]byte(strings.ReplaceAll(string(b), "@@", srv.URL)))
			return
		}
		http.NotFound(rw, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// The weekly engine check: it decides, writes the decision down, and changes nothing until it is
// told to with --apply.
func TestCheckUpgradeDecidesAndOnlyApplyChangesAnything(t *testing.T) {
	w := newWorld(t)
	fakeEngines(t, w.m.dir)
	w.seams.exe = fakeExe(t, w.m.dir)
	w.mustCLI("install", "--no-bootstrap", "--launchd-dir", w.m.launch)
	cfgBefore, _ := install.LoadConfig(w.paths, w.m.home)
	pinBefore := cfgBefore.Pins["titus"]

	srv := fakeReleases(t, map[string]string{"v9.10.0": "new", "v9.9.9": "old"})
	w.seams.upgradeAPI = srv.URL
	scores := map[string]upgrade.Row{
		"old": {Version: "9.9.9", Recall: 0.95, RecallAll: 0.80, Precision: 0.97, Seconds: 1.0},
		"new": {Version: "9.10.0", Recall: 0.96, RecallAll: 0.82, Precision: 0.98, Seconds: 1.0},
	}
	w.seams.scorer = upgrade.ScorerFunc(func(_ context.Context, _ string, bin string) (upgrade.Row, error) {
		b, err := os.ReadFile(bin)
		if err != nil {
			return upgrade.Row{}, err
		}
		if strings.Contains(string(b), "titus version 9.10.0") {
			return scores["new"], nil
		}
		return scores["old"], nil
	})

	out, errs, code := w.cli("engines", "check-upgrade", "--engines", "titus", "--runs", "1")
	if code != exitOK {
		t.Fatalf("check-upgrade: exit %d\n%s\n%s", code, out, errs)
	}
	for _, want := range []string{"titus", "9.9.9", "9.10.0", "BETTER", "--apply"} {
		if !strings.Contains(out, want) {
			t.Errorf("the table lacks %q:\n%s", want, out)
		}
	}
	// Nothing was switched: the pin, the config, the bin directory.
	cfg, _ := install.LoadConfig(w.paths, w.m.home)
	if cfg.Pins["titus"] != pinBefore || cfg.Engines["titus"] != cfgBefore.Engines["titus"] {
		t.Errorf("a check without --apply changed the pin: %+v", cfg.Pins["titus"])
	}
	if _, err := os.Stat(install.EnginePath(w.paths, "titus", "9.10.0")); err == nil {
		t.Error("a check without --apply put a new engine in bin")
	}
	rec, ok := install.LoadUpgrade(w.paths)
	if !ok || len(rec.Engines) != 1 || !rec.Engines[0].Switch || rec.Engines[0].Applied || rec.Engines[0].Latest != "9.10.0" {
		t.Fatalf("the decision was not recorded: %+v ok=%v", rec, ok)
	}
	if dated, _ := filepath.Glob(filepath.Join(install.UpgradeDir(w.paths), "2*.json")); len(dated) != 1 {
		t.Errorf("a dated copy of the decision was not kept: %v", dated)
	}
	// What it staged is cleaned up: the data root is left with the engines and no download.
	if left, _ := filepath.Glob(filepath.Join(upgradeRoot(w.paths), "*")); len(left) != 0 {
		t.Errorf("the check left its staging behind: %v", left)
	}
	// The doctor now says a better engine is waiting, and whose call it is to take it.
	rep := w.doctorReport()
	c, found := findCheck(rep, "engines.upgrade")
	if !found || c.Status != install.Warn || !strings.Contains(c.Summary, "titus 9.10.0") || !slices.Contains(rep.Triage().NeedsUser, c.Fix) {
		t.Errorf("the doctor does not show the waiting engine: %+v found=%v", c, found)
	}

	// --apply takes it, verified against the release's own checksum, and the old copy stays.
	out, errs, code = w.cli("engines", "check-upgrade", "--engines", "titus", "--runs", "1", "--apply")
	if code != exitOK || !strings.Contains(out, "SWITCHED to 9.10.0") {
		t.Fatalf("--apply: exit %d\n%s\n%s", code, out, errs)
	}
	cfg, _ = install.LoadConfig(w.paths, w.m.home)
	want := install.EnginePath(w.paths, "titus", "9.10.0")
	if cfg.Engines["titus"] != want || cfg.Pins["titus"].Version != "9.10.0" || cfg.Pins["titus"].SHA256 != fileHash(t, want) {
		t.Errorf("after --apply: %s %+v", cfg.Engines["titus"], cfg.Pins["titus"])
	}
	if _, err := os.Stat(install.EnginePath(w.paths, "titus", "9.9.9")); err != nil {
		t.Error("the pinned copy it replaced is gone: going back needs it")
	}
	rec, _ = install.LoadUpgrade(w.paths)
	if len(rec.Engines) != 1 || !rec.Engines[0].Applied {
		t.Errorf("the record does not say it was applied: %+v", rec)
	}
	// And now it is the best on offer.
	if out, _, code = w.cli("engines", "check-upgrade", "--engines", "titus", "--runs", "1"); code != exitOK || strings.Contains(out, "BETTER") {
		t.Errorf("after the switch there is nothing better: %d\n%s", code, out)
	}
}

// A candidate that fails the gate is kept out, and says why.
func TestCheckUpgradeRefusesASlowerCandidate(t *testing.T) {
	w := newWorld(t)
	fakeEngines(t, w.m.dir)
	w.seams.exe = fakeExe(t, w.m.dir)
	w.mustCLI("install", "--no-bootstrap", "--launchd-dir", w.m.launch)
	srv := fakeReleases(t, map[string]string{"v9.10.0": "new", "v9.9.9": "old"})
	w.seams.upgradeAPI = srv.URL
	w.seams.scorer = upgrade.ScorerFunc(func(_ context.Context, _ string, bin string) (upgrade.Row, error) {
		b, _ := os.ReadFile(bin)
		if strings.Contains(string(b), "titus version 9.10.0") {
			return upgrade.Row{Version: "9.10.0", Recall: 0.95, RecallAll: 0.80, Precision: 0.97, Seconds: 1.5}, nil
		}
		return upgrade.Row{Version: "9.9.9", Recall: 0.95, RecallAll: 0.80, Precision: 0.97, Seconds: 1.0}, nil
	})
	out, errs, code := w.cli("engines", "check-upgrade", "--engines", "titus", "--runs", "1", "--apply")
	if code != exitOK || strings.Contains(out, "SWITCHED") || !strings.Contains(out, "kept") || !strings.Contains(out, "speed") {
		t.Fatalf("a slower candidate: exit %d\n%s\n%s", code, out, errs)
	}
	cfg, _ := install.LoadConfig(w.paths, w.m.home)
	if cfg.Pins["titus"].Version != "9.9.9" {
		t.Errorf("--apply switched to a candidate that failed the gate: %+v", cfg.Pins["titus"])
	}
	if rec, _ := install.LoadUpgrade(w.paths); rec.Engines[0].Switch {
		t.Errorf("the record says a failing candidate is better: %+v", rec)
	}
}

// With GitHub unreachable the check says so and exits non-zero, which a launchd log shows.
func TestCheckUpgradeSaysWhenItCouldNotLook(t *testing.T) {
	w := newWorld(t)
	fakeEngines(t, w.m.dir)
	w.seams.exe = fakeExe(t, w.m.dir)
	w.mustCLI("install", "--no-bootstrap", "--launchd-dir", w.m.launch)
	srv := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)
	w.seams.upgradeAPI = srv.URL
	w.seams.scorer = upgrade.ScorerFunc(func(_ context.Context, _ string, _ string) (upgrade.Row, error) { return upgrade.Row{}, nil })
	out, _, code := w.cli("engines", "check-upgrade", "--engines", "titus")
	if code != exitFailed || !strings.Contains(out, "could not check") {
		t.Errorf("exit %d\n%s", code, out)
	}
	rec, ok := install.LoadUpgrade(w.paths)
	if !ok || rec.Engines[0].Error == "" {
		t.Errorf("the failure was not recorded: %+v", rec)
	}
}

// ----- a hook with an engine that is not the pinned binary -----

func TestHookTakesTheNextEngineWhenOneIsNotThePinnedBinary(t *testing.T) {
	w := newWorld(t)
	fakeEngines(t, w.m.dir)
	w.seams.exe = fakeExe(t, w.m.dir)
	w.mustCLI("install", "--no-bootstrap", "--launchd-dir", w.m.launch)

	var errb strings.Builder
	h := &hookEnv{c: &cli{ctx: context.Background(), out: &errb, err: &errb, seams: w.seams}, paths: w.paths}
	e, err := h.engine(install.TierPreCommit)
	if err != nil || e.Name() != "betterleaks" {
		t.Fatalf("a pinned engine: %v %v", e, err)
	}

	// betterleaks is swapped for something else.
	cfg, _ := install.LoadConfig(w.paths, w.m.home)
	if err := os.WriteFile(cfg.Engines["betterleaks"], []byte("#!/bin/sh\necho 'betterleaks version 9.9.9'\n# swapped\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	h = &hookEnv{c: &cli{ctx: context.Background(), out: &errb, err: &errb, seams: w.seams}, paths: w.paths}
	e, err = h.engine(install.TierPreCommit)
	if err != nil || e.Name() != "gitleaks" {
		t.Fatalf("the next engine of the tier should be taken: %v %v", e, err)
	}
	h.engine(install.TierPreCommit)
	h.engine(install.TierPrePush)
	if n := strings.Count(errb.String(), "betterleaks is not the binary that was pinned"); n != 1 {
		t.Errorf("the refusal was said %d times, want once per hook:\n%s", n, errb.String())
	}

	// Every engine of the tier is refused: the hook has none to use and says why.
	if err := os.WriteFile(cfg.Engines["gitleaks"], []byte("#!/bin/sh\necho 'gitleaks version 9.9.9'\n# swapped\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	h = &hookEnv{c: &cli{ctx: context.Background(), out: &errb, err: &errb, seams: w.seams}, paths: w.paths}
	if e, err := h.engine(install.TierPreCommit); err == nil || !strings.Contains(err.Error(), "betterleaks, gitleaks changed since it was pinned") {
		t.Errorf("every engine refused: %v %v", e, err)
	}
	// Engines of other tiers that were never touched still run.
	if e, err := h.engine(install.TierVerify); err != nil || e.Name() != "trufflehog" {
		t.Errorf("an untouched engine: %v %v", e, err)
	}
}

// A sweep or a publish check never reads an engine that would not run as a clean scan (PLAN
// invariant 5): it fails, and the output says why. Control first: the same machine, the same
// repo and the pin that is right, clean.
func TestPublishCheckFailsWhenTheEngineIsNotThePinnedBinary(t *testing.T) {
	w := newWorld(t)
	repo := w.m.repo("clean-repo")
	w.commit(repo, "init", map[string]string{"README.md": "hello\n"})

	// The real betterleaks, pinned where it is: the same machine, the same repo, the right pin.
	cfg, err := install.LoadConfig(w.paths, w.m.home)
	if err != nil {
		t.Fatal(err)
	}
	testkit.EnginePath(t, "betterleaks") // skips here, but fails under KEYGUARD_TEST_REQUIRE_ENGINES=1
	if cfg.Engines["betterleaks"] == "" {
		t.Fatal("the test kit finds betterleaks and the installer's own search does not")
	}
	pin := install.PinEngines(cfg)["betterleaks"]
	cfg.Pins = map[string]install.Pin{"betterleaks": pin}
	cfg.Tiers[install.TierDeep], cfg.Tiers[install.TierPoll] = []string{"betterleaks"}, []string{"betterleaks"}
	if err := cfg.Save(w.paths); err != nil {
		t.Fatal(err)
	}
	if out, errs, code := w.cli("publish-check", "--no-verify", repo); code != exitOK || !strings.Contains(out, "clean") {
		t.Fatalf("the control (the right pin): exit %d\n%s\n%s", code, out, errs)
	}

	cfg.Pins["betterleaks"] = install.Pin{Version: pin.Version, SHA256: strings.Repeat("0", 64)}
	if err := cfg.Save(w.paths); err != nil {
		t.Fatal(err)
	}
	out, errs, code := w.cli("publish-check", "--no-verify", repo)
	if code == exitOK || strings.Contains(out, "clean:") {
		t.Fatalf("a binary that is not the pinned one was read as a clean scan: exit %d\n%s\n%s", code, out, errs)
	}
	if !strings.Contains(out+errs, "pinned") {
		t.Errorf("the failure does not say why:\n%s\n%s", out, errs)
	}
	// A sweep says the same thing about its sources: failed, never scanned and called quiet.
	w.addRepo("open", core.Public)
	w.commit(w.origins["github.com/o/open"], "init", map[string]string{"README.md": "hello\n"})
	out = w.mustCLI("poll", "--no-daily", "--no-verify")
	if !strings.Contains(out, "FAILED") && !strings.Contains(out, "pinned") {
		t.Errorf("a poll with an engine it must not run said nothing:\n%s", out)
	}
}

// ----- the daily survey of GitHub's own protection -----

func TestDailyCheckSurveysGitHubAndRaisesAnAlertWhenProtectionWentOff(t *testing.T) {
	w := newWorld(t)
	w.config("betterleaks")
	w.addRepo("open", core.Public)
	w.addRepo("also", core.Public)
	w.saveInventorySnapshot()

	on := map[string]map[string]string{
		"o/open": {"secret_scanning": "enabled", "secret_scanning_push_protection": "enabled"},
		"o/also": {"secret_scanning": "enabled", "secret_scanning_push_protection": "enabled"},
	}
	fk := ghclitest.New(t, func(c ghclitest.Call) ghclitest.Reply {
		name := strings.TrimPrefix(c.Path, "repos/")
		sa := map[string]any{}
		for f, v := range on[name] {
			sa[f] = map[string]string{"status": v}
		}
		return ghclitest.JSON(200, map[string]any{"full_name": name, "security_and_analysis": sa})
	}, "o")
	w.seams.gh = ghcli.New(fk)

	broken := filepath.Join(w.m.dir, "broken")
	if err := os.WriteFile(broken, []byte("#!/bin/sh\nexit 3\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	w.seams.exe = broken

	out := w.mustCLI("poll", "--daily", "--no-verify")
	if !strings.Contains(out, "GitHub protects 2 of 2 repos") {
		t.Errorf("the daily check should say what GitHub protects:\n%s", out)
	}
	pr, ok := install.LoadProtection(w.paths)
	if !ok || pr.Protected != 2 || len(pr.Gaps) != 0 || len(pr.Drift) != 0 {
		t.Fatalf("the first survey: %+v ok=%v", pr, ok)
	}

	// A day later one repo's secret scanning is off. That is the alert, by name, at high severity.
	on["o/also"]["secret_scanning"] = "disabled"
	before := len(w.notices.list())
	out = w.mustCLI("poll", "--daily", "--no-verify")
	pr, _ = install.LoadProtection(w.paths)
	if len(pr.Drift) != 1 || pr.Drift[0].Source != "github.com/o/also" || pr.Drift[0].Feature != "secret_scanning" || len(pr.Gaps) != 1 {
		t.Fatalf("the second survey: %+v", pr)
	}
	var alert *notice
	for _, n := range w.notices.list()[before:] {
		if strings.Contains(n.body, "GitHub protection went off") {
			alert = &n
		}
	}
	if alert == nil || alert.sev != core.High || !strings.Contains(alert.body, "o/also secret scanning") {
		t.Fatalf("no alert about protection going off: %+v\n%s", w.notices.list()[before:], out)
	}
	rep := w.doctorReport()
	if c, found := findCheck(rep, "github.protection"); !found || c.Status != install.Fail {
		t.Errorf("the doctor does not fail on a drift: %+v", c)
	}
	// Nothing in what was written holds anything but names and counts.
	if b, _ := os.ReadFile(install.ProtectionPath(w.paths)); strings.Contains(string(b), "token") {
		t.Errorf("the summary holds more than names and counts: %s", b)
	}
}

// ----- run records -----

func TestArchiveRunsFilesQuietPollsAfterADayAndKeepsTheRest(t *testing.T) {
	p := core.PathsAt(t.TempDir())
	if err := os.MkdirAll(p.Runs, 0o700); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	record := func(name string, st core.RunStats) {
		t.Helper()
		b, _ := json.Marshal(st)
		if err := os.WriteFile(filepath.Join(p.Runs, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	quiet := core.RunStats{Kind: "poll", Sources: 13, Skipped: 13}
	record("20261102T090000.000Z.json", quiet)                                                                               // yesterday, did nothing
	record("20261102T090100.000Z.json", core.RunStats{Kind: "poll", Scanned: 1, NewFPs: 1})                                  // yesterday, found a key
	record("20261102T090200.000Z.json", core.RunStats{Kind: "poll", Failed: 1})                                              // yesterday, a source failed
	record("20261102T090300.000Z.json", core.RunStats{Kind: "full"})                                                         // yesterday, not a poll
	record("20261102T090400.000Z.json", core.RunStats{Kind: "poll", Engines: map[string]core.EngineStats{"x": {Errors: 1}}}) // an engine failed
	record("20261103T113000.000Z.json", quiet)                                                                               // half an hour ago: too new to file
	record("20261001T010000.000Z.json", core.RunStats{Kind: "poll", Scanned: 2})                                             // 33 days old, found something

	archiveRuns(p, now)

	filed := filepath.Join(p.Runs, "archive", "202611", "20261102", "20261102T090000.000Z.json")
	if _, err := os.Stat(filed); err != nil {
		t.Errorf("the quiet poll of yesterday was not filed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(p.Runs, "archive", "202610", "20261001T010000.000Z.json")); err != nil {
		t.Errorf("the old record was not filed by month: %v", err)
	}
	for _, stays := range []string{"20261102T090100.000Z.json", "20261102T090200.000Z.json", "20261102T090300.000Z.json", "20261102T090400.000Z.json", "20261103T113000.000Z.json"} {
		if _, err := os.Stat(filepath.Join(p.Runs, stays)); err != nil {
			t.Errorf("%s should have stayed where the doctor reads it: %v", stays, err)
		}
	}
	// Nothing is deleted: everything that is not in runs/ is under runs/archive/.
	var count int
	_ = filepath.WalkDir(p.Runs, func(path string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(path, ".json") {
			count++
		}
		return nil
	})
	if count != 7 {
		t.Errorf("%d records on disk, want all 7", count)
	}
	// The cursor spares the next pass the records it has already looked at.
	if b, _ := os.ReadFile(filepath.Join(p.Runs, ".compacted")); !strings.HasPrefix(string(b), "20261102T0904") {
		t.Errorf("cursor: %q", b)
	}
	// An hour on, the half-hour-old quiet poll is still too new; a day on, it is filed.
	archiveRuns(p, now.Add(time.Hour))
	if _, err := os.Stat(filepath.Join(p.Runs, "20261103T113000.000Z.json")); err != nil {
		t.Error("filed too soon")
	}
	archiveRuns(p, now.Add(25*time.Hour))
	if _, err := os.Stat(filepath.Join(p.Runs, "archive", "202611", "20261103", "20261103T113000.000Z.json")); err != nil {
		t.Errorf("a day later the quiet poll should be filed: %v", err)
	}
}

// The openers: a hook never makes a salt, anything else may the first time.
func TestOpenKeyringHookNeverMintsASalt(t *testing.T) {
	p := core.PathsAt(t.TempDir())
	if _, err := openKeyringHook(p); err == nil || !strings.Contains(err.Error(), "keyguard install") {
		t.Errorf("a hook with no salt: %v", err)
	}
	if _, err := os.Stat(filepath.Join(p.Known, "salt")); err == nil {
		t.Fatal("a hook made a salt")
	}
	if _, err := openKeyring(p); err != nil {
		t.Fatal(err)
	}
	a, err := openKeyringHook(p)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := openKeyring(p)
	if a.FP("x") != b.FP("x") {
		t.Error("the two openers read different salts")
	}
}

func TestFlagsOnScan(t *testing.T) {
	w := newWorld(t)
	if _, errs, code := w.cli("scan", "--fresh", "--no-ledger"); code != exitUsage || !strings.Contains(errs, "contradict") {
		t.Errorf("--fresh with --no-ledger: exit %d %q", code, errs)
	}
}

// activityInv is the world's inventory with the one thing the real one adds: it names the pages
// (an issue, a pull request, a release) whose text changed, by exact URL.
type activityInv struct {
	fakeInv
	pages []sweep.Activity
}

func (a *activityInv) ChangedActivity(ctx context.Context, prev map[string]core.Source) ([]core.Source, []core.Event, []sweep.Activity, error) {
	changed, events, err := a.Changed(ctx, prev)
	return changed, events, a.pages, err
}

// STEAL P0-22: a page that changed is read by its exact URL with the token of the account that can
// see it, and the sweep gets that token from gh, by account, when it needs one. Left unwired the
// sweep says there is no token source and scans nothing, which is a quiet hole in the API scans.
// gh here holds a token for nobody, so no scanner is started and nothing reaches a network.
func TestPollAsksGHForTheTokenOfTheAccountThatOwnsAChangedPage(t *testing.T) {
	w := newWorld(t)
	w.config("betterleaks")
	a := w.addRepo("a", core.Public)
	w.commit(a, "init", map[string]string{"a.txt": "1\n"})
	fk := ghclitest.New(t, func(ghclitest.Call) ghclitest.Reply {
		return ghclitest.JSON(404, map[string]string{"message": "Not Found"})
	}, "somebody-else")
	w.seams.gh = ghcli.New(fk)
	inv := &activityInv{fakeInv: fakeInv{w}, pages: []sweep.Activity{
		{Source: "github.com/o/a", Kind: "issue", URL: "https://github.com/o/a/issues/7", At: "2026-11-03T09:00:00Z"},
	}}
	w.seams.inventory = func(install.Config, core.Paths) (core.Inventory, error) { return inv, nil }

	out, errs, code := w.cli("poll", "--no-daily", "--no-verify")
	if strings.Contains(out, "Config.Token is not set") {
		t.Fatalf("the sweep was given no token source:\n%s", out)
	}
	if !strings.Contains(out, `no GitHub token for "o"`) {
		t.Fatalf("the sweep did not ask for the token of the account that owns the page (exit %d):\n%s\n%s", code, out, errs)
	}
	asked := false
	for _, c := range fk.Commands() {
		asked = asked || (slices.Contains(c, "token") && slices.Contains(c, "o"))
	}
	if !asked {
		t.Errorf("gh was never asked for a token: %v", fk.Commands())
	}
}

// PLAN.md "Sweep scope": whatever a command asks for, the mirror it builds refuses a source a
// stranger cannot read before git starts. The git here records its calls and fails, so a mirror
// that did go on to fetch would show in the record and nothing could reach a network.
func TestTheMirrorTheCLIBuildsRefusesAPrivateSource(t *testing.T) {
	dir := t.TempDir()
	rec := filepath.Join(dir, "calls")
	git := filepath.Join(dir, "git")
	if err := os.WriteFile(git, []byte("#!/bin/sh\necho \"$@\" >> '"+rec+"'\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := mirrorConfig(install.Config{}, core.PathsAt(filepath.Join(dir, "root")), false)
	cfg.Git = git
	m, err := mirror.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	closed := core.Source{ID: "github.com/o/closed", Kind: "repo", Owner: "o", Name: "closed", Account: "o",
		CloneURL: "https://github.com/o/closed.git", Visibility: core.Private}
	if _, _, err := m.Sync(context.Background(), closed); !errors.Is(err, mirror.ErrNotExposed) {
		t.Fatalf("a private source was not refused: %v", err)
	}
	if b, _ := os.ReadFile(rec); len(b) != 0 {
		t.Fatalf("git ran for a source that was refused:\n%s", b)
	}
	if noFetch := mirrorConfig(install.Config{}, core.PathsAt(dir), true); !noFetch.NoFetch || !noFetch.ExposedOnly {
		t.Errorf("--no-fetch must keep the scope: %+v", noFetch)
	}
}

// STEAL P0-14: the guard answers for the tools that write a file as well as for Bash. A learned key
// in the content of a Write, the new_string of an Edit or one edit of a MultiEdit, a notebook cell,
// or the input of an MCP tool is denied in the decision shape Claude Code reads, and the reason is
// made of shapes: it never repeats the value.
func TestGuardClaudeDeniesAKeyInTheInputOfEveryToolThatCanWriteOne(t *testing.T) {
	m := newMachine(t)
	key := fakeKey(t, "sk-proj-", 48)
	m.learn("OPENAI_API_KEY", key)
	call := func(tool string, in map[string]any) result {
		b, _ := json.Marshal(map[string]any{"tool_name": tool, "tool_input": in, "cwd": m.dir})
		return m.kgIn(string(b), "guard", "claude")
	}
	file := filepath.Join(m.dir, "app.py")
	body := "K = \"" + key + "\"\n"
	for name, r := range map[string]result{
		"Write":        call("Write", map[string]any{"file_path": file, "content": body}),
		"Edit":         call("Edit", map[string]any{"file_path": file, "old_string": "x", "new_string": body}),
		"MultiEdit":    call("MultiEdit", map[string]any{"file_path": file, "edits": []map[string]string{{"old_string": "x", "new_string": body}}}),
		"NotebookEdit": call("NotebookEdit", map[string]any{"notebook_path": file, "new_source": body}),
		"an MCP tool":  call("mcp__files__write", map[string]any{"path": file, "text": body}),
	} {
		if r.code != 2 || !strings.Contains(r.out, `"permissionDecision":"deny"`) {
			t.Errorf("%s with a learned key should be denied with the PreToolUse decision: exit %d\n%s", name, r.code, r.out)
		}
		if strings.Contains(r.out, key) {
			t.Errorf("%s: the reason repeats the key", name)
		}
	}
	if r := call("Write", map[string]any{"file_path": file, "content": "K = os.environ['K']\n"}); r.code != 0 {
		t.Errorf("a Write with no key in it should pass: exit %d\n%s", r.code, r.out)
	}
}

// A poll a minute writes 1,440 run records a day. archiveRuns is tested above on its own; this is
// the poll calling it, which is the only way the directory the doctor reads stays small.
func TestPollFilesYesterdaysQuietRunsAway(t *testing.T) {
	w := newWorld(t)
	w.config("betterleaks")
	w.addRepo("open", core.Public)
	w.saveInventorySnapshot()
	broken := filepath.Join(w.m.dir, "broken")
	if err := os.WriteFile(broken, []byte("#!/bin/sh\nexit 3\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	w.seams.exe = broken // the daily selftest of this binary fails at once; only the housekeeping matters here

	if err := os.MkdirAll(w.paths.Runs, 0o700); err != nil {
		t.Fatal(err)
	}
	stamp := func(at time.Time) string { return at.UTC().Format("20060102T150405.000Z") + ".json" }
	put := func(name string) {
		t.Helper()
		b, _ := json.Marshal(core.RunStats{Kind: "poll", Sources: 1, Skipped: 1})
		if err := os.WriteFile(filepath.Join(w.paths.Runs, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	twoDays := stamp(time.Now().Add(-48 * time.Hour))
	ancient := "20200101T090000.000Z.json"
	put(twoDays)
	put(ancient)

	w.mustCLI("poll", "--daily", "--no-verify")

	for _, name := range []string{twoDays, ancient} {
		if _, err := os.Stat(filepath.Join(w.paths.Runs, name)); err == nil {
			t.Errorf("%s is still where the doctor reads the runs", name)
		}
	}
	if _, err := os.Stat(filepath.Join(w.paths.Runs, "archive", "202001", ancient)); err != nil {
		t.Errorf("the record older than a month was not filed by month: %v", err)
	}
	if _, err := os.Stat(filepath.Join(w.paths.Runs, "archive", twoDays[:6], twoDays[:8], twoDays)); err != nil {
		t.Errorf("yesterday's quiet poll was not filed by day: %v", err)
	}
	var left int
	ents, _ := os.ReadDir(w.paths.Runs)
	for _, e := range ents {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			left++
		}
	}
	if left == 0 {
		t.Error("the poll's own record is not in runs/")
	}
}
