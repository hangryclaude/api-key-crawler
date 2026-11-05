package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"keyguard/internal/core"
	"keyguard/internal/db"
	"keyguard/internal/fp"
	"keyguard/internal/inventory/ghcli"
	"keyguard/internal/inventory/ghcli/ghclitest"
)

// openStore reads the findings the way the report does.
func openStore(t testing.TB, w *world) *db.Store {
	t.Helper()
	st, err := db.Open(w.paths)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func keyring(t testing.TB, w *world) *fp.Keyring {
	t.Helper()
	kr, err := fp.Load(w.paths.Known)
	if err != nil {
		t.Fatal(err)
	}
	return kr
}

func fileHolds(t testing.TB, root string, needles ...string) []string {
	t.Helper()
	var bad []string
	filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if rel, _ := filepath.Rel(root, p); strings.HasPrefix(rel, "cache"+string(filepath.Separator)) {
			return nil // mirrors are git stores of the repos being watched, which hold the fakes by construction
		}
		b, _ := os.ReadFile(p)
		for _, n := range needles {
			if strings.Contains(string(b), n) {
				bad = append(bad, p)
			}
		}
		return nil
	})
	return bad
}

// grepHolds asks the system grep which files under root hold any of the values, raw or in
// either base64 form, skipping the mirrors (git stores of the repos being watched).
func grepHolds(t testing.TB, root string, values ...string) string {
	t.Helper()
	args := []string{"-r", "-l", "-a", "-F", "--exclude-dir=cache"}
	for _, v := range values {
		args = append(args, "-e", v,
			"-e", base64.StdEncoding.EncodeToString([]byte(v)),
			"-e", base64.RawURLEncoding.EncodeToString([]byte(v)))
	}
	out, err := exec.Command("grep", append(args, root)...).Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && ee.ExitCode() == 1 {
			return "" // no match
		}
		t.Fatalf("grep: %v", err)
	}
	return string(out)
}

func TestPollScansOnlyWhatAStrangerCanRead(t *testing.T) {
	w := newWorld(t)
	w.config("betterleaks")
	learned := fakeKey(t, "sk-proj-", 48)
	w.m.learn("OPENAI_API_KEY", learned)
	token := fakeKey(t, "ghp_", 36)

	open := w.addRepo("open", core.Public)
	closed := w.addRepo("closed", core.Private)
	w.commit(open, "init", map[string]string{"deploy.env": "OPENAI_API_KEY=" + learned + "\n", "app.py": "T = \"" + token + "\"\n"})
	w.commit(closed, "init", map[string]string{"deploy.env": "OPENAI_API_KEY=" + learned + "\n"})

	out := w.mustCLI("poll", "--no-daily", "--no-verify")
	if !strings.Contains(out, "poll: sources 1 scanned 1") && !strings.Contains(out, "scanned 1") {
		t.Fatalf("the first poll should scan the one public repo:\n%s", out)
	}
	if !strings.Contains(out, "private source(s) were listed and left alone") {
		t.Errorf("the poll does not say it left a private repo alone:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(w.paths.Mirrors, "github.com", "o", "closed.git")); err == nil {
		t.Fatal("the private repo was fetched")
	}
	if _, err := os.Stat(filepath.Join(w.paths.Mirrors, "github.com", "o", "open.git")); err != nil {
		t.Fatalf("the public repo was not fetched: %v", err)
	}

	st := openStore(t, w)
	kr := keyring(t, w)
	sec, ok := st.Get(kr.FP(learned))
	if !ok || sec.Known == "" || sec.Severity != core.Critical {
		t.Fatalf("a learned key in a public repo should be critical: %+v ok=%v", sec, ok)
	}
	for _, l := range sec.Locations {
		if !strings.HasSuffix(l.Source, "/open") {
			t.Errorf("a location in %s: the private repo must not have been scanned", l.Source)
		}
	}
	tok, ok := st.Get(kr.FP(token))
	if !ok || tok.Severity < core.Medium || !tok.Exposed() {
		t.Fatalf("the token in the public repo: %+v ok=%v", tok, ok)
	}

	crit := 0
	for _, n := range w.notices.list() {
		if n.sev == core.Critical {
			crit++
		}
		if strings.Contains(n.title+n.body, learned) || strings.Contains(n.title+n.body, token) {
			t.Fatalf("an alert carries a secret: %q", n.body)
		}
	}
	if crit == 0 {
		t.Fatal("no critical alert for a learned key in a public repo")
	}
	if bad := fileHolds(t, w.paths.Root, learned, token); len(bad) > 0 {
		t.Fatalf("raw secrets on disk: %v", bad)
	}
	// The same claim checked with a different instrument than the Go code that made the files:
	// grep, over the whole data root bar the mirrors, for both values and their base64.
	if out := grepHolds(t, w.paths.Root, learned, token); out != "" {
		t.Fatalf("grep finds a secret in what keyguard wrote:\n%s", out)
	}

	// An idle poll does nothing, and says so on one line.
	idle := w.mustCLI("poll", "--no-daily", "--no-verify")
	if !strings.Contains(idle, "scanned 0") {
		t.Errorf("idle poll:\n%s", idle)
	}

	// The report was written by the poll; `report` rewrites it and --open shows it.
	if _, err := os.Stat(w.paths.Report); err != nil {
		t.Fatalf("no report after a poll: %v", err)
	}
	if b, _ := os.ReadFile(w.paths.Report); strings.Contains(string(b), learned) || !strings.Contains(string(b), sec.ID) {
		t.Error("the report must list the key by id and never hold it")
	}
	rep := strings.TrimSpace(w.mustCLI("report", "--open"))
	if rep != w.paths.Report || len(w.opened) != 1 || w.opened[0] != w.paths.Report {
		t.Errorf("report --open: printed %q opened %v", rep, w.opened)
	}

	// scan: one source, full or not; a private or unknown source is refused, not skipped.
	if got := w.mustCLI("scan", "--full", "--repo", "github.com/o/open", "--no-verify"); !strings.Contains(got, "full finished") {
		t.Errorf("scan --full --repo:\n%s", got)
	}
	if _, errs, code := w.cli("scan", "--repo", "github.com/o/closed", "--no-verify"); code != exitFailed || !strings.Contains(errs, "private") {
		t.Errorf("scan of a private repo: %d %s", code, errs)
	}
	if _, errs, code := w.cli("scan", "--repo", "github.com/o/nowhere", "--no-verify"); code != exitFailed || !strings.Contains(errs, "not in the inventory") {
		t.Errorf("scan of an unknown repo: %d %s", code, errs)
	}
	if got := w.mustCLI("scan", "--no-verify"); !strings.Contains(got, "open findings:") {
		t.Errorf("scan summary:\n%s", got)
	}

	// inventory: the saved one and the live one agree, and list every source, private included.
	cached := w.mustCLI("inventory", "--cached", "--all")
	if !strings.Contains(cached, "github.com/o/closed") || !strings.Contains(cached, "github.com/o/open") {
		t.Errorf("inventory --cached --all:\n%s", cached)
	}
	live, errs, code := w.cli("inventory", "--json")
	var srcs []core.Source
	if code != 0 || json.Unmarshal([]byte(live), &srcs) != nil || len(srcs) != 2 || !strings.Contains(errs, "listed 2 sources") {
		t.Errorf("inventory --json: %d %v\n%s\n%s", code, srcs, live, errs)
	}

	// sync fetches the public one and says it left the private one alone.
	got, errs, code := w.cli("sync")
	if code != 0 || !strings.Contains(errs, "leaving 1 private source alone") || !strings.Contains(got, "1 source:") {
		t.Errorf("sync: %d\n%s\n%s", code, got, errs)
	}
}

func TestVerifyRescansTheReposThatHoldASecret(t *testing.T) {
	w := newWorld(t)
	w.config("gitleaks") // an engine that does not call out, so the test needs no network
	token := fakeKey(t, "ghp_", 36)
	open := w.addRepo("open", core.Public)
	w.commit(open, "oops", map[string]string{"app.py": "T = \"" + token + "\"\n"})
	w.mustCLI("poll", "--no-daily", "--no-verify")

	st := openStore(t, w)
	sec, ok := st.Get(keyring(t, w).FP(token))
	if !ok {
		t.Fatal("the token was not found")
	}
	out := w.mustCLI("verify", sec.ID)
	if !strings.Contains(out, "rescanning 1 source in full") || !strings.Contains(out, sec.ID) || !strings.Contains(out, "unverified") {
		t.Errorf("verify:\n%s", out)
	}
	if got := w.mustCLI("verify", "--all"); !strings.Contains(got, "rescanning 1 source") {
		t.Errorf("verify --all:\n%s", got)
	}
	if _, errs, code := w.cli("verify", "kgffffff"); code != exitFailed || !strings.Contains(errs, "no finding has id") {
		t.Errorf("verify of an unknown id: %d %s", code, errs)
	}
	if _, errs, code := w.cli("verify"); code != exitUsage {
		t.Errorf("verify with nothing to verify: %d %s", code, errs)
	}
}

func TestDeepRelearnsImportsAlertsAndRescans(t *testing.T) {
	w := newWorld(t)
	w.config("gitleaks")
	alertTok := fakeKey(t, "ghp_", 36)
	open := w.addRepo("open", core.Public)
	w.addRepo("closed", core.Private)
	w.commit(open, "init", map[string]string{"README.md": "hello\n"})
	w.m.write(filepath.Join(w.m.home, "dev", "app", ".env"), "STRIPE_SECRET="+fakeKey(t, "sk_live_", 40)+"\n")

	var mu sync.Mutex
	var asked []string
	fk := ghclitest.New(t, func(c ghclitest.Call) ghclitest.Reply {
		mu.Lock()
		asked = append(asked, c.Method+" "+c.Path)
		mu.Unlock()
		if strings.HasPrefix(c.Path, "repos/o/open/secret-scanning/alerts") {
			alert := map[string]any{
				"number": 7, "state": "open", "created_at": "2026-11-01T10:00:00Z",
				"html_url":    "https://github.com/o/open/security/secret-scanning/7",
				"secret_type": "github_personal_access_token", "secret_type_display_name": "GitHub Personal Access Token",
				"validity": "unknown", "publicly_leaked": true, "push_protection_bypassed": false,
			}
			// GitHub leaves the value out when asked to hide it (STEAL P0-20); a server that is not
			// asked sends it. The value then never reaches this process at all.
			if !strings.Contains(c.Path, "hide_secret=true") {
				alert["secret"] = alertTok
			}
			return ghclitest.JSON(200, []map[string]any{alert})
		}
		return ghclitest.JSON(404, map[string]string{"message": "Not Found"})
	}, "o")
	w.seams.gh = ghcli.New(fk)

	out := w.mustCLI("deep", "--no-verify")
	for _, want := range []string{"relearned:", "GitHub alerts imported: 1 alert", "deep finished"} {
		if !strings.Contains(out, want) {
			t.Errorf("deep output lacks %q:\n%s", want, out)
		}
	}
	for _, a := range asked {
		if strings.Contains(a, "closed") {
			t.Errorf("the private repo's alerts were read: %s", a)
		}
	}
	// Keyed to the alert itself, since the value was never sent: the same alert is the same finding.
	sec, ok := openStore(t, w).Get(keyring(t, w).FP("github-alert:github.com/o/open#7"))
	if !ok || !strings.Contains(strings.Join(sec.Engines, ","), "github-alerts") || !sec.Exposed() {
		t.Fatalf("the alert was not imported as an exposed finding: %+v ok=%v", sec, ok)
	}
	if _, found := openStore(t, w).Get(keyring(t, w).FP(alertTok)); found {
		t.Error("a finding is keyed by the alert's token, which GitHub was asked not to send")
	}
	if bad := fileHolds(t, w.paths.Root, alertTok); len(bad) > 0 {
		t.Fatalf("the alert's secret reached disk: %v", bad)
	}
	// The learned key from ~/dev was relearned.
	if got := w.mustCLI("known", "list"); !strings.Contains(got, "STRIPE_SECRET") {
		t.Errorf("deep did not relearn:\n%s", got)
	}
}

func TestGitHubSettingsAuditApplyAndProbe(t *testing.T) {
	w := newWorld(t)
	w.addRepo("on", core.Public)
	w.addRepo("off", core.Public)
	w.addRepo("closed", core.Private)

	var mu sync.Mutex
	state := map[string]map[string]string{
		"o/on":  {"secret_scanning": "enabled", "secret_scanning_push_protection": "enabled", "secret_scanning_non_provider_patterns": "enabled", "secret_scanning_validity_checks": "enabled"},
		"o/off": {"secret_scanning": "disabled", "secret_scanning_push_protection": "disabled", "secret_scanning_non_provider_patterns": "disabled", "secret_scanning_validity_checks": "disabled"},
	}
	var patches []string
	fk := ghclitest.New(t, func(c ghclitest.Call) ghclitest.Reply {
		mu.Lock()
		defer mu.Unlock()
		name := strings.TrimPrefix(strings.SplitN(c.Path, "/secret-scanning", 2)[0], "repos/")
		switch {
		case strings.Contains(c.Path, "/secret-scanning/alerts"):
			return ghclitest.JSON(200, []any{})
		case c.Method == "PATCH" && name == "o/closed":
			patches = append(patches, "PATCH "+name)
			return ghclitest.JSON(422, map[string]any{"message": "Validation Failed", "errors": []string{"Secret scanning is not available for this repository"}})
		case c.Method == "PATCH":
			patches = append(patches, "PATCH "+name+" "+string(c.Body))
			var body struct {
				SA map[string]struct{ Status string } `json:"security_and_analysis"`
			}
			_ = json.Unmarshal(c.Body, &body)
			for f, v := range body.SA {
				state[name][f] = v.Status
			}
		}
		sa := map[string]any{}
		for f, v := range state[name] {
			sa[f] = map[string]string{"status": v}
		}
		return ghclitest.JSON(200, map[string]any{"full_name": name, "security_and_analysis": sa})
	}, "o")
	w.seams.gh = ghcli.New(fk)
	w.saveInventorySnapshot()

	out := w.mustCLI("github-settings", "--no-alerts")
	if !strings.Contains(out, "public repos: 2   private: 1") || !strings.Contains(out, "secret_scanning_push_protection") {
		t.Fatalf("audit:\n%s", out)
	}
	if !strings.Contains(out, "github.com/o/off") || strings.Contains(out, "github.com/o/on  ") {
		t.Errorf("the audit should list the repo that lacks a feature, and only that one:\n%s", out)
	}
	if !strings.Contains(out, "--apply") || !strings.Contains(out, "https://github.com/settings/security_analysis") {
		t.Errorf("the audit should say what --apply does and where the manual setting is:\n%s", out)
	}
	if len(patches) != 0 {
		t.Fatalf("an audit changed GitHub: %v", patches)
	}

	out = w.mustCLI("github-settings", "--apply", "--no-alerts")
	if !strings.Contains(out, "applied: 1 changed, 1 already as wanted") {
		t.Errorf("apply:\n%s", out)
	}
	// A private repo is classified from the GET that reads it, never written to (STEAL P0-18).
	if !strings.Contains(out, "1 private repo cannot be scanned by GitHub on this plan") || !strings.Contains(out, "GitHub protects 2 of 3 repos") {
		t.Errorf("the survey should say what GitHub cannot do for the private repo and the new headline:\n%s", out)
	}
	if !strings.Contains(out, "optional features") || !strings.Contains(out, "secret_scanning_validity_checks") {
		t.Errorf("the plan's optional features were not asked about:\n%s", out)
	}
	for _, p := range patches {
		if strings.HasPrefix(p, "PATCH o/on") {
			t.Errorf("a repo that was already fully on was patched: %s", p)
		}
	}
	if state["o/off"]["secret_scanning"] != "enabled" || state["o/off"]["secret_scanning_push_protection"] != "enabled" {
		t.Errorf("the public repo was not switched on: %v", state["o/off"])
	}
}

func TestTriageExportAndImport(t *testing.T) {
	w := newWorld(t)
	w.config("gitleaks")
	token := fakeKey(t, "ghp_", 36)
	open := w.addRepo("open", core.Public)
	w.commit(open, "oops", map[string]string{"app.py": "T = \"" + token + "\"\n"})
	w.mustCLI("poll", "--no-daily", "--no-verify")
	sec, ok := openStore(t, w).Get(keyring(t, w).FP(token))
	if !ok {
		t.Fatal("no finding to judge")
	}

	file := filepath.Join(w.m.dir, "export.json")
	w.mustCLI("export-triage", "--out", file)
	raw, _ := os.ReadFile(file)
	if strings.Contains(string(raw), token) {
		t.Fatal("the export holds the secret")
	}
	var exp triageExport
	if err := json.Unmarshal(raw, &exp); err != nil || exp.Schema != triageSchema || len(exp.Items) != 1 || exp.Items[0].ID != sec.ID {
		t.Fatalf("export: %v\n%s", err, raw)
	}
	it := exp.Items[0]
	if it.Shape != sec.Shape || len(it.Locations) != 1 || it.Locations[0].Path != "app.py" || !it.Exposed || len(it.Contexts) == 0 {
		t.Errorf("item: %+v", it)
	}
	if fi, _ := os.Stat(file); fi.Mode().Perm() != 0o600 {
		t.Errorf("export mode %v", fi.Mode().Perm())
	}
	// To stdout it is the same document.
	if out := w.mustCLI("export-triage"); !strings.Contains(out, sec.ID) || strings.Contains(out, token) {
		t.Errorf("stdout export:\n%s", out)
	}

	verdicts := `{"verdicts":[{"id":"` + sec.ID + `","triage":"placeholder","why":"an example in docs"},{"id":"kgffffff","triage":"real","why":"x"},{"id":"` + sec.ID + `","triage":"bogus","why":"x"}]}`
	vf := w.m.write("verdicts.json", verdicts)

	// A dry run says what would happen and writes nothing.
	out := w.mustCLI("import-triage", "--by", "claude", "--file", vf, "--dry-run")
	if !strings.Contains(out, "would") || !strings.Contains(out, "no such finding") || !strings.Contains(out, `"bogus" is not a label`) {
		t.Errorf("dry run:\n%s", out)
	}
	if now, _ := openStore(t, w).Get(sec.FP); now.TriageBy == "claude" {
		t.Fatal("a dry run changed the finding")
	}

	out = w.mustCLI("import-triage", "--by", "claude", "--file", vf)
	if !strings.Contains(out, "1 judged, 2 skipped") {
		t.Errorf("import:\n%s", out)
	}
	now, _ := openStore(t, w).Get(sec.FP)
	if now.Triage != "placeholder" || now.TriageBy != "claude" || now.TriageWhy != "an example in docs" || now.Severity >= sec.Severity {
		t.Errorf("after import: triage %q by %q why %q severity %v (was %v)", now.Triage, now.TriageBy, now.TriageWhy, now.Severity, sec.Severity)
	}
	// A reviewed finding is no longer in the residue.
	if out := w.mustCLI("export-triage"); strings.Contains(out, sec.ID) {
		t.Errorf("a judged finding was exported again:\n%s", out)
	}
	// Usage and bad input.
	if _, _, code := w.cli("import-triage", "--file", vf); code != exitUsage {
		t.Errorf("import-triage without --by: %d", code)
	}
	bad := w.m.write("bad.json", "not json at all")
	if _, errs, code := w.cli("import-triage", "--by", "human", "--file", bad); code != exitFailed || !strings.Contains(errs, "not valid JSON") {
		t.Errorf("bad verdicts: %d %s", code, errs)
	}
	// A bare array works too.
	arr := w.m.write("arr.json", `[{"id":"`+sec.ID+`","triage":"real","why":"it is"}]`)
	w.mustCLI("import-triage", "--by", "human", "--file", arr)
	if now, _ := openStore(t, w).Get(sec.FP); now.TriageBy != "human" || now.Triage != "real" {
		t.Errorf("array form: %+v", now)
	}
}

func TestBenchScoresThePipeline(t *testing.T) {
	w := newWorld(t)
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	out := filepath.Join(w.m.dir, "bench-out")
	stdout, errs, code := w.cli("bench", "--engines", "betterleaks", "--json", "--out", out)
	if code != 0 {
		t.Fatalf("bench: %d\n%s\n%s", code, stdout, errs)
	}
	var res struct {
		Seed     uint64 `json:"seed"`
		Pipeline struct {
			Recall    float64 `json:"recall"`
			Precision float64 `json:"precision"`
		} `json:"pipeline"`
		Engines []struct {
			Name   string  `json:"name"`
			Recall float64 `json:"recall"`
		} `json:"engines"`
	}
	if err := json.Unmarshal([]byte(stdout), &res); err != nil {
		t.Fatalf("bench --json: %v", err)
	}
	// The engine asked for, and the learned-secret matcher, which is scored beside the engines.
	if res.Seed != 1 || len(res.Engines) != 2 || res.Engines[0].Name != "betterleaks" || res.Engines[1].Name != "known" {
		t.Errorf("results: %+v", res)
	}
	// PLAN.md acceptance: pipeline recall >= 98% on plants marked detectable, precision >= 95%.
	if res.Pipeline.Recall < 0.98 || res.Pipeline.Precision < 0.95 {
		t.Errorf("pipeline recall %.3f precision %.3f; the plan wants >= 0.98 and >= 0.95", res.Pipeline.Recall, res.Pipeline.Precision)
	}
	for _, f := range []string{"results.json", "results.md"} {
		if _, err := os.Stat(filepath.Join(out, f)); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
	if left, _ := filepath.Glob(filepath.Join(tmp, "keyguard-bench-*")); len(left) != 0 {
		t.Errorf("the corpus was left behind: %v", left)
	}
	if !strings.Contains(errs, "results written to") {
		t.Errorf("stderr: %s", errs)
	}
}

func TestSyncWithoutAnyExposedSource(t *testing.T) {
	w := newWorld(t)
	w.addRepo("closed", core.Private)
	w.saveInventorySnapshot()
	out, errs, code := w.cli("sync")
	if code != 0 || !strings.Contains(out, "nothing to fetch") || !strings.Contains(errs, "leaving 1 private source alone") {
		t.Errorf("sync: %d\n%s\n%s", code, out, errs)
	}
	if _, errs, code := w.cli("inventory", "--cached"); code != 0 {
		t.Errorf("inventory --cached: %d %s", code, errs)
	}
	// With no saved inventory, --cached has nothing to show and says how to get one.
	os.Remove(w.paths.Inventory)
	if _, errs, code := w.cli("inventory", "--cached"); code != exitFailed || !strings.Contains(errs, "no saved inventory") {
		t.Errorf("inventory --cached with none: %d %s", code, errs)
	}
}

func TestPollSkipsQuietlyWhileAnotherRunHoldsTheLock(t *testing.T) {
	w := newWorld(t)
	w.config("betterleaks")
	w.addRepo("open", core.Public)
	lock, err := db.AcquireLock(w.paths.Lock)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Release()
	out := w.mustCLI("poll", "--no-daily")
	if !strings.Contains(out, "poll skipped") || !strings.Contains(out, "is running") {
		t.Errorf("a poll behind a deep scan is early, not broken:\n%s", out)
	}
	// A command a person ran says no, with the exit code that means "wait".
	if _, errs, code := w.cli("scan", "--no-verify"); code != exitLocked || !strings.Contains(errs, "wait for it to finish") {
		t.Errorf("scan while locked: %d %s", code, errs)
	}
	// allow still works while a sweep runs: ignore.json is written whole.
	if _, errs, code := w.cli("allow", strings.Repeat("0", 32), "--reason", "x"); code != 0 {
		t.Errorf("allow while locked: %d %s", code, errs)
	}
}
