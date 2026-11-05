package ghsettings

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"keyguard/internal/core"
	"keyguard/internal/inventory/ghcli"
)

// skews are the two ways this Mac's clock can disagree with GitHub's. The real one ran two hours
// fast; the other direction is its mirror image.
var skews = map[string]time.Duration{"mac 2h fast": 2 * time.Hour, "mac 2h slow": -2 * time.Hour}

func off() map[string]string {
	return map[string]string{
		"secret_scanning": "disabled", "secret_scanning_push_protection": "disabled",
		"secret_scanning_non_provider_patterns": "disabled", "secret_scanning_validity_checks": "disabled",
	}
}

func on() map[string]string {
	return map[string]string{
		"secret_scanning": "enabled", "secret_scanning_push_protection": "enabled",
		"secret_scanning_non_provider_patterns": "disabled", "secret_scanning_validity_checks": "disabled",
	}
}

// methods is the order of requests a repo saw, as GET/PATCH, with the field a PATCH set.
func (g *ghub) methods(name string) []string {
	var out []string
	for _, l := range g.log {
		parts := strings.SplitN(l, " ", 3)
		if parts[1] != name {
			continue
		}
		m := parts[0]
		if m == "PATCH" {
			switch {
			case strings.Contains(parts[2], `"secret_scanning":`):
				m += ":secret_scanning"
			case strings.Contains(parts[2], "push_protection"):
				m += ":push_protection"
			default:
				m += ":other"
			}
		}
		out = append(out, m)
	}
	return out
}

func assertNoParameterFlags(t *testing.T, fx *fixture) {
	t.Helper()
	for _, cmd := range fx.f.Commands() {
		if cmd[0] != "api" {
			continue
		}
		method := ""
		for i, a := range cmd {
			switch a {
			case "-f", "-F", "--field", "--raw-field":
				t.Errorf("parameter flag %s in %v: gh would send a POST", a, cmd)
			case "--method":
				method = cmd[i+1]
			}
		}
		if method == "" {
			t.Errorf("no --method in %v", cmd)
		}
	}
}

func TestApplyEnablesTheTwoFeaturesInOrderAndReadsTheRepoAgain(t *testing.T) {
	g := newGhub()
	g.add("o/r", hrepo{sa: off()})
	fx := newFixture(t, g, nil)

	res := fx.s.Apply(bg(), []core.Source{repoSrc("o", "r", core.Public)})
	if len(res) != 1 || res[0].Err != nil {
		t.Fatalf("result = %+v", res)
	}
	want := []string{"GET", "PATCH:secret_scanning", "PATCH:push_protection", "GET"}
	if got := g.methods("o/r"); !equalStrings(got, want) {
		t.Fatalf("requests = %v, want read, the two writes in dependency order, then a read to compare", got)
	}
	// The optional features are not switched on per repo: whether the plan has them is asked once.
	for _, p := range g.patches() {
		if strings.Contains(p, "non_provider") || strings.Contains(p, "validity") {
			t.Errorf("an optional feature was written per repo: %s", p)
		}
	}
	f := res[0].Fields
	if len(f) != 2 || f[0].Feature != SecretScanning || f[1].Feature != PushProtection {
		t.Fatalf("fields = %+v, want exactly secret scanning then push protection", f)
	}
	for i, fr := range f {
		if !fr.Done() || !fr.Sent || fr.Status != 200 || fr.Before != Disabled || fr.After != Enabled || fr.Reply != Enabled {
			t.Errorf("field %d = %+v", i, fr)
		}
	}
	assertNoParameterFlags(t, fx)
}

func TestApplyLeavesWhatIsAlreadyOnAlone(t *testing.T) {
	g := newGhub()
	g.add("o/r", hrepo{sa: on()})
	fx := newFixture(t, g, nil)
	res := fx.s.Apply(bg(), []core.Source{repoSrc("o", "r", core.Public)})
	if got := g.methods("o/r"); !equalStrings(got, []string{"GET"}) {
		t.Fatalf("requests = %v: a repo that is already protected costs one read and nothing else", got)
	}
	f := res[0].Fields
	if len(f) != 2 || f[0].Sent || f[1].Sent || !f[0].Done() || !f[1].Done() || f[0].Message != reasonEnabled || f[0].After != Enabled {
		t.Errorf("fields = %+v", f)
	}
	if p := fx.pauses(); len(p) != 0 {
		t.Errorf("paused %v although nothing was written", p)
	}
}

// A 200 is a claim. The reply says "enabled"; the repo, read again, says it is not.
func TestApplyJudgesAWriteByTheRereadAndNotByTheReply(t *testing.T) {
	g := newGhub()
	g.add("o/r", hrepo{sa: off(), noStick: map[string]bool{"secret_scanning": true}})
	fx := newFixture(t, g, nil)
	res := fx.s.Apply(bg(), []core.Source{repoSrc("o", "r", core.Public)})
	f := res[0].Fields[0]
	if f.Status != 200 || f.Reply != Enabled || f.After != Disabled || f.Done() {
		t.Fatalf("secret scanning = %+v: a 200 that did not stick is not a switched-on feature", f)
	}
	if !strings.Contains(f.Message, "did not stick") {
		t.Errorf("message = %q", f.Message)
	}
	if got := g.methods("o/r"); got[len(got)-1] != "GET" {
		t.Errorf("requests = %v: the last word is the re-read", got)
	}
}

func TestApplyDoesNotCountAWriteItCouldNotConfirm(t *testing.T) {
	g := newGhub()
	g.add("o/r", hrepo{sa: off(), getBroken: true})
	fx := newFixture(t, g, nil)
	res := fx.s.Apply(bg(), []core.Source{repoSrc("o", "r", core.Public)})
	for _, f := range res[0].Fields {
		if !f.Sent || f.After != Unreported || f.Done() || !strings.Contains(f.Message, "unconfirmed") {
			t.Errorf("%s = %+v: a write whose result could not be read is not done", f.Feature, f)
		}
	}
}

func TestApplyRecordsARefusalInGitHubsWordsAndStillRereads(t *testing.T) {
	g := newGhub()
	g.add("o/r", hrepo{sa: off(), refuse: map[string]string{"secret_scanning": "Secret scanning is not available for this repository."}})
	fx := newFixture(t, g, nil)
	res := fx.s.Apply(bg(), []core.Source{repoSrc("o", "r", core.Public)})
	f := res[0].Fields
	if f[0].Status != 422 || f[0].Done() || f[0].After != Disabled || !strings.Contains(f[0].Message, "Validation Failed") || !strings.Contains(f[0].Message, "not available") {
		t.Errorf("secret scanning = %+v", f[0])
	}
	if f[1].Sent || f[1].Message != reasonNeedsScan {
		t.Errorf("push protection = %+v: it needs secret scanning, which is off", f[1])
	}
}

func TestApplyDoesNotWriteWhereGitHubShowsNothing(t *testing.T) {
	g := newGhub()
	g.add("o/blind", hrepo{hidden: true})
	fx := newFixture(t, g, nil)
	res := fx.s.Apply(bg(), []core.Source{repoSrc("o", "blind", core.Public)})
	if len(g.patches()) != 0 {
		t.Fatalf("PATCHes = %q: with no admin rights the write is refused anyway", g.patches())
	}
	for _, f := range res[0].Fields {
		if f.Sent || f.Done() || f.Message != reasonUnreported {
			t.Errorf("%s = %+v", f.Feature, f)
		}
	}
}

// The gap is between any two writes, repos included, and is measured so that it never exceeds a
// second of waiting when the writes themselves took time.
func TestApplyWaitsAGapBetweenAnyTwoWrites(t *testing.T) {
	for name, skew := range skews {
		t.Run(name, func(t *testing.T) {
			g := newGhub()
			var srcs []core.Source
			for i := range 3 {
				n := fmt.Sprintf("r%d", i)
				g.add("o/"+n, hrepo{sa: off()})
				srcs = append(srcs, repoSrc("o", n, core.Public))
			}
			fx := newFixtureSkew(t, g, skew, nil)
			fx.s.Apply(bg(), srcs)
			if len(g.patchAt) != 6 {
				t.Fatalf("%d writes, want 6", len(g.patchAt))
			}
			for i := 1; i < len(g.patchAt); i++ {
				if gap := g.patchAt[i].Sub(g.patchAt[i-1]); gap < time.Second {
					t.Errorf("writes %d and %d are %v apart on GitHub's clock", i-1, i, gap)
				}
			}
			p := fx.pauses()
			if len(p) != 5 {
				t.Fatalf("pauses = %v: one between each of the 6 writes, none before the first or after the last", p)
			}
			for _, d := range p {
				if d != time.Second {
					t.Errorf("pause = %v", d)
				}
			}
		})
	}
}

// The gap runs from the end of the last write, so the reads that come between two writes (the
// re-read of one repo, the read of the next) are time already spent waiting.
func TestApplyGapCountsTheTimeTheReadsBetweenTwoWritesTook(t *testing.T) {
	g := newGhub()
	g.add("o/a", hrepo{sa: off()})
	g.add("o/b", hrepo{sa: off()})
	fx := newFixture(t, g, func(c *Config) { c.Gap = 3 * time.Second })
	g.latency = func(method string) {
		if method == "GET" {
			fx.ck.Advance(400 * time.Millisecond)
		}
	}
	fx.s.Apply(bg(), []core.Source{repoSrc("o", "a", core.Public), repoSrc("o", "b", core.Public)})
	want := []time.Duration{3 * time.Second, 2200 * time.Millisecond, 3 * time.Second}
	got := fx.pauses()
	if len(got) != len(want) {
		t.Fatalf("pauses = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("pause %d = %v, want %v", i, got[i], want[i])
		}
	}
}

func TestApplyStopsAtARateLimitAndSaysHowLongOnGitHubsClock(t *testing.T) {
	for name, skew := range skews {
		t.Run(name, func(t *testing.T) {
			g := newGhub()
			var srcs []core.Source
			for i := range 3 {
				n := fmt.Sprintf("r%d", i)
				g.add("o/"+n, hrepo{sa: off()})
				srcs = append(srcs, repoSrc("o", n, core.Public))
			}
			g.rateLimitAfter, g.resetIn = 2, 30*time.Second // the second write is refused
			fx := newFixtureSkew(t, g, skew, nil)
			res := fx.s.Apply(bg(), srcs)

			var rl *ghcli.RateLimitError
			if !errors.As(res[0].Err, &rl) {
				t.Fatalf("first repo err = %v, want the rate limit", res[0].Err)
			}
			// Reset is 30 s after GitHub's clock (after the 1 s pause between the writes), plus the
			// margin. A wait worked out on the Mac's clock would be hours off in either direction.
			if got := rl.Wait(fx.s.githubNow()); got != 32*time.Second {
				t.Errorf("Wait = %v, want 32s", got)
			}
			if f := res[0].Fields[1]; f.Sent != true || !strings.Contains(f.Message, "wait 32s") {
				t.Errorf("push protection = %+v", f)
			}
			for i := 1; i < 3; i++ {
				if !errors.Is(res[i].Err, res[0].Err) || len(res[i].Fields) != 0 {
					t.Errorf("repo %d = %+v: not reached, and it says why", i, res[i])
				}
			}
			if g.patchCount != 2 {
				t.Errorf("%d writes after the limit was hit, want to stop at 2", g.patchCount)
			}
			for _, l := range g.log {
				if strings.Contains(l, "o/r1") || strings.Contains(l, "o/r2") {
					t.Errorf("a repo past the limit was touched: %s", l)
				}
			}
		})
	}
}

func TestApplyWritesWhatGitHubReportedToTheStateFile(t *testing.T) {
	for name, skew := range skews {
		t.Run(name, func(t *testing.T) {
			g := newGhub()
			g.add("o/fixed", hrepo{sa: off()})
			g.add("o/stuck", hrepo{sa: off(), noStick: map[string]bool{"secret_scanning": true}})
			fx := newFixtureSkew(t, g, skew, nil)
			fx.s.Apply(bg(), []core.Source{repoSrc("o", "fixed", core.Public), repoSrc("o", "stuck", core.Public)})

			st := fx.readSaved(t)
			a, b := st.Repos["github.com/o/fixed"], st.Repos["github.com/o/stuck"]
			if a.Class != Protected || a.Features["secret_scanning"] != "enabled" || a.Features["secret_scanning_push_protection"] != "enabled" || a.Visibility != "public" || !a.Reported {
				t.Errorf("fixed = %+v", a)
			}
			if b.Class != Gap || b.Features["secret_scanning"] != "disabled" {
				t.Errorf("stuck = %+v: the state records what the re-read said, not what the reply claimed", b)
			}
			// Every stamp is GitHub's time, which is the Mac's minus its skew.
			want := fx.ck.GitHub().UTC().Format(time.RFC3339)
			if st.Updated != want || a.Checked != want {
				t.Errorf("stamps updated=%s checked=%s, want GitHub's %s (the Mac says %s)", st.Updated, a.Checked, want, fx.ck.Mac().UTC().Format(time.RFC3339))
			}
			fi, err := os.Stat(fx.state)
			if err != nil || fi.Mode().Perm() != 0o600 {
				t.Errorf("state file: %v %v", fi, err)
			}
			raw, _ := os.ReadFile(fx.state)
			for _, acct := range []string{"hangryclaude", "alt-builds"} {
				if strings.Contains(string(raw), fx.f.Token(acct)) {
					t.Errorf("the token for %s is in the state file", acct)
				}
			}
		})
	}
}

func TestApplyKeepsTheStateOfReposItDidNotTouch(t *testing.T) {
	g := newGhub()
	g.add("o/a", hrepo{sa: off()})
	g.add("o/b", hrepo{sa: on()})
	fx := newFixture(t, g, nil)
	fx.s.Apply(bg(), []core.Source{repoSrc("o", "a", core.Public)})
	fx.s.Apply(bg(), []core.Source{repoSrc("o", "b", core.Public)})
	st := fx.readSaved(t)
	if _, ok := st.Repos["github.com/o/a"]; !ok || len(st.Repos) != 2 {
		t.Errorf("repos = %v: the second run forgot the first", keysOf(st.Repos))
	}
}

func TestApplyIsRefusedForNonRepos(t *testing.T) {
	g := newGhub()
	fx := newFixture(t, g, nil)
	res := fx.s.Apply(bg(), []core.Source{{ID: "gist.github.com/o/abc", Kind: "gist", Owner: "o", Name: "abc", Visibility: core.Public}})
	if !errors.Is(res[0].Err, ErrNotRepo) || len(g.log) != 0 {
		t.Errorf("gist: %+v %q", res[0], g.log)
	}
	if _, err := os.Stat(fx.state); err == nil {
		t.Error("a state file was written for a run that read nothing")
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func keysOf[V any](m map[string]V) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

// readSaved parses the state file the way a later run will.
func (fx *fixture) readSaved(t *testing.T) Saved {
	t.Helper()
	st, err := fx.s.Saved()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(fx.state); err != nil {
		t.Fatalf("no state file: %v", err)
	}
	return st
}
