package report

import (
	"strings"
	"testing"
	"time"

	"keyguard/internal/core"
)

func TestSummarizeHasNothingToSayWithoutRotateWork(t *testing.T) {
	f := newFixture(t)
	f.add(t, spec{kind: 0, sev: core.Medium, vis: core.Public})
	f.add(t, spec{kind: 1, sev: core.Low, vis: core.Private})
	f.add(t, spec{kind: 2, sev: core.Info, vis: core.Public})
	f.add(t, spec{kind: 3, sev: core.Critical, status: "resolved", verified: core.Dead, vis: core.Public})
	f.add(t, spec{kind: 4, sev: core.Critical, status: "ignored", vis: core.Public})
	if s := Summarize(f.secrets); s != (Summary{}) {
		t.Errorf("Summarize = %+v, want the zero Summary", s)
	}
	if s := Summarize(nil); s != (Summary{}) {
		t.Errorf("Summarize(nil) = %+v", s)
	}
}

func TestSummarizeOneLiveCritical(t *testing.T) {
	f := newFixture(t)
	f.add(t, spec{kind: 0, sev: core.Critical, verified: core.Live, vis: core.Public})
	s := Summarize(f.secrets)
	if s.Sev != core.Critical || s.Title != "1 live key exposed — rotate now" {
		t.Fatalf("summary = %+v", s)
	}
	want := "Anthropic " + f.secrets[0].Shape + " in hangryclaude/demo-anthropic (Public). Rotate: https://platform.claude.com/settings/keys"
	if s.Body != want {
		t.Errorf("body = %q\nwant   %q", s.Body, want)
	}
}

// The banner and the page must never word the same facts differently.
func TestSummarizeTitleIsTheHeroSentence(t *testing.T) {
	mk := func(sevv core.Severity, v core.Verified, n int) []core.Secret {
		f := newFixture(t)
		for i := 0; i < n; i++ {
			f.add(t, spec{kind: i, sev: sevv, verified: v, vis: core.Public})
		}
		return f.secrets
	}
	cases := map[string][]core.Secret{
		"one live critical":   mk(core.Critical, core.Live, 1),
		"two live critical":   mk(core.Critical, core.Live, 2),
		"unverified critic":   mk(core.Critical, core.Unverified, 2),
		"high only":           mk(core.High, core.Live, 2),
		"mixed crit and high": append(mk(core.Critical, core.Live, 1), mk(core.High, core.Live, 3)...),
	}
	for name, ss := range cases {
		hero := build(inputOf(ss, healthyRun(), nil)).Hero.Headline
		if got := Summarize(ss).Title; got != hero {
			t.Errorf("%s: notification says %q, page says %q", name, got, hero)
		}
	}
	// The severity decides which channels fire: high is a banner, critical adds a text.
	for name, want := range map[string]core.Severity{
		"high only": core.High, "mixed crit and high": core.Critical, "one live critical": core.Critical,
	} {
		if got := Summarize(cases[name]).Sev; got != want {
			t.Errorf("%s: severity %v, want %v", name, got, want)
		}
	}
}

func TestSummarizeListsTheWorstFirstAndSaysHowManyMore(t *testing.T) {
	f := newFixture(t)
	high := f.add(t, spec{kind: 4, sev: core.High, verified: core.Live, vis: core.Private, age: 90 * day24})
	var crit []core.Secret
	for i := 0; i < 5; i++ {
		crit = append(crit, f.add(t, spec{kind: i, sev: core.Critical, verified: core.Live, vis: core.Public, age: time.Duration(i+1) * day24}))
	}
	s := Summarize(f.secrets)
	lines := strings.Split(s.Body, "\n")
	if len(lines) != maxListed+1 {
		t.Fatalf("%d lines, want %d listed plus the overflow line:\n%s", len(lines), maxListed, s.Body)
	}
	if lines[maxListed] != "and 3 more. Open the report." {
		t.Errorf("overflow line = %q", lines[maxListed])
	}
	// Among equally urgent critical keys the one out longest comes first (age 5, 4, 3 days).
	for i, want := range []core.Secret{crit[4], crit[3], crit[2]} {
		if !strings.Contains(lines[i], want.Shape) {
			t.Errorf("line %d should be the key from %s: %q", i, want.ID, lines[i])
		}
	}
	if strings.Contains(s.Body, high.Shape) {
		t.Error("a high secret was listed ahead of critical ones")
	}
	if s.Sev != core.Critical || s.Title != "5 live keys exposed — rotate now" {
		t.Errorf("summary = %q / %v", s.Title, s.Sev)
	}
}

func TestSummarizeCarriesNoRawAndSurvivesMask(t *testing.T) {
	f := mixed30(t)
	s := Summarize(f.secrets)
	if s.Sev != core.Critical {
		t.Fatalf("sev = %v", s.Sev)
	}
	for i := range f.raws {
		if at, ok := hasWindow(s.Title+"\n"+s.Body, f.rands[i], 10); ok {
			t.Fatalf("raw secret #%d leaks at %d into the notification", i, at)
		}
	}
	// notify masks key-like runs before sending; the summary must already be clean, or the
	// masker would eat the repo name or the link it is there to deliver.
	for _, l := range strings.Split(s.Body, "\n") {
		if Mask(l) != l {
			t.Errorf("Mask changes a line Summarize wrote: %q -> %q", l, Mask(l))
		}
	}
}

func TestSummarizeUnknownTypeSaysWhatToDo(t *testing.T) {
	f := newFixture(t)
	f.add(t, spec{kind: 0, sev: core.Critical, verified: core.Live, vis: core.Public})
	f.secrets[0].Type = "some-new-rule"
	s := Summarize(f.secrets)
	if !strings.Contains(s.Body, "Rotate it where it was issued.") || strings.Contains(s.Body, "Rotate: ") {
		t.Errorf("body = %q", s.Body)
	}
	f.secrets[0].Type = "card"
	if s := Summarize(f.secrets); !strings.Contains(s.Body, "Call the card issuer.") {
		t.Errorf("a type with no link should carry its instruction: %q", s.Body)
	}
}
