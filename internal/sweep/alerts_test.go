package sweep

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"keyguard/internal/core"
	"keyguard/internal/fp"
)

func TestAlertsBeyondTheLimitBecomeOneDigest(t *testing.T) {
	w := newWorld(t)
	w.cfg.MaxNotify = 5
	var raws []string
	for i := 0; i < 15; i++ {
		name := fmt.Sprintf("r%02d", i)
		repo := w.addRepo(name, core.Private)
		raw := fakeKey(t, "sk-", 48)
		raws = append(raws, raw)
		w.plantAll(raw, "openai", core.Live)
		repo.commit("env", map[string]string{".env": "K=" + raw + "\n"})
	}
	st := mustPoll(t, w.runner())
	got := w.notif.list()
	if len(got) != 6 {
		t.Fatalf("want 5 alerts and 1 digest, got %d: %v", len(got), got)
	}
	digests := 0
	for _, n := range got {
		if strings.Contains(n.title, "more keys need attention") {
			digests++
			if !strings.Contains(n.title, "10 more") || n.sev != core.High {
				t.Fatalf("digest: %+v", n)
			}
			if strings.Count(n.body, "kg") != 8 || !strings.Contains(n.body, "+2 more") {
				t.Fatalf("digest body should list 8 and count the rest:\n%s", n.body)
			}
		}
	}
	if digests != 1 {
		t.Fatalf("%d digests", digests)
	}
	for _, raw := range raws {
		if s := w.secret(raw); s.Notified != core.High {
			t.Fatalf("%s was announced (singly or in the digest) but Notified is %v", s.ID, s.Notified)
		}
	}
	if !slices.ContainsFunc(st.Notes, func(n string) bool { return strings.Contains(n, "beyond the limit of 5") }) {
		t.Fatalf("the cap should be in the notes: %v", st.Notes)
	}
	mustPoll(t, w.runner())
	if w.notif.count() != 6 {
		t.Fatalf("a quiet poll re-sent alerts: %d", w.notif.count())
	}
}

func TestFailedNotificationIsRetriedNotForgotten(t *testing.T) {
	w := newWorld(t)
	a := w.addRepo("a", core.Public)
	raw := fakeKey(t, "sk-", 48)
	w.plantAll(raw, "openai", core.Live)
	a.commit("env", map[string]string{".env": "K=" + raw + "\n"})
	r := w.runner()

	w.notif.fail = errors.New("osascript: not allowed to send notifications")
	st := mustPoll(t, r)
	if !slices.ContainsFunc(st.Notes, func(n string) bool { return strings.HasPrefix(n, "notify:") }) {
		t.Fatalf("a failed alert must be in the notes: %v", st.Notes)
	}
	if s := w.secret(raw); s.Notified != core.None || s.Severity != core.Critical {
		t.Fatalf("an alert that was not delivered must not be recorded as delivered: notified=%v", s.Notified)
	}
	w.notif.fail = nil
	mustPoll(t, r) // idle poll: the alert is still owed
	if n := w.notif.list(); len(n) != 1 || n[0].sev != core.Critical {
		t.Fatalf("the owed alert was not sent when the notifier recovered: %+v", n)
	}
	if w.secret(raw).Notified != core.Critical {
		t.Fatal("delivery not recorded")
	}
}

// flakyNotifier delivers the first n notifications and fails the rest.
type flakyNotifier struct {
	fakeNotifier
	okFor int
}

func (f *flakyNotifier) Notify(title, body string, sev core.Severity) error {
	f.mu.Lock()
	ok := len(f.got) < f.okFor
	f.mu.Unlock()
	if !ok {
		return errors.New("imessage: not signed in")
	}
	return f.fakeNotifier.Notify(title, body, sev)
}

func TestADigestThatFailsIsOwedAgain(t *testing.T) {
	w := newWorld(t)
	w.cfg.MaxNotify = 1
	flaky := &flakyNotifier{okFor: 1}
	w.cfg.Notifier = flaky
	var raws []string
	for i := 0; i < 4; i++ {
		raw := fakeKey(t, "sk-", 48)
		raws = append(raws, raw)
		w.plantAll(raw, "openai", core.Live)
		w.addRepo(fmt.Sprintf("r%d", i), core.Private).commit("env", map[string]string{".env": "K=" + raw + "\n"})
	}
	r := w.runner()
	st := mustPoll(t, r)
	if !hasNote(st, "notify: imessage: not signed in") {
		t.Fatalf("notes: %v", st.Notes)
	}
	told := 0
	for _, raw := range raws {
		if w.secret(raw).Notified == core.High {
			told++
		}
	}
	if told != 1 || flaky.count() != 1 {
		t.Fatalf("only the one delivered alert may be recorded as told: %d secrets marked, %d delivered", told, flaky.count())
	}

	flaky.okFor = 100 // the notifier recovers; the three owed alerts go out as a digest next time
	mustPoll(t, r)
	if flaky.count() < 2 {
		t.Fatalf("the owed alerts were forgotten: %d delivered", flaky.count())
	}
	for _, raw := range raws {
		if w.secret(raw).Notified != core.High {
			t.Fatal("a secret is still owed an alert")
		}
	}
}

func TestSecondExposedPlaceEscalatesAHighSecret(t *testing.T) {
	w := newWorld(t)
	b := w.addRepo("b", core.Private)
	raw := fakeKey(t, "sk-", 48)
	w.plantAll(raw, "openai", core.Live)
	b.commit("env", map[string]string{".env": "K=" + raw + "\n"})
	r := w.runner()
	mustPoll(t, r)
	if n := w.notif.list(); len(n) != 1 || n[0].sev != core.High {
		t.Fatalf("%+v", n)
	}
	c := w.addRepo("c", core.Public) // the same key is pushed somewhere public
	c.commit("oops", map[string]string{"notes.md": "key: " + raw + "\n"})
	mustPoll(t, r)
	n := w.notif.list()
	if len(n) != 2 || n[1].sev != core.Critical || !strings.Contains(n[1].title, "ESCALATED") {
		t.Fatalf("a second, public place must escalate: %+v", n)
	}
	if !strings.Contains(n[1].body, w.src("c")) {
		t.Fatalf("the alert should point at the public place first:\n%s", n[1].body)
	}
}

func TestNoNotifierIsNotedAndNothingIsMarkedSent(t *testing.T) {
	w := newWorld(t)
	w.cfg.Notifier = nil
	a := w.addRepo("a", core.Public)
	raw := fakeKey(t, "sk-", 48)
	w.plantAll(raw, "openai", core.Live)
	a.commit("env", map[string]string{".env": "K=" + raw + "\n"})
	st := mustPoll(t, w.runner())
	if !slices.ContainsFunc(st.Notes, func(n string) bool { return strings.Contains(n, "no notifier is configured") }) {
		t.Fatalf("notes: %v", st.Notes)
	}
	if s := w.secret(raw); s.Notified != core.None || s.Severity != core.Critical {
		t.Fatalf("notified=%v", s.Notified)
	}
}

func TestAlertTextCarriesDisplayFieldsOnly(t *testing.T) {
	w := newWorld(t)
	a := w.addRepo("a", core.Public)
	raw := fakeKey(t, "sk-ant-api03-", 60)
	w.plantAll(raw, "anthropic", core.Live)
	a.commit("env", map[string]string{"deploy/.env": "A=1\nANTHROPIC_API_KEY=" + raw + "\n"})
	mustPoll(t, w.runner())
	n := w.notif.list()
	if len(n) != 1 {
		t.Fatalf("%d notices", len(n))
	}
	id := fp.ID(w.kr.FP(raw))
	want := []string{"keyguard CRITICAL: live anthropic key is exposed"}
	if n[0].title != want[0] {
		t.Fatalf("title %q", n[0].title)
	}
	for _, part := range []string{id, fp.Shape(raw), "the provider confirmed it works", w.src("a"), "deploy/.env:2", "(public)", "Rotate it"} {
		if !strings.Contains(n[0].body, part) {
			t.Fatalf("body lacks %q:\n%s", part, n[0].body)
		}
	}
	if strings.Contains(n[0].title+n[0].body, raw[len("sk-ant-api03-"):]) {
		t.Fatal("the raw value is in the alert")
	}
	if n[0].sev != core.Critical {
		t.Fatalf("sev %v", n[0].sev)
	}
}

func TestDescribeCoversTheKnownAndPrivateCases(t *testing.T) {
	base := core.Secret{
		ID: "kg123456", Type: "openai", Shape: "sk-…ab12", Severity: core.High, Known: "kg123456 OPENAI_API_KEY",
		Locations: []core.Location{
			{Source: "github.com/o/z", Visibility: core.Private, Path: "z.env", Line: 4},
			{Source: "github.com/o/y", Visibility: core.Private, Path: "y.env"},
			{Source: "github.com/o/x", Visibility: core.Private, Path: "x.env"},
		},
	}
	title, body := describe(base)
	if title != "keyguard HIGH: your openai key is in a private place" {
		t.Fatalf("title %q", title)
	}
	if !strings.Contains(body, "learned from this Mac (OPENAI_API_KEY)") || !strings.Contains(body, "+1 more place(s)") {
		t.Fatalf("body:\n%s", body)
	}
	base.Notified = core.High
	base.Severity = core.Critical
	base.Locations[0].Visibility = core.SecretGist
	title, body = describe(base)
	if title != "keyguard ESCALATED to CRITICAL: your openai key is exposed" || !strings.Contains(body, "secret gist") {
		t.Fatalf("%q\n%s", title, body)
	}
	if !strings.HasPrefix(strings.Split(body, "\n")[2], "github.com/o/z") {
		t.Fatalf("the exposed place should be listed first:\n%s", body)
	}
	generic := core.Secret{ID: "kgaaaaaa", Type: "generic", Shape: "…", Severity: core.High, Verified: core.Live,
		Locations: []core.Location{{Source: "s", Visibility: core.Private}}}
	if title, _ := describe(generic); title != "keyguard HIGH: live secret in a private place" {
		t.Fatalf("%q", title)
	}
}
