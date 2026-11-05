package notify

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"keyguard/internal/core"
	"keyguard/internal/fp"
	"keyguard/internal/report"
)

const (
	alnum  = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	b64url = alnum + "-_"
	target = "+15555550123" // 555-01xx numbers are reserved for fiction
)

func randStr(t testing.TB, charset string, n int) string {
	t.Helper()
	b := make([]byte, n)
	for i := range b {
		x, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			t.Fatal(err)
		}
		b[i] = charset[x.Int64()]
	}
	return string(b)
}

type call struct {
	name string
	args []string
}

// rec is a Runner that records calls and fails the commands it is told to, by base name.
type rec struct {
	mu    sync.Mutex
	calls []call
	fail  map[string]error
}

func (r *rec) run(_ context.Context, name string, args ...string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, call{name, append([]string(nil), args...)})
	return r.fail[filepath.Base(name)]
}

func (r *rec) named(base string) []call {
	var out []call
	for _, c := range r.calls {
		if filepath.Base(c.name) == base {
			out = append(out, c)
		}
	}
	return out
}

type logs struct {
	mu    sync.Mutex
	lines []string
}

func (l *logs) logf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, strings.TrimSpace(fmt.Sprintf(format, args...)))
}

func newN(t *testing.T, cfg Config) (*Notifier, *rec, *logs) {
	t.Helper()
	r, l := &rec{fail: map[string]error{}}, &logs{}
	cfg.Run, cfg.Logf = r.run, l.logf
	if cfg.Osascript == "" {
		cfg.Osascript = "/fake/osascript"
	}
	if cfg.IMsg == "" {
		cfg.IMsg = "/fake/imsg"
	}
	n, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return n, r, l
}

// --- argv -----------------------------------------------------------------------------

func TestHighIsABannerOnly(t *testing.T) {
	n, r, _ := newN(t, Config{IMessageTo: target})
	if err := n.Notify("Live OpenAI key in a private repo", "sk-proj-…a1b2 in hangryclaude/foo", core.High); err != nil {
		t.Fatal(err)
	}
	want := []call{{"/fake/osascript", []string{"-e",
		`display notification "sk-proj-…a1b2 in hangryclaude/foo" with title "Live OpenAI key in a private repo" subtitle "keyguard · high" sound name "Ping"`}}}
	if len(r.calls) != 1 || r.calls[0].name != want[0].name || strings.Join(r.calls[0].args, "|") != strings.Join(want[0].args, "|") {
		t.Fatalf("calls = %+v\nwant   %+v", r.calls, want)
	}
}

func TestCriticalIsABannerAndAnIMessage(t *testing.T) {
	n, r, _ := newN(t, Config{IMessageTo: target})
	if err := n.Notify("2 live keys exposed", "sk-ant-api03-…ks7D in hangryclaude/foo (public)", core.Critical); err != nil {
		t.Fatal(err)
	}
	if len(r.calls) != 2 {
		t.Fatalf("%d calls, want 2: %+v", len(r.calls), r.calls)
	}
	if got := strings.Join(r.calls[0].args, "|"); got !=
		`-e|display notification "sk-ant-api03-…ks7D in hangryclaude/foo (public)" with title "2 live keys exposed" subtitle "keyguard · critical" sound name "Sosumi"` {
		t.Errorf("banner argv = %s", got)
	}
	im := r.calls[1]
	wantArgs := []string{"send", "--to", target, "--text", "keyguard (critical): 2 live keys exposed\nsk-ant-api03-…ks7D in hangryclaude/foo (public)"}
	if im.name != "/fake/imsg" || strings.Join(im.args, "\x00") != strings.Join(wantArgs, "\x00") {
		t.Errorf("imsg call = %+v\nwant      %v", im, wantArgs)
	}
}

func TestBelowHighStaysSilent(t *testing.T) {
	n, r, l := newN(t, Config{IMessageTo: target})
	for _, sev := range []core.Severity{core.None, core.Info, core.Low, core.Medium, core.Severity(-1)} {
		if err := n.Notify("t", "b", sev); err != nil {
			t.Errorf("sev %d: %v", sev, err)
		}
	}
	if len(r.calls) != 0 || len(l.lines) != 0 {
		t.Errorf("below high must do nothing, got %d calls and %d log lines", len(r.calls), len(l.lines))
	}
}

func TestNoTargetMeansNoIMessage(t *testing.T) {
	n, r, _ := newN(t, Config{})
	if err := n.Notify("t", "b", core.Critical); err != nil {
		t.Fatal(err)
	}
	if len(r.named("imsg")) != 0 || len(r.named("osascript")) != 1 {
		t.Errorf("calls = %+v", r.calls)
	}
}

func TestCorruptSeverityDoesNotPanic(t *testing.T) {
	n, r, _ := newN(t, Config{IMessageTo: target})
	if err := n.Notify("t", "b", core.Severity(42)); err != nil {
		t.Fatal(err)
	}
	if len(r.calls) != 2 || !strings.Contains(strings.Join(r.calls[0].args, " "), "keyguard · critical") {
		t.Errorf("severity 42 should be treated as critical: %+v", r.calls)
	}
}

func TestEmptyMessageIsAnError(t *testing.T) {
	n, r, _ := newN(t, Config{})
	if err := n.Notify("  ", "\n\t", core.Critical); err == nil {
		t.Error("an empty notification is a bug in the caller and should say so")
	}
	if len(r.calls) != 0 {
		t.Error("nothing should be sent for an empty message")
	}
}

// sweep words its own titles ("keyguard CRITICAL: ..."); saying keyguard twice in one
// banner or text helps nobody.
func TestBrandedTitlesAreNotPrefixedAgain(t *testing.T) {
	n, r, _ := newN(t, Config{IMessageTo: target})
	title := "keyguard CRITICAL: live openai key is exposed"
	if err := n.Notify(title, "kg1a2b3c  sk-proj-…a1b2\nRotate it, then open the report.", core.Critical); err != nil {
		t.Fatal(err)
	}
	if got := r.calls[0].args[1]; strings.Contains(got, "subtitle") || !strings.Contains(got, `with title "`+title+`" sound name "Sosumi"`) {
		t.Errorf("a branded title needs no subtitle: %s", got)
	}
	want := title + "\nkg1a2b3c sk-proj-…a1b2\nRotate it, then open the report."
	if got := r.calls[1].args[4]; got != want {
		t.Errorf("text = %q\nwant   %q", got, want)
	}
	// And the other way round: a plain title still gets the brand.
	if !branded("  KeyGuard: x") || branded("something keyguard") || branded("") {
		t.Error("branded()")
	}
}

func TestTitleOrBodyAloneStillMakesABanner(t *testing.T) {
	n, r, _ := newN(t, Config{IMessageTo: target})
	n.Notify("only a title", "", core.High)
	n.Notify("", "only a body", core.High)
	n.Notify("", "body without a title", core.Critical)
	if got := r.named("imsg")[0].args[4]; got != "keyguard (critical)\nbody without a title" {
		t.Errorf("a text with no title should not start with a dangling colon: %q", got)
	}
	a, b := strings.Join(r.calls[0].args, " "), strings.Join(r.calls[1].args, " ")
	if !strings.Contains(a, `notification "only a title" with title "keyguard"`) {
		t.Errorf("title-only banner: %s", a)
	}
	if !strings.Contains(b, `notification "only a body" with title "keyguard"`) {
		t.Errorf("body-only banner: %s", b)
	}
}

// --- what may and may not travel -------------------------------------------------------

func TestKeyLikeTextIsMaskedOnBothChannels(t *testing.T) {
	rand1 := randStr(t, b64url, 90)
	rand2 := randStr(t, alnum, 40)
	n, r, _ := newN(t, Config{IMessageTo: target})
	err := n.Notify("key sk-ant-api03-"+rand1+" exposed", "found ghp_"+rand2+" in hangryclaude/foo", core.Critical)
	if err != nil {
		t.Fatal(err)
	}
	all := ""
	for _, c := range r.calls {
		all += strings.Join(c.args, "\n")
	}
	for _, raw := range []string{rand1, rand2} {
		for i := 0; i+10 <= len(raw); i++ {
			if strings.Contains(all, raw[i:i+10]) {
				t.Fatalf("part of a raw key reached a command line (window %d of a %d-character value)", i, len(raw))
			}
		}
	}
	if !strings.Contains(all, "hangryclaude/foo") || !strings.Contains(all, "«…»") {
		t.Errorf("the readable parts should survive and the key should be marked: %q", report.Mask(all))
	}
}

func TestLegitimateTextIsNotMangled(t *testing.T) {
	n, r, _ := newN(t, Config{})
	body := "OpenAI sk-proj-…a1b2 in hangryclaude/shop-factory-2026-11-final (public). Rotate: https://platform.openai.com/api-keys"
	n.Notify("1 live key exposed — rotate now", body, core.High)
	if got := strings.Join(r.calls[0].args, " "); !strings.Contains(got, body) || !strings.Contains(got, "1 live key exposed — rotate now") {
		t.Errorf("repo names, shapes and links must pass untouched: %s", got)
	}
}

func TestLongTextIsCappedOnRuneBoundaries(t *testing.T) {
	n, r, _ := newN(t, Config{})
	n.Notify(strings.Repeat("é", 300), strings.Repeat("日本語 ", 300), core.High)
	script := r.calls[0].args[1]
	if !strings.Contains(script, "…") {
		t.Error("long text should be cut with an ellipsis")
	}
	if len([]rune(script)) > 600 {
		t.Errorf("script is %d runes; the cap did not apply", len([]rune(script)))
	}
	for _, c := range r.calls {
		for _, a := range c.args {
			if strings.ToValidUTF8(a, "") != a {
				t.Error("truncation produced invalid UTF-8")
			}
		}
	}
}

func TestMultiLineBodyFoldsForTheBannerAndStaysForTheText(t *testing.T) {
	n, r, _ := newN(t, Config{IMessageTo: target})
	a := "Anthropic sk-ant-api03-…ks7D in hangryclaude/a (Public). Rotate: https://platform.claude.com/settings/keys"
	b := "GitHub ghp_…2xqk in hangryclaude/b (Public). Rotate: https://github.com/settings/tokens"
	if err := n.Notify("2 live keys exposed — rotate now", a+"\r\n\n"+b+"\n", core.Critical); err != nil {
		t.Fatal(err)
	}
	if got := r.calls[0].args[1]; !strings.Contains(got, `notification "`+a+" · "+b+`" with title`) {
		t.Errorf("banner should fold the lines with a dot: %s", got)
	}
	want := "keyguard (critical): 2 live keys exposed — rotate now\n" + a + "\n" + b
	if got := r.calls[1].args[4]; got != want {
		t.Errorf("text = %q\nwant   %q", got, want)
	}
}

func TestTextBodyIsCappedLongerThanTheBanner(t *testing.T) {
	n, r, _ := newN(t, Config{IMessageTo: target})
	var body []string
	for i := 0; i < 20; i++ {
		body = append(body, "line "+strings.Repeat("word ", 18))
	}
	n.Notify("t", strings.Join(body, "\n"), core.Critical)
	if got := len([]rune(r.calls[1].args[4])); got < 700 || got > 840 {
		t.Errorf("text is %d runes; want it capped near 800, far longer than the 240-rune banner", got)
	}
	if got := len([]rune(r.calls[0].args[1])); got > 500 {
		t.Errorf("banner script is %d runes; the banner body should be capped at 240", got)
	}
}

// report.Summarize and Notify are meant to be used together: what the summary writes must go
// out as written, with no raw value in it and nothing eaten by the masker.
func TestReportSummaryGoesOutAsWritten(t *testing.T) {
	kr := fp.NewEphemeral()
	var rands []string
	var secrets []core.Secret
	for i, c := range []struct{ typ, prefix string }{{"anthropic", "sk-ant-api03-"}, {"github", "ghp_"}, {"stripe", "sk_live_"}, {"openai", "sk-proj-"}} {
		rnd := randStr(t, b64url, 60)
		raw := c.prefix + rnd
		rands = append(rands, rnd)
		sec := core.Secret{
			FP: kr.FP(raw), Type: c.typ, Shape: fp.Shape(raw), Len: len(raw), Verified: core.Live,
			Severity: core.Critical, Status: "open", Triage: "real", FirstSeen: "2026-11-0" + string(rune('1'+i)) + "T00:00:00Z",
			Locations: []core.Location{{Source: "github.com/hangryclaude/demo-" + c.typ, Kind: "repo", Visibility: core.Public, Path: "src/a.py", Line: 3}},
		}
		sec.ID = fp.ID(sec.FP)
		secrets = append(secrets, sec)
	}
	sum := report.Summarize(secrets)
	for _, l := range strings.Split(sum.Body, "\n") {
		if text(l, 300) != l {
			t.Errorf("the masker changed a line the summary wrote: %q -> %q", l, text(l, 300))
		}
	}
	n, r, _ := newN(t, Config{IMessageTo: target})
	if err := n.Notify(sum.Title, sum.Body, sum.Sev); err != nil {
		t.Fatal(err)
	}
	msg := r.calls[1].args[4]
	for _, want := range []string{"4 live keys exposed — rotate now", "https://platform.claude.com/settings/keys",
		"https://github.com/settings/tokens", "https://dashboard.stripe.com/apikeys", "and 1 more. Open the report."} {
		if !strings.Contains(msg, want) {
			t.Errorf("text is missing %q:\n%s", want, report.Mask(msg)) // masked: a failing test must not print a raw value
		}
	}
	all := ""
	for _, c := range r.calls {
		all += strings.Join(c.args, "\n")
	}
	for i, rnd := range rands {
		for j := 0; j+10 <= len(rnd); j++ {
			if strings.Contains(all, rnd[j:j+10]) {
				t.Fatalf("raw value #%d leaked into a command line", i)
			}
		}
	}
}

// --- escaping, against the real AppleScript interpreter -------------------------------

var nasty = []string{
	`plain`,
	`say "hi"`,
	`back\slash`,
	`trailing backslash\`,
	`\"`,
	`"; do shell script "echo INJECTED" --`,
	`" & (do shell script "echo INJECTED") & "`,
	"line1\nline2\rline3\ttab",
	`curly “quotes” and ‘single’`,
	`unicode é ✓ 🙂 日本語`,
	"$(echo INJECTED) and `echo INJECTED`",
	strings.Repeat(`\"`, 50),
	`end of script" end tell`,
}

func realOsascript(t *testing.T) string {
	t.Helper()
	p := "/usr/bin/osascript"
	if _, err := os.Stat(p); err != nil {
		t.Skip("osascript is a macOS tool; this test runs on the Mac keyguard is built for")
	}
	return p
}

// The escaper is checked by asking the real interpreter to hand each string back, not by
// asserting a particular escaped form. No notification is shown: `return` displays nothing.
func TestQuoteRoundTripsThroughRealAppleScript(t *testing.T) {
	osa := realOsascript(t)
	for _, in := range nasty {
		want := strings.Join(strings.Fields(report.Mask(in)), " ") // what text() hands to quote
		out, err := exec.Command(osa, "-e", "return "+quote(want)).CombinedOutput()
		if err != nil {
			t.Errorf("osascript rejected %q: %v: %s", in, err, out)
			continue
		}
		if got := strings.TrimSuffix(string(out), "\n"); got != want {
			t.Errorf("round trip of %q gave %q, want %q", in, got, want)
		}
	}
}

// The whole banner script, as sent, must at least compile for hostile text. osacompile
// compiles without running, so nothing is displayed here either.
func TestBannerScriptCompilesForHostileText(t *testing.T) {
	realOsascript(t)
	out := filepath.Join(t.TempDir(), "x.scpt")
	for _, in := range nasty {
		s := text(in, 240)
		for _, sev := range []core.Severity{core.High, core.Critical} {
			sound := "Ping"
			if sev == core.Critical {
				sound = "Sosumi"
			}
			for _, sub := range []string{"keyguard · " + sev.String(), ""} { // with and without a subtitle clause
				script := bannerScript(s, sub, s, sound)
				if b, err := exec.Command("/usr/bin/osacompile", "-e", script, "-o", out).CombinedOutput(); err != nil {
					t.Errorf("script for %q (subtitle %q) does not compile: %v: %s", in, sub, err, b)
				}
			}
		}
	}
}

// --- failure handling ------------------------------------------------------------------

func TestIMsgNonZeroExitIsLoggedOnceAndNeverRetried(t *testing.T) {
	n, r, l := newN(t, Config{IMessageTo: target})
	r.fail["imsg"] = &ExitError{Code: 1} // imsg's self-send: delivered, exit 1
	if err := n.Notify("2 live keys exposed", "private body text", core.Critical); err != nil {
		t.Fatalf("a delivered-but-exit-1 message must count as sent, got %v", err)
	}
	if n := len(r.named("imsg")); n != 1 {
		t.Fatalf("imsg ran %d times, want exactly 1 (no retry)", n)
	}
	if len(l.lines) != 1 || l.lines[0] != "notify: imsg exited with status 1; delivery unknown, not retried" {
		t.Fatalf("log = %q", l.lines)
	}
	for _, line := range l.lines {
		if strings.Contains(line, "private body") || strings.Contains(line, target) {
			t.Error("log lines must not carry the message or the phone number")
		}
	}
}

func TestIMsgThatNeverStartedIsAFailure(t *testing.T) {
	n, r, l := newN(t, Config{IMessageTo: target})
	r.fail["imsg"] = exec.ErrNotFound
	r.fail["osascript"] = errors.New("fork/exec /usr/bin/osascript: permission denied")
	err := n.Notify("t", "secret-free body", core.Critical)
	if err == nil {
		t.Fatal("with both channels dead the caller must hear about it")
	}
	if !strings.Contains(err.Error(), "macOS banner") || !strings.Contains(err.Error(), "imsg") {
		t.Errorf("error should name both channels: %v", err)
	}
	if strings.Contains(err.Error(), "secret-free body") || strings.Contains(err.Error(), target) {
		t.Errorf("error leaks the message or number: %v", err)
	}
	if len(l.lines) != 2 {
		t.Errorf("want one log line per failed channel, got %q", l.lines)
	}
	for _, line := range l.lines {
		if strings.Contains(line, "secret-free body") || strings.Contains(line, target) {
			t.Errorf("log line leaks the message or number: %q", line)
		}
	}
	if len(r.named("imsg")) != 1 || len(r.named("osascript")) != 1 {
		t.Error("nothing is retried")
	}
}

func TestOneChannelDeliveringIsEnough(t *testing.T) {
	n, r, l := newN(t, Config{IMessageTo: target})
	r.fail["osascript"] = &ExitError{Code: 1}
	if err := n.Notify("t", "b", core.Critical); err != nil {
		t.Errorf("iMessage got through, so the user was told: %v", err)
	}
	if len(l.lines) != 1 || !strings.Contains(l.lines[0], "macOS banner failed") {
		t.Errorf("the banner failure must still be logged: %q", l.lines)
	}

	n, r, _ = newN(t, Config{IMessageTo: target})
	r.fail["imsg"] = errors.New("boom")
	if err := n.Notify("t", "b", core.Critical); err != nil {
		t.Errorf("the banner showed, so the user was told: %v", err)
	}
}

func TestFloodGuard(t *testing.T) {
	n, r, l := newN(t, Config{IMessageTo: target, MaxMessages: 3})
	for i := 0; i < 8; i++ {
		if err := n.Notify("new critical", "one of many", core.Critical); err != nil {
			t.Fatal(err)
		}
	}
	ims := r.named("imsg")
	if len(ims) != 4 {
		t.Fatalf("%d iMessages, want 3 plus one that says there are more", len(ims))
	}
	if last := ims[3].args[4]; !strings.Contains(last, "more critical findings") {
		t.Errorf("the fourth text should say there is more: %q", last)
	}
	if len(r.named("osascript")) != 8 {
		t.Error("the banner is not capped: it is local and silent after the first sound")
	}
	if len(l.lines) != 1 || !strings.Contains(l.lines[0], "3 iMessages sent this run") {
		t.Errorf("the cap should be logged exactly once: %q", l.lines)
	}
}

func TestFloodGuardIsSafeAcrossGoroutines(t *testing.T) {
	n, r, _ := newN(t, Config{IMessageTo: target, MaxMessages: 5})
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); n.Notify("t", "b", core.Critical) }()
	}
	wg.Wait()
	if got := len(r.named("imsg")); got != 6 {
		t.Errorf("%d iMessages under concurrency, want 6", got)
	}
}

func TestTargetValidation(t *testing.T) {
	for _, ok := range []string{"", "+15555550123", "5555550123", "+1 (555) 555-0123", "me@example.com", "a.b_c-d@x.co"} {
		if _, err := New(Config{IMessageTo: ok}); err != nil {
			t.Errorf("target %q rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{"--help", "-x", " +1555", "+1555;rm", "a b\nc", "+1555\x00", "$(id)", "x@y\"z"} {
		if _, err := New(Config{IMessageTo: bad}); err == nil {
			t.Errorf("target %q accepted", bad)
		}
	}
}

func TestDefaults(t *testing.T) {
	n, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	if n.osascript != "/usr/bin/osascript" || n.timeout != 20*time.Second || n.max != 12 || n.run == nil || n.logf == nil {
		t.Errorf("defaults not applied: %+v", n)
	}
	if n.imsg != "" {
		t.Errorf("with no target there is nothing to look up, got imsg=%q", n.imsg)
	}
	n, _ = New(Config{IMessageTo: target})
	if n.imsg == "" {
		t.Error("imsg path should be resolved at New when iMessage is on")
	}
}

// --- real processes, fake binaries -----------------------------------------------------

// fakeBin writes an executable shell script that records every call and exits with code.
func fakeBin(t *testing.T, dir, name string, code int, sleep string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	script := "#!/bin/sh\n" +
		"d=\"$(dirname \"$0\")\"\n" +
		"echo call >> \"$d/" + name + ".calls\"\n" +
		"printf '%s\\n' \"$@\" > \"$d/" + name + ".last\"\n" +
		sleep +
		"exit " + string(rune('0'+code)) + "\n"
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func lines(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
}

// The default runner against real processes: exit 1 from imsg is mapped to ExitError, the
// message is sent exactly once, and every byte of argv arrives as built.
func TestRealProcessesImsgExitOneIsNotRetried(t *testing.T) {
	dir := t.TempDir()
	osa, im := fakeBin(t, dir, "osascript", 0, ""), fakeBin(t, dir, "imsg", 1, "")
	l := &logs{}
	n, err := New(Config{IMessageTo: target, Osascript: osa, IMsg: im, Logf: l.logf})
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Notify(`say "hi" \ there`, "body line", core.Critical); err != nil {
		t.Fatalf("Notify = %v", err)
	}
	if c := lines(t, filepath.Join(dir, "imsg.calls")); len(c) != 1 {
		t.Fatalf("imsg ran %d times, want 1", len(c))
	}
	if c := lines(t, filepath.Join(dir, "osascript.calls")); len(c) != 1 {
		t.Fatalf("osascript ran %d times, want 1", len(c))
	}
	got := strings.Join(lines(t, filepath.Join(dir, "imsg.last")), "\n")
	want := "send\n--to\n" + target + "\n--text\nkeyguard (critical): say \"hi\" \\ there\nbody line"
	if got != want {
		t.Errorf("imsg argv = %q\nwant        %q", got, want)
	}
	osaArgs := lines(t, filepath.Join(dir, "osascript.last"))
	if len(osaArgs) != 2 || osaArgs[0] != "-e" || osaArgs[1] !=
		`display notification "body line" with title "say \"hi\" \\ there" subtitle "keyguard · critical" sound name "Sosumi"` {
		t.Errorf("osascript argv = %q", osaArgs)
	}
	if len(l.lines) != 1 || !strings.Contains(l.lines[0], "status 1") {
		t.Errorf("log = %q", l.lines)
	}
}

func TestRealProcessesMissingAndHungBinaries(t *testing.T) {
	dir := t.TempDir()
	l := &logs{}
	// Nothing to run at all: both channels fail outright.
	n, _ := New(Config{IMessageTo: target, Osascript: filepath.Join(dir, "nope"), IMsg: filepath.Join(dir, "nada"), Logf: l.logf})
	if err := n.Notify("t", "b", core.Critical); err == nil {
		t.Error("missing binaries must be an error")
	}

	// imsg hangs: the timeout kills it and that counts as a failure, not as delivered.
	osa, im := fakeBin(t, dir, "osascript", 0, ""), fakeBin(t, dir, "imsg", 0, "exec sleep 5\n")
	l = &logs{}
	n, _ = New(Config{IMessageTo: target, Osascript: osa, IMsg: im, Logf: l.logf, Timeout: 300 * time.Millisecond})
	start := time.Now()
	if err := n.Notify("t", "b", core.Critical); err != nil {
		t.Errorf("the banner showed, so Notify is nil, got %v", err)
	}
	if time.Since(start) > 4*time.Second {
		t.Error("a hung imsg stalled Notify past its timeout")
	}
	if len(l.lines) != 1 || !strings.Contains(l.lines[0], "imsg failed") || !strings.Contains(l.lines[0], "deadline exceeded") {
		t.Errorf("a timeout should be logged as a failure: %q", l.lines)
	}
}
