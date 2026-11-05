// Package notify reaches the user when a key needs rotating: a macOS banner for high and
// critical findings, and an iMessage for critical ones only. Both channels are commands
// run through an injectable Runner, so tests send nothing real.
//
//	n, err := notify.New(notify.Config{IMessageTo: target}) // target from config.json
//	err = n.Notify(title, body, core.Critical)              // body may hold several lines
package notify

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"keyguard/internal/core"
	"keyguard/internal/report"
)

// Runner runs one command to completion. It returns no output on purpose: nothing a
// notification command prints should find its way into a log.
type Runner func(ctx context.Context, name string, args ...string) error

// ExitError means the command started and exited non-zero. Notify needs to tell this apart
// from a command that never started: imsg exits non-zero on a message to yourself even
// when it was delivered.
type ExitError struct{ Code int }

func (e *ExitError) Error() string { return "exit status " + strconv.Itoa(e.Code) }

// Config is everything a Notifier needs. The zero value is a banner-only notifier that
// runs the real osascript.
type Config struct {
	IMessageTo  string                           // phone number or email for imsg; "" turns iMessage off
	Osascript   string                           // default /usr/bin/osascript
	IMsg        string                           // default: imsg on PATH, then the usual install spots
	Run         Runner                           // default: exec
	Logf        func(format string, args ...any) // default: one line on stderr
	Timeout     time.Duration                    // per command; default 20 s so a stuck Messages.app cannot stall a poll
	MaxMessages int                              // iMessages per Notifier before it goes quiet; default 12
}

// Notifier implements core.Notifier.
type Notifier struct {
	to, osascript, imsg string
	run                 Runner
	logf                func(string, ...any)
	timeout             time.Duration
	max                 int

	mu   sync.Mutex
	sent int // iMessages attempted so far
}

var _ core.Notifier = (*Notifier)(nil)

// A target is a phone number or an email address. Refusing anything else keeps a stray
// "-" from turning the value into an imsg flag.
var targetRe = regexp.MustCompile(`^[A-Za-z0-9+][A-Za-z0-9+@._() -]*$`)

// New checks the config once, at start-up: a bad target found while an alert is being sent
// is a missed alert.
func New(cfg Config) (*Notifier, error) {
	if cfg.IMessageTo != "" && !targetRe.MatchString(cfg.IMessageTo) {
		return nil, errors.New("notify: iMessage target must be a phone number or an email address")
	}
	n := &Notifier{
		to: cfg.IMessageTo, osascript: cfg.Osascript, imsg: cfg.IMsg, run: cfg.Run, logf: cfg.Logf,
		timeout: cfg.Timeout, max: cfg.MaxMessages,
	}
	if n.osascript == "" {
		n.osascript = "/usr/bin/osascript"
	}
	if n.imsg == "" && n.to != "" {
		n.imsg = findIMsg()
	}
	if n.run == nil {
		n.run = execRunner
	}
	if n.logf == nil {
		n.logf = func(format string, args ...any) { fmt.Fprintf(os.Stderr, "keyguard: "+format+"\n", args...) }
	}
	if n.timeout <= 0 {
		n.timeout = 20 * time.Second
	}
	if n.max <= 0 {
		// A backstop, not the limiter: sweep already sends its first ten alerts one by one and
		// the rest as one digest, so 12 never cuts a message it meant to send.
		n.max = 12
	}
	return n, nil
}

// Notify tells the user. High gets a banner; critical gets a banner and an iMessage. Below
// high there is nothing worth interrupting them for, so it does nothing and returns nil.
//
// It returns nil when they were probably told by at least one channel, and an error only when
// every channel failed outright. The caller records "notified" on nil, so an iMessage that
// exited non-zero but was delivered must count as told: an error here would make the next
// poll send it again, every minute. Nothing is retried inside Notify either.
func (n *Notifier) Notify(title, body string, sev core.Severity) error {
	if sev < core.High {
		return nil
	}
	if sev > core.Critical { // a corrupt value must not index past core's severity names
		sev = core.Critical
	}
	title = text(title, 100)
	lines := bodyLines(body)
	if title == "" && len(lines) == 0 {
		return errors.New("notify: empty message")
	}
	// A banner has room for one line; a text can carry the list as written.
	bannerBody, textBody := text(strings.Join(lines, " · "), 240), clip(strings.Join(lines, "\n"), 800)

	var errs []error
	told := false
	if err := n.banner(title, bannerBody, sev); err != nil {
		n.logf("notify: macOS banner failed: %v", err)
		errs = append(errs, fmt.Errorf("notify: macOS banner: %w", err))
	} else {
		told = true
	}

	if sev == core.Critical && n.to != "" {
		var exit *ExitError
		switch err := n.message(title, textBody, sev); {
		case err == nil:
			told = true
		case errors.Is(err, errQuiet):
		case errors.As(err, &exit):
			// Delivery is unknowable and a retry could send it twice. Log it once, count it
			// as sent, move on.
			n.logf("notify: imsg exited with status %d; delivery unknown, not retried", exit.Code)
			told = true
		default:
			n.logf("notify: imsg failed: %v", err)
			errs = append(errs, fmt.Errorf("notify: imsg: %w", err))
		}
	}
	if told {
		return nil
	}
	return errors.Join(errs...)
}

// text makes s safe to hand to a command: key-like runs masked, control characters and
// line breaks folded into single spaces, length capped. A notification is stored by
// Notification Center and, for iMessage, passes through Apple's servers; it must carry
// shapes only, whatever the caller meant to pass.
func text(s string, max int) string {
	return clip(strings.Join(strings.Fields(report.Mask(s)), " "), max)
}

// bodyLines splits a body on line breaks and treats each line as text, so a multi-line body
// (sweep's alerts, report.Summarize's list) keeps its lines for iMessage and folds into one
// line for the banner.
func bodyLines(body string) []string {
	var out []string
	for _, l := range strings.Split(body, "\n") {
		if l = text(l, 300); l != "" {
			out = append(out, l)
		}
	}
	return out
}

func clip(s string, max int) string {
	if utf8.RuneCountInString(s) > max {
		return string([]rune(s)[:max-1]) + "…"
	}
	return s
}

// --- macOS banner ---------------------------------------------------------------------

func (n *Notifier) banner(title, body string, sev core.Severity) error {
	if title == "" { // a banner needs both lines; the app name alone says nothing
		title = "keyguard"
	}
	if body == "" {
		body, title = title, "keyguard"
	}
	sound := "Ping"
	if sev == core.Critical {
		sound = "Sosumi"
	}
	// The banner's app name is "Script Editor"; the subtitle is what says it is keyguard,
	// unless the caller's title already does.
	sub := "keyguard · " + sev.String()
	if branded(title) {
		sub = ""
	}
	return n.invoke(n.osascript, "-e", bannerScript(title, sub, body, sound))
}

// branded reports whether the caller's title already starts with "keyguard", as sweep's
// do ("keyguard CRITICAL: live openai key is exposed"); prefixing again would say it twice.
func branded(title string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(title)), "keyguard")
}

// bannerScript builds the AppleScript for one banner. Every piece of text goes through
// quote; sound is one of two constants. An empty subtitle leaves the clause out.
func bannerScript(title, subtitle, body, sound string) string {
	s := "display notification " + quote(body) + " with title " + quote(title)
	if subtitle != "" {
		s += " subtitle " + quote(subtitle)
	}
	return s + ` sound name "` + sound + `"`
}

// quote renders s as an AppleScript string literal. Backslash goes first so the
// backslashes added for quotes are not doubled. text has already removed control
// characters, which are the only other thing a literal cannot hold.
func quote(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}

// --- iMessage -------------------------------------------------------------------------

// errQuiet marks a message dropped by the flood guard: neither sent nor failed.
var errQuiet = errors.New("notify: iMessage cap reached")

// message sends one iMessage. A first deep scan can find dozens of keys at once; the
// guard sends the first few, then one line saying there are more, then nothing, so one run
// cannot flood their phone or get the number flagged as spam.
func (n *Notifier) message(title, body string, sev core.Severity) error {
	n.mu.Lock()
	n.sent++
	k := n.sent
	n.mu.Unlock()

	var msg string
	switch {
	case k <= n.max:
		switch {
		case branded(title):
			msg = title
		case title != "":
			msg = "keyguard (" + sev.String() + "): " + title
		default:
			msg = "keyguard (" + sev.String() + ")"
		}
		if body != "" {
			msg += "\n" + body
		}
	case k == n.max+1:
		n.logf("notify: %d iMessages sent this run; the rest are in the report", n.max)
		msg = "keyguard: more critical findings than I will text about at once. Open the report on your Mac."
	default:
		return errQuiet
	}
	return n.invoke(n.imsg, "send", "--to", n.to, "--text", msg)
}

// findIMsg looks where launchd's short PATH will not: Homebrew's bin dirs and ~/.local/bin.
func findIMsg() string {
	if p, err := exec.LookPath("imsg"); err == nil {
		return p
	}
	home, _ := os.UserHomeDir()
	for _, p := range []string{"/opt/homebrew/bin/imsg", "/usr/local/bin/imsg", filepath.Join(home, ".local", "bin", "imsg")} {
		if st, err := os.Stat(p); err == nil && !st.IsDir() && st.Mode()&0o111 != 0 {
			return p
		}
	}
	return "imsg"
}

// --- running commands -----------------------------------------------------------------

func (n *Notifier) invoke(name string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), n.timeout)
	defer cancel()
	return n.run(ctx, name, args...)
}

// execRunner discards output and maps a non-zero exit to ExitError. A timeout is not an
// exit status: the process was killed, so delivery is not "unknown but probably fine".
func execRunner(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.WaitDelay = 2 * time.Second
	err := cmd.Run()
	if err == nil {
		return nil
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return &ExitError{Code: ee.ExitCode()}
	}
	return err
}
