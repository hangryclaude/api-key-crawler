package ghcli_test

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"keyguard/internal/inventory/ghcli"
	"keyguard/internal/inventory/ghcli/ghclitest"
)

// github is a fixed instant of GitHub's clock. This Mac's clock in the tests below is hours
// off it, the way it really was on 2026-11-03.
var github = time.Date(2026, 11, 3, 23, 31, 37, 0, time.UTC)

// skewed builds a client whose Mac clock reads GitHub's plus skew and a fake that stamps every
// reply with GitHub's own time. Both clocks stand still until the test moves them.
type skewed struct {
	cl     *ghcli.Client
	f      *ghclitest.Fake
	mu     sync.Mutex
	ghNow  time.Time
	macNow time.Time
}

func newSkewed(t *testing.T, skew time.Duration, h func(ghclitest.Call) ghclitest.Reply) *skewed {
	t.Helper()
	s := &skewed{ghNow: github, macNow: github.Add(skew)}
	s.f = ghclitest.New(t, h, "alice")
	s.f.SetClock(func() time.Time { s.mu.Lock(); defer s.mu.Unlock(); return s.ghNow })
	s.cl = newClient(s.f)
	s.cl.Clock().SetLocal(func() time.Time { s.mu.Lock(); defer s.mu.Unlock(); return s.macNow })
	return s
}

// pass lets d go by on both clocks, the way real time does.
func (s *skewed) pass(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ghNow, s.macNow = s.ghNow.Add(d), s.macNow.Add(d)
}

func ok200(ghclitest.Call) ghclitest.Reply { return ghclitest.JSON(200, map[string]string{}) }

// The two directions that matter: a Mac two hours fast (the real one) and two hours slow.
var skews = map[string]time.Duration{"mac 2h fast": 2 * time.Hour, "mac 2h slow": -2 * time.Hour}

func TestClockIsGitHubsNotTheMacs(t *testing.T) {
	for name, skew := range skews {
		t.Run(name, func(t *testing.T) {
			s := newSkewed(t, skew, ok200)
			if s.cl.Clock().Known() {
				t.Fatal("the clock claims to know GitHub's time before any response")
			}
			if _, err := s.cl.Do(context.Background(), "alice", ghcli.Request{Path: "user"}); err != nil {
				t.Fatal(err)
			}
			if !s.cl.Clock().Known() {
				t.Fatal("the Date header of a response was not taken")
			}
			if got := s.cl.Clock().Now(); !got.Equal(github) {
				t.Errorf("Now = %s, want GitHub's %s", got, github)
			}
			if got, ok := s.cl.Clock().Skew(); !ok || got != skew {
				t.Errorf("Skew = %v, %v, want %v", got, ok, skew)
			}
			// Time passing is measured on the Mac's clock, whose error cancels out.
			s.pass(90 * time.Second)
			if got := s.cl.Clock().Now(); !got.Equal(github.Add(90 * time.Second)) {
				t.Errorf("90 s later Now = %s", got)
			}
		})
	}
}

func TestClockFallsBackToTheMacOnlyUntilGitHubHasSpoken(t *testing.T) {
	mac := time.Date(2026, 11, 4, 1, 31, 37, 0, time.UTC)
	k := ghcli.NewClock(func() time.Time { return mac })
	if got := k.Now(); !got.Equal(mac) {
		t.Errorf("before any response Now = %s, want the Mac's %s", got, mac)
	}
	if _, ok := k.Skew(); ok {
		t.Error("a skew was reported without a response to measure it against")
	}
	h := http.Header{}
	h.Set("Date", "not a date")
	k.Observe(h)
	if k.Known() {
		t.Error("an unreadable Date header was taken")
	}
	h.Set("Date", github.Format(http.TimeFormat))
	k.Observe(h)
	if got := k.Now(); !got.Equal(github) {
		t.Errorf("Now = %s after a Date header", got)
	}
	h.Set("Date", "")
	k.Observe(h)
	if got := k.Now(); !got.Equal(github) {
		t.Errorf("a response with no Date moved the clock to %s", got)
	}
}

func TestEveryKindOfResponseFeedsTheClock(t *testing.T) {
	for _, status := range []int{200, 304, 404, 422, 502} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			s := newSkewed(t, 2*time.Hour, func(ghclitest.Call) ghclitest.Reply { return ghclitest.Reply{Status: status} })
			s.cl.MaxAttempts = 1
			if _, err := s.cl.Do(context.Background(), "alice", ghcli.Request{Path: "user"}); err != nil {
				t.Fatal(err)
			}
			if got := s.cl.Clock().Now(); !got.Equal(github) {
				t.Errorf("HTTP %d: Now = %s, want %s", status, got, github)
			}
		})
	}
}

func limited(reset time.Time, extra map[string]string) func(ghclitest.Call) ghclitest.Reply {
	return func(ghclitest.Call) ghclitest.Reply {
		r := ghclitest.JSON(403, map[string]string{"message": "API rate limit exceeded for user ID 1."})
		r.Header = map[string]string{"X-Ratelimit-Remaining": "0", "X-Ratelimit-Reset": strconv.FormatInt(reset.Unix(), 10)}
		for k, v := range extra {
			r.Header[k] = v
		}
		return r
	}
}

// The wait is the reset time minus GitHub's now plus two seconds, whatever this Mac thinks the
// time is. With the Mac two hours fast the old arithmetic went hours negative, so a poll would
// have hammered a spent limit; with it slow the poll would have slept for two hours.
func TestRateLimitWaitIsMeasuredOnGitHubsClock(t *testing.T) {
	for name, skew := range skews {
		t.Run(name, func(t *testing.T) {
			s := newSkewed(t, skew, limited(github.Add(30*time.Second), nil))
			resp, err := s.cl.Do(context.Background(), "alice", ghcli.Request{Path: "user"})
			if err != nil {
				t.Fatal(err)
			}
			rl := asRateLimit(t, resp.Err())
			if want := 32 * time.Second; rl.Wait(s.cl.Clock().Now()) != want {
				t.Errorf("Wait = %v, want %v", rl.Wait(s.cl.Clock().Now()), want)
			}
			if !rl.At.Equal(github) {
				t.Errorf("At = %s, want the Date GitHub stamped, %s", rl.At, github)
			}
			// Without a clock of the caller's own, the stamp on the response stands in for it.
			if got := rl.Wait(time.Time{}); got != 32*time.Second {
				t.Errorf("Wait with no now = %v, want 32s from the response's own Date", got)
			}
			// Ten seconds later the same limit asks for ten seconds less.
			s.pass(10 * time.Second)
			if got, isLimit := s.cl.RateLimitWait(resp.Err()); !isLimit || got != 22*time.Second {
				t.Errorf("RateLimitWait 10 s later = %v, %v, want 22s", got, isLimit)
			}
		})
	}
}

func TestRateLimitWaitEdges(t *testing.T) {
	now := github
	reset := func(d time.Duration) time.Time { return now.Add(d) }
	for _, tc := range []struct {
		name string
		rl   ghcli.RateLimitError
		want time.Duration
	}{
		{"retry-after wins over the reset", ghcli.RateLimitError{RetryAfter: 45 * time.Second, Reset: reset(10 * time.Minute)}, 45 * time.Second},
		{"the reset has passed: wait nothing, never a negative sleep", ghcli.RateLimitError{Reset: reset(-5 * time.Minute)}, 0},
		{"the reset is a second away: the margin still applies", ghcli.RateLimitError{Reset: reset(time.Second)}, 3 * time.Second},
		{"no reset and no retry-after: a minute", ghcli.RateLimitError{}, time.Minute},
		{"a reset hours away is capped", ghcli.RateLimitError{Reset: reset(5 * time.Hour)}, ghcli.MaxWait},
		{"a huge retry-after is capped too", ghcli.RateLimitError{RetryAfter: 24 * time.Hour}, ghcli.MaxWait},
	} {
		if got := tc.rl.Wait(now); got != tc.want {
			t.Errorf("%s: Wait = %v, want %v", tc.name, got, tc.want)
		}
	}
	// A reset but nothing to measure it against is a guess, and the guess is the cautious one.
	if got := (&ghcli.RateLimitError{Reset: github}).Wait(time.Time{}); got != time.Minute {
		t.Errorf("no clock at all: Wait = %v, want a minute", got)
	}
	// Retry-After beats the reset in a real response as well.
	s := newSkewed(t, 2*time.Hour, limited(github.Add(20*time.Minute), map[string]string{"Retry-After": "60"}))
	resp, _ := s.cl.Do(context.Background(), "alice", ghcli.Request{Path: "user"})
	if got, _ := s.cl.RateLimitWait(resp.Err()); got != time.Minute {
		t.Errorf("retry-after 60 gave a wait of %v", got)
	}
	if _, isLimit := s.cl.RateLimitWait(fmt.Errorf("not a limit")); isLimit {
		t.Error("an ordinary error was read as a rate limit")
	}
}

func asRateLimit(t *testing.T, err error) *ghcli.RateLimitError {
	t.Helper()
	rl, _ := err.(*ghcli.RateLimitError)
	if rl == nil {
		t.Fatalf("err = %#v, want a *RateLimitError", err)
	}
	return rl
}

func TestGraphQLRateLimitKeepsItsResetAndClock(t *testing.T) {
	s := newSkewed(t, 2*time.Hour, func(ghclitest.Call) ghclitest.Reply {
		r := ghclitest.Reply{Status: 200, Body: []byte(`{"data":{"viewer":null},"errors":[{"type":"RATE_LIMITED","message":"API rate limit exceeded"}]}`)}
		r.Header = map[string]string{"X-Ratelimit-Reset": strconv.FormatInt(github.Add(90*time.Second).Unix(), 10)}
		return r
	})
	_, err := s.cl.GraphQL(context.Background(), "alice", "query{}", nil)
	rl := asRateLimit(t, err)
	if got := rl.Wait(s.cl.Clock().Now()); got != 92*time.Second {
		t.Errorf("a GraphQL rate limit waits %v, want 92s", got)
	}
}

func TestFakeSendsADateHeaderLikeGitHub(t *testing.T) {
	f := ghclitest.New(t, ok200, "alice")
	cl := newClient(f)
	before := time.Now().Add(-2 * time.Second)
	resp, err := cl.Do(context.Background(), "alice", ghcli.Request{Path: "user"})
	if err != nil {
		t.Fatal(err)
	}
	d, ok := resp.Date()
	if !ok || d.Before(before) || d.After(time.Now().Add(2*time.Second)) {
		t.Errorf("default Date = %s, %v; want about now", d, ok)
	}
	f.SetClock(func() time.Time { return github })
	resp, _ = cl.Do(context.Background(), "alice", ghcli.Request{Path: "user"})
	if d, _ := resp.Date(); !d.Equal(github) {
		t.Errorf("Date = %s, want %s", d, github)
	}
	// A reply that sets its own Date keeps it.
	f2 := ghclitest.New(t, func(ghclitest.Call) ghclitest.Reply {
		r := ghclitest.JSON(200, map[string]string{})
		r.Header = map[string]string{"Date": "Mon, 02 Nov 2026 10:00:00 GMT"}
		return r
	}, "alice")
	resp, _ = newClient(f2).Do(context.Background(), "alice", ghcli.Request{Path: "user"})
	if d, _ := resp.Date(); d.Day() != 2 {
		t.Errorf("an explicit Date was replaced: %s", d)
	}
}

// spyTB records what the fake would have failed the test with, so the fake's own policing can
// be tested without failing this test.
type spyTB struct {
	testing.TB
	errs []string
}

func (s *spyTB) Errorf(format string, args ...any) {
	s.errs = append(s.errs, fmt.Sprintf(format, args...))
}
func (s *spyTB) Helper() {}

func TestFakeRefusesParameterFlagsAndAMissingMethod(t *testing.T) {
	spy := &spyTB{TB: t}
	f := ghclitest.New(spy, ok200, "alice")
	run := func(args ...string) {
		_, _ = f.Run(context.Background(), ghcli.Cmd{Name: "gh", Args: append([]string{"api", "-i"}, args...), Env: []string{"GH_TOKEN=" + f.Token("alice")}})
	}
	run("--method", "GET", "repos/o/r/secret-scanning/alerts")
	if len(spy.errs) != 0 {
		t.Fatalf("a clean GET was refused: %v", spy.errs)
	}
	for _, flag := range []string{"-f", "-F", "--field", "--raw-field"} {
		spy.errs = nil
		run("--method", "GET", flag, "state=open", "repos/o/r/secret-scanning/alerts")
		if len(spy.errs) != 1 || !strings.Contains(spy.errs[0], flag) || !strings.Contains(spy.errs[0], "GET into a POST") {
			t.Errorf("%s: errors = %q", flag, spy.errs)
		}
	}
	spy.errs = nil
	run("repos/o/r")
	if len(spy.errs) != 1 || !strings.Contains(spy.errs[0], "--method") {
		t.Errorf("a call with no --method: errors = %q", spy.errs)
	}
}

func TestEveryRequestNamesItsMethodAndCarriesNoParameterFlag(t *testing.T) {
	f := ghclitest.New(t, ok200, "alice")
	cl := newClient(f)
	ctx := context.Background()
	if _, err := cl.Do(ctx, "alice", ghcli.Request{Path: "user/repos?visibility=public&per_page=100&page=2"}); err != nil {
		t.Fatal(err)
	}
	if _, err := cl.Do(ctx, "alice", ghcli.Request{Method: "PATCH", Path: "repos/o/r", Body: []byte(`{}`)}); err != nil {
		t.Fatal(err)
	}
	if _, err := cl.GraphQL(ctx, "alice", "query{}", map[string]any{"n": 1}); err != nil {
		t.Fatal(err)
	}
	for _, cmd := range f.Commands() {
		if cmd[0] != "api" {
			continue
		}
		method := ""
		for i, a := range cmd {
			switch a {
			case "-f", "-F", "--field", "--raw-field":
				t.Errorf("parameter flag %s in %v", a, cmd)
			case "--method":
				method = cmd[i+1]
			}
		}
		if method == "" {
			t.Errorf("no --method in %v", cmd)
		}
	}
	// The query of a GET stays in the path, where gh sends it as a query string.
	if got := f.Calls()[0].Path; got != "user/repos?visibility=public&per_page=100&page=2" {
		t.Errorf("path = %q", got)
	}
}

func TestAPIPathCannotBeReadAsAFlag(t *testing.T) {
	f := ghclitest.New(t, func(ghclitest.Call) ghclitest.Reply { t.Fatal("gh must not run"); return ghclitest.Reply{} }, "alice")
	for _, p := range []string{"-f", "--field", "-X", "-"} {
		if _, err := newClient(f).Do(context.Background(), "alice", ghcli.Request{Path: p}); err == nil {
			t.Errorf("path %q was run", p)
		}
	}
	if n := len(f.Commands()); n != 0 {
		t.Errorf("%d processes started", n)
	}
}

func TestSkewOKIsAMinuteEitherWay(t *testing.T) {
	for skew, want := range map[time.Duration]bool{
		0: true, time.Minute: true, -time.Minute: true, 61 * time.Second: false, -61 * time.Second: false,
		2 * time.Hour: false, -2 * time.Hour: false, 1199 * time.Millisecond: true,
	} {
		if got := ghcli.SkewOK(skew); got != want {
			t.Errorf("SkewOK(%v) = %v", skew, got)
		}
	}
}
