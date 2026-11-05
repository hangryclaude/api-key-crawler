package ghcli

import (
	"errors"
	"net/http"
	"sync"
	"time"
)

// Clock is GitHub's time as this process last heard it. Every cursor and every backoff in
// keyguard is measured on it and never on this Mac's clock, which has run about two hours fast
// (STEAL P0-16): a `since` taken from the Mac skips real pushes, and a rate-limit sleep worked
// out from the Mac's clock goes negative or lasts hours.
//
// The only source is the Date header of the responses Client.Do sees. Between responses the
// Mac's clock is trusted for how much time passed, not for what time it is: Now is the last
// Date plus the time elapsed since that response arrived, measured on one clock, so the Mac's
// error cancels. Before any response it falls back to the Mac's clock, because nothing better
// exists yet; Known says which.
type Clock struct {
	mu    sync.Mutex
	local func() time.Time
	date  time.Time // Date header of the latest response, GitHub's clock
	at    time.Time // local() when that response arrived
	known bool
}

// NewClock makes a clock over local, this Mac's clock (nil means time.Now).
func NewClock(local func() time.Time) *Clock { return &Clock{local: local} }

// SetLocal replaces this Mac's clock. Tests give it one that is hours off.
func (k *Clock) SetLocal(local func() time.Time) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.local = local
}

func (k *Clock) localNow() time.Time {
	if k.local != nil {
		return k.local()
	}
	return time.Now()
}

// Local is this Mac's time now. It is for measuring elapsed time and for nothing that ends up
// in a cursor.
func (k *Clock) Local() time.Time {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.localNow()
}

// Observe takes the Date header of one response. A response without a usable one is ignored,
// so the clock never moves backwards on a header it cannot read.
func (k *Clock) Observe(h http.Header) {
	t, err := http.ParseTime(h.Get("Date"))
	if err != nil {
		return
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	k.date, k.at, k.known = t.UTC(), k.localNow(), true
}

// Known reports whether any response has been heard yet.
func (k *Clock) Known() bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.known
}

// Now is GitHub's time now, as well as this process can tell.
func (k *Clock) Now() time.Time {
	k.mu.Lock()
	defer k.mu.Unlock()
	if !k.known {
		return k.localNow().UTC()
	}
	return k.date.Add(k.localNow().Sub(k.at)).UTC()
}

// Skew is how far this Mac's clock is ahead of GitHub's (negative: behind) and whether it is
// known at all. Doctor fails when it is more than a minute either way.
func (k *Clock) Skew() (time.Duration, bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if !k.known {
		return 0, false
	}
	return k.at.Sub(k.date), true
}

// MaxSkew is how far this Mac's clock may be from GitHub's before doctor calls it broken (STEAL
// P0-16). Every cursor here is GitHub's, so a skew costs nothing in the sweep itself; but a Mac
// that far off is wrong for the launchd schedule, the notification stamps and the git commits
// too, and it has been two hours.
const MaxSkew = time.Minute

// SkewOK reports whether a skew from Clock.Skew is small enough to leave alone.
func SkewOK(skew time.Duration) bool { return skew >= -MaxSkew && skew <= MaxSkew }

// Rate-limit waits. GitHub documents "wait until the reset time" for the primary limit and "at
// least one minute" for a secondary one that says nothing else.
const (
	// WaitMargin is added to a wait computed from the reset time, for the second GitHub's own
	// clock may be off from the one it stamped on the header.
	WaitMargin = 2 * time.Second
	// DefaultWait is the pause when a limit gives no reset time and no retry-after.
	DefaultWait = time.Minute
	// MaxWait stops a bad header from parking a poll for hours. Primary limits reset hourly.
	MaxWait = time.Hour + WaitMargin
)

// Wait is how long to stay quiet after this limit, on GitHub's clock (STEAL P0-16): retry-after
// when GitHub sent one, else the reset time minus now plus a two-second margin. now is GitHub's
// time now (Client.Clock().Now()); when it is zero the time GitHub stamped on the response
// itself stands in, which is the same clock a moment earlier. The result is never negative and
// never longer than MaxWait.
func (e *RateLimitError) Wait(now time.Time) time.Duration {
	if e.RetryAfter > 0 {
		return min(e.RetryAfter, MaxWait)
	}
	if e.Reset.IsZero() {
		return DefaultWait
	}
	if now.IsZero() {
		now = e.At
	}
	if now.IsZero() {
		// Neither GitHub's time nor a stamp: the Mac's clock is all there is, and no honest
		// answer exists. Take the cautious one.
		return DefaultWait
	}
	return min(max(e.Reset.Sub(now)+WaitMargin, 0), MaxWait)
}

// RateLimitWait reports how long err asks the caller to wait, on this client's view of GitHub's
// clock, and whether err was a rate limit at all.
func (c *Client) RateLimitWait(err error) (time.Duration, bool) {
	var rl *RateLimitError
	if !errors.As(err, &rl) {
		return 0, false
	}
	return rl.Wait(c.Clock().Now()), true
}
