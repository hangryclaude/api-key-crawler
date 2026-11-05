package ghsettings

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"keyguard/internal/core"
	"keyguard/internal/fp"
	"keyguard/internal/inventory/ghcli"
	"keyguard/internal/inventory/ghcli/ghclitest"
)

// ghub is the slice of GitHub this package talks to: repo objects with a security_and_analysis
// block, the PATCH that edits it (with the refusals a plan can impose), and the alerts list.
type ghub struct {
	mu    sync.Mutex
	repos map[string]*hrepo // "owner/name"
	log   []string          // "PATCH owner/name <body>" and "GET ..." in arrival order

	now     func() time.Time    // GitHub's clock, to stamp the writes with
	latency func(method string) // called as every request arrives; a test makes requests take time with it
	patchAt []time.Time         // when each PATCH arrived, on that clock
	// rateLimitAfter makes every PATCH from the n-th on (1-based, 0 = never) answer with a
	// rate limit that resets resetIn after GitHub's clock.
	rateLimitAfter int
	resetIn        time.Duration
	patchCount     int

	inflightPatch, maxPatch atomic.Int32
}

type hrepo struct {
	hidden       bool              // security_and_analysis is omitted from GET (no admin rights)
	null         bool              // security_and_analysis is JSON null, as on a private repo of a free plan
	sa           map[string]string // feature -> status
	refuse       map[string]string // feature -> 422 message when someone tries to enable it
	refuseStatus int               // the status refuse answers with; 0 means 422
	noStick      map[string]bool   // feature -> a PATCH answers 200 and "enabled" but changes nothing
	getBroken    bool              // GET answers 500 once a PATCH has been made
	patched      bool
	missing      bool // GET and PATCH answer 404
	alerts       []halert
	alertsStatus int    // forced status for the alerts endpoint
	alertsMsg    string // and its message
	ignoresHide  bool   // the alerts endpoint sends the secret although hide_secret=true was asked
}

type halert struct {
	number                         int
	typ, display, secret, validity string
	created                        string
}

func newGhub() *ghub { return &ghub{repos: map[string]*hrepo{}} }

func (g *ghub) add(name string, r hrepo) *hrepo {
	if r.sa == nil {
		r.sa = map[string]string{}
	}
	g.repos[name] = &r
	return &r
}

func (g *ghub) patches() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	var out []string
	for _, l := range g.log {
		if strings.HasPrefix(l, "PATCH ") {
			out = append(out, l)
		}
	}
	return out
}

func repoReply(name string, r *hrepo) map[string]any {
	m := map[string]any{"full_name": name, "private": r.null}
	switch {
	case r.null:
		m["security_and_analysis"] = nil
	case !r.hidden:
		sa := map[string]any{}
		for f, st := range r.sa {
			sa[f] = map[string]string{"status": st}
		}
		m["security_and_analysis"] = sa
	}
	return m
}

func (g *ghub) handler(t testing.TB) func(ghclitest.Call) ghclitest.Reply {
	return func(c ghclitest.Call) ghclitest.Reply {
		path, query, _ := strings.Cut(c.Path, "?")
		if path == "rate_limit" { // free of quota; the way to learn GitHub's time without spending any
			return ghclitest.JSON(200, map[string]any{"resources": map[string]any{}})
		}
		rest, ok := strings.CutPrefix(path, "repos/")
		if !ok {
			t.Errorf("ghub: unexpected path %s", c.Path)
			return ghclitest.JSON(404, map[string]string{"message": "Not Found"})
		}
		parts := strings.Split(rest, "/")
		name := parts[0] + "/" + parts[1]
		isAlerts := len(parts) == 4 && parts[2] == "secret-scanning" && parts[3] == "alerts"

		if g.latency != nil {
			g.latency(c.Method)
		}
		if c.Method == "PATCH" {
			n := g.inflightPatch.Add(1)
			defer g.inflightPatch.Add(-1)
			if n > g.maxPatch.Load() {
				g.maxPatch.Store(n)
			}
			time.Sleep(2 * time.Millisecond) // widen the window in which an overlap would show
		}

		g.mu.Lock()
		defer g.mu.Unlock()
		g.log = append(g.log, c.Method+" "+name+" "+string(c.Body))
		r := g.repos[name]
		if r == nil || r.missing {
			return ghclitest.JSON(404, map[string]string{"message": "Not Found"})
		}
		switch {
		case isAlerts && c.Method == "GET":
			return g.alerts(t, r, query)
		case c.Method == "GET":
			if r.getBroken && r.patched {
				return ghclitest.JSON(500, map[string]string{"message": "Server Error"})
			}
			return ghclitest.JSON(200, repoReply(name, r))
		case c.Method == "PATCH":
			g.patchCount++
			if g.now != nil {
				g.patchAt = append(g.patchAt, g.now())
			}
			if g.rateLimitAfter > 0 && g.patchCount >= g.rateLimitAfter {
				reset := g.now().Add(g.resetIn)
				rl := ghclitest.JSON(403, map[string]string{"message": "You have exceeded a secondary rate limit."})
				rl.Header = map[string]string{"X-Ratelimit-Remaining": "0", "X-Ratelimit-Reset": strconv.FormatInt(reset.Unix(), 10)}
				return rl
			}
			r.patched = true
			var body struct {
				SA map[string]struct {
					Status string `json:"status"`
				} `json:"security_and_analysis"`
			}
			if err := json.Unmarshal(c.Body, &body); err != nil || len(body.SA) != 1 {
				t.Errorf("ghub: PATCH body %q is not one security_and_analysis field", c.Body)
				return ghclitest.JSON(400, map[string]string{"message": "Problems parsing JSON"})
			}
			reply := map[string]any{}
			for f, v := range body.SA {
				if msg := r.refuse[f]; msg != "" {
					status := r.refuseStatus
					if status == 0 {
						status = 422
					}
					return ghclitest.JSON(status, map[string]any{"message": "Validation Failed", "errors": []string{msg}, "status": strconv.Itoa(status)})
				}
				if f == "secret_scanning_push_protection" && r.sa["secret_scanning"] != "enabled" {
					return ghclitest.JSON(422, map[string]any{"message": "Validation Failed", "errors": []string{"Secret scanning must be enabled"}})
				}
				if r.noStick[f] {
					reply[f] = map[string]string{"status": "enabled"} // the claim, with nothing behind it
					continue
				}
				r.sa[f] = v.Status
			}
			out := repoReply(name, r)
			if len(reply) > 0 {
				claimed := map[string]any{}
				for f, st := range r.sa {
					claimed[f] = map[string]string{"status": st}
				}
				for f, v := range reply {
					claimed[f] = v
				}
				out["security_and_analysis"] = claimed
			}
			return ghclitest.JSON(200, out)
		}
		t.Errorf("ghub: unexpected %s %s", c.Method, c.Path)
		return ghclitest.JSON(405, map[string]string{"message": "Method Not Allowed"})
	}
}

func (g *ghub) alerts(t testing.TB, r *hrepo, query string) ghclitest.Reply {
	q, _ := url.ParseQuery(query)
	// STEAL P0-20: the raw value must never reach keyguard, so every alerts call asks GitHub to
	// leave it out. A call that does not fails whatever it was testing.
	hide := q.Get("hide_secret") == "true"
	if !hide {
		t.Errorf("ghub: alerts requested without hide_secret=true: %q", query)
	}
	if r.alertsStatus != 0 {
		return ghclitest.JSON(r.alertsStatus, map[string]string{"message": r.alertsMsg})
	}
	if q.Get("state") != "open" {
		t.Errorf("ghub: alerts requested with state=%q, want open", q.Get("state"))
	}
	per, _ := strconv.Atoi(q.Get("per_page"))
	pg, _ := strconv.Atoi(q.Get("page"))
	lo := min((pg-1)*per, len(r.alerts))
	hi := min(lo+per, len(r.alerts))
	items := make([]map[string]any, 0, hi-lo)
	for _, a := range r.alerts[lo:hi] {
		it := map[string]any{
			"number": a.number, "state": "open", "created_at": a.created,
			"html_url":    fmt.Sprintf("https://github.com/o/r/security/secret-scanning/%d", a.number),
			"secret_type": a.typ, "secret_type_display_name": a.display, "validity": a.validity,
			"publicly_leaked": false, "push_protection_bypassed": false,
		}
		if a.secret != "" && (!hide || r.ignoresHide) {
			it["secret"] = a.secret
		}
		items = append(items, it)
	}
	return ghclitest.JSON(200, items)
}

// clocks are the two clocks of a test: GitHub's, which stamps every reply and every write, and
// this Mac's, which is hours off it and which the code under test may use only to measure how
// long ago something happened.
type clocks struct {
	mu      sync.Mutex
	gh, mac time.Time
}

// github is a fixed instant of GitHub's clock.
var github = time.Date(2026, 11, 3, 23, 31, 37, 0, time.UTC)

func newClocks(skew time.Duration) *clocks { return &clocks{gh: github, mac: github.Add(skew)} }

func (c *clocks) GitHub() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.gh }
func (c *clocks) Mac() time.Time    { c.mu.Lock(); defer c.mu.Unlock(); return c.mac }
func (c *clocks) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gh, c.mac = c.gh.Add(d), c.mac.Add(d)
}

// fixture bundles a ghub, the fake gh in front of it and a Settings.
type fixture struct {
	g     *ghub
	f     *ghclitest.Fake
	s     *Settings
	kr    *fp.Keyring
	ck    *clocks
	state string // the state file

	mu     sync.Mutex
	sleeps []time.Duration // every pause Apply asked for; the fixture makes them instant
}

func newFixture(t *testing.T, g *ghub, mod func(*Config)) *fixture {
	t.Helper()
	return newFixtureSkew(t, g, 2*time.Hour, mod)
}

// newFixtureSkew is newFixture with this Mac's clock skew apart from GitHub's. The default is
// two hours fast, the way the real Mac was.
func newFixtureSkew(t *testing.T, g *ghub, skew time.Duration, mod func(*Config)) *fixture {
	t.Helper()
	tmp := t.TempDir()
	cfgFile := filepath.Join(tmp, "gitconfig")
	if err := os.WriteFile(cfgFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KEYGUARD_HOME", filepath.Join(tmp, "kg"))
	t.Setenv("HOME", filepath.Join(tmp, "home"))
	t.Setenv("GIT_CONFIG_GLOBAL", cfgFile)
	fx := &fixture{g: g, ck: newClocks(skew), state: filepath.Join(tmp, "kg", "state", "ghsettings.json")}
	g.now = fx.ck.GitHub
	fk := ghclitest.New(t, g.handler(t), "hangryclaude", "alt-builds")
	fk.SetClock(fx.ck.GitHub)
	cl := ghcli.New(fk)
	cl.Backoff = time.Millisecond
	cl.Clock().SetLocal(fx.ck.Mac)
	kr := fp.NewEphemeral()
	cfg := Config{
		Client: cl, FP: kr, PerPage: 2, Workers: 4, StatePath: fx.state, Now: fx.ck.Mac,
		Sleep: func(ctx context.Context, d time.Duration) error {
			fx.mu.Lock()
			fx.sleeps = append(fx.sleeps, d)
			fx.mu.Unlock()
			fx.ck.Advance(d)
			return ctx.Err()
		},
	}
	if mod != nil {
		mod(&cfg)
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	fx.f, fx.s, fx.kr = fk, s, kr
	return fx
}

func (fx *fixture) pauses() []time.Duration {
	fx.mu.Lock()
	defer fx.mu.Unlock()
	return append([]time.Duration(nil), fx.sleeps...)
}

func repoSrc(owner, name string, vis core.Visibility) core.Source {
	return core.Source{
		ID: "github.com/" + owner + "/" + name, Kind: "repo", Owner: owner, Name: name,
		Account: "hangryclaude", Visibility: vis, CloneURL: "https://github.com/" + owner + "/" + name + ".git",
	}
}

// fakeSecret builds a token-shaped string at run time so no such literal exists in source.
func fakeSecret(t testing.TB, prefix string, n int) string {
	t.Helper()
	const cs = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		x, err := rand.Int(rand.Reader, big.NewInt(int64(len(cs))))
		if err != nil {
			t.Fatal(err)
		}
		b[i] = cs[x.Int64()]
	}
	return prefix + string(b)
}
