package ghcli_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"keyguard/internal/inventory/ghcli"
	"keyguard/internal/inventory/ghcli/ghclitest"
)

func newClient(r ghcli.Runner) *ghcli.Client {
	c := ghcli.New(r)
	c.Backoff = time.Millisecond
	return c
}

func TestDoSendsTokenOnlyThroughEnv(t *testing.T) {
	f := ghclitest.New(t, func(c ghclitest.Call) ghclitest.Reply {
		return ghclitest.JSON(200, map[string]string{"ok": "yes"})
	}, "alice", "bob")
	cl := newClient(f)
	resp, err := cl.Do(context.Background(), "bob", ghcli.Request{
		Method: "PATCH", Path: "repos/o/r", Header: map[string]string{"If-None-Match": `"abc"`}, Body: []byte(`{"x":1}`),
	})
	if err != nil || !resp.OK() {
		t.Fatalf("Do: %v %+v", err, resp.Status)
	}
	calls := f.Calls()
	if len(calls) != 1 {
		t.Fatalf("%d calls", len(calls))
	}
	c := calls[0]
	if c.Acct != "bob" || c.Method != "PATCH" || c.Path != "repos/o/r" || c.Header["If-None-Match"] != `"abc"` || string(c.Body) != `{"x":1}` {
		t.Fatalf("call = %+v", c)
	}
	for _, cmd := range f.Commands() {
		if len(cmd) > 1 && cmd[0] == "auth" && cmd[1] == "switch" {
			t.Fatal("auth switch was run")
		}
	}
}

func TestTokenIsAskedPerCallAndNotRetained(t *testing.T) {
	f := ghclitest.New(t, func(ghclitest.Call) ghclitest.Reply { return ghclitest.JSON(200, map[string]string{}) }, "alice")
	cl := newClient(f)
	for range 3 {
		if _, err := cl.Do(context.Background(), "alice", ghcli.Request{Path: "rate_limit"}); err != nil {
			t.Fatal(err)
		}
	}
	reads := 0
	for _, cmd := range f.Commands() {
		if cmd[0] == "auth" && cmd[1] == "token" {
			reads++
		}
	}
	if reads != 3 {
		t.Fatalf("token read %d times for 3 calls, want once per call", reads)
	}
	tok := f.Token("alice")
	for i, b := range f.Buffers() {
		if strings.Contains(string(b), tok) {
			t.Fatalf("buffer %d still holds the token after the call returned", i)
		}
	}
}

func TestUnknownAccountFailsWithoutLeaking(t *testing.T) {
	f := ghclitest.New(t, func(ghclitest.Call) ghclitest.Reply { t.Fatal("api must not run"); return ghclitest.Reply{} }, "alice")
	_, err := newClient(f).Do(context.Background(), "mallory", ghcli.Request{Path: "user"})
	if err == nil || !strings.Contains(err.Error(), "mallory") {
		t.Fatalf("want an error naming the account, got %v", err)
	}
	if strings.Contains(err.Error(), f.Token("alice")) {
		t.Fatal("error leaked another account's token")
	}
}

func TestInvalidLoginNeverReachesAProcess(t *testing.T) {
	f := ghclitest.New(t, func(ghclitest.Call) ghclitest.Reply { return ghclitest.Reply{} })
	for _, bad := range []string{"", "a b", "a;b", "$(x)", "-lead", strings.Repeat("a", 40), "a/b", "a\nb"} {
		if _, err := newClient(f).Token(context.Background(), bad); err == nil {
			t.Errorf("Token(%q) accepted", bad)
		}
	}
	if n := len(f.Commands()); n != 0 {
		t.Fatalf("%d processes started for invalid logins", n)
	}
	for _, ok := range []string{"hangryclaude", "alt-builds", "Loony-Labs-Video", "a", "octo_cat", "a-b-c"} {
		if !ghcli.ValidLogin(ok) {
			t.Errorf("ValidLogin(%q) = false", ok)
		}
	}
	for _, bad := range []string{"", ".", "..", "a/b", "a b", "x;y"} {
		if ghcli.ValidName(bad) {
			t.Errorf("ValidName(%q) = true", bad)
		}
	}
	for _, ok := range []string{".github", "repo.wiki", "a_b-c.d", "Acme"} {
		if !ghcli.ValidName(ok) {
			t.Errorf("ValidName(%q) = false", ok)
		}
	}
}

func TestNon2xxIsDataNotError(t *testing.T) {
	f := ghclitest.New(t, func(c ghclitest.Call) ghclitest.Reply {
		switch c.Path {
		case "repos/o/gone":
			return ghclitest.JSON(404, map[string]string{"message": "Not Found"})
		case "events":
			return ghclitest.Reply{Status: 304, Header: map[string]string{"Etag": `"v1"`}}
		}
		return ghclitest.JSON(422, map[string]any{
			"message": "Validation Failed",
			"errors":  []any{map[string]string{"resource": "Repository", "field": "security_and_analysis", "code": "invalid"}, "plain text reason"},
		})
	}, "alice")
	cl := newClient(f)

	resp, err := cl.Do(context.Background(), "alice", ghcli.Request{Path: "repos/o/gone"})
	if err != nil || resp.Status != 404 {
		t.Fatalf("404: err=%v status=%d", err, resp.Status)
	}
	var ae *ghcli.APIError
	if !errors.As(resp.Err(), &ae) || ae.Status != 404 || ae.Message != "Not Found" {
		t.Fatalf("404 Err() = %v", resp.Err())
	}

	resp, err = cl.Do(context.Background(), "alice", ghcli.Request{Path: "events", Header: map[string]string{"If-None-Match": `"v1"`}})
	if err != nil || resp.Status != 304 || len(resp.Body) != 0 || resp.Header.Get("ETag") != `"v1"` {
		t.Fatalf("304: err=%v status=%d body=%q etag=%q", err, resp.Status, resp.Body, resp.Header.Get("ETag"))
	}

	resp, err = cl.Do(context.Background(), "alice", ghcli.Request{Method: "PATCH", Path: "repos/o/r", Body: []byte(`{}`)})
	if err != nil || resp.Status != 422 {
		t.Fatalf("422: err=%v status=%d", err, resp.Status)
	}
	msg := resp.Message()
	for _, want := range []string{"Validation Failed", "Repository security_and_analysis invalid", "plain text reason"} {
		if !strings.Contains(msg, want) {
			t.Errorf("Message() = %q, missing %q", msg, want)
		}
	}
}

func TestRateLimitIsDistinguishedFromPermission(t *testing.T) {
	f := ghclitest.New(t, func(c ghclitest.Call) ghclitest.Reply {
		if c.Path == "limited" {
			r := ghclitest.JSON(403, map[string]string{"message": "API rate limit exceeded for user ID 1."})
			r.Header = map[string]string{"X-Ratelimit-Remaining": "0", "X-Ratelimit-Reset": "1793747131"}
			return r
		}
		return ghclitest.JSON(403, map[string]string{"message": "Must have admin rights to Repository."})
	}, "alice")
	cl := newClient(f)

	resp, _ := cl.Do(context.Background(), "alice", ghcli.Request{Path: "limited"})
	var rl *ghcli.RateLimitError
	if !errors.As(resp.Err(), &rl) || rl.Reset.Unix() != 1793747131 {
		t.Fatalf("limited Err() = %#v", resp.Err())
	}
	resp, _ = cl.Do(context.Background(), "alice", ghcli.Request{Path: "forbidden"})
	var ae *ghcli.APIError
	if !errors.As(resp.Err(), &ae) || ae.Status != 403 {
		t.Fatalf("forbidden Err() = %#v", resp.Err())
	}
}

func TestRetriesGatewayErrorsOnly(t *testing.T) {
	var hits atomic.Int32
	f := ghclitest.New(t, func(c ghclitest.Call) ghclitest.Reply {
		n := hits.Add(1)
		switch {
		case c.Path == "flaky" && n < 3:
			return ghclitest.JSON(502, map[string]string{"message": "Bad Gateway"})
		case c.Path == "flaky":
			return ghclitest.JSON(200, map[string]string{"ok": "1"})
		case c.Path == "dead":
			return ghclitest.JSON(503, map[string]string{"message": "Service Unavailable"})
		}
		return ghclitest.JSON(404, map[string]string{"message": "Not Found"})
	}, "alice")
	cl := newClient(f)

	resp, err := cl.Do(context.Background(), "alice", ghcli.Request{Path: "flaky"})
	if err != nil || resp.Status != 200 || hits.Load() != 3 {
		t.Fatalf("flaky: err=%v status=%d attempts=%d", err, resp.Status, hits.Load())
	}

	hits.Store(0)
	resp, err = cl.Do(context.Background(), "alice", ghcli.Request{Path: "dead"})
	if err != nil || resp.Status != 503 || hits.Load() != 3 {
		t.Fatalf("dead: err=%v status=%d attempts=%d; want the last 503 returned after 3 tries", err, resp.Status, hits.Load())
	}

	hits.Store(0)
	resp, _ = cl.Do(context.Background(), "alice", ghcli.Request{Path: "missing"})
	if resp.Status != 404 || hits.Load() != 1 {
		t.Fatalf("404 was retried: status=%d attempts=%d", resp.Status, hits.Load())
	}
}

// netDown fails the first n api calls the way gh does when the network is gone: no HTTP
// exchange, a line on stderr, exit 1.
type netDown struct {
	inner ghcli.Runner
	left  atomic.Int32
	tok   string
}

func (n *netDown) Run(ctx context.Context, c ghcli.Cmd) (ghcli.Result, error) {
	if c.Args[0] == "api" && n.left.Add(-1) >= 0 {
		return ghcli.Result{Stderr: []byte("error connecting to api.github.com " + n.tok + "\ncheck your internet connection\n")}, errors.New("exit status 1")
	}
	return n.inner.Run(ctx, c)
}

func TestNetworkFailureRetriedAndTokenMaskedWhenGivingUp(t *testing.T) {
	f := ghclitest.New(t, func(ghclitest.Call) ghclitest.Reply { return ghclitest.JSON(200, map[string]string{}) }, "alice")
	n := &netDown{inner: f, tok: f.Token("alice")}
	n.left.Store(2)
	if resp, err := newClient(n).Do(context.Background(), "alice", ghcli.Request{Path: "user"}); err != nil || resp.Status != 200 {
		t.Fatalf("two outages should be ridden out: %v", err)
	}

	n.left.Store(99)
	_, err := newClient(n).Do(context.Background(), "alice", ghcli.Request{Path: "user?cursor=opaque"})
	if err == nil {
		t.Fatal("permanent outage reported success")
	}
	if strings.Contains(err.Error(), f.Token("alice")) {
		t.Fatal("error leaks the token")
	}
	if masked, queryKept := strings.Contains(err.Error(), "«token»"), strings.Contains(err.Error(), "opaque"); !masked || queryKept {
		t.Fatalf("want token masked and query dropped: masked=%v query kept=%v", masked, queryKept)
	}
}

func TestContextCancellationStopsRetries(t *testing.T) {
	f := ghclitest.New(t, func(ghclitest.Call) ghclitest.Reply { return ghclitest.JSON(502, map[string]string{"message": "x"}) }, "alice")
	cl := ghcli.New(f)
	cl.Backoff = time.Hour
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := cl.Do(ctx, "alice", ghcli.Request{Path: "user"})
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 3*time.Second {
		t.Fatalf("err=%v after %v", err, time.Since(start))
	}
}

func TestGraphQLPartialDataKeepsErrors(t *testing.T) {
	f := ghclitest.New(t, func(c ghclitest.Call) ghclitest.Reply {
		var body struct {
			Query     string         `json:"query"`
			Variables map[string]any `json:"variables"`
		}
		if err := json.Unmarshal(c.Body, &body); err != nil || body.Variables["n"] != float64(3) {
			t.Errorf("body = %s", c.Body)
		}
		switch body.Query {
		case "partial":
			return ghclitest.Reply{Status: 200, Body: []byte(`{"data":{"a":{"login":"x"},"c":null},"errors":[{"type":"NOT_FOUND","path":["c"],"message":"Could not resolve to an Organization"}]}`)}
		case "none":
			return ghclitest.Reply{Status: 200, Body: []byte(`{"data":null,"errors":[{"type":"FORBIDDEN","message":"nope"}]}`)}
		case "limited":
			return ghclitest.Reply{Status: 200, Body: []byte(`{"data":{"viewer":null},"errors":[{"type":"RATE_LIMITED","message":"API rate limit exceeded"}]}`)}
		}
		return ghclitest.Reply{Status: 200, Body: []byte(`{"data":{"viewer":{"login":"alice"}}}`)}
	}, "alice")
	cl := newClient(f)
	vars := map[string]any{"n": 3}

	g, err := cl.GraphQL(context.Background(), "alice", "partial", vars)
	if err != nil || len(g.Errors) != 1 || g.Errors[0].Type != "NOT_FOUND" || !strings.Contains(string(g.Data), `"login":"x"`) {
		t.Fatalf("partial: err=%v %+v", err, g)
	}
	if _, err := cl.GraphQL(context.Background(), "alice", "none", vars); err == nil || !strings.Contains(err.Error(), "FORBIDDEN") {
		t.Fatalf("no data must be an error, got %v", err)
	}
	var rl *ghcli.RateLimitError
	if _, err := cl.GraphQL(context.Background(), "alice", "limited", vars); !errors.As(err, &rl) {
		t.Fatalf("RATE_LIMITED must surface as RateLimitError, got %v", err)
	}
	if g, err := cl.GraphQL(context.Background(), "alice", "ok", vars); err != nil || len(g.Errors) != 0 {
		t.Fatalf("ok: %v %+v", err, g)
	}
}

func TestResponseWipeOverwritesBody(t *testing.T) {
	marker := "needle-" + strings.Repeat("z", 20)
	f := ghclitest.New(t, func(ghclitest.Call) ghclitest.Reply {
		return ghclitest.Reply{Status: 200, Body: []byte(`[{"v":"` + marker + `"}]`)}
	}, "alice")
	resp, err := newClient(f).Do(context.Background(), "alice", ghcli.Request{Path: "x"})
	if err != nil || !strings.Contains(string(resp.Body), marker) {
		t.Fatalf("setup: %v", err)
	}
	resp.Wipe()
	if resp.Body != nil {
		t.Fatal("Body kept after Wipe")
	}
	for _, b := range f.Buffers() {
		if strings.Contains(string(b), marker) {
			t.Fatal("stdout buffer still holds the payload after Wipe")
		}
	}
}

func TestExecRunnerStdinEnvAndKill(t *testing.T) {
	t.Setenv("KG_TEST_KEEP", "inherited")
	t.Setenv("KG_TEST_OVER", "old")
	res, err := ghcli.ExecRunner{}.Run(context.Background(), ghcli.Cmd{
		Name: "/bin/sh", Args: []string{"-c", `cat; echo "$KG_TEST_KEEP $KG_TEST_OVER"; echo oops >&2; exit 3`},
		Env: []string{"KG_TEST_OVER=new"}, Stdin: []byte("hello\n"),
	})
	if err == nil {
		t.Fatal("exit 3 reported as success")
	}
	if got := string(res.Stdout); got != "hello\ninherited new\n" {
		t.Fatalf("stdout = %q", got)
	}
	if string(res.Stderr) != "oops\n" {
		t.Fatalf("stderr = %q", res.Stderr)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = ghcli.ExecRunner{}.Run(ctx, ghcli.Cmd{Name: "/bin/sh", Args: []string{"-c", "sleep 20"}})
	if err == nil || time.Since(start) > 10*time.Second {
		t.Fatalf("runaway process not stopped: err=%v after %v", err, time.Since(start))
	}
}

func TestStatusConstantsMatchFake(t *testing.T) {
	// Guards the fake itself: if its status line stopped parsing, every other test would
	// quietly exercise the wrong path.
	f := ghclitest.New(t, func(ghclitest.Call) ghclitest.Reply { return ghclitest.Reply{Status: http.StatusNoContent} }, "alice")
	resp, err := newClient(f).Do(context.Background(), "alice", ghcli.Request{Method: "DELETE", Path: "x"})
	if err != nil || resp.Status != 204 || !resp.OK() {
		t.Fatalf("204: %v %d", err, resp.Status)
	}
}
