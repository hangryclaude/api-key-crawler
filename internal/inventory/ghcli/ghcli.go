// Package ghcli drives the gh CLI as a named account. The active gh account is global state
// other sessions depend on, so it is never switched: every call reads that account's token
// and hands it to the child through GH_TOKEN alone — never argv, never disk, never a log.
package ghcli

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

// Cmd is one process invocation. Env entries replace same-named inherited variables.
type Cmd struct {
	Name  string
	Args  []string
	Env   []string
	Stdin []byte
}

// Result is what the process wrote. It is returned even when the process failed: with
// `gh api -i` an HTTP error body reaches stdout before the non-zero exit.
type Result struct {
	Stdout, Stderr []byte
}

// Runner starts processes. ExecRunner is the real one; tests substitute a fake.
type Runner interface {
	Run(ctx context.Context, c Cmd) (Result, error)
}

// ExecRunner runs real processes. Stdin is /dev/null unless the command carries input,
// so gh can never stop to prompt.
type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, c Cmd) (Result, error) {
	cmd := exec.CommandContext(ctx, c.Name, c.Args...)
	cmd.Env = mergeEnv(os.Environ(), c.Env)
	if len(c.Stdin) > 0 {
		cmd.Stdin = bytes.NewReader(c.Stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	cmd.WaitDelay = 3 * time.Second // a gh stuck on a dead socket must not outlive its context
	err := cmd.Run()
	return Result{Stdout: out.Bytes(), Stderr: errb.Bytes()}, err
}

func mergeEnv(base, over []string) []string {
	drop := make(map[string]bool, len(over))
	for _, kv := range over {
		k, _, _ := strings.Cut(kv, "=")
		drop[k] = true
	}
	out := make([]string, 0, len(base)+len(over))
	for _, kv := range base {
		k, _, _ := strings.Cut(kv, "=")
		if !drop[k] {
			out = append(out, kv)
		}
	}
	return append(out, over...)
}

var (
	loginRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,38}$`)
	nameRE  = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)
)

// ValidLogin reports whether s can be a GitHub user or org login. Logins are spliced into
// API paths and GraphQL text, so anything else is refused rather than escaped.
func ValidLogin(s string) bool { return loginRE.MatchString(s) }

// ValidName reports whether s can be a repository name (or a ".wiki" name).
func ValidName(s string) bool { return nameRE.MatchString(s) && s != "." && s != ".." }

// AuthStatusArgs ask gh for the github.com accounts it is logged in to, the active one
// first, one login per line. The filter runs inside gh because the status JSON can carry
// the tokens, and they have no reason to reach this process.
var AuthStatusArgs = []string{"auth", "status", "--hostname", "github.com", "--json", "hosts", "--jq",
	`.hosts["github.com"] | map(select(.state == "success")) | sort_by(.active | not) | .[].login`}

// OrgsArgs ask gh for the organizations the active account belongs to, one login per line.
var OrgsArgs = []string{"api", "--paginate", "user/memberships/orgs?state=active", "--jq", ".[].organization.login"}

// Logins keeps the valid logins of gh output that holds one per line, in order, once each.
func Logins(out []byte) []string {
	var logins []string
	for _, l := range strings.Fields(string(out)) {
		if ValidLogin(l) && !slices.Contains(logins, l) {
			logins = append(logins, l)
		}
	}
	return logins
}

// Client runs gh as a named account. The only state it keeps is GitHub's clock, which is safe
// for concurrent use, so the client is too.
type Client struct {
	Runner      Runner
	GH          string        // path to gh; looked up once when empty
	Timeout     time.Duration // per attempt; 0 means 90 s
	MaxAttempts int           // tries per call, retrying 5xx and network failures; 0 means 3
	Backoff     time.Duration // pause before the first retry, doubling after; 0 means 500 ms

	clockOnce sync.Once
	clock     *Clock
}

// Clock is GitHub's clock as heard from the Date header of every response this client has seen.
// Cursors and backoffs read it instead of this Mac's clock (STEAL P0-16).
func (c *Client) Clock() *Clock {
	c.clockOnce.Do(func() {
		if c.clock == nil {
			c.clock = NewClock(nil)
		}
	})
	return c.clock
}

// New returns a client over r, or over real processes when r is nil.
func New(r Runner) *Client {
	if r == nil {
		r = ExecRunner{}
	}
	return &Client{Runner: r}
}

// ghBinary is gh on PATH, else where Homebrew puts it. launchd starts jobs with a bare PATH,
// and a poll that cannot find gh would fail silently every ten minutes.
var ghBinary = sync.OnceValue(func() string {
	if p, err := exec.LookPath("gh"); err == nil {
		return p
	}
	return "/opt/homebrew/bin/gh"
})

func (c *Client) gh() string { return cmp.Or(c.GH, ghBinary()) }

func (c *Client) run(ctx context.Context, cmd Cmd) (Result, error) {
	ctx, cancel := context.WithTimeout(ctx, cmp.Or(c.Timeout, 90*time.Second))
	defer cancel()
	return c.Runner.Run(ctx, cmd)
}

// Token reads the OAuth token gh holds for acct. It is asked for on every call instead of
// being cached: the token then exists in this process only while a request needs it.
func (c *Client) Token(ctx context.Context, acct string) (string, error) {
	if !ValidLogin(acct) {
		return "", fmt.Errorf("ghcli: %q is not a GitHub login", acct)
	}
	res, err := c.run(ctx, Cmd{Name: c.gh(), Args: []string{"auth", "token", "--hostname", "github.com", "--user", acct}})
	tok := strings.TrimSpace(string(res.Stdout))
	clear(res.Stdout)
	if err != nil || tok == "" {
		return "", fmt.Errorf("ghcli: gh holds no token for account %s: %s", acct, snippet(res.Stderr, err, ""))
	}
	if strings.ContainsFunc(tok, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) {
		return "", fmt.Errorf("ghcli: gh printed something other than one token for account %s", acct)
	}
	return tok, nil
}

// Request is one GitHub API call.
type Request struct {
	Method string            // "" means GET
	Path   string            // "repos/o/r", "users/x/events?per_page=100", "graphql"
	Header map[string]string // extra request headers, e.g. If-None-Match
	Body   []byte            // JSON, sent on stdin so it never shows in argv
}

// Response is one HTTP exchange as `gh api -i` prints it. Non-2xx statuses are data, not
// errors: 304 and 404 are normal outcomes and a 422 carries the reason text callers need.
type Response struct {
	Status int
	Header http.Header
	Body   []byte
	raw    []byte
}

// Wipe overwrites the response bytes. Callers that read secrets out of a body (secret
// scanning alerts) call it as soon as they have extracted what they need.
func (r *Response) Wipe() {
	clear(r.raw)
	r.raw, r.Body = nil, nil
}

// OK reports a 2xx status.
func (r Response) OK() bool { return r.Status >= 200 && r.Status < 300 }

// Date is GitHub's own clock at the moment it answered, from the Date header.
func (r Response) Date() (time.Time, bool) {
	t, err := http.ParseTime(r.Header.Get("Date"))
	return t.UTC(), err == nil
}

// Message is GitHub's own explanation of a failure: the "message" plus any "errors" texts.
// It never echoes the body when the body is not a GitHub error object.
func (r Response) Message() string {
	var b struct {
		Message string            `json:"message"`
		Errors  []json.RawMessage `json:"errors"`
	}
	if json.Unmarshal(r.Body, &b) != nil || b.Message == "" {
		return http.StatusText(r.Status)
	}
	parts := []string{b.Message}
	for _, e := range b.Errors {
		var s string
		var o struct {
			Message  string `json:"message"`
			Resource string `json:"resource"`
			Field    string `json:"field"`
			Code     string `json:"code"`
		}
		switch {
		case json.Unmarshal(e, &s) == nil && s != "":
			parts = append(parts, s)
		case json.Unmarshal(e, &o) == nil:
			parts = append(parts, cmp.Or(o.Message, strings.TrimSpace(o.Resource+" "+o.Field+" "+o.Code)))
		}
	}
	return clip(strings.Join(parts, "; "), 300)
}

// Err converts a non-2xx response into a typed error.
func (r Response) Err() error {
	if r.OK() {
		return nil
	}
	msg := r.Message()
	if r.limited(msg) {
		return r.rateLimit(msg)
	}
	return &APIError{Status: r.Status, Message: msg}
}

// rateLimit reads the limit's own words out of the headers: when it resets and when GitHub said
// so, both on GitHub's clock.
func (r Response) rateLimit(msg string) *RateLimitError {
	rl := &RateLimitError{Status: r.Status, Message: msg}
	if s, err := strconv.ParseInt(r.Header.Get("X-Ratelimit-Reset"), 10, 64); err == nil {
		rl.Reset = time.Unix(s, 0)
	}
	if s, err := strconv.Atoi(r.Header.Get("Retry-After")); err == nil && s > 0 {
		rl.RetryAfter = time.Duration(s) * time.Second
	}
	rl.At, _ = r.Date()
	return rl
}

func (r Response) limited(msg string) bool {
	switch r.Status {
	case http.StatusTooManyRequests:
		return true
	case http.StatusForbidden:
		return r.Header.Get("X-Ratelimit-Remaining") == "0" || r.Header.Get("Retry-After") != "" ||
			strings.Contains(strings.ToLower(msg), "rate limit")
	}
	return false
}

// APIError is a non-2xx answer from GitHub.
type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string { return fmt.Sprintf("github: HTTP %d: %s", e.Status, e.Message) }

// RateLimitError says a quota or abuse limit is spent. Callers skip the work and report;
// retrying inside the window only digs deeper.
type RateLimitError struct {
	Status     int
	Reset      time.Time // GitHub's clock; zero when unsaid
	RetryAfter time.Duration
	At         time.Time // GitHub's clock when it answered (the Date header); zero when unsaid
	Message    string
}

func (e *RateLimitError) Error() string {
	if !e.Reset.IsZero() {
		return fmt.Sprintf("github: rate limited (HTTP %d, resets %s): %s", e.Status, e.Reset.UTC().Format(time.RFC3339), e.Message)
	}
	return fmt.Sprintf("github: rate limited (HTTP %d): %s", e.Status, e.Message)
}

// Do runs `gh api -i` as acct. The error is non-nil only when no HTTP exchange completed
// (gh missing, no token for acct, network down after retries, context done).
func (c *Client) Do(ctx context.Context, acct string, rq Request) (Response, error) {
	if rq.Path == "" {
		return Response{}, errors.New("ghcli: empty API path")
	}
	if strings.HasPrefix(rq.Path, "-") {
		// gh would read it as a flag. -f and -F turn a GET into a POST, so a path is never allowed
		// to start one (STEAL P0-20).
		return Response{}, errors.New("ghcli: an API path cannot start with a dash")
	}
	tok, err := c.Token(ctx, acct)
	if err != nil {
		return Response{}, err
	}
	method := cmp.Or(rq.Method, http.MethodGet)
	args := []string{"api", "-i", "--method", method}
	for _, k := range slices.Sorted(maps.Keys(rq.Header)) {
		args = append(args, "-H", k+": "+rq.Header[k])
	}
	if len(rq.Body) > 0 {
		args = append(args, "--input", "-")
	}
	args = append(args, rq.Path)
	cmd := Cmd{
		Name: c.gh(),
		Args: args,
		// GH_HOST and the prompt/pager switches pin gh to the same behavior whatever the
		// caller's shell exported; GH_TOKEN beats any stored credential and any GITHUB_TOKEN.
		Env:   []string{"GH_TOKEN=" + tok, "GH_HOST=github.com", "GH_PROMPT_DISABLED=1", "GH_NO_UPDATE_NOTIFIER=1", "GH_PAGER=cat", "NO_COLOR=1"},
		Stdin: rq.Body,
	}
	attempts := cmp.Or(c.MaxAttempts, 3)
	wait := cmp.Or(c.Backoff, 500*time.Millisecond)
	for try := 1; ; try++ {
		res, runErr := c.run(ctx, cmd)
		resp, ok := parseHTTP(res.Stdout)
		if ok {
			c.Clock().Observe(resp.Header)
		}
		if ok && !(transientStatus(resp.Status) && try < attempts) {
			return resp, nil
		}
		clear(res.Stdout) // an attempt we are about to discard may still carry a payload
		if err := ctx.Err(); err != nil {
			return Response{}, err
		}
		if try >= attempts || (!ok && !transientText(string(res.Stderr), runErr)) {
			return Response{}, fmt.Errorf("ghcli: gh api %s %s as %s: %s", method, redactPath(rq.Path), acct, snippet(res.Stderr, runErr, tok))
		}
		select {
		case <-ctx.Done():
			return Response{}, ctx.Err()
		case <-time.After(wait):
			wait *= 2
		}
	}
}

func transientStatus(s int) bool {
	return s == http.StatusInternalServerError || s == http.StatusBadGateway ||
		s == http.StatusServiceUnavailable || s == http.StatusGatewayTimeout
}

// transientText recognises the failures gh reports when no HTTP exchange completed and
// trying again is sensible. A missing binary or a revoked token is not one of them.
func transientText(stderr string, err error) bool {
	s := strings.ToLower(stderr)
	if err != nil {
		s += " " + strings.ToLower(err.Error())
	}
	for _, w := range []string{"error connecting to", "timeout", "timed out", "connection reset", "connection refused", "no such host", "eof", "tls handshake", "network is unreachable", "temporary failure"} {
		if strings.Contains(s, w) {
			return true
		}
	}
	return false
}

// redactPath keeps only the path in error text; a query string can carry opaque cursors
// nobody needs in a log line.
func redactPath(p string) string {
	if i := strings.IndexByte(p, '?'); i >= 0 {
		return p[:i]
	}
	return p
}

// snippet is the first useful line of stderr (or the run error), with the token masked in
// case a wrapper ever echoes it, cut to a log-friendly length.
func snippet(stderr []byte, err error, tok string) string {
	s := ""
	for _, ln := range strings.Split(string(stderr), "\n") {
		if ln = strings.TrimSpace(ln); ln != "" {
			s = ln
			break
		}
	}
	if s == "" && err != nil {
		s = err.Error()
	}
	if tok != "" {
		s = strings.ReplaceAll(s, tok, "«token»")
	}
	return clip(s, 200)
}

func clip(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return s
}

// parseHTTP splits `gh api -i` output: a status line, headers, a blank line, the body.
// ok is false when stdout holds no HTTP exchange at all.
func parseHTTP(out []byte) (resp Response, ok bool) {
	if !bytes.HasPrefix(out, []byte("HTTP/")) {
		return Response{}, false
	}
	head, body := out, []byte(nil)
	if i := bytes.Index(out, []byte("\r\n\r\n")); i >= 0 {
		head, body = out[:i], out[i+4:]
	} else if i := bytes.Index(out, []byte("\n\n")); i >= 0 {
		head, body = out[:i], out[i+2:]
	}
	lines := strings.Split(strings.ReplaceAll(string(head), "\r\n", "\n"), "\n")
	f := strings.Fields(lines[0])
	if len(f) < 2 {
		return Response{}, false
	}
	code, err := strconv.Atoi(f[1])
	if err != nil {
		return Response{}, false
	}
	h := http.Header{}
	for _, ln := range lines[1:] {
		if k, v, found := strings.Cut(ln, ":"); found {
			h.Add(strings.TrimSpace(k), strings.TrimSpace(v))
		}
	}
	return Response{Status: code, Header: h, Body: body, raw: out}, true
}

// GQLError is one entry of a GraphQL "errors" array.
type GQLError struct {
	Type    string `json:"type"`
	Path    []any  `json:"path"`
	Message string `json:"message"`
}

func (e GQLError) Error() string {
	if len(e.Path) > 0 {
		return fmt.Sprintf("graphql %s at %v: %s", cmp.Or(e.Type, "error"), e.Path, e.Message)
	}
	return fmt.Sprintf("graphql %s: %s", cmp.Or(e.Type, "error"), e.Message)
}

// GQLResponse is a GraphQL reply that carried data. Errors may be non-empty alongside it:
// GitHub answers a query for one missing org with HTTP 200, data for the rest, and an
// error entry for the missing one, so callers decide which errors matter to them.
type GQLResponse struct {
	Data   json.RawMessage `json:"data"`
	Errors []GQLError      `json:"errors"`
}

// GraphQL posts a query as acct. It fails when the exchange fails, when the quota is spent,
// or when there is no data at all; partial data comes back with its errors.
func (c *Client) GraphQL(ctx context.Context, acct, query string, vars map[string]any) (GQLResponse, error) {
	if vars == nil {
		vars = map[string]any{} // a JSON null for "variables" is not what every server expects
	}
	body, err := json.Marshal(map[string]any{"query": query, "variables": vars})
	if err != nil {
		return GQLResponse{}, err
	}
	resp, err := c.Do(ctx, acct, Request{Method: http.MethodPost, Path: "graphql", Body: body})
	if err != nil {
		return GQLResponse{}, err
	}
	if err := resp.Err(); err != nil {
		return GQLResponse{}, err
	}
	var g GQLResponse
	if err := json.Unmarshal(resp.Body, &g); err != nil {
		return GQLResponse{}, fmt.Errorf("ghcli: graphql reply for %s is not JSON: %w", acct, err)
	}
	for _, e := range g.Errors {
		if e.Type == "RATE_LIMITED" {
			return GQLResponse{}, resp.rateLimit(e.Message)
		}
	}
	if len(g.Errors) > 0 && (len(g.Data) == 0 || string(g.Data) == "null") {
		return GQLResponse{}, fmt.Errorf("ghcli: graphql as %s: %w", acct, g.Errors[0])
	}
	return g, nil
}
