// Package ghclitest is a fake gh for tests. It speaks the real CLI's dialect — `gh api -i`
// output, exit status 1 for any non-2xx or GraphQL error, `gh auth token --user` — so code
// under test goes through its real parsing path, and it fails the test on anything a real
// run must never do: switching accounts, letting a token reach argv or stdin, or sending a
// parameter flag (-f, -F), which turns a GET into a POST. Every reply carries the Date header
// the real GitHub sends, from a clock a test can set apart from this Mac's.
package ghclitest

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math/big"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"keyguard/internal/inventory/ghcli"
)

// Call is one `gh api` request as the account behind GH_TOKEN made it.
type Call struct {
	Acct   string
	Method string
	Path   string
	Header map[string]string
	Body   []byte
}

// Reply is what the fake GitHub answers.
type Reply struct {
	Status int
	Header map[string]string
	Body   []byte
}

// JSON is a Reply whose body is v marshalled.
func JSON(status int, v any) Reply {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return Reply{Status: status, Body: b}
}

// Fake implements ghcli.Runner. Handler sees only well-formed, correctly authenticated
// api calls; everything else is policed here.
type Fake struct {
	t       testing.TB
	handler func(Call) Reply
	tokens  map[string]string

	mu     sync.Mutex
	clock  func() time.Time
	calls  []Call
	cmds   [][]string
	buffer [][]byte
}

// SetClock sets GitHub's clock, the time the fake stamps into the Date header of every reply
// that does not carry one of its own. The real GitHub always sends one; without a clock the fake
// answers with the real time, the same as it. A test that wants this Mac's clock to disagree
// with GitHub's gives the code under test a local clock of its own and sets this one apart.
func (f *Fake) SetClock(now func() time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.clock = now
}

func (f *Fake) githubNow() time.Time {
	f.mu.Lock()
	now := f.clock
	f.mu.Unlock()
	if now == nil {
		return time.Now().UTC()
	}
	return now().UTC()
}

// New makes a fake with one random token per account. The tokens are built at run time
// (prefix plus random characters) so no secret-shaped literal exists in source.
func New(t testing.TB, handler func(Call) Reply, accts ...string) *Fake {
	t.Helper()
	f := &Fake{t: t, handler: handler, tokens: map[string]string{}}
	for _, a := range accts {
		f.tokens[a] = "gho_" + randAlnum(t, 36)
	}
	return f
}

func randAlnum(t testing.TB, n int) string {
	const cs = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		x, err := rand.Int(rand.Reader, big.NewInt(int64(len(cs))))
		if err != nil {
			t.Fatal(err)
		}
		b[i] = cs[x.Int64()]
	}
	return string(b)
}

// Token is the fake token for acct, for assertions that it never leaks.
func (f *Fake) Token(acct string) string { return f.tokens[acct] }

// Calls returns the api calls seen so far, in arrival order.
func (f *Fake) Calls() []Call {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

// Commands returns every gh invocation's arguments, token reads included.
func (f *Fake) Commands() [][]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.cmds)
}

// Buffers returns the exact stdout slices handed to callers, so a test can check that code
// which wipes secrets out of a response really did.
func (f *Fake) Buffers() [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.buffer)
}

func (f *Fake) Run(ctx context.Context, c ghcli.Cmd) (ghcli.Result, error) {
	f.t.Helper()
	if err := ctx.Err(); err != nil {
		return ghcli.Result{}, err // a real process would never start under a finished context
	}
	if filepath.Base(c.Name) != "gh" {
		f.t.Errorf("ghclitest: unexpected process %q", c.Name)
		return ghcli.Result{}, errors.New("unexpected process")
	}
	f.mu.Lock()
	f.cmds = append(f.cmds, slices.Clone(c.Args))
	f.mu.Unlock()
	if len(c.Args) == 0 {
		f.t.Errorf("ghclitest: gh run with no arguments")
		return ghcli.Result{}, errors.New("no arguments")
	}
	switch c.Args[0] {
	case "auth":
		return f.auth(c)
	case "api":
		return f.api(c)
	}
	f.t.Errorf("ghclitest: unexpected gh subcommand %q", c.Args[0])
	return ghcli.Result{}, errors.New("unexpected subcommand")
}

func (f *Fake) auth(c ghcli.Cmd) (ghcli.Result, error) {
	if len(c.Args) < 2 || c.Args[1] != "token" {
		// switch/login/logout/refresh all rewrite the shared active-account state.
		f.t.Errorf("ghclitest: forbidden `gh %s`: the active account must never change", strings.Join(c.Args, " "))
		return ghcli.Result{}, errors.New("forbidden")
	}
	i := slices.Index(c.Args, "--user")
	if i < 0 || i+1 >= len(c.Args) {
		f.t.Errorf("ghclitest: `gh auth token` without --user would read the active account")
		return ghcli.Result{}, errors.New("no --user")
	}
	acct := c.Args[i+1]
	tok, ok := f.tokens[acct]
	if !ok {
		return ghcli.Result{Stderr: []byte("no oauth token found for github.com account " + acct + "\n")}, errors.New("exit status 1")
	}
	return f.out([]byte(tok+"\n"), nil, nil)
}

func (f *Fake) api(c ghcli.Cmd) (ghcli.Result, error) {
	var tok string
	for _, kv := range c.Env {
		if v, ok := strings.CutPrefix(kv, "GH_TOKEN="); ok {
			tok = v
		}
	}
	acct := ""
	for a, t := range f.tokens {
		if t == tok && tok != "" {
			acct = a
		}
	}
	if acct == "" {
		f.t.Errorf("ghclitest: api call without a known account token in GH_TOKEN")
		return f.out(nil, []byte("gh: HTTP 401\n"), errors.New("exit status 1"))
	}
	for _, a := range c.Args {
		if strings.Contains(a, tok) {
			f.t.Errorf("ghclitest: token for %s reached argv", acct)
		}
	}
	if bytes.Contains(c.Stdin, []byte(tok)) {
		f.t.Errorf("ghclitest: token for %s reached stdin", acct)
	}
	call := Call{Acct: acct, Method: http.MethodGet, Header: map[string]string{}, Body: bytes.Clone(c.Stdin)}
	var haveI, haveInput, haveMethod bool
	args := c.Args[1:]
	for i := 0; i < len(args); i++ {
		switch a := args[i]; a {
		case "-i":
			haveI = true
		case "--method":
			i++
			call.Method = args[i]
			haveMethod = true
		case "-f", "-F", "--field", "--raw-field":
			// gh turns any parameter flag into a request body and a GET into a POST. A query
			// belongs in the path (STEAL P0-20), so no call may carry one, whatever its method.
			f.t.Errorf("ghclitest: `gh api %s`: a parameter flag turns a GET into a POST; put the query in the path", a)
			i++
		case "-H":
			i++
			k, v, _ := strings.Cut(args[i], ": ")
			call.Header[k] = v
		case "--input":
			i++
			haveInput = args[i] == "-"
		default:
			call.Path = a
		}
	}
	if !haveI {
		f.t.Errorf("ghclitest: api call without -i; status and ETag would be invisible")
	}
	if !haveMethod {
		f.t.Errorf("ghclitest: api call without --method; gh picks POST when it has a body and GET otherwise")
	}
	if haveInput != (len(c.Stdin) > 0) {
		f.t.Errorf("ghclitest: --input and stdin disagree")
	}
	f.mu.Lock()
	f.calls = append(f.calls, call)
	f.mu.Unlock()

	r := f.handler(call)
	if r.Status == 0 {
		r.Status = http.StatusOK
	}
	var failed error
	var stderr []byte
	switch {
	case r.Status < 200 || r.Status >= 300:
		failed = errors.New("exit status 1")
		stderr = []byte(failureLine(r) + "\n")
	case call.Path == "graphql":
		// gh exits 1 on a GraphQL "errors" array even though the HTTP status is 200.
		var g struct {
			Errors []struct {
				Message string `json:"message"`
			} `json:"errors"`
		}
		if json.Unmarshal(r.Body, &g) == nil && len(g.Errors) > 0 {
			failed = errors.New("exit status 1")
			stderr = []byte("gh: " + g.Errors[0].Message + "\n")
		}
	}
	return f.out(render(r, f.githubNow()), stderr, failed)
}

func failureLine(r Reply) string {
	if r.Status == http.StatusNotModified {
		return "gh: HTTP 304"
	}
	var b struct {
		Message string `json:"message"`
	}
	_ = json.Unmarshal(r.Body, &b)
	return fmt.Sprintf("gh: %s (HTTP %d)", b.Message, r.Status)
}

func (f *Fake) out(stdout, stderr []byte, err error) (ghcli.Result, error) {
	f.mu.Lock()
	f.buffer = append(f.buffer, stdout)
	f.mu.Unlock()
	return ghcli.Result{Stdout: stdout, Stderr: stderr}, err
}

func render(r Reply, now time.Time) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "HTTP/2.0 %d %s\r\n", r.Status, http.StatusText(r.Status))
	h := map[string]string{"Content-Type": "application/json; charset=utf-8", "Date": now.Format(http.TimeFormat)}
	maps.Copy(h, r.Header)
	for _, k := range slices.Sorted(maps.Keys(h)) {
		fmt.Fprintf(&b, "%s: %s\r\n", k, h[k])
	}
	b.WriteString("\r\n")
	b.Write(r.Body)
	return b.Bytes()
}
