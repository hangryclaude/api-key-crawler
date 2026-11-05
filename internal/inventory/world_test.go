package inventory

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"keyguard/internal/inventory/ghcli"
	"keyguard/internal/inventory/ghcli/ghclitest"
)

// world is a small GitHub: the data behind the GraphQL and events endpoints the inventory
// talks to, answering in GitHub's own JSON shapes. Tests change the world between polls
// (push, flip visibility, delete) and check what the inventory notices.
type world struct {
	mu sync.Mutex

	repos []wrepo
	gists map[string][]wgist         // account -> gists
	orgs  map[string][]string        // org -> accounts whose token can read it
	feeds map[string][]wevent        // account -> events, newest first
	ops   []string                   // GraphQL operation names, in arrival order
	fail  map[string]ghclitest.Reply // "<acct> <Op>" -> forced reply
	polls map[string][]string        // acct -> If-None-Match values seen on events
	login map[string]string          // acct -> login the viewer reports, when a test wants a mismatch
	date  string                     // Date header on events replies, to give GitHub a clock of its own
	extra map[string]int             // counters tests can read

	items        []witem               // issues and pull requests, for the search the activity fallback asks
	releases     map[string][]wrelease // "owner/name" -> releases, newest first
	moreActivity bool                  // the search says another page exists
	restCalls    map[string]int        // REST request label -> how many, 304s included
	rest304      map[string]int        // and how many of them were answered 304
}

// witem is an issue or pull request that involves a login.
type witem struct {
	login, owner, repo, kind string // kind: Issue or PullRequest
	number                   int
	updated                  string
}

type wrelease struct{ tag, updated string }

type wrepo struct {
	owner, name, vis, pushed, branch string
	wiki, fork, archived             bool
	size                             int
}

type wgist struct {
	id, pushed, updated string
	public              bool
}

type wevent struct {
	id, typ, repo, at string
	gist              string
	number            int    // the issue or pull request an event is about
	tag               string // the release a ReleaseEvent is about
}

func newWorld() *world {
	return &world{
		gists: map[string][]wgist{}, orgs: map[string][]string{}, feeds: map[string][]wevent{}, login: map[string]string{},
		fail: map[string]ghclitest.Reply{}, polls: map[string][]string{}, extra: map[string]int{},
		releases: map[string][]wrelease{}, restCalls: map[string]int{}, rest304: map[string]int{},
	}
}

func (w *world) add(r wrepo) {
	if r.vis == "" {
		r.vis = "PRIVATE"
	}
	if r.branch == "" {
		r.branch = "main"
	}
	w.repos = append(w.repos, r)
}

func (w *world) find(owner, name string) *wrepo {
	for i := range w.repos {
		if w.repos[i].owner == owner && w.repos[i].name == name {
			return &w.repos[i]
		}
	}
	return nil
}

func (w *world) drop(owner, name string) {
	w.repos = slices.DeleteFunc(w.repos, func(r wrepo) bool { return r.owner == owner && r.name == name })
}

func (w *world) opCount(op string) int {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := 0
	for _, o := range w.ops {
		if o == op {
			n++
		}
	}
	return n
}

func (w *world) resetOps() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.ops = nil
}

func (w *world) viewer(acct string) string {
	if l, ok := w.login[acct]; ok {
		return l
	}
	return acct
}

func (w *world) canRead(acct, org string) bool {
	return slices.Contains(w.orgs[org], acct)
}

// scopeRepos is what a viewer/org query would enumerate, newest push first.
func (w *world) scopeRepos(owner string) []wrepo {
	var out []wrepo
	for _, r := range w.repos {
		if r.owner == owner {
			out = append(out, r)
		}
	}
	slices.SortStableFunc(out, func(a, b wrepo) int {
		if c := strings.Compare(b.pushed, a.pushed); c != 0 {
			return c
		}
		return strings.Compare(a.name, b.name)
	})
	return out
}

func cursor(off int) string {
	return base64.StdEncoding.EncodeToString([]byte("c:" + strconv.Itoa(off)))
}

func offsetOf(t testing.TB, after any) int {
	s, _ := after.(string)
	if s == "" {
		return 0
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || !strings.HasPrefix(string(b), "c:") {
		t.Errorf("world: bad cursor %q", s)
		return 0
	}
	n, _ := strconv.Atoi(string(b)[2:])
	return n
}

func page[T any](all []T, n, off int) (nodes []T, hasNext bool, end string) {
	if off > len(all) {
		off = len(all)
	}
	hi := min(off+n, len(all))
	nodes = all[off:hi]
	return nodes, hi < len(all), cursor(hi)
}

// repoJSON answers only the fields the query selected, as GraphQL does: defaultBranchRef is
// left out unless asked for, so a test notices if the poll starts paying for it again.
func repoJSON(r wrepo, branch bool) map[string]any {
	m := map[string]any{
		"name": r.name, "owner": map[string]string{"login": r.owner}, "visibility": r.vis,
		"isFork": r.fork, "isArchived": r.archived, "pushedAt": nil, "hasWikiEnabled": r.wiki,
		"diskUsage": r.size,
	}
	if r.pushed != "" {
		m["pushedAt"] = r.pushed
	}
	if branch {
		m["defaultBranchRef"] = nil
		if r.branch != "-" {
			m["defaultBranchRef"] = map[string]string{"name": r.branch}
		}
	}
	return m
}

func (w *world) repoConn(t testing.TB, owner string, n, off int, branch bool) map[string]any {
	all := w.scopeRepos(owner)
	nodes, more, end := page(all, n, off)
	js := make([]any, 0, len(nodes))
	for _, r := range nodes {
		js = append(js, repoJSON(r, branch))
	}
	return map[string]any{"totalCount": len(all), "pageInfo": map[string]any{"hasNextPage": more, "endCursor": end}, "nodes": js}
}

func (w *world) pubConn(owner string) map[string]any {
	var nodes []any
	for _, r := range w.scopeRepos(owner) {
		if r.vis == "PUBLIC" {
			nodes = append(nodes, map[string]any{"name": r.name, "owner": map[string]string{"login": r.owner}})
		}
	}
	more := len(nodes) > 100
	if more {
		nodes = nodes[:100]
	}
	return map[string]any{"totalCount": len(nodes), "pageInfo": map[string]any{"hasNextPage": more}, "nodes": nodes}
}

func (w *world) gistConn(acct string, n, off int) map[string]any {
	all := slices.Clone(w.gists[acct])
	slices.SortStableFunc(all, func(a, b wgist) int { return strings.Compare(b.updated, a.updated) })
	nodes, more, end := page(all, n, off)
	js := make([]any, 0, len(nodes))
	for _, g := range nodes {
		js = append(js, map[string]any{"name": g.id, "isPublic": g.public, "pushedAt": nilIfEmpty(g.pushed), "updatedAt": g.updated})
	}
	return map[string]any{"totalCount": len(all), "pageInfo": map[string]any{"hasNextPage": more, "endCursor": end}, "nodes": js}
}

func nilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

var (
	opRE    = regexp.MustCompile(`^query (\w+)`)
	orgRE   = regexp.MustCompile(`(o\d+):organization\(login:"([^"]+)"\)`)
	byNamRE = regexp.MustCompile(`(r\d+):repository\(owner:"([^"]+)",name:"([^"]+)"\)`)
)

func notFound(path, msg string) map[string]any {
	return map[string]any{"type": "NOT_FOUND", "path": []string{path}, "message": msg}
}

// handler is the ghclitest handler. Tests hand it to ghclitest.New.
func (w *world) handler(t testing.TB) func(ghclitest.Call) ghclitest.Reply {
	return func(c ghclitest.Call) ghclitest.Reply {
		w.mu.Lock()
		defer w.mu.Unlock()
		if c.Path == "graphql" {
			return w.graphql(t, c)
		}
		if rest, ok := strings.CutPrefix(c.Path, "users/"); ok {
			return w.events(t, c, rest)
		}
		if c.Path == "rate_limit" {
			return ghclitest.JSON(200, map[string]any{"resources": map[string]any{}})
		}
		if label, ok := restLabel(c.Path); ok {
			return w.restList(t, c, label)
		}
		t.Errorf("world: unexpected request %s %s", c.Method, c.Path)
		return ghclitest.JSON(404, map[string]string{"message": "Not Found"})
	}
}

func (w *world) graphql(t testing.TB, c ghclitest.Call) ghclitest.Reply {
	var body struct {
		Query     string         `json:"query"`
		Variables map[string]any `json:"variables"`
	}
	if err := json.Unmarshal(c.Body, &body); err != nil {
		t.Errorf("world: bad GraphQL body: %v", err)
		return ghclitest.JSON(400, map[string]string{"message": "bad"})
	}
	m := opRE.FindStringSubmatch(body.Query)
	if m == nil {
		t.Errorf("world: unnamed GraphQL operation %q", body.Query)
		return ghclitest.JSON(400, map[string]string{"message": "bad"})
	}
	op := m[1]
	w.ops = append(w.ops, op)
	if f, ok := w.fail[c.Acct+" "+op]; ok {
		return f
	}
	num := func(k string) int { f, _ := body.Variables[k].(float64); return int(f) }
	branch := strings.Contains(body.Query, "defaultBranchRef")
	data := map[string]any{}
	var errs []map[string]any
	switch op {
	case "Repos":
		data["viewer"] = map[string]any{"login": w.viewer(c.Acct), "repos": w.repoConn(t, c.Acct, num("n"), offsetOf(t, body.Variables["after"]), branch)}
	case "OrgRepos":
		org, _ := body.Variables["org"].(string)
		if !w.canRead(c.Acct, org) {
			data["org"] = nil
			errs = append(errs, notFound("org", "Could not resolve to an Organization with the login of '"+org+"'."))
			break
		}
		data["org"] = map[string]any{"login": org, "repos": w.repoConn(t, org, num("n"), offsetOf(t, body.Variables["after"]), branch)}
	case "Gists":
		data["viewer"] = map[string]any{"login": c.Acct, "gists": w.gistConn(c.Acct, num("g"), offsetOf(t, body.Variables["after"]))}
	case "Poll":
		if strings.Contains(body.Query, "viewer{") {
			data["viewer"] = map[string]any{
				"login": w.viewer(c.Acct), "repos": w.repoConn(t, c.Acct, num("n"), 0, branch),
				"pub": w.pubConn(c.Acct), "gists": w.gistConn(c.Acct, num("g"), 0),
			}
		}
		for _, om := range orgRE.FindAllStringSubmatch(body.Query, -1) {
			alias, org := om[1], om[2]
			if !w.canRead(c.Acct, org) {
				data[alias] = nil
				errs = append(errs, notFound(alias, "Could not resolve to an Organization with the login of '"+org+"'."))
				continue
			}
			data[alias] = map[string]any{"login": org, "repos": w.repoConn(t, org, num("n"), 0, branch), "pub": w.pubConn(org)}
		}
	case "Activity":
		if strings.Contains(body.Query, "$q") {
			q, _ := body.Variables["q"].(string)
			data["s"] = w.search(q)
		}
		for _, rm := range byNamRE.FindAllStringSubmatch(body.Query, -1) {
			alias, owner, name := rm[1], rm[2], rm[3]
			if w.find(owner, name) == nil {
				data[alias] = nil
				errs = append(errs, notFound(alias, "Could not resolve to a Repository with the name '"+owner+"/"+name+"'."))
				continue
			}
			var nodes []any
			for _, r := range w.releases[owner+"/"+name] {
				nodes = append(nodes, map[string]string{"tagName": r.tag, "updatedAt": r.updated})
			}
			data[alias] = map[string]any{"releases": map[string]any{"nodes": nodes}}
		}
	case "ReposByName":
		for _, rm := range byNamRE.FindAllStringSubmatch(body.Query, -1) {
			alias, owner, name := rm[1], rm[2], rm[3]
			r := w.find(owner, name)
			if r == nil || !(r.owner == c.Acct || w.canRead(c.Acct, r.owner)) {
				data[alias] = nil
				errs = append(errs, notFound(alias, "Could not resolve to a Repository with the name '"+owner+"/"+name+"'."))
				continue
			}
			data[alias] = repoJSON(*r, branch)
		}
	default:
		t.Errorf("world: unknown operation %s", op)
	}
	out := map[string]any{"data": data}
	if len(errs) > 0 {
		out["errors"] = errs
	}
	return ghclitest.JSON(200, out)
}

func etagOf(evs []wevent) string {
	h := sha256.New()
	for _, e := range evs {
		h.Write([]byte(e.id + e.typ))
	}
	return `"` + hex.EncodeToString(h.Sum(nil))[:16] + `"`
}

func (w *world) events(t testing.TB, c ghclitest.Call, rest string) ghclitest.Reply {
	login, q, _ := strings.Cut(rest, "/events?")
	if f, ok := w.fail[c.Acct+" events"]; ok {
		return f
	}
	vals, err := url.ParseQuery(q)
	if err != nil || login != c.Acct {
		t.Errorf("world: events request %q as %s", rest, c.Acct)
	}
	pg, _ := strconv.Atoi(vals.Get("page"))
	per, _ := strconv.Atoi(vals.Get("per_page"))
	feed := w.feeds[login]
	etag := etagOf(feed)
	if pg == 1 {
		w.polls[c.Acct] = append(w.polls[c.Acct], c.Header["If-None-Match"])
		if c.Header["If-None-Match"] == etag {
			return ghclitest.Reply{Status: 304, Header: map[string]string{"Etag": etag}} // a real 304 omits X-Poll-Interval
		}
	} else if c.Header["If-None-Match"] != "" {
		t.Errorf("world: If-None-Match sent on page %d", pg)
	}
	nodes, more, _ := page(feed, per, (pg-1)*per)
	items := make([]any, 0, len(nodes))
	for _, e := range nodes {
		it := map[string]any{
			"id": e.id, "type": e.typ, "repo": map[string]string{"name": e.repo}, "created_at": e.at,
			// Payloads carry user-written text; the inventory must not keep any of it.
			"payload": map[string]any{"comment": map[string]string{"body": "free text that may hold a key"}},
		}
		if e.gist != "" {
			it["payload"] = map[string]any{"gist": map[string]string{"id": e.gist}}
		}
		pl, _ := it["payload"].(map[string]any)
		switch e.typ {
		case "IssuesEvent", "IssueCommentEvent":
			pl["issue"] = map[string]any{"number": e.number, "title": "free text that may hold a key"}
		case "PullRequestEvent", "PullRequestReviewEvent", "PullRequestReviewCommentEvent":
			pl["pull_request"] = map[string]any{"number": e.number, "title": "free text that may hold a key"}
		case "ReleaseEvent":
			pl["release"] = map[string]any{"tag_name": e.tag, "body": "free text that may hold a key"}
		}
		items = append(items, it)
	}
	r := ghclitest.JSON(200, items)
	r.Header = map[string]string{"Etag": etag, "X-Poll-Interval": "60"}
	if w.date != "" {
		r.Header["Date"] = w.date
	}
	if more {
		r.Header["Link"] = fmt.Sprintf(`<https://api.github.com/users/%s/events?page=%d>; rel="next"`, login, pg+1)
	}
	return r
}

// isolate points everything a test could reach at a private temp directory.
func isolate(t *testing.T) {
	t.Helper()
	tmp := t.TempDir()
	cfg := filepath.Join(tmp, "gitconfig")
	if err := os.WriteFile(cfg, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KEYGUARD_HOME", filepath.Join(tmp, "kg"))
	t.Setenv("HOME", filepath.Join(tmp, "home"))
	t.Setenv("GIT_CONFIG_GLOBAL", cfg)
}

// fixture builds an Inventory over a world with temp state, per-account fake tokens, and
// fast retries.
type fixture struct {
	w   *world
	f   *ghclitest.Fake
	inv *Inventory
	cfg Config
	dir string
	t   *testing.T
	now time.Time
}

func newFixture(t *testing.T, w *world, mod func(*Config)) *fixture {
	t.Helper()
	return newFixtureH(t, w, w.handler(t), mod)
}

// newFixtureH is newFixture with a hand-written handler in place of the simulated GitHub.
func newFixtureH(t *testing.T, w *world, h func(ghclitest.Call) ghclitest.Reply, mod func(*Config)) *fixture {
	t.Helper()
	return newFixtureSkew(t, w, h, 0, mod)
}

// newFixtureSkew is newFixtureH with this Mac's clock skew ahead of GitHub's. fx.now is GitHub's
// clock; the code under test is given a Mac whose clock reads skew later. Before the cheap poll
// existed there was one clock in these tests, so the skew defaults to none.
func newFixtureSkew(t *testing.T, w *world, h func(ghclitest.Call) ghclitest.Reply, skew time.Duration, mod func(*Config)) *fixture {
	t.Helper()
	isolate(t)
	fx := &fixture{w: w, t: t, dir: t.TempDir(), now: time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)}
	fx.f = ghclitest.New(t, h, "hangryclaude", "alt-builds")
	// GitHub's clock, unless a test sets its own: the fixture's "now".
	fx.f.SetClock(func() time.Time { return fx.now })
	cl := ghcli.New(fx.f)
	cl.Backoff = time.Millisecond
	fx.cfg = testConfig(fx.dir)
	fx.cfg.Client = cl
	fx.cfg.Now = func() time.Time { return fx.now.Add(skew) }
	// The tests of the full GraphQL poll run it on every Changed. The detector that skips it has
	// tests of its own (watch_test.go), which turn it back on.
	fx.cfg.NoWatch = true
	if mod != nil {
		mod(&fx.cfg)
	}
	inv, err := New(fx.cfg)
	if err != nil {
		t.Fatal(err)
	}
	fx.inv = inv
	return fx
}

// fresh is a new Inventory over the same config: a new process reading saved state.
func (fx *fixture) fresh() *Inventory {
	fx.t.Helper()
	inv, err := New(fx.cfg)
	if err != nil {
		fx.t.Fatal(err)
	}
	return inv
}

// assertNoTokenAnywhere fails if either account's token appears in argv, in any saved file
// under the state dir, or in the given errors.
func (fx *fixture) assertNoTokenAnywhere(errs ...error) {
	fx.t.Helper()
	for _, acct := range []string{"hangryclaude", "alt-builds"} {
		tok := fx.f.Token(acct)
		for _, args := range fx.f.Commands() {
			for _, a := range args {
				if strings.Contains(a, tok) {
					fx.t.Fatalf("token for %s reached argv (%d arguments)", acct, len(args))
				}
			}
		}
		for _, err := range errs {
			if err != nil && strings.Contains(err.Error(), tok) {
				fx.t.Fatalf("token for %s reached an error message", acct)
			}
		}
		err := filepath.WalkDir(fx.dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			b, rerr := os.ReadFile(path)
			if rerr != nil {
				return rerr
			}
			if strings.Contains(string(b), tok) {
				fx.t.Fatalf("token for %s was written to %s", acct, path)
			}
			return nil
		})
		if err != nil {
			fx.t.Fatal(err)
		}
	}
}

// standardWorld is a miniature of the user's GitHub: two accounts, two orgs read through the
// first, wikis on some repos, gists on one account.
func standardWorld() *world {
	w := newWorld()
	w.add(wrepo{owner: "hangryclaude", name: "alpha", vis: "PUBLIC", pushed: "2026-11-03T10:00:00Z", wiki: true, size: 4164})
	w.add(wrepo{owner: "hangryclaude", name: "bravo", pushed: "2026-11-02T09:00:00Z"})
	w.add(wrepo{owner: "hangryclaude", name: "charlie", pushed: "2026-11-01T09:00:00Z", wiki: true, fork: true})
	w.add(wrepo{owner: "hangryclaude", name: "delta", pushed: "2026-10-20T09:00:00Z"})
	w.add(wrepo{owner: "hangryclaude", name: "echo", pushed: "2026-10-01T09:00:00Z", archived: true})
	w.add(wrepo{owner: "alt-builds", name: "foxtrot", vis: "PUBLIC", pushed: "2026-11-02T01:00:00Z"})
	w.add(wrepo{owner: "alt-builds", name: "golf", pushed: "2026-09-01T00:00:00Z"})
	w.add(wrepo{owner: "acme-apps", name: "hotel", vis: "PUBLIC", pushed: "2026-08-01T00:00:00Z"})
	w.add(wrepo{owner: "acme-apps", name: "india", pushed: "2026-07-01T00:00:00Z", wiki: true})
	w.add(wrepo{owner: "Loony-Labs-Video", name: "juliet", vis: "PUBLIC", pushed: "2026-06-01T00:00:00Z"})
	w.orgs["acme-apps"] = []string{"hangryclaude"}
	w.orgs["Loony-Labs-Video"] = []string{"hangryclaude"}
	w.gists["hangryclaude"] = []wgist{
		{id: "0a1b2c3d4e5f60718293a4b5c6d7e8f9", updated: "2026-08-06T01:16:55Z", pushed: "2026-08-06T01:16:55Z"},
		{id: "1b2c3d4e5f60718293a4b5c6d7e8f9a0", updated: "2026-08-02T19:58:14Z", pushed: "2026-08-02T19:58:14Z"},
		{id: "2c3d4e5f60718293a4b5c6d7e8f9a0b1", updated: "2026-10-30T00:00:00Z", public: true},
	}
	return w
}

// search answers the activity fallback's one search: items that involve the login and were
// updated at or after the time in the query, newest first, the way GitHub's search sorts them.
func (w *world) search(q string) map[string]any {
	var login, since string
	for _, f := range strings.Fields(q) {
		if v, ok := strings.CutPrefix(f, "involves:"); ok {
			login = v
		}
		if v, ok := strings.CutPrefix(f, "updated:>="); ok {
			since = v
		}
	}
	var hits []witem
	for _, it := range w.items {
		if it.login == login && !newer(since, it.updated) {
			hits = append(hits, it)
		}
	}
	slices.SortStableFunc(hits, func(a, b witem) int { return strings.Compare(b.updated, a.updated) })
	var nodes []any
	for _, it := range hits[:min(len(hits), 50)] {
		nodes = append(nodes, map[string]any{
			"__typename": it.kind, "number": it.number, "updatedAt": it.updated,
			"repository": map[string]string{"nameWithOwner": it.owner + "/" + it.repo},
		})
	}
	return map[string]any{"pageInfo": map[string]any{"hasNextPage": w.moreActivity}, "nodes": nodes}
}

// restLabel names the REST lists the cheap poll reads, for the counters and for failure injection.
func restLabel(path string) (string, bool) {
	switch {
	case strings.HasPrefix(path, "user/repos?"):
		return "repos", true
	case strings.HasPrefix(path, "gists?"):
		return "gists", true
	case strings.HasPrefix(path, "orgs/"):
		org, _, _ := strings.Cut(strings.TrimPrefix(path, "orgs/"), "/")
		return "org:" + org, true
	}
	return "", false
}

func restRepoJSON(r wrepo) map[string]any {
	m := map[string]any{
		"name": r.name, "owner": map[string]string{"login": r.owner}, "private": r.vis != "PUBLIC",
		"visibility": strings.ToLower(r.vis), "fork": r.fork, "archived": r.archived, "pushed_at": nil,
		"has_wiki": r.wiki, "size": r.size,
		// Text a person wrote, which the inventory must not keep.
		"description": "free text that may hold a key",
	}
	if r.pushed != "" {
		m["pushed_at"] = r.pushed
	}
	return m
}

// restList answers the public repo lists and the gist list with the ETag a conditional request
// needs: the same ETag for the same page, a 304 when If-None-Match carries it.
func (w *world) restList(t testing.TB, c ghclitest.Call, label string) ghclitest.Reply {
	path, query, _ := strings.Cut(c.Path, "?")
	vals, err := url.ParseQuery(query)
	if err != nil {
		t.Errorf("world: bad query in %s", c.Path)
	}
	w.restCalls[label]++
	if f, ok := w.fail[c.Acct+" "+label]; ok {
		return f
	}
	pg, _ := strconv.Atoi(vals.Get("page"))
	per, _ := strconv.Atoi(vals.Get("per_page"))
	if pg < 1 || per < 1 {
		t.Errorf("world: %s needs page and per_page", c.Path)
		pg, per = 1, 100
	}
	var items []any
	switch {
	case label == "repos":
		if vals.Get("visibility") != "public" || vals.Get("affiliation") != "owner" {
			t.Errorf("world: %s must ask for the account's own public repos", c.Path)
		}
		for _, r := range w.scopeRepos(w.viewer(c.Acct)) {
			if r.vis == "PUBLIC" {
				items = append(items, restRepoJSON(r))
			}
		}
	case label == "gists":
		all := slices.Clone(w.gists[c.Acct])
		slices.SortStableFunc(all, func(a, b wgist) int { return strings.Compare(b.updated, a.updated) })
		for _, g := range all {
			items = append(items, map[string]any{"id": g.id, "owner": map[string]string{"login": w.viewer(c.Acct)}, "public": g.public, "updated_at": g.updated, "description": "free text that may hold a key"})
		}
	default:
		org := strings.TrimPrefix(label, "org:")
		if w.orgs[org] == nil {
			return ghclitest.JSON(404, map[string]string{"message": "Not Found"})
		}
		if vals.Get("type") != "public" {
			t.Errorf("world: %s must ask for public repos", c.Path)
		}
		for _, r := range w.scopeRepos(org) {
			if r.vis == "PUBLIC" {
				items = append(items, restRepoJSON(r))
			}
		}
	}
	_ = path
	nodes, more, _ := page(items, per, (pg-1)*per)
	body, _ := json.Marshal(nodes)
	if nodes == nil {
		body = []byte("[]")
	}
	sum := sha256.Sum256(body)
	etag := `W/"` + hex.EncodeToString(sum[:8]) + `"`
	if c.Header["If-None-Match"] == etag {
		w.rest304[label]++
		return ghclitest.Reply{Status: 304, Header: map[string]string{"Etag": etag}}
	}
	r := ghclitest.Reply{Status: 200, Body: body, Header: map[string]string{"Etag": etag}}
	if more {
		r.Header["Link"] = fmt.Sprintf(`<https://api.github.com/%s?page=%d>; rel="next"`, path, pg+1)
	}
	return r
}

// assertNoParameterFlags fails if any gh call the code under test made carried -f or -F, which
// turn a GET into a POST (STEAL P0-20), or lacked an explicit --method. The fake refuses them as
// they arrive; this reads the record afterwards, so a weakened fake would not hide one.
func assertNoParameterFlags(t *testing.T, f *ghclitest.Fake) {
	t.Helper()
	apiCalls := 0
	for _, cmd := range f.Commands() {
		if cmd[0] != "api" {
			continue
		}
		apiCalls++
		method := ""
		for i, a := range cmd {
			switch a {
			case "-f", "-F", "--field", "--raw-field":
				t.Errorf("parameter flag %s in a gh call: it would send a POST", a)
			case "--method":
				method = cmd[i+1]
			}
		}
		if method == "" {
			t.Errorf("a gh call named no --method: %v", cmd[:min(len(cmd), 4)])
		}
	}
	if apiCalls == 0 {
		t.Error("no gh api call was made, so nothing was checked")
	}
}
