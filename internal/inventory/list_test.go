package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"

	"keyguard/internal/core"
	"keyguard/internal/inventory/ghcli"
	"keyguard/internal/inventory/ghcli/ghclitest"
)

func ids(srcs []core.Source) []string {
	out := make([]string, len(srcs))
	for i, s := range srcs {
		out[i] = s.ID
	}
	return out
}

func byID(t *testing.T, srcs []core.Source, id string) core.Source {
	t.Helper()
	for _, s := range srcs {
		if s.ID == id {
			return s
		}
	}
	t.Fatalf("%s not in %v", id, ids(srcs))
	return core.Source{}
}

// gqlVars returns the "after" cursors the fake saw for one operation as one account, in order.
func gqlVars(t *testing.T, f *ghclitest.Fake, acct, op, key string) []any {
	t.Helper()
	var out []any
	for _, c := range f.Calls() {
		if c.Path != "graphql" || c.Acct != acct {
			continue
		}
		var b struct {
			Query     string         `json:"query"`
			Variables map[string]any `json:"variables"`
		}
		if err := json.Unmarshal(c.Body, &b); err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(b.Query, "query "+op+"(") || strings.HasPrefix(b.Query, "query "+op+"{") {
			out = append(out, b.Variables[key])
		}
	}
	return out
}

func TestListWalksEveryPageOfEveryScope(t *testing.T) {
	w := standardWorld()
	fx := newFixture(t, w, func(c *Config) { c.PageSize = 2 })
	got, err := fx.inv.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	want := []string{
		"gist.github.com/hangryclaude/0a1b2c3d4e5f60718293a4b5c6d7e8f9",
		"gist.github.com/hangryclaude/1b2c3d4e5f60718293a4b5c6d7e8f9a0",
		"gist.github.com/hangryclaude/2c3d4e5f60718293a4b5c6d7e8f9a0b1",
		"github.com/Loony-Labs-Video/juliet",
		"github.com/acme-apps/hotel",
		"github.com/acme-apps/india",
		"github.com/acme-apps/india.wiki",
		"github.com/alt-builds/foxtrot",
		"github.com/alt-builds/golf",
		"github.com/hangryclaude/alpha",
		"github.com/hangryclaude/alpha.wiki",
		"github.com/hangryclaude/bravo",
		"github.com/hangryclaude/charlie",
		"github.com/hangryclaude/charlie.wiki",
		"github.com/hangryclaude/delta",
		"github.com/hangryclaude/echo",
	}
	if !slices.Equal(ids(got), want) {
		t.Fatalf("sources:\n got %v\nwant %v", ids(got), want)
	}

	alpha := byID(t, got, "github.com/hangryclaude/alpha")
	wantAlpha := core.Source{
		ID: "github.com/hangryclaude/alpha", Kind: "repo", Owner: "hangryclaude", Name: "alpha", Account: "hangryclaude",
		CloneURL: "https://github.com/hangryclaude/alpha.git", Visibility: core.Public, PushedAt: "2026-11-03T10:00:00Z",
		DefaultBranch: "main", SizeKB: 4164,
	}
	if alpha != wantAlpha {
		t.Errorf("alpha = %+v\nwant   %+v", alpha, wantAlpha)
	}
	wiki := byID(t, got, "github.com/hangryclaude/alpha.wiki")
	wantWiki := core.Source{
		ID: "github.com/hangryclaude/alpha.wiki", Kind: "wiki", Owner: "hangryclaude", Name: "alpha.wiki", Account: "hangryclaude",
		CloneURL: "https://github.com/hangryclaude/alpha.wiki.git", Visibility: core.Public,
	}
	if wiki != wantWiki {
		t.Errorf("wiki = %+v\nwant  %+v", wiki, wantWiki)
	}
	if c := byID(t, got, "github.com/hangryclaude/charlie"); !c.Fork || c.Visibility != core.Private {
		t.Errorf("charlie = %+v", c)
	}
	if e := byID(t, got, "github.com/hangryclaude/echo"); !e.Archived {
		t.Errorf("echo = %+v", e)
	}
	if in := byID(t, got, "github.com/acme-apps/india"); in.Account != "hangryclaude" || in.Owner != "acme-apps" {
		t.Errorf("an org repo must be owned by the org and read by the account behind it: %+v", in)
	}
	secret := byID(t, got, "gist.github.com/hangryclaude/0a1b2c3d4e5f60718293a4b5c6d7e8f9")
	wantGist := core.Source{
		ID: "gist.github.com/hangryclaude/0a1b2c3d4e5f60718293a4b5c6d7e8f9", Kind: "gist", Owner: "hangryclaude",
		Name: "0a1b2c3d4e5f60718293a4b5c6d7e8f9", Account: "hangryclaude",
		CloneURL: "https://gist.github.com/0a1b2c3d4e5f60718293a4b5c6d7e8f9.git", Visibility: core.SecretGist, PushedAt: "2026-08-06T01:16:55Z",
	}
	if secret != wantGist {
		t.Errorf("gist = %+v\nwant  %+v", secret, wantGist)
	}
	if g := byID(t, got, "gist.github.com/hangryclaude/2c3d4e5f60718293a4b5c6d7e8f9a0b1"); g.Visibility != core.Public || g.PushedAt != "2026-10-30T00:00:00Z" {
		t.Errorf("public gist with no pushedAt must fall back to updatedAt: %+v", g)
	}

	// 5 hangryclaude repos at 2 per page, chained by the cursor GitHub returned.
	after := gqlVars(t, fx.f, "hangryclaude", "Repos", "after")
	if len(after) != 3 || after[0] != nil || after[1] != cursor(2) || after[2] != cursor(4) {
		t.Errorf("hangryclaude repo cursors = %v", after)
	}
	if n := w.opCount("Repos"); n != 4 {
		t.Errorf("Repos calls = %d, want 3 + 1", n)
	}
	if n := w.opCount("OrgRepos"); n != 2 {
		t.Errorf("OrgRepos calls = %d", n)
	}
	for _, o := range []string{"acme-apps", "Loony-Labs-Video"} {
		if v := gqlVars(t, fx.f, "hangryclaude", "OrgRepos", "org"); !slices.Contains(v, any(o)) {
			t.Errorf("org %s was not read with hangryclaude's token: %v", o, v)
		}
	}
	if v := gqlVars(t, fx.f, "alt-builds", "OrgRepos", "org"); len(v) != 0 {
		t.Errorf("alt-builds' token was used for orgs: %v", v)
	}
	fx.assertNoTokenAnywhere()
}

func TestListNeverSwitchesTheActiveAccount(t *testing.T) {
	fx := newFixture(t, standardWorld(), nil)
	if _, err := fx.inv.List(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := fx.inv.Changed(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	for _, args := range fx.f.Commands() {
		if args[0] == "auth" && args[1] != "token" {
			t.Fatalf("gh %v", args)
		}
		if args[0] == "auth" && !slices.Contains(args, "--user") {
			t.Fatalf("token read without --user would use the active account: %v", args)
		}
	}
}

func TestListReturnsWhatItCanWhenAnOrgIsUnreadable(t *testing.T) {
	w := standardWorld()
	delete(w.orgs, "acme-apps")
	fx := newFixture(t, w, nil)
	got, err := fx.inv.List(context.Background())
	if err == nil || !strings.Contains(err.Error(), "acme-apps") {
		t.Fatalf("want an error naming the org, got %v", err)
	}
	if len(got) != 13 {
		t.Fatalf("got %d sources from the readable scopes, want 13: %v", len(got), ids(got))
	}
	for _, s := range got {
		if s.Owner == "acme-apps" {
			t.Errorf("unreadable org leaked a source: %v", s.ID)
		}
	}
	fx.assertNoTokenAnywhere(err)
}

func TestListRefusesATokenThatBelongsToSomeoneElse(t *testing.T) {
	w := standardWorld()
	w.login["hangryclaude"] = "alt-builds"
	fx := newFixture(t, w, nil)
	got, err := fx.inv.List(context.Background())
	if err == nil || !strings.Contains(err.Error(), "belongs to alt-builds") {
		t.Fatalf("err = %v", err)
	}
	for _, s := range got {
		if s.Owner == "hangryclaude" && s.Kind == "repo" {
			t.Errorf("repos of a mismatched token were trusted: %v", s.ID)
		}
	}
}

func TestListPartialPageFailureKeepsEarlierPages(t *testing.T) {
	w := standardWorld()
	h := w.handler(t)
	calls := 0
	fx := newFixtureH(t, w, func(c ghclitest.Call) ghclitest.Reply {
		if strings.Contains(string(c.Body), "query Repos(") && c.Acct == "hangryclaude" {
			// Only this account's repo pages arrive here, one after another; the second
			// page fails on every retry.
			if calls++; calls >= 2 {
				return ghclitest.JSON(500, map[string]string{"message": "Server Error"})
			}
		}
		return h(c)
	}, func(c *Config) { c.PageSize = 2 })
	got, err := fx.inv.List(context.Background())
	if err == nil || !strings.Contains(err.Error(), "HTTP 500") {
		t.Fatalf("err = %v", err)
	}
	// Page 1 (alpha, bravo) arrived before page 2 failed for good.
	have := ids(got)
	if !slices.Contains(have, "github.com/hangryclaude/alpha") || !slices.Contains(have, "github.com/hangryclaude/bravo") {
		t.Errorf("first page lost: %v", have)
	}
	if slices.Contains(have, "github.com/hangryclaude/charlie") {
		t.Errorf("page 2 content cannot have arrived: %v", have)
	}
	// The other scopes are unaffected.
	if !slices.Contains(have, "github.com/alt-builds/foxtrot") || !slices.Contains(have, "github.com/acme-apps/hotel") {
		t.Errorf("other scopes were lost: %v", have)
	}
}

func TestListDecodesOddShapesFromRealisticFixture(t *testing.T) {
	raw, err := os.ReadFile("testdata/viewer_repos_odd.json")
	if err != nil {
		t.Fatal(err)
	}
	w := standardWorld()
	h := w.handler(t)
	fx := newFixtureH(t, w, func(c ghclitest.Call) ghclitest.Reply {
		if strings.Contains(string(c.Body), "query Repos(") && c.Acct == "hangryclaude" {
			return ghclitest.Reply{Status: 200, Body: raw}
		}
		return h(c)
	}, func(c *Config) { c.Accounts = []string{"hangryclaude"}; c.Orgs = nil })
	got, err := fx.inv.List(context.Background())
	if err == nil || !strings.Contains(err.Error(), "unusable name") {
		t.Fatalf("an unusable repo name must be reported, got %v", err)
	}
	for _, s := range got {
		if strings.Contains(s.ID, "..") || strings.Contains(s.Name, "/") {
			t.Fatalf("path-unsafe source accepted: %+v", s)
		}
	}
	vis := map[string]core.Visibility{}
	for _, s := range got {
		vis[s.ID] = s.Visibility
	}
	for id, want := range map[string]core.Visibility{
		"github.com/hangryclaude/ghost-type":    core.Public,
		"github.com/hangryclaude/internal-tool": core.Private,
		"github.com/hangryclaude/empty-repo":    core.Private,
		"github.com/hangryclaude/mystery":       core.Unknown,
	} {
		if vis[id] != want {
			t.Errorf("%s visibility = %q, want %q", id, vis[id], want)
		}
	}
	e := byID(t, got, "github.com/hangryclaude/empty-repo")
	if e.PushedAt != "" || e.DefaultBranch != "" {
		t.Errorf("null pushedAt/defaultBranchRef must decode empty: %+v", e)
	}
	if byID(t, got, "github.com/hangryclaude/empty-repo.wiki").PushedAt != "" {
		t.Error("a wiki has no push time of its own")
	}
	if m := byID(t, got, "github.com/hangryclaude/mystery"); !m.Fork || !m.Archived {
		t.Errorf("mystery = %+v", m)
	}
	if byID(t, got, "github.com/hangryclaude/internal-tool").DefaultBranch != "trunk" {
		t.Error("default branch not carried")
	}
}

func TestListFailsLoudlyWhenNothingWorks(t *testing.T) {
	w := standardWorld()
	fx := newFixtureH(t, w, func(c ghclitest.Call) ghclitest.Reply {
		return ghclitest.JSON(401, map[string]string{"message": "Bad credentials"})
	}, nil)
	got, err := fx.inv.List(context.Background())
	if len(got) != 0 || err == nil {
		t.Fatalf("got %d sources, err=%v", len(got), err)
	}
	var ae *ghcli.APIError
	if !errors.As(err, &ae) || ae.Status != 401 {
		t.Errorf("the HTTP status must stay inspectable through the join: %v", err)
	}
	fx.assertNoTokenAnywhere(err)
}

// testConfig is the setup the fixtures model, the kind a first install writes from gh: two
// accounts, and two orgs read through the first.
func testConfig(stateDir string) Config {
	c := DefaultConfig(stateDir)
	c.Accounts = []string{"hangryclaude", "alt-builds"}
	c.Orgs = []Org{{Login: "Loony-Labs-Video", Via: "hangryclaude"}, {Login: "acme-apps", Via: "hangryclaude"}}
	return c
}

func TestNewValidatesConfig(t *testing.T) {
	if d := DefaultConfig(""); len(d.Accounts) != 0 || len(d.Orgs) != 0 {
		t.Errorf("the defaults name accounts of their own: %v %v", d.Accounts, d.Orgs)
	}
	good := testConfig("")
	if _, err := New(good); err != nil {
		t.Fatalf("a config of two accounts and two orgs rejected: %v", err)
	}
	for name, mod := range map[string]func(*Config){
		"empty":          func(c *Config) { c.Accounts, c.Orgs = nil, nil },
		"bad account":    func(c *Config) { c.Accounts = []string{"ok", "no way"} },
		"injection":      func(c *Config) { c.Accounts = []string{`x"){y}#`} },
		"bad org":        func(c *Config) { c.Orgs = []Org{{Login: "a/b", Via: "hangryclaude"}} },
		"bad via":        func(c *Config) { c.Orgs = []Org{{Login: "a", Via: ""}} },
		"page too large": func(c *Config) { c.PageSize = 101 },
		"page negative":  func(c *Config) { c.PageSize = -1 },
	} {
		c := testConfig("")
		mod(&c)
		if _, err := New(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// The JSON tags are the contract with state/config.json.
	b, _ := json.Marshal(testConfig("/x"))
	if string(b) != `{"accounts":["hangryclaude","alt-builds"],"orgs":[{"login":"Loony-Labs-Video","via":"hangryclaude"},{"login":"acme-apps","via":"hangryclaude"}]}` {
		t.Errorf("config JSON = %s", b)
	}
}

func TestListCanSkipTheSlowDefaultBranchLookup(t *testing.T) {
	w := standardWorld()
	fast := newFixture(t, w, func(c *Config) { c.NoDefaultBranch = true })
	got, err := fast.inv.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range queryOf(t, fast.f, "hangryclaude") {
		if strings.Contains(q, "defaultBranchRef") {
			t.Fatalf("a fast List still selects defaultBranchRef")
		}
	}
	for _, s := range got {
		if s.DefaultBranch != "" {
			t.Fatalf("%s carries a branch although none was requested", s.ID)
		}
	}
	slow := newFixture(t, w, nil)
	full, err := slow.inv.List(context.Background())
	if err != nil || len(full) != len(got) {
		t.Fatalf("the two listings must agree on what exists: %v %d vs %d", err, len(full), len(got))
	}
	if byID(t, full, "github.com/hangryclaude/alpha").DefaultBranch != "main" {
		t.Error("the default List must still record the branch")
	}
}
