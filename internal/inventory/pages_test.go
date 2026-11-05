package inventory

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"

	"keyguard/internal/core"
	"keyguard/internal/inventory/ghcli"
	"keyguard/internal/inventory/ghcli/ghclitest"
)

// pagesServer is a GraphQL endpoint with a fixed number of issues, pull requests and releases
// in one repo, 100 to a page, answering for the connection and cursor a query names.
type pagesServer struct {
	mu       sync.Mutex
	issues   int
	prs      int
	tags     []string
	queries  []string // "<field> <cursor>" in arrival order
	notFound map[string]bool
	runaway  bool
}

func (p *pagesServer) handle(c ghclitest.Call) ghclitest.Reply {
	var req struct {
		Query     string         `json:"query"`
		Variables map[string]any `json:"variables"`
	}
	if err := json.Unmarshal(c.Body, &req); err != nil || c.Path != "graphql" {
		return ghclitest.JSON(404, map[string]string{"message": "Not Found"})
	}
	field := ""
	for _, f := range []string{"issues", "pullRequests", "releases"} {
		if strings.Contains(req.Query, f+"(first:100") {
			field = f
		}
	}
	cursor, _ := req.Variables["c"].(string)
	owner, name := req.Variables["o"], req.Variables["n"]
	p.mu.Lock()
	p.queries = append(p.queries, field+" "+cursor)
	missing := p.notFound[fmt.Sprint(owner)+"/"+fmt.Sprint(name)]
	p.mu.Unlock()
	if missing {
		return ghclitest.JSON(200, map[string]any{"data": map[string]any{"repository": nil},
			"errors": []map[string]any{{"type": "NOT_FOUND", "path": []any{"repository"}, "message": "Could not resolve to a Repository"}}})
	}
	total := map[string]int{"issues": p.issues, "pullRequests": p.prs, "releases": len(p.tags)}[field]
	start := 0
	if cursor != "" {
		fmt.Sscanf(cursor, "c%d", &start)
	}
	end := min(start+100, total)
	var nodes []map[string]any
	for i := start; i < end; i++ {
		n := map[string]any{"updatedAt": fmt.Sprintf("2026-11-0%dT10:00:00Z", 1+i%3)}
		if field == "releases" {
			n["tagName"] = p.tags[i]
		} else {
			n["number"] = i + 1
		}
		nodes = append(nodes, n)
	}
	more := end < total || p.runaway
	return ghclitest.JSON(200, map[string]any{"data": map[string]any{"repository": map[string]any{
		field: map[string]any{"pageInfo": map[string]any{"hasNextPage": more, "endCursor": fmt.Sprintf("c%d", end)}, "nodes": nodes}}}})
}

func pagesInventory(t *testing.T, p *pagesServer) *Inventory {
	t.Helper()
	fk := ghclitest.New(t, p.handle, "o")
	inv, err := New(Config{Accounts: []string{"o"}, Client: ghcli.New(fk), StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	return inv
}

func repoSource(owner, name string) core.Source {
	return core.Source{ID: "github.com/" + owner + "/" + name, Kind: "repo", Owner: owner, Name: name, Account: "o", Visibility: core.Public}
}

// The weekly deep run reads every page of the exposed repos with no cursor (STEAL P0-22): the
// pages a poll that failed, or an account whose feed was empty, never named.
func TestListPagesNamesEveryIssuePullRequestAndReleaseByExactURL(t *testing.T) {
	p := &pagesServer{issues: 230, prs: 3, tags: []string{"v1.0.0", "v2.0.0-rc.1", "feature/beta"}}
	inv := pagesInventory(t, p)

	pages, err := inv.ListPages(context.Background(), []core.Source{repoSource("o", "r")})
	if err != nil {
		t.Fatal(err)
	}
	byKind := map[string]int{}
	urls := map[string]bool{}
	for _, a := range pages {
		byKind[a.Kind]++
		urls[a.URL] = true
		if a.Source != "github.com/o/r" || a.At == "" {
			t.Errorf("%+v", a)
		}
	}
	if byKind["issue"] != 230 || byKind["pr"] != 3 || byKind["release"] != 3 {
		t.Fatalf("pages by kind: %v", byKind)
	}
	for _, want := range []string{
		"https://github.com/o/r/issues/1", "https://github.com/o/r/issues/230", "https://github.com/o/r/pull/3",
		"https://github.com/o/r/releases/tag/v1.0.0", "https://github.com/o/r/releases/tag/feature%2Fbeta",
	} {
		if !urls[want] {
			t.Errorf("no page %s", want)
		}
	}
	// A repo with 230 issues costs three queries for them, one each for the others: no cursor
	// is ever skipped, and the cursor GitHub handed back is the one used.
	var issueQueries []string
	for _, q := range p.queries {
		if strings.HasPrefix(q, "issues ") {
			issueQueries = append(issueQueries, q)
		}
	}
	if strings.Join(issueQueries, "|") != "issues |issues c100|issues c200" || len(p.queries) != 5 {
		t.Errorf("queries: %v", p.queries)
	}
	// Sorted, so the same repo lists the same way twice.
	for i := 1; i < len(pages); i++ {
		if pages[i-1].At > pages[i].At {
			t.Fatalf("not sorted by time: %s then %s", pages[i-1].At, pages[i].At)
		}
	}
}

func TestListPagesSkipsWhatCannotBeReadAndSaysWhatFailed(t *testing.T) {
	p := &pagesServer{issues: 2, notFound: map[string]bool{"o/gone": true}}
	inv := pagesInventory(t, p)
	srcs := []core.Source{
		repoSource("o", "gone"), // deleted, or a token that cannot see it: nothing to list, no error
		{ID: "github.com/o/r.wiki", Kind: "wiki", Owner: "o", Name: "r.wiki", Account: "o"}, // a wiki has no issues
		repoSource("o", "r"),
		repoSource("o", "bad name"), // never reaches a query
	}
	pages, err := inv.ListPages(context.Background(), srcs)
	if err != nil {
		t.Fatalf("a repo that is gone is not an error: %v", err)
	}
	if len(pages) != 2 {
		t.Errorf("pages: %+v", pages)
	}
	for _, q := range p.queries {
		if strings.Contains(q, "bad") {
			t.Errorf("a query for a repo with an unusable name: %s", q)
		}
	}

	// A failing request is an error beside the pages that were found elsewhere.
	failing := ghclitest.New(t, func(c ghclitest.Call) ghclitest.Reply {
		var req struct{ Variables map[string]any }
		_ = json.Unmarshal(c.Body, &req)
		if req.Variables["n"] == "broken" {
			return ghclitest.JSON(502, map[string]string{"message": "Bad Gateway"})
		}
		return p.handle(c)
	}, "o")
	inv2, _ := New(Config{Accounts: []string{"o"}, Client: ghcli.New(failing), StateDir: t.TempDir()})
	pages, err = inv2.ListPages(context.Background(), []core.Source{repoSource("o", "broken"), repoSource("o", "r")})
	if err == nil || !strings.Contains(err.Error(), "github.com/o/broken") || len(pages) != 2 {
		t.Errorf("a failing repo beside a good one: %d pages, error %v", len(pages), err)
	}
}

// A cursor that never ends is cut off, and the run says so.
func TestListPagesStopsARunawayCursor(t *testing.T) {
	p := &pagesServer{issues: 1, runaway: true}
	inv := pagesInventory(t, p)
	_, err := inv.ListPages(context.Background(), []core.Source{repoSource("o", "r")})
	if err == nil || !strings.Contains(err.Error(), "run past 500 queries") {
		t.Errorf("a runaway cursor: %v", err)
	}
	if n := len(p.queries); n > 3*maxPageQueries {
		t.Errorf("%d queries", n)
	}
}

func TestListPagesStopsWhenTheRunIsCancelled(t *testing.T) {
	p := &pagesServer{issues: 5000}
	inv := pagesInventory(t, p)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := inv.ListPages(ctx, []core.Source{repoSource("o", "r"), repoSource("o", "s")}); err == nil {
		t.Error("a cancelled run reported success")
	}
	if len(p.queries) > 1 {
		t.Errorf("%d queries after the context was cancelled", len(p.queries))
	}
}
