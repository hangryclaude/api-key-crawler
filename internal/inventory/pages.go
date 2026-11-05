package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"keyguard/internal/core"
	"keyguard/internal/inventory/ghcli"
)

// ListPages names every issue, pull request and release page of the repos it is given, with no
// cursor. The cheap poll can say only what changed since it last looked (Poll, Activity); a page
// that changed while nobody was looking (a poll that failed, an account whose events feed was
// empty) is found by reading all of them, which is what the weekly deep run does for the exposed
// repos. Each page is named by its exact URL, the shape core.APIScanner takes, and nothing of
// their text is read or kept: only a number or a tag and when GitHub says it was last written.
//
// It is GraphQL, 100 to a page, one connection at a time (issues, pull requests, releases), so a
// repo with 3,000 issues costs 30 queries and an empty one costs 3. The token of the account
// that can read the repo is used (Source.Account), and a repo that cannot be read costs an error
// beside the pages of the ones that can: results come back together with the joined errors.
func (inv *Inventory) ListPages(ctx context.Context, repos []core.Source) ([]Activity, error) {
	got := map[string]Activity{}
	var errs []error
	for _, r := range repos {
		if r.Kind != "repo" || !ghcli.ValidLogin(r.Owner) || !ghcli.ValidName(r.Name) {
			continue
		}
		acct := r.Account
		if acct == "" {
			acct = inv.defaultAccount()
		}
		for _, c := range []struct{ kind, field, node string }{
			{"issue", "issues", "number"},
			{"pr", "pullRequests", "number"},
			{"release", "releases", "tagName"},
		} {
			if err := inv.pagesOf(ctx, acct, r, c.kind, c.field, c.node, got); err != nil {
				errs = append(errs, err)
				if ctx.Err() != nil {
					return sortedActivity(got), errors.Join(errs...)
				}
			}
		}
	}
	return sortedActivity(got), errors.Join(errs...)
}

// maxPageQueries bounds one connection of one repo, so a runaway cursor cannot loop for ever:
// 500 queries of 100 is 50,000 items.
const maxPageQueries = 500

// pagesOf walks one connection of one repo to its end and adds each item to got.
func (inv *Inventory) pagesOf(ctx context.Context, acct string, r core.Source, kind, field, node string, got map[string]Activity) error {
	query := fmt.Sprintf(`query($o:String!,$n:String!,$c:String){repository(owner:$o,name:$n){%s(first:100,after:$c){pageInfo{hasNextPage endCursor} nodes{%s updatedAt}}}}`, field, node)
	cursor := ""
	for i := 0; i < maxPageQueries; i++ {
		vars := map[string]any{"o": r.Owner, "n": r.Name}
		if cursor != "" {
			vars["c"] = cursor
		}
		g, err := inv.gql(ctx, acct, query, vars)
		if err != nil {
			return fmt.Errorf("inventory: the %s pages of %s: %w", kind, r.ID, err)
		}
		for _, e := range g.Errors {
			if e.Type == "NOT_FOUND" {
				return nil // the repo is gone or the token cannot see it: nothing to list
			}
			return fmt.Errorf("inventory: the %s pages of %s: %w", kind, r.ID, e)
		}
		var data struct {
			Repository map[string]struct {
				PageInfo pageInfo `json:"pageInfo"`
				Nodes    []struct {
					Number    int    `json:"number"`
					TagName   string `json:"tagName"`
					UpdatedAt string `json:"updatedAt"`
				} `json:"nodes"`
			} `json:"repository"`
		}
		if err := json.Unmarshal(g.Data, &data); err != nil {
			return fmt.Errorf("inventory: the %s pages of %s: unreadable GraphQL data: %w", kind, r.ID, err)
		}
		conn, ok := data.Repository[field]
		if !ok {
			return nil // a repo with the connection switched off (issues disabled) answers null
		}
		for _, n := range conn.Nodes {
			if u, ok := pageURL(r.Owner, r.Name, kind, n.Number, n.TagName); ok {
				got[u] = Activity{Source: repoID(r.Owner, r.Name), Kind: kind, URL: u, At: n.UpdatedAt}
			}
		}
		if !conn.PageInfo.HasNextPage || conn.PageInfo.EndCursor == "" {
			return nil
		}
		cursor = conn.PageInfo.EndCursor
	}
	return fmt.Errorf("inventory: the %s pages of %s run past %d queries; the rest were not listed", kind, r.ID, maxPageQueries)
}

// defaultAccount is the account whose token reads a repo that names none.
func (inv *Inventory) defaultAccount() string {
	switch {
	case len(inv.cfg.Accounts) > 0:
		return inv.cfg.Accounts[0]
	case len(inv.cfg.Orgs) > 0:
		return inv.cfg.Orgs[0].Via
	}
	return ""
}
