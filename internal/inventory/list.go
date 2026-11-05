package inventory

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"keyguard/internal/core"
)

// maxPages bounds a page walk so a cursor that never advances cannot spin forever.
// 1000 pages of 100 is far beyond any account.
const maxPages = 1000

// The idle poll looks at only the newest repos and gists: a 30-repo page answers in about
// 1 s where a 100-repo page takes about 1.7 s, and the walk goes on to further pages if all
// of those turn out to have changed.
const (
	pollPageSize = 30
	gistPollSize = 30
)

// List walks every repo, wiki and gist of the configured accounts and orgs. Scopes are read
// in parallel, pages within a scope one after another (each cursor comes from the last page).
// When one scope fails the rest still come back, together with the joined errors: a deep scan
// of 460 sources should not be lost to one unreadable org.
func (inv *Inventory) List(ctx context.Context) ([]core.Source, error) {
	var (
		mu   sync.Mutex
		out  []core.Source
		errs []error
		wg   sync.WaitGroup
	)
	add := func(s []core.Source, err error) {
		mu.Lock()
		defer mu.Unlock()
		out = append(out, s...)
		if err != nil {
			errs = append(errs, err)
		}
	}
	for _, a := range inv.cfg.Accounts {
		wg.Go(func() { add(inv.listRepos(ctx, scope{via: a})) })
		wg.Go(func() { add(inv.listGists(ctx, a)) })
	}
	for _, o := range inv.cfg.Orgs {
		wg.Go(func() { add(inv.listRepos(ctx, scope{via: o.Via, org: o.Login})) })
	}
	wg.Wait()
	sortSources(out)
	return dedupe(out), errors.Join(errs...)
}

// repoPage fetches one page of a scope's repositories, newest push first. branch asks for
// each repo's default branch, which costs a git lookup per repo; only List wants it.
func (inv *Inventory) repoPage(ctx context.Context, sc scope, after string, branch bool) (*repoConn, error) {
	vars := map[string]any{"n": inv.pageSize(), "after": nil}
	if after != "" {
		vars["after"] = after
	}
	query, key := viewerReposQuery(branch), "viewer"
	if sc.org != "" {
		query, key = orgReposQuery(branch), "org"
		vars["org"] = sc.org
	}
	g, err := inv.gql(ctx, sc.via, query, vars)
	if err != nil {
		return nil, fmt.Errorf("inventory: repos of %s: %w", sc.owner(), err)
	}
	data, err := decodeScopes(g)
	if err != nil {
		return nil, err
	}
	sd := data[key]
	if sd == nil || sd.Repos == nil {
		return nil, fmt.Errorf("inventory: %s is not readable as %s: %s", sc.owner(), sc.via, missing(g, key))
	}
	if sc.org == "" && !strings.EqualFold(sd.Login, sc.via) {
		return nil, fmt.Errorf("inventory: gh's token for %s belongs to %s", sc.via, sd.Login)
	}
	return sd.Repos, nil
}

func (inv *Inventory) listRepos(ctx context.Context, sc scope) ([]core.Source, error) {
	var (
		out  []core.Source
		errs []error
	)
	for after, pages := "", 0; ; pages++ {
		conn, err := inv.repoPage(ctx, sc, after, !inv.cfg.NoDefaultBranch)
		if err != nil {
			return out, errors.Join(append(errs, err)...)
		}
		for _, n := range conn.Nodes {
			switch {
			case n == nil:
			case !n.usable():
				errs = append(errs, fmt.Errorf("inventory: skipped a repo of %s with an unusable name", sc.owner()))
			default:
				out = append(out, n.sources(sc.via)...)
			}
		}
		if !conn.PageInfo.HasNextPage {
			return out, errors.Join(errs...)
		}
		if conn.PageInfo.EndCursor == "" || pages >= maxPages {
			return out, errors.Join(append(errs, fmt.Errorf("inventory: repo pages of %s do not end", sc.owner()))...)
		}
		after = conn.PageInfo.EndCursor
	}
}

// gistPage fetches one page of the account's gists, most recently updated first.
func (inv *Inventory) gistPage(ctx context.Context, acct string, size int, after string) (*gistConn, error) {
	vars := map[string]any{"g": size, "after": nil}
	if after != "" {
		vars["after"] = after
	}
	g, err := inv.gql(ctx, acct, gistsQuery(), vars)
	if err != nil {
		return nil, fmt.Errorf("inventory: gists of %s: %w", acct, err)
	}
	data, err := decodeScopes(g)
	if err != nil {
		return nil, err
	}
	sd := data["viewer"]
	if sd == nil || sd.Gists == nil {
		return nil, fmt.Errorf("inventory: gists of %s are not readable: %s", acct, missing(g, "viewer"))
	}
	return sd.Gists, nil
}

func (inv *Inventory) listGists(ctx context.Context, acct string) ([]core.Source, error) {
	var out []core.Source
	for after, pages := "", 0; ; pages++ {
		conn, err := inv.gistPage(ctx, acct, 100, after)
		if err != nil {
			return out, err
		}
		for _, n := range conn.Nodes {
			if n != nil && n.usable() {
				out = append(out, n.source(acct, acct))
			}
		}
		if !conn.PageInfo.HasNextPage {
			return out, nil
		}
		if conn.PageInfo.EndCursor == "" || pages >= maxPages {
			return out, fmt.Errorf("inventory: gist pages of %s do not end", acct)
		}
		after = conn.PageInfo.EndCursor
	}
}
