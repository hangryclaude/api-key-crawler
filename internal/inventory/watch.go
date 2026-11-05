package inventory

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"keyguard/internal/core"
	"keyguard/internal/inventory/ghcli"
)

// The cheap change detector. A poll that finds nothing should cost nothing, and a 304 answers a
// conditional request without counting against the rate limit. So the endpoints that reveal a push
// to, or a visibility flip of, an exposed source are read with If-None-Match, and what they said
// last time is kept beside the ETag. The question each answers:
//
//   - the account's public repos, sorted by push (GET /user/repos?visibility=public): a push moves
//     pushed_at and changes the page; a repo that turned public joins the list and one that turned
//     private leaves it. This one list is both the push signal and the flip signal.
//   - an org's public repos (GET /orgs/{org}/repos?type=public): the same, for the orgs.
//   - the account's gists (GET /gists): a push to a secret gist moves updated_at.
//   - the account's events (GET /users/{login}/events), polled elsewhere: issues, comments,
//     releases and wiki pushes, which move no pushed_at.
//
// All four are complete for what the sweep scans, wikis excepted, which come from the repo's
// has_wiki and are moved by events. Private repos are metadata and are not watched: a push to one
// would change the answer of a list that is only ever asked for public repos, so the idle cost
// of watching them would not be zero. They are refreshed by the full GraphQL poll every
// RefreshEvery.

// restRepo is the part of a REST repository object that is read. Nothing else is decoded, so a
// description, a homepage or a topic never reaches the state directory.
type restRepo struct {
	Name  string `json:"name"`
	Owner struct {
		Login string `json:"login"`
	} `json:"owner"`
	Private    bool   `json:"private"`
	Visibility string `json:"visibility"`
	Fork       bool   `json:"fork"`
	Archived   bool   `json:"archived"`
	PushedAt   string `json:"pushed_at"`
	HasWiki    bool   `json:"has_wiki"`
	Size       int    `json:"size"`
}

// node maps a REST repo onto the GraphQL node the rest of the package builds sources from, so
// both routes produce the same Source.
func (r restRepo) node() *repoNode {
	vis := strings.ToUpper(r.Visibility)
	if vis == "" {
		vis = "PUBLIC"
		if r.Private {
			vis = "PRIVATE"
		}
	}
	n := &repoNode{Name: r.Name, Visibility: vis, IsFork: r.Fork, IsArchived: r.Archived, PushedAt: r.PushedAt, HasWikiEnabled: r.HasWiki, DiskUsage: r.Size}
	n.Owner.Login = r.Owner.Login
	return n
}

type restGist struct {
	ID    string `json:"id"`
	Owner struct {
		Login string `json:"login"`
	} `json:"owner"`
	Public    bool   `json:"public"`
	UpdatedAt string `json:"updated_at"`
}

// decoder turns one page into sources and says how many items the page held. Items it cannot use
// are skipped and reported through warn.
type decoder func(body []byte, warn func(error)) (srcs []core.Source, items int, err error)

// reposDecoder reads a repo list. The owner of every item must be wantOwner: a token that
// belongs to someone else lists someone else's repos, and the account would be inventoried as
// theirs.
func reposDecoder(via, wantOwner string) decoder {
	return func(body []byte, warn func(error)) ([]core.Source, int, error) {
		var items []restRepo
		if err := json.Unmarshal(body, &items); err != nil {
			return nil, 0, fmt.Errorf("inventory: a repo list is not JSON: %w", err)
		}
		var out []core.Source
		for _, r := range items {
			n := r.node()
			switch {
			case !n.usable():
				warn(fmt.Errorf("inventory: skipped a repo of %s with an unusable name", wantOwner))
			case !strings.EqualFold(n.Owner.Login, wantOwner):
				return nil, 0, fmt.Errorf("inventory: gh's token for %s lists repos of %s", via, n.Owner.Login)
			default:
				out = append(out, n.sources(via)...)
			}
		}
		return out, len(items), nil
	}
}

func gistsDecoder(acct string) decoder {
	return func(body []byte, warn func(error)) ([]core.Source, int, error) {
		var items []restGist
		if err := json.Unmarshal(body, &items); err != nil {
			return nil, 0, fmt.Errorf("inventory: a gist list is not JSON: %w", err)
		}
		var out []core.Source
		for _, g := range items {
			if g.Owner.Login != "" && !strings.EqualFold(g.Owner.Login, acct) {
				return nil, 0, fmt.Errorf("inventory: gh's token for %s lists gists of %s", acct, g.Owner.Login)
			}
			n := &gistNode{Name: g.ID, IsPublic: g.Public, UpdatedAt: g.UpdatedAt}
			if !n.usable() {
				warn(fmt.Errorf("inventory: skipped a gist of %s with an unusable id", acct))
				continue
			}
			out = append(out, n.source(acct, acct))
		}
		return out, len(items), nil
	}
}

// watch is one list to read with conditional requests.
type watch struct {
	acct   string // the token that reads it
	base   string // path and query, without a page number
	decode decoder
}

// watchesOf lists what one token's poll reads.
func (inv *Inventory) watchesOf(g group) []watch {
	n := inv.pageSize()
	var out []watch
	if g.viewer {
		out = append(out,
			watch{g.via, fmt.Sprintf("user/repos?visibility=public&affiliation=owner&sort=pushed&direction=desc&per_page=%d", n), reposDecoder(g.via, g.via)},
			watch{g.via, fmt.Sprintf("gists?per_page=%d", n), gistsDecoder(g.via)},
		)
	}
	for _, org := range g.orgs {
		out = append(out, watch{g.via, fmt.Sprintf("orgs/%s/repos?type=public&sort=pushed&direction=desc&per_page=%d", org, n), reposDecoder(g.via, org)})
	}
	return out
}

// watched is what one token's lists said.
type watched struct {
	view    []core.Source         // every exposed source the lists showed
	entries map[string]watchEntry // the entries to keep, for the next poll's If-None-Match
	errs    []error               // lists that could not be read: the full poll stands in for them
	warns   []error               // items skipped inside lists that could: reported, but the list is fine
}

// watchGroup reads every list of one token, in parallel. A list that fails keeps its old entries
// and puts its error in errs; the caller then falls back to the full GraphQL poll for the token.
func (inv *Inventory) watchGroup(ctx context.Context, g group, old map[string]watchEntry) watched {
	ws := inv.watchesOf(g)
	results := make([]watched, len(ws))
	var wg sync.WaitGroup
	for i, w := range ws {
		wg.Go(func() { results[i] = inv.fetchWatched(ctx, w, old) })
	}
	wg.Wait()
	out := watched{entries: map[string]watchEntry{}}
	for _, r := range results {
		out.view = append(out.view, r.view...)
		for k, e := range r.entries {
			out.entries[k] = e
		}
		out.errs = append(out.errs, r.errs...)
		out.warns = append(out.warns, r.warns...)
	}
	return out
}

// fetchWatched reads one list, page after page while the pages come full. A page that answers 304
// is taken from the entry kept for it, which is the cached body of the earlier 200. A list that
// cannot be read at all hands back its old entries untouched.
func (inv *Inventory) fetchWatched(ctx context.Context, w watch, old map[string]watchEntry) watched {
	out := watched{entries: map[string]watchEntry{}}
	keep := func() { // the list could not be read: remember what was known about every page of it
		for k, e := range old {
			if strings.HasPrefix(k, w.acct+" "+w.base+"&page=") {
				out.entries[k] = e
			}
		}
	}
	per := inv.pageSize()
	for page := 1; ; page++ {
		path := fmt.Sprintf("%s&page=%d", w.base, page)
		key := w.acct + " " + path
		prev, have := old[key]
		rq := ghcli.Request{Path: path}
		if have && prev.ETag != "" {
			rq.Header = map[string]string{"If-None-Match": prev.ETag}
		}
		resp, err := inv.get(ctx, w.acct, rq)
		if err != nil {
			keep()
			return watched{entries: out.entries, warns: out.warns, errs: append(out.errs, err)}
		}
		var more bool
		switch {
		case resp.Status == http.StatusNotModified && have && prev.ETag != "":
			out.view = append(out.view, prev.Sources...)
			out.entries[key] = prev
			more = prev.More
		case resp.OK():
			srcs, items, derr := w.decode(resp.Body, func(e error) { out.warns = append(out.warns, e) })
			etag := resp.Header.Get("ETag")
			resp.Wipe()
			if derr != nil {
				keep()
				return watched{entries: out.entries, warns: out.warns, errs: append(out.errs, derr)}
			}
			e := watchEntry{ETag: etag, Sources: srcs, More: items >= per}
			out.entries[key] = e
			out.view = append(out.view, srcs...)
			more = e.More
		default:
			err := resp.Err()
			resp.Wipe()
			keep()
			return watched{entries: out.entries, warns: out.warns, errs: append(out.errs, fmt.Errorf("inventory: %s as %s: %w", pathOnly(path), w.acct, err))}
		}
		if !more {
			return out
		}
		if page >= maxPages {
			keep()
			return watched{entries: out.entries, warns: out.warns, errs: append(out.errs, fmt.Errorf("inventory: %s pages do not end", pathOnly(w.base)))}
		}
	}
}

// changedOf is the definition of changed applied to a view: what the last inventory does not
// know, or knows differently, or knows to be older. A repo keeps the default branch List last
// recorded; the cheap poll does not ask for it.
func changedOf(view []core.Source, prev map[string]core.Source) []core.Source {
	var out []core.Source
	for _, s := range view {
		if s.Kind == "repo" {
			s.DefaultBranch = prev[s.ID].DefaultBranch
		}
		if changedVs(prev, s) {
			out = append(out, s)
		}
	}
	return out
}

// disappeared names the repos prev holds as public in the scopes of one token that the public
// lists no longer show: they are private now, or deleted. The caller looks them up by name.
func (inv *Inventory) disappeared(g group, view []core.Source, prev map[string]core.Source) []string {
	shown := make(map[string]bool, len(view))
	for _, s := range view {
		shown[s.ID] = true
	}
	scopes := make([]scope, 0, 1+len(g.orgs))
	if g.viewer {
		scopes = append(scopes, scope{via: g.via})
	}
	for _, o := range g.orgs {
		scopes = append(scopes, scope{via: g.via, org: o})
	}
	var need []string
	for id, p := range prev {
		if p.Kind != "repo" || p.Visibility != core.Public || shown[id] {
			continue
		}
		for _, sc := range scopes {
			if sc.owns(p) {
				need = append(need, id)
				break
			}
		}
	}
	slices.Sort(need)
	return need
}

// refreshDue says whether the full GraphQL poll should run for this token: it never has, the
// last one is older than RefreshEvery on GitHub's clock, or GitHub's clock is not known yet and
// no age can be judged (STEAL P0-16: a Mac two hours fast must not make every poll look overdue,
// so the decision waits for a response and then uses the Date header).
func (inv *Inventory) refreshDue(via string, st stateFile) bool {
	if !inv.cl.Clock().Known() {
		return true
	}
	at, err := time.Parse(time.RFC3339, st.refreshed[via])
	if err != nil {
		return true
	}
	return inv.now().Sub(at) >= cmp.Or(inv.cfg.RefreshEvery, 30*time.Minute)
}

// pathOnly keeps the path of a request in error text; a query string can carry opaque cursors
// nobody needs in a log line.
func pathOnly(p string) string {
	if i := strings.IndexByte(p, '?'); i >= 0 {
		return p[:i]
	}
	return p
}
