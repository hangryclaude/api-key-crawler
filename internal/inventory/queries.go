package inventory

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"keyguard/internal/core"
	"keyguard/internal/inventory/ghcli"
)

// Operations are named so a fake GitHub (and GitHub's own logs) can tell them apart.
// GraphQL rejects a declared-but-unused variable, so each text declares only what it uses.
//
// defaultBranchRef is a separate git lookup per repository: measured against the real
// account it adds about 2.5 s to a 100-repo page (1.8 s without, 4.2 s with). List pays that
// once a week; the poll leaves it out and carries the last known branch forward.
const (
	repoFields       = `name owner{login} visibility isFork isArchived pushedAt hasWikiEnabled diskUsage`
	repoFieldsBranch = repoFields + ` defaultBranchRef{name}`
)

func reposSel(org, cursor, branch bool) string {
	fields := repoFields
	if branch {
		fields = repoFieldsBranch
	}
	args := "first:$n"
	if cursor {
		args += ",after:$after"
	}
	if !org {
		args += ",ownerAffiliations:OWNER"
	}
	return `repos:repositories(` + args + `,orderBy:{field:PUSHED_AT,direction:DESC}){totalCount pageInfo{hasNextPage endCursor} nodes{` + fields + `}}`
}

// pubSel lists only the public repos. A repo that turned public does not move pushedAt, so
// comparing this short list with the last inventory is what catches a private-to-public flip
// without crawling every page.
func pubSel(org bool) string {
	args := "first:100,privacy:PUBLIC"
	if !org {
		args += ",ownerAffiliations:OWNER"
	}
	return `pub:repositories(` + args + `){totalCount pageInfo{hasNextPage} nodes{name owner{login}}}`
}

func gistsSel(cursor bool) string {
	args := "first:$g,privacy:ALL,orderBy:{field:UPDATED_AT,direction:DESC}"
	if cursor {
		args += ",after:$after"
	}
	return `gists(` + args + `){totalCount pageInfo{hasNextPage endCursor} nodes{name isPublic pushedAt updatedAt}}`
}

func viewerReposQuery(branch bool) string {
	return `query Repos($n:Int!,$after:String){viewer{login ` + reposSel(false, true, branch) + `}}`
}

func orgReposQuery(branch bool) string {
	return `query OrgRepos($org:String!,$n:Int!,$after:String){org:organization(login:$org){login ` + reposSel(true, true, branch) + `}}`
}

func gistsQuery() string {
	return `query Gists($g:Int!,$after:String){viewer{login ` + gistsSel(true) + `}}`
}

// pollQuery is the idle-poll request: for one token, the newest page of every scope it
// reads, the public lists, and the newest gists — one round trip.
func pollQuery(g group) string {
	var b strings.Builder
	b.WriteString("query Poll($n:Int!")
	if g.viewer {
		b.WriteString(",$g:Int!")
	}
	b.WriteString("){")
	if g.viewer {
		b.WriteString("viewer{login " + reposSel(false, false, false) + " " + pubSel(false) + " " + gistsSel(false) + "}")
	}
	for i, org := range g.orgs {
		// Logins are validated by ghcli.ValidLogin, so quoting by hand is safe.
		fmt.Fprintf(&b, ` o%d:organization(login:%q){login %s %s}`, i, org, reposSel(true, false, false), pubSel(true))
	}
	b.WriteString("}")
	return b.String()
}

// byNameQuery resolves specific repos: ones that flipped visibility while far down the
// push-ordered list, where a page walk would not reach them.
func byNameQuery(ids []string) string {
	var b strings.Builder
	b.WriteString("query ReposByName{")
	for i, id := range ids {
		owner, name, _ := strings.Cut(strings.TrimPrefix(id, "github.com/"), "/")
		fmt.Fprintf(&b, "r%d:repository(owner:%q,name:%q){%s} ", i, owner, name, repoFields)
	}
	b.WriteString("}")
	return b.String()
}

type pageInfo struct {
	HasNextPage bool   `json:"hasNextPage"`
	EndCursor   string `json:"endCursor"`
}

// repoNode is one repository as GraphQL returns it. The public-list query selects only
// name and owner, so the rest stay zero there.
type repoNode struct {
	Name  string `json:"name"`
	Owner struct {
		Login string `json:"login"`
	} `json:"owner"`
	Visibility       string `json:"visibility"`
	IsFork           bool   `json:"isFork"`
	IsArchived       bool   `json:"isArchived"`
	PushedAt         string `json:"pushedAt"` // JSON null decodes to ""
	HasWikiEnabled   bool   `json:"hasWikiEnabled"`
	DiskUsage        int    `json:"diskUsage"`
	DefaultBranchRef *struct {
		Name string `json:"name"`
	} `json:"defaultBranchRef"`
}

type repoConn struct {
	TotalCount int         `json:"totalCount"`
	PageInfo   pageInfo    `json:"pageInfo"`
	Nodes      []*repoNode `json:"nodes"` // GraphQL may return null for an inaccessible node
}

type gistNode struct {
	Name      string `json:"name"`
	IsPublic  bool   `json:"isPublic"`
	PushedAt  string `json:"pushedAt"`
	UpdatedAt string `json:"updatedAt"`
}

type gistConn struct {
	TotalCount int         `json:"totalCount"`
	PageInfo   pageInfo    `json:"pageInfo"`
	Nodes      []*gistNode `json:"nodes"`
}

// scopeData is what one viewer/organization selection decodes to.
type scopeData struct {
	Login string    `json:"login"`
	Repos *repoConn `json:"repos"`
	Pub   *repoConn `json:"pub"`
	Gists *gistConn `json:"gists"`
}

// decodeScopes splits a reply into its named selections. A selection GitHub could not
// resolve (an org the token cannot see) decodes to nil; the matching error is in g.Errors.
func decodeScopes(g ghcli.GQLResponse) (map[string]*scopeData, error) {
	m := map[string]*scopeData{}
	if err := json.Unmarshal(g.Data, &m); err != nil {
		return nil, fmt.Errorf("inventory: unreadable GraphQL data: %w", err)
	}
	return m, nil
}

// missing explains why a selection came back empty, from the reply's own error entries.
func missing(g ghcli.GQLResponse, alias string) string {
	for _, e := range g.Errors {
		if len(e.Path) > 0 && fmt.Sprint(e.Path[0]) == alias {
			return e.Message
		}
	}
	return "no data returned"
}

func visibility(v string) core.Visibility {
	switch v {
	case "PUBLIC":
		return core.Public
	case "PRIVATE", "INTERNAL": // internal means "members of the enterprise", not strangers
		return core.Private
	}
	return core.Unknown
}

func repoID(owner, name string) string { return "github.com/" + owner + "/" + name }

// usable reports whether a node can safely become a Source. Owner and name become file
// system path segments in the mirror cache.
func (n *repoNode) usable() bool { return ghcli.ValidLogin(n.Owner.Login) && ghcli.ValidName(n.Name) }

// sources turns a node into its repo Source and, when the wiki is enabled, the wiki Source.
// A wiki has no push time of its own: repo pushes do not touch it, so it is changed by
// events and visibility flips, never by pushedAt.
func (n *repoNode) sources(account string) []core.Source {
	vis := visibility(n.Visibility)
	repo := core.Source{
		ID:         repoID(n.Owner.Login, n.Name),
		Kind:       "repo",
		Owner:      n.Owner.Login,
		Name:       n.Name,
		Account:    account,
		CloneURL:   "https://github.com/" + n.Owner.Login + "/" + n.Name + ".git",
		Visibility: vis,
		PushedAt:   n.PushedAt,
		Fork:       n.IsFork,
		Archived:   n.IsArchived,
		SizeKB:     n.DiskUsage,
	}
	if n.DefaultBranchRef != nil {
		repo.DefaultBranch = n.DefaultBranchRef.Name
	}
	out := []core.Source{repo}
	if n.HasWikiEnabled {
		out = append(out, core.Source{
			ID:         repo.ID + ".wiki",
			Kind:       "wiki",
			Owner:      n.Owner.Login,
			Name:       n.Name + ".wiki",
			Account:    account,
			CloneURL:   "https://github.com/" + n.Owner.Login + "/" + n.Name + ".wiki.git",
			Visibility: vis,
		})
	}
	return out
}

func (g *gistNode) usable() bool { return ghcli.ValidName(g.Name) }

// source maps a gist. Its PushedAt is the later of pushedAt and updatedAt: gists are
// polled by UPDATED_AT, and a git push always moves it, so this never hides a push.
func (g *gistNode) source(owner, account string) core.Source {
	vis := core.SecretGist
	if g.IsPublic {
		vis = core.Public
	}
	at := g.UpdatedAt
	if newer(g.PushedAt, at) {
		at = g.PushedAt
	}
	return core.Source{
		ID:         "gist.github.com/" + owner + "/" + g.Name,
		Kind:       "gist",
		Owner:      owner,
		Name:       g.Name,
		Account:    account,
		CloneURL:   "https://gist.github.com/" + g.Name + ".git",
		Visibility: vis,
		PushedAt:   at,
	}
}

// newer reports whether timestamp a is strictly later than b. An empty b is older than any
// a; unparseable values fall back to string order, which is right for same-format RFC 3339.
func newer(a, b string) bool {
	if a == "" {
		return false
	}
	if b == "" {
		return true
	}
	ta, errA := time.Parse(time.RFC3339, a)
	tb, errB := time.Parse(time.RFC3339, b)
	if errA != nil || errB != nil {
		return a > b
	}
	return ta.After(tb)
}
