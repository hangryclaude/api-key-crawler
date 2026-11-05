// Package inventory lists everything keyguard watches — the repos, wikis and gists of the
// configured accounts and orgs — and answers the cheap poll question "what changed since
// last time" without spending anything when nothing did.
//
// List walks every repo, wiki and gist as metadata. Poll is the cheap poll: the lists that
// reveal a push to, or a visibility flip of, a source a stranger can read (public repos, gists)
// and each account's events are read with conditional requests, which answer 304 and cost no
// quota when nothing moved; the GraphQL query over every repo, private ones included, runs only
// every RefreshEvery. Exposed says which sources the sweep scans, and Flip which of them just
// became exposed (PLAN.md "Sweep scope").
//
// Every cursor and every age is GitHub's clock, from the Date header of its responses, never
// this Mac's (STEAL P0-16). An events feed that is empty while its account is being pushed to is
// marked unusable and the activity it would have named is found through GraphQL (P0-21).
//
// Every request runs as a named account through ghcli, which hands gh that account's token
// per call; the globally active gh account is never touched.
package inventory

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"keyguard/internal/core"
	"keyguard/internal/inventory/ghcli"
)

// Org is an organization and the account whose token can read it.
type Org struct {
	Login string `json:"login"`
	Via   string `json:"via"`
}

// Config says whose repos to watch. The json tags are the shape state/config.json uses.
type Config struct {
	Accounts []string `json:"accounts"`
	Orgs     []Org    `json:"orgs"`

	StateDir    string        `json:"-"` // core.Paths.State: event ETags live here; "" keeps them in memory only
	PageSize    int           `json:"-"` // repos per page, GraphQL or REST, at most 100; 0 means 100
	Client      *ghcli.Client `json:"-"` // nil means real gh
	EventWindow time.Duration `json:"-"` // how far back a first events poll looks; 0 means 24 h
	// Now is this Mac's clock, for measuring how much time passed between two responses and for
	// nothing else (STEAL P0-16). Every cursor and every age is GitHub's clock, from the Date
	// header of the last response. Nil means time.Now. It is handed to the client's clock.
	Now func() time.Time `json:"-"`

	// NoWatch turns the cheap change detector off, so every poll runs the GraphQL query over every
	// repo, the way v1 did. The detector reads the public repo lists, the gists and the events
	// with conditional requests, which cost no quota when nothing changed, and runs the GraphQL
	// query only every RefreshEvery for the private repos, which are metadata and never scanned.
	NoWatch bool `json:"-"`
	// RefreshEvery is how often the detector runs the full GraphQL poll anyway; 0 means 30 min.
	// It bounds how stale the metadata of a private repo can get. Exposed sources are never as
	// stale as this: their lists are checked on every poll.
	RefreshEvery time.Duration `json:"-"`

	// NoDefaultBranch makes List skip each repo's default branch, which GitHub resolves with a
	// git lookup per repo: about 2.5 s of every 4.2 s page on this account. Nothing in the
	// scan path reads it, so a caller that wants a fast listing can leave it out.
	NoDefaultBranch bool `json:"-"`
}

// DefaultConfig names no account and no org: install fills both in from gh on a first run
// (ghcli.AuthStatusArgs, ghcli.OrgsArgs), and config.json keeps them from then on.
func DefaultConfig(stateDir string) Config {
	return Config{StateDir: stateDir}
}

// Inventory implements core.Inventory.
type Inventory struct {
	cfg Config
	cl  *ghcli.Client

	mu     sync.Mutex
	state  stateFile // loaded from StateDir on first use
	loaded bool

	n counters
}

// counters tally the requests of the current Poll or List, so a caller (and the live check) can
// say how many were answered 304, which cost nothing.
type counters struct{ rest, notModified, graphql atomic.Int64 }

func (c *counters) reset() { c.rest.Store(0); c.notModified.Store(0); c.graphql.Store(0) }

// get is a REST request, counted.
func (inv *Inventory) get(ctx context.Context, acct string, rq ghcli.Request) (ghcli.Response, error) {
	inv.n.rest.Add(1)
	resp, err := inv.cl.Do(ctx, acct, rq)
	if err == nil && resp.Status == 304 {
		inv.n.notModified.Add(1)
	}
	return resp, err
}

// gql is a GraphQL request, counted.
func (inv *Inventory) gql(ctx context.Context, acct, query string, vars map[string]any) (ghcli.GQLResponse, error) {
	inv.n.graphql.Add(1)
	return inv.cl.GraphQL(ctx, acct, query, vars)
}

var _ core.Inventory = (*Inventory)(nil)

// New validates cfg. Logins end up inside API paths and query text, so a bad one is an
// error here instead of an injection later.
func New(cfg Config) (*Inventory, error) {
	if len(cfg.Accounts) == 0 && len(cfg.Orgs) == 0 {
		return nil, errors.New("inventory: no accounts or orgs configured")
	}
	if cfg.PageSize < 0 || cfg.PageSize > 100 {
		return nil, fmt.Errorf("inventory: page size %d outside 1..100", cfg.PageSize)
	}
	for _, a := range cfg.Accounts {
		if !ghcli.ValidLogin(a) {
			return nil, fmt.Errorf("inventory: %q is not a GitHub login", a)
		}
	}
	for _, o := range cfg.Orgs {
		if !ghcli.ValidLogin(o.Login) || !ghcli.ValidLogin(o.Via) {
			return nil, fmt.Errorf("inventory: org %q via %q is not a pair of GitHub logins", o.Login, o.Via)
		}
	}
	if cfg.RefreshEvery < 0 {
		return nil, fmt.Errorf("inventory: refresh interval %v cannot be negative", cfg.RefreshEvery)
	}
	inv := &Inventory{cfg: cfg, cl: cfg.Client, state: newStateFile()}
	if inv.cl == nil {
		inv.cl = ghcli.New(nil)
	}
	if cfg.Now != nil {
		inv.cl.Clock().SetLocal(cfg.Now)
	}
	return inv, nil
}

func (inv *Inventory) pageSize() int { return cmp.Or(inv.cfg.PageSize, 100) }

// now is GitHub's time, as heard from the Date header of the last response (STEAL P0-16). Before
// any response it is this Mac's clock, because nothing better exists yet; the first request of a
// poll settles that, and nothing here stamps or compares a time before it.
func (inv *Inventory) now() time.Time { return inv.cl.Clock().Now() }

// Clock is GitHub's clock as this inventory last heard it.
func (inv *Inventory) Clock() *ghcli.Clock { return inv.cl.Clock() }

// Skew asks GitHub what time it is, with the one request that costs no quota, and says how far
// this Mac's clock is ahead of it (negative: behind). Doctor fails when the answer is more than a
// minute either way: every cursor here is GitHub's, but a Mac that far off is lying to something
// else too (the launchd schedule, the notification stamps, the git commits).
func (inv *Inventory) Skew(ctx context.Context) (time.Duration, error) {
	acct := ""
	switch {
	case len(inv.cfg.Accounts) > 0:
		acct = inv.cfg.Accounts[0]
	case len(inv.cfg.Orgs) > 0:
		acct = inv.cfg.Orgs[0].Via
	}
	if _, err := inv.get(ctx, acct, ghcli.Request{Path: "rate_limit"}); err != nil {
		return 0, fmt.Errorf("inventory: could not learn GitHub's time: %w", err)
	}
	d, ok := inv.cl.Clock().Skew()
	if !ok {
		return 0, errors.New("inventory: GitHub's answer carried no Date header")
	}
	return d, nil
}

// scope is one place repositories live: an account's own, or an organization's.
type scope struct {
	via string // account whose token reads it
	org string // "" for the account's own repos
}

func (s scope) owner() string { return cmp.Or(s.org, s.via) }

// owns reports whether a source sits in this scope.
func (s scope) owns(src core.Source) bool {
	return src.Kind == "repo" && strings.EqualFold(src.Owner, s.owner())
}

// group is everything one account's token reads in a single poll request.
type group struct {
	via    string
	viewer bool     // the account's own repos and gists
	orgs   []string // orgs read through this token
}

func (inv *Inventory) groups() []group {
	by := map[string]*group{}
	var order []string
	get := func(via string) *group {
		if by[via] == nil {
			by[via] = &group{via: via}
			order = append(order, via)
		}
		return by[via]
	}
	for _, a := range inv.cfg.Accounts {
		get(a).viewer = true
	}
	for _, o := range inv.cfg.Orgs {
		g := get(o.Via)
		g.orgs = append(g.orgs, o.Login)
	}
	out := make([]group, 0, len(order))
	for _, v := range order {
		out = append(out, *by[v])
	}
	return out
}

// Index keys sources by ID, the shape Changed takes as its baseline.
func Index(sources []core.Source) map[string]core.Source {
	m := make(map[string]core.Source, len(sources))
	for _, s := range sources {
		m[s.ID] = s
	}
	return m
}

// sortSources orders by ID so output is stable between runs and a wiki follows its repo.
func sortSources(s []core.Source) {
	slices.SortStableFunc(s, func(a, b core.Source) int { return strings.Compare(a.ID, b.ID) })
}

// dedupe keeps the first source per ID.
func dedupe(in []core.Source) []core.Source {
	seen := make(map[string]bool, len(in))
	out := in[:0:0]
	for _, s := range in {
		if !seen[s.ID] {
			seen[s.ID] = true
			out = append(out, s)
		}
	}
	return out
}
