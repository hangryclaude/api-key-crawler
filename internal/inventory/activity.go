package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"keyguard/internal/core"
	"keyguard/internal/inventory/ghcli"
)

// Activity is one page of GitHub that is not git and that someone wrote on: an issue, a pull
// request or a release. URL names it exactly, the shape core.APIScanner takes (STEAL P0-22). A
// `--since` listing stops at the first item created before its cursor, so a new comment on an old
// issue is never seen, and it costs about 6 GraphQL points a repo page even when nothing matches;
// one URL costs about 1.
type Activity struct {
	Source string `json:"source"` // the repo it belongs to: "github.com/o/r"
	Kind   string `json:"kind"`   // issue|pr|release, the core.Location kinds
	URL    string `json:"url"`    // https://github.com/o/r/issues/N, /pull/N or /releases/tag/T
	At     string `json:"at"`     // when GitHub says it was last written, GitHub's clock
}

const githubWeb = "https://github.com/"

func pageURL(owner, name, kind string, n int, tag string) (string, bool) {
	if !ghcli.ValidLogin(owner) || !ghcli.ValidName(name) {
		return "", false
	}
	base := githubWeb + owner + "/" + name
	switch kind {
	case "issue":
		return base + "/issues/" + fmt.Sprint(n), n > 0
	case "pr":
		return base + "/pull/" + fmt.Sprint(n), n > 0
	case "release":
		// A tag is whatever its author typed, so it is escaped into one path segment and bounded.
		return base + "/releases/tag/" + url.PathEscape(tag), tag != "" && len(tag) <= 200 && !strings.ContainsAny(tag, "\x00\r\n")
	}
	return "", false
}

// activitiesOf names the pages that events refer to. The events API payload carries the issue or
// pull request number and the release tag; that is all that is read from it, and no text.
func activitiesOf(items []ghEvent) []Activity {
	byURL := map[string]Activity{}
	for _, e := range items {
		owner, name, ok := strings.Cut(e.Repo.Name, "/")
		if !ok {
			continue
		}
		var kind string
		var n int
		var tag string
		switch e.Type {
		case "IssuesEvent", "IssueCommentEvent":
			if e.Payload.Issue != nil {
				kind, n = "issue", e.Payload.Issue.Number
			}
		case "PullRequestEvent", "PullRequestReviewEvent", "PullRequestReviewCommentEvent":
			if e.Payload.PullRequest != nil {
				kind, n = "pr", e.Payload.PullRequest.Number
			}
		case "ReleaseEvent":
			if e.Payload.Release != nil {
				kind, tag = "release", e.Payload.Release.TagName
			}
		}
		u, ok := pageURL(owner, name, kind, n, tag)
		if kind == "" || !ok {
			continue
		}
		if old, seen := byURL[u]; !seen || newer(e.CreatedAt, old.At) {
			byURL[u] = Activity{Source: repoID(owner, name), Kind: kind, URL: u, At: e.CreatedAt}
		}
	}
	return sortedActivity(byURL)
}

func sortedActivity(m map[string]Activity) []Activity {
	out := make([]Activity, 0, len(m))
	for _, a := range m {
		out = append(out, a)
	}
	slices.SortFunc(out, func(a, b Activity) int {
		if c := strings.Compare(a.At, b.At); c != 0 {
			return c
		}
		return strings.Compare(a.URL, b.URL)
	})
	return out
}

// Search results come 50 to a page; a fallback that needs more than one says so.
const (
	activityPage   = 50
	activityChunk  = 25 // repos per query, for their releases
	activityMaxTag = 5  // releases looked at per repo, newest first
)

// activityQuery is one GraphQL document: the issues and pull requests that involve login and
// were updated since the cursor, anywhere on GitHub, and the newest releases of each repo given.
// A comment on an old issue moves that issue's updatedAt, which is exactly what `--since` on a
// creation date misses. withSearch is false for the second and later chunks of a long repo list.
// GraphQL rejects a variable declared and not used, so $q is declared only with the search.
func activityQuery(repos []core.Source, withSearch bool) string {
	var b strings.Builder
	b.WriteString("query Activity")
	if withSearch {
		b.WriteString("($q:String!)")
	}
	b.WriteString("{")
	if withSearch {
		fmt.Fprintf(&b, "s:search(query:$q,type:ISSUE,first:%d){pageInfo{hasNextPage} nodes{__typename ... on Issue{number updatedAt repository{nameWithOwner}} ... on PullRequest{number updatedAt repository{nameWithOwner}}}}", activityPage)
	}
	for i, r := range repos {
		// Owner and name were validated by ghcli, so quoting by hand is safe.
		fmt.Fprintf(&b, " r%d:repository(owner:%q,name:%q){releases(first:%d,orderBy:{field:CREATED_AT,direction:DESC}){nodes{tagName updatedAt}}}", i, r.Owner, r.Name, activityMaxTag)
	}
	b.WriteString("}")
	return b.String()
}

type searchData struct {
	PageInfo pageInfo `json:"pageInfo"`
	Nodes    []struct {
		Typename   string `json:"__typename"`
		Number     int    `json:"number"`
		UpdatedAt  string `json:"updatedAt"`
		Repository struct {
			NameWithOwner string `json:"nameWithOwner"`
		} `json:"repository"`
	} `json:"nodes"`
}

type releasesData struct {
	Releases struct {
		Nodes []struct {
			TagName   string `json:"tagName"`
			UpdatedAt string `json:"updatedAt"`
		} `json:"nodes"`
	} `json:"releases"`
}

// listActivity is the fallback for an account whose events feed cannot be believed (STEAL P0-21):
// the issues and pull requests that involve it and the newest releases of repos, updated since
// the cursor, by exact page. It is what the feed would have said, found by asking GitHub's
// GraphQL instead. It returns the newest timestamp it saw so the caller can move the cursor.
func (inv *Inventory) listActivity(ctx context.Context, acct string, repos []core.Source, since time.Time) ([]Activity, string, error) {
	if !ghcli.ValidLogin(acct) {
		return nil, "", fmt.Errorf("inventory: %q is not a GitHub login", acct)
	}
	sinceStamp := stamp(since)
	var (
		got    = map[string]Activity{}
		newest string
		errs   []error
	)
	note := func(a Activity) {
		if newer(sinceStamp, a.At) {
			return // older than the cursor: the search is by date, the edge needs checking
		}
		got[a.URL] = a
		newest = newerStamp(newest, a.At)
	}
	chunks := slices.Collect(slices.Chunk(repos, activityChunk))
	if len(chunks) == 0 {
		chunks = [][]core.Source{nil}
	}
	for ci, chunk := range chunks {
		var vars map[string]any
		if ci == 0 {
			vars = map[string]any{"q": fmt.Sprintf("involves:%s updated:>=%s", acct, sinceStamp)}
		}
		g, err := inv.gql(ctx, acct, activityQuery(chunk, ci == 0), vars)
		if err != nil {
			errs = append(errs, fmt.Errorf("inventory: activity of %s: %w", acct, err))
			continue
		}
		for _, e := range g.Errors {
			if e.Type != "NOT_FOUND" {
				errs = append(errs, fmt.Errorf("inventory: activity of %s: %w", acct, e))
			}
		}
		var data map[string]json.RawMessage
		if err := json.Unmarshal(g.Data, &data); err != nil {
			errs = append(errs, fmt.Errorf("inventory: activity of %s: unreadable GraphQL data: %w", acct, err))
			continue
		}
		if raw, ok := data["s"]; ok {
			var sd searchData
			if err := json.Unmarshal(raw, &sd); err != nil {
				errs = append(errs, fmt.Errorf("inventory: activity of %s: unreadable search: %w", acct, err))
			}
			for _, n := range sd.Nodes {
				owner, name, _ := strings.Cut(n.Repository.NameWithOwner, "/")
				kind := map[string]string{"Issue": "issue", "PullRequest": "pr"}[n.Typename]
				if u, ok := pageURL(owner, name, kind, n.Number, ""); ok {
					note(Activity{Source: repoID(owner, name), Kind: kind, URL: u, At: n.UpdatedAt})
				}
			}
			if sd.PageInfo.HasNextPage {
				errs = append(errs, fmt.Errorf("inventory: more than %d issues and pull requests involve %s since %s; the rest wait for the weekly deep scan", activityPage, acct, sinceStamp))
			}
		}
		for i, r := range chunk {
			var rd releasesData
			raw, ok := data[fmt.Sprintf("r%d", i)]
			if !ok || string(raw) == "null" || json.Unmarshal(raw, &rd) != nil {
				continue
			}
			for _, n := range rd.Releases.Nodes {
				if u, ok := pageURL(r.Owner, r.Name, "release", 0, n.TagName); ok {
					note(Activity{Source: repoID(r.Owner, r.Name), Kind: "release", URL: u, At: n.UpdatedAt})
				}
			}
		}
	}
	return sortedActivity(got), newest, errors.Join(errs...)
}
