package inventory

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"keyguard/internal/core"
	"keyguard/internal/inventory/ghcli"
)

// eventState is what survives between polls for one account: the ETag of the newest page
// and the highest event ID already handed out, and what is known about whether the feed can be
// trusted at all (STEAL P0-21). Every field is comparable, so a state is compared with ==.
type eventState struct {
	ETag   string `json:"etag"`
	LastID int64  `json:"last_id"`
	// Count is how many events the newest page held the last time it was read with a 200, and
	// Checked is when, on GitHub's clock; "" means never. A 304 keeps both: the feed has not
	// changed, so it is still as full, or as empty, as it was.
	Count   int    `json:"count,omitempty"`
	Checked string `json:"checked,omitempty"`
	// Usable says whether the feed can be believed. It is false when the feed is empty although
	// a repo of this account was pushed within a week: alt-builds' feed is empty while its repos
	// are pushed, and an empty feed is not a quiet account.
	Usable tri `json:"events_usable,omitempty"`
	// Pushed is the newest push seen to a repo of this account, and Seen the newest GitHub
	// timestamp of any kind seen for it. Both are GitHub's clock. The cursor is Seen minus ten
	// minutes (STEAL P0-16).
	Pushed string `json:"pushed,omitempty"`
	Seen   string `json:"seen,omitempty"`
	// Listed is GitHub's clock at the start of the last activity listing that came back whole.
	// The next one starts ten minutes before it. It is kept apart from Seen on purpose: a push or
	// an event seen during an outage says nothing about what the listing has covered, and
	// resuming from it would skip an issue updated while nothing was listing.
	Listed string `json:"listed,omitempty"`
	// PollInterval is the shortest time, in seconds, GitHub asked between two polls of this feed
	// (X-Poll-Interval). A 304 does not carry the header, so the last 200's value is kept.
	PollInterval int `json:"poll_interval,omitempty"`
}

// The events API keeps 90 days and at most 300 events, served 100 to a page.
const (
	eventsPerPage   = 100
	maxEventPages   = 3
	defaultEventAge = 24 * time.Hour
)

// ghEvent is the part of an events API item keyguard reads. Payloads carry issue and
// comment text, which is exactly what may hold a leaked key, so nothing past these fields
// is decoded or kept.
type ghEvent struct {
	ID   string `json:"id"`
	Type string `json:"type"`
	Repo struct {
		Name string `json:"name"` // "owner/name"
	} `json:"repo"`
	CreatedAt string `json:"created_at"`
	Payload   struct {
		Gist *struct {
			ID string `json:"id"`
		} `json:"gist"`
		// Only numbers and a tag are read from the rest: enough to name the page to scan, and
		// none of the text a person wrote there.
		Issue *struct {
			Number int `json:"number"`
		} `json:"issue"`
		PullRequest *struct {
			Number int `json:"number"`
		} `json:"pull_request"`
		Release *struct {
			TagName string `json:"tag_name"`
		} `json:"release"`
	} `json:"payload"`
}

func (e ghEvent) id() int64 {
	n, _ := strconv.ParseInt(e.ID, 10, 64)
	return n
}

// Event types worth acting on, by who may have produced them. Issues, PRs, comments,
// releases and discussions hold text the user wrote, and a key pasted into a stranger's
// tracker is as exposed there as in their own repo, so they count anywhere. The others
// describe the user's own repositories and only count there.
var (
	anywhere = map[string]bool{
		"IssuesEvent": true, "IssueCommentEvent": true, "PullRequestEvent": true,
		"PullRequestReviewEvent": true, "PullRequestReviewCommentEvent": true,
		"CommitCommentEvent": true, "ReleaseEvent": true,
		"DiscussionEvent": true, "DiscussionCommentEvent": true,
	}
	ownOnly = map[string]bool{
		"PublicEvent": true, "CreateEvent": true, "GistEvent": true,
		// A wiki push does not move the repo's pushedAt; this is the only signal it happened.
		"GollumEvent": true,
	}
)

// owners is the set of logins whose repos count as the user's own.
func (inv *Inventory) owners() map[string]bool {
	m := map[string]bool{}
	for _, a := range inv.cfg.Accounts {
		m[strings.ToLower(a)] = true
	}
	for _, o := range inv.cfg.Orgs {
		m[strings.ToLower(o.Login)] = true
	}
	return m
}

// toEvent maps one API item to a core.Event, or reports that it does not matter.
func toEvent(e ghEvent, acct string, owners map[string]bool) (core.Event, bool) {
	if !anywhere[e.Type] && !ownOnly[e.Type] {
		return core.Event{}, false
	}
	var src string
	switch e.Type {
	case "GistEvent":
		if e.Payload.Gist == nil || e.Payload.Gist.ID == "" {
			return core.Event{}, false
		}
		src = "gist.github.com/" + acct + "/" + e.Payload.Gist.ID
	default:
		owner, name, ok := strings.Cut(e.Repo.Name, "/")
		if !ok || owner == "" || name == "" {
			return core.Event{}, false
		}
		if ownOnly[e.Type] && !owners[strings.ToLower(owner)] {
			return core.Event{}, false
		}
		src = repoID(owner, name)
		if e.Type == "GollumEvent" {
			src += ".wiki"
		}
	}
	return core.Event{Source: src, Type: e.Type, At: e.CreatedAt}, true
}

// pollEvents reads acct's recent activity. With a stored ETag an unchanged feed answers 304
// and costs no rate limit. Without stored state only events younger than the event window
// are returned: the first full scan covers everything older. Beside the events it returns the
// exact pages they name (an issue, a pull request, a release), for a scanner that takes a URL.
func (inv *Inventory) pollEvents(ctx context.Context, acct string, st eventState) ([]core.Event, []Activity, eventState, bool, error) {
	ns := st
	window := cmp.Or(inv.cfg.EventWindow, defaultEventAge)
	var (
		fresh     []ghEvent
		maxID     = st.LastID
		cutoff    time.Time
		exhausted bool
	)
	for page := 1; ; page++ {
		rq := ghcli.Request{Path: fmt.Sprintf("users/%s/events?per_page=%d&page=%d", acct, eventsPerPage, page)}
		if page == 1 && st.ETag != "" {
			rq.Header = map[string]string{"If-None-Match": st.ETag}
		}
		resp, err := inv.get(ctx, acct, rq)
		if err != nil {
			return nil, nil, st, false, err
		}
		if sec, err := strconv.Atoi(resp.Header.Get("X-Poll-Interval")); err == nil && sec > 0 {
			st.PollInterval, ns.PollInterval = sec, sec
		}
		if resp.Status == http.StatusNotModified {
			return nil, nil, st, true, nil
		}
		if err := resp.Err(); err != nil {
			return nil, nil, st, false, fmt.Errorf("inventory: events of %s: %w", acct, err)
		}
		var items []ghEvent
		err = json.Unmarshal(resp.Body, &items)
		etag := resp.Header.Get("ETag")
		if page == 1 {
			// GitHub's own clock, from this very response: events are stamped with it, and this
			// Mac's clock can be minutes or hours off. The response's own Date beats the shared
			// clock, which another request may have moved a moment ago.
			now, ok := resp.Date()
			if !ok {
				now = inv.now()
			}
			cutoff = now.Add(-window)
			if err == nil {
				ns.ETag, ns.Count, ns.Checked = etag, len(items), stamp(now)
			}
		}
		resp.Wipe()
		if err != nil {
			return nil, nil, st, false, fmt.Errorf("inventory: events of %s are not JSON: %w", acct, err)
		}
		sawOld := false
		for _, e := range items {
			maxID = max(maxID, e.id())
			ns.Seen = newerStamp(ns.Seen, e.CreatedAt)
			if e.id() <= st.LastID || st.LastID == 0 && olderThan(e.CreatedAt, cutoff) {
				sawOld = true
				continue
			}
			fresh = append(fresh, e)
		}
		if sawOld || len(items) < eventsPerPage {
			break
		}
		if page == maxEventPages {
			exhausted = true
			break
		}
	}
	ns.LastID = maxID
	evs, acts := eventsOf(fresh, acct, inv.owners()), activitiesOf(fresh)
	if exhausted {
		// Every reachable page was still new, so older new events are beyond the API's
		// reach. Say so rather than pretend the feed was complete.
		return evs, acts, ns, true, fmt.Errorf("inventory: %s made %d+ events since the last poll; older ones are beyond the events API window", acct, maxEventPages*eventsPerPage)
	}
	return evs, acts, ns, true, nil
}

// stamp writes a time the way every file here does.
func stamp(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// newerStamp is the later of two stamps; an unreadable or empty one loses.
func newerStamp(a, b string) string {
	if newer(b, a) {
		return b
	}
	return a
}

func olderThan(rfc3339 string, cutoff time.Time) bool {
	t, err := time.Parse(time.RFC3339, rfc3339)
	return err == nil && t.Before(cutoff)
}

// eventsOf maps and orders items oldest first, the order a consumer would replay them in.
func eventsOf(items []ghEvent, acct string, owners map[string]bool) []core.Event {
	slices.SortFunc(items, func(a, b ghEvent) int { return cmp.Compare(a.id(), b.id()) })
	var out []core.Event
	for _, e := range items {
		if ev, ok := toEvent(e, acct, owners); ok {
			out = append(out, ev)
		}
	}
	return out
}
