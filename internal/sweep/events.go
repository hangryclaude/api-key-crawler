package sweep

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"keyguard/internal/core"
)

// A page that fails is tried again at every poll, up to maxAPITries times in all: about an
// hour and a half of polls rides out a GitHub outage, and a page that never works (a deleted
// issue, a URL the scanner will not take) does not stay on the list for ever. maxPendingAPI
// bounds the list of one source. What falls off either end is named in a note and left to the
// weekly deep run.
const (
	maxAPITries   = 8
	maxPendingAPI = 500
)

// apiEvents are the events that mean text was written (and so may hold a key) in a resource
// the API scanner can open by its page. A comment on an issue or a pull request is a change to
// that issue or pull request's page, so every one of these resolves to a resource URL.
var apiEvents = map[string]bool{
	"IssuesEvent":                   true,
	"IssueCommentEvent":             true,
	"PullRequestEvent":              true,
	"PullRequestReviewEvent":        true,
	"PullRequestReviewCommentEvent": true,
	"ReleaseEvent":                  true,
	"WorkflowRunEvent":              true, // not in GitHub's events feed; the inventory makes one when it sees a run
}

// gitEvents are events that mean git content changed somewhere pushedAt may not show it. A
// wiki push is the clear case: it never moves its repo's pushedAt, so the event is the only
// sign. Events are delivered once, so ignoring one here would lose the push.
var gitEvents = map[string]bool{"PublicEvent": true, "CreateEvent": true, "GistEvent": true, "GollumEvent": true}

// resourcePath is the part of a URL that names one scannable resource of a repo; segment is
// one owner or repo name as GitHub allows it.
var (
	resourcePath = regexp.MustCompile(`^/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/(issues/[0-9]+|pull/[0-9]+|releases/tag/[^\s?#]+|actions/runs/[0-9]+)$`)
	segment      = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
)

// resourceURL is the canonical page of the resource raw names, provided it is one of the four
// kinds a scanner opens, on github.com over https, and in the repo the event is about. The
// scanner is handed a token for whatever URL it is given, so a URL that came from outside is
// held to the one host the token belongs to and the one repo the event named; a comment
// anchor or query string is dropped, since the page is the resource.
func resourceURL(src core.Source, raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host != "github.com" || u.User != nil {
		return "", false
	}
	path := strings.TrimSuffix(u.EscapedPath(), "/")
	m := resourcePath.FindStringSubmatch(path)
	if m == nil || !strings.EqualFold(m[1], src.Owner) || !strings.EqualFold(m[2], src.Name) || src.Kind != "repo" {
		return "", false
	}
	return "https://github.com" + path, true
}

// safeURL is a resource URL fit for a note. Its shape is checked, but a release tag is text
// anyone can write, so it goes through the same mask as an alert: names and paths stay
// readable, anything shaped like a key does not.
func safeURL(u string) string { return maskLines(u) }

// eventWork is what a poll's events add to its work.
type eventWork struct {
	git         []core.Source       // sources whose git content an event says changed
	api         map[string][]string // source id -> exact resource URLs to scan, sorted, no repeats
	sources     map[string]core.Source
	unknownGit  int            // git events for sources not in the inventory
	unlinked    int            // API events that named no usable resource URL
	unscannable map[string]int // event type -> count, for events no scanner here understands
}

// foldEvents sorts events into git work, API work and what cannot be scanned. known is every
// source keyguard already knows. urlOf says which page an event is about; without it no API
// event can be scanned, and they are counted instead.
func foldEvents(events []core.Event, activity []Activity, known map[string]core.Source, queued []core.Source, urlOf func(core.Event) string, covered bool) eventWork {
	w := eventWork{api: map[string][]string{}, sources: map[string]core.Source{}, unscannable: map[string]int{}}
	inQueue := map[string]bool{}
	for _, s := range queued {
		inQueue[s.ID] = true
	}
	for _, e := range events {
		switch {
		case gitEvents[e.Type]:
			src, ok := known[e.Source]
			switch {
			case inQueue[e.Source]:
			case !ok:
				w.unknownGit++
			default:
				inQueue[src.ID] = true
				w.git = append(w.git, src)
			}
		case apiEvents[e.Type] && covered:
			// The inventory names these pages itself, in activity, from this very event or from
			// GraphQL where the feed is empty. Reading the event again could only repeat it.
		case apiEvents[e.Type]:
			src, ok := known[e.Source]
			if !ok {
				src = sourceFromID(e.Source)
			}
			raw := ""
			if urlOf != nil {
				raw = urlOf(e)
			}
			u, good := resourceURL(src, raw)
			if !good {
				w.unlinked++
				continue
			}
			if !ok {
				w.sources[src.ID] = src
			}
			w.api[src.ID] = addURL(w.api[src.ID], u)
		default:
			w.unscannable[e.Type]++
		}
	}
	for _, a := range activity {
		src, ok := known[a.Source]
		if !ok {
			src = sourceFromID(a.Source)
		}
		u, good := resourceURL(src, a.URL)
		if !good {
			w.unlinked++ // a page the inventory named that is not one this repo owns: dropped, and counted
			continue
		}
		if !ok {
			w.sources[src.ID] = src
		}
		w.api[src.ID] = addURL(w.api[src.ID], u)
	}
	return w
}

func addURL(urls []string, u string) []string {
	if slices.Contains(urls, u) {
		return urls
	}
	urls = append(urls, u)
	slices.Sort(urls)
	return urls
}

// sourceFromID builds a Source for something an event names but the inventory does not
// hold: an issue the user commented on in a stranger's repo. Its visibility is unknown, which
// counts as exposed, because the cautious reading is the one that gets a key rotated.
func sourceFromID(id string) core.Source {
	s := core.Source{ID: id, Kind: "repo", Visibility: core.Unknown}
	if parts := strings.Split(id, "/"); len(parts) == 3 {
		s.Owner, s.Name = parts[1], parts[2]
		switch {
		case strings.HasPrefix(parts[0], "gist."):
			s.Kind = "gist"
		case strings.HasSuffix(parts[2], ".wiki"):
			s.Kind = "wiki"
		}
	}
	return s
}

func (w eventWork) notes(hasScanner bool) []string {
	var out []string
	if w.unknownGit > 0 {
		out = append(out, fmt.Sprintf("%d event(s) mention a wiki, gist or repo that is not in the inventory; they were not scanned", w.unknownGit))
	}
	if !hasScanner && len(w.api) > 0 {
		out = append(out, fmt.Sprintf("issues, pull requests, comments or releases changed on %d source(s) but no API scanner is configured; they were not scanned", len(w.api)))
	}
	if w.unlinked > 0 {
		out = append(out, fmt.Sprintf("%d issue, pull request or release event(s) named no scannable resource URL on github.com of the repo they are about (Config.EventURL is unset, or the event carries none, or the inventory named a page that is not this repo's); they were not scanned", w.unlinked))
	}
	if len(w.unscannable) > 0 {
		types := make([]string, 0, len(w.unscannable))
		for t, n := range w.unscannable {
			types = append(types, fmt.Sprintf("%s x%d", t, n))
		}
		sort.Strings(types)
		out = append(out, "events of kinds no scanner here reads were skipped: "+strings.Join(types, ", "))
	}
	return out
}

// pendingAPI gathers the URLs earlier runs failed to scan. Events are delivered once, so a
// resource whose scan failed would otherwise be lost: the retry list is the cursor that the
// removed `since` used to be, and unlike a time it cannot skip anything.
func (rn *run) pendingAPI(known map[string]core.Source) map[string][]string {
	out := map[string][]string{}
	for _, id := range sortedKeys(known) {
		if rn.r.cfg.ExposedOnly && !known[id].Visibility.Exposed() {
			continue
		}
		if st, _ := loadState(rn.r.cfg.Paths.Sources, id); st != nil {
			for _, p := range st.APIPending {
				out[id] = append(out[id], p.URL)
			}
		}
	}
	return out
}

func sortedKeys(m map[string]core.Source) []string {
	ids := make([]string, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// mergeAPI folds the retry list into the new events' URLs.
func mergeAPI(into map[string][]string, more map[string][]string) {
	for id, urls := range more {
		for _, u := range urls {
			into[id] = addURL(into[id], u)
		}
	}
}

// tokenCache remembers one token (or one failure) per gh login for the length of a run.
type tokenCache struct {
	mu sync.Mutex
	by map[string]tokenEntry
}

type tokenEntry struct {
	tok string
	err error
}

// token returns the GitHub token for an account, asking Config.Token once per run. The token is
// handed to the scanner's environment and is never put in a note, an error or a file.
func (rn *run) token(ctx context.Context, account string) (string, error) {
	cfg := rn.r.cfg
	if cfg.Token == nil {
		return "", errors.New("no token source is configured (Config.Token)")
	}
	rn.apiToken.mu.Lock()
	defer rn.apiToken.mu.Unlock()
	if e, ok := rn.apiToken.by[account]; ok {
		return e.tok, e.err
	}
	tok, err := cfg.Token(ctx, account)
	if err == nil && tok == "" {
		err = errors.New("the token source returned an empty token")
	}
	if rn.apiToken.by == nil {
		rn.apiToken.by = map[string]tokenEntry{}
	}
	rn.apiToken.by[account] = tokenEntry{tok, err}
	return tok, err
}

// apiAll scans the given resources with a small worker pool: one job per source, since a
// source's retry list is one file. work maps a source id to the exact URLs to read; with full
// each URL is a repo's page and the scanner reads everything in it, release files included.
func (rn *run) apiAll(ctx context.Context, work map[string][]string, sources map[string]core.Source, full bool) {
	cfg := rn.r.cfg
	scanner := rn.r.apiScanner()
	if scanner == nil || len(work) == 0 {
		return
	}
	if cfg.Token == nil {
		rn.note(fmt.Sprintf("GitHub resources changed on %d source(s) but Config.Token is not set, so there is no token to read them with; they were not scanned", len(work)))
		return
	}
	ids := make([]string, 0, len(work))
	for id := range work {
		if cfg.ExposedOnly && !sources[id].Visibility.Exposed() {
			continue
		}
		ids = append(ids, id)
	}
	sort.Strings(ids)
	jobs := make(chan string)
	var wg sync.WaitGroup
	for range min(cfg.APIJobs, len(ids)) {
		wg.Go(func() {
			for id := range jobs {
				if ctx.Err() == nil {
					rn.apiScan(ctx, scanner, sources[id], work[id], full)
				}
			}
		})
	}
	for _, id := range ids {
		jobs <- id
	}
	close(jobs)
	wg.Wait()
}

// apiScan reads one source's resources, one scanner call per exact URL. A URL that fails goes
// on the source's retry list; one that succeeds comes off it.
func (rn *run) apiScan(ctx context.Context, scanner core.APIScanner, src core.Source, urls []string, full bool) {
	defer func() {
		if p := recover(); p != nil {
			rn.note(fmt.Sprintf("%s: internal error in the API scan: %s", src.ID, safeText(fmt.Sprint(p))))
		}
	}()
	cfg := rn.r.cfg
	ctx, cancel := context.WithTimeout(ctx, cfg.SourceTimeout)
	defer cancel()

	var st *sourceState
	if rn.live {
		var note string
		if st, note = loadState(cfg.Paths.Sources, src.ID); note != "" {
			rn.note(note)
		}
	}
	tok, terr := rn.token(ctx, src.Account)
	if terr != nil {
		rn.note(fmt.Sprintf("%s: %d API resource(s) not scanned, no GitHub token for %q: %s", src.ID, len(urls), src.Account, safeErr(terr)))
		rn.keepPending(src, st, nil, urls, false)
		return
	}
	opts := core.ScanOpts{
		Verify: !cfg.NoVerify, Threads: rn.r.threads, Rules: cfg.Rules,
		// The token travels in the environment, never in argv, where ps and the scanner's own
		// logs would show it.
		Env:           []string{"GITHUB_TOKEN=" + tok},
		ReleaseAssets: full,
		Loc:           core.Location{Source: src.ID, Visibility: src.Visibility},
	}
	var done, failed []string
	buf := &hitBuffer{rn: rn, src: src}
	t0 := time.Now()
	for _, u := range urls {
		if ctx.Err() != nil {
			failed = append(failed, u)
			continue
		}
		err := scanner.ScanAPI(ctx, u, opts, buf.add)
		buf.flush()
		switch {
		case err == nil:
			done = append(done, u)
		case errors.Is(err, core.ErrUnsupported):
			rn.note(src.ID + ": the API scanner cannot open " + safeURL(u) + "; it was not scanned")
		default:
			failed = append(failed, u)
			if !errors.Is(err, context.Canceled) {
				rn.note(fmt.Sprintf("%s: API scan of %s failed: %s", src.ID, safeURL(u), safeErr(err)))
			}
		}
	}
	rn.engineStat("api", time.Since(t0), buf.n, len(failed) > 0)
	rn.mu.Lock()
	rn.stats.APIResources += len(done)
	rn.mu.Unlock()
	if err := rn.save(); err != nil {
		rn.note(src.ID + ": cannot save findings: " + safeErr(err))
		rn.keepPending(src, st, nil, urls, false) // the hits did not reach disk: read them again
		return
	}
	rn.keepPending(src, st, done, failed, true)
}

// keepPending records the outcome of an API scan in the source's state: the URLs that were
// read leave the retry list, the ones that failed join it (counted as a try when the scanner
// was the one that failed, count), and LastAPI notes when, on GitHub's clock, the source was last
// read. Nothing reads LastAPI as a cursor (P0-22: a time cannot say which comment on an old
// issue is new); it is for the person reading the file.
func (rn *run) keepPending(src core.Source, st *sourceState, done, failed []string, count bool) {
	if !rn.live {
		return
	}
	if st == nil {
		st = newState(src.ID) // no git scan yet: no engine progress, so the first git scan is a full one
	}
	next := st.clone()
	pending := slices.DeleteFunc(slices.Clone(next.APIPending), func(p apiTry) bool { return slices.Contains(done, p.URL) })
	for _, u := range failed {
		i := slices.IndexFunc(pending, func(p apiTry) bool { return p.URL == u })
		if i < 0 {
			pending = append(pending, apiTry{URL: u})
			i = len(pending) - 1
		}
		if count {
			pending[i].Tries++
		}
	}
	var gaveUp int
	pending = slices.DeleteFunc(pending, func(p apiTry) bool {
		if p.Tries >= maxAPITries {
			gaveUp++
			return true
		}
		return false
	})
	if gaveUp > 0 {
		rn.note(fmt.Sprintf("%s: %d API resource(s) failed %d times in a row and were given up on; the weekly deep run reads them again", src.ID, gaveUp, maxAPITries))
	}
	slices.SortFunc(pending, func(a, b apiTry) int { return strings.Compare(a.URL, b.URL) })
	if len(pending) > maxPendingAPI {
		rn.note(fmt.Sprintf("%s: %d API resource(s) are waiting to be retried; only %d are kept, and the weekly deep run reads the rest", src.ID, len(pending), maxPendingAPI))
		pending = pending[:maxPendingAPI]
	}
	next.APIPending = pending
	if len(done) > 0 {
		next.LastAPI = stamp(rn.r.now())
	}
	if err := saveState(rn.r.cfg.Paths.Sources, next); err != nil {
		rn.note(src.ID + ": cannot save state: " + safeErr(err))
	}
}
