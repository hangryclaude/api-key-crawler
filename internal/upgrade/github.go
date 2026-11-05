package upgrade

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Asset is one file attached to a release, as the API lists it.
type Asset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
	Size int64  `json:"size"`
	// Digest is "sha256:<hex>", which GitHub computes when the file is uploaded. It is a second
	// witness beside the project's own checksums file.
	Digest string `json:"digest"`
}

// Release is a GitHub release.
type Release struct {
	Tag        string  `json:"tag_name"`
	Draft      bool    `json:"draft"`
	Prerelease bool    `json:"prerelease"`
	Assets     []Asset `json:"assets"`
}

// RateLimitError says GitHub refused a request because the anonymous quota is spent. Wait is how
// long to hold off, worked out from GitHub's own clock and not this Mac's, which has run about two
// hours fast (docs/STEAL.md P0-16): the time the quota resets minus the time GitHub says it is now,
// plus two seconds. A Retry-After header wins.
type RateLimitError struct {
	Wait  time.Duration
	Reset time.Time // GitHub's clock
}

func (e *RateLimitError) Error() string {
	return fmt.Sprintf("GitHub rate limit reached; try again in %s", e.Wait.Round(time.Second))
}

// rateLimit reads a refusal. ok is false when the response is not one.
func rateLimit(resp *http.Response) (*RateLimitError, bool) {
	if resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusTooManyRequests {
		return nil, false
	}
	remaining := resp.Header.Get("X-RateLimit-Remaining")
	retry := resp.Header.Get("Retry-After")
	if remaining != "0" && retry == "" && resp.StatusCode != http.StatusTooManyRequests {
		return nil, false
	}
	e := &RateLimitError{}
	now, err := http.ParseTime(resp.Header.Get("Date"))
	if err != nil {
		now = time.Now() // no Date: the best that is left
	}
	if reset, err := strconv.ParseInt(resp.Header.Get("X-RateLimit-Reset"), 10, 64); err == nil {
		e.Reset = time.Unix(reset, 0)
		e.Wait = max(0, e.Reset.Sub(now)) + 2*time.Second
	}
	if secs, err := strconv.Atoi(retry); err == nil {
		e.Wait = time.Duration(secs) * time.Second
	}
	if e.Wait == 0 {
		e.Wait = time.Minute
	}
	return e, true
}

// get fetches one URL as the anonymous API user would.
func (o *Options) get(ctx context.Context, rawURL string, accept string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", accept)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", o.userAgent())
	resp, err := o.client().Do(req)
	if err != nil {
		return nil, err
	}
	if rl, ok := rateLimit(resp); ok {
		resp.Body.Close()
		return nil, rl
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("upgrade: GET %s: %s", redactURL(rawURL), resp.Status)
	}
	return resp, nil
}

func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "(unparsable)"
	}
	u.RawQuery = ""
	return u.String()
}

// Skip says why a release is not a candidate.
type Skip struct {
	Tag, Why string
}

// Releases lists the releases of a repo, newest first as GitHub orders them, and splits them into
// the stable ones and the ones that are skipped: drafts, anything GitHub marks as a pre-release,
// and any tag with a pre-release part, whether or not GitHub marked it (a project can tag
// 2.0.0-rc.6 as an ordinary release).
func (o *Options) Releases(ctx context.Context, repo string) (stable []Release, skipped []Skip, err error) {
	resp, err := o.get(ctx, o.api()+"/repos/"+repo+"/releases?per_page=30", "application/vnd.github+json")
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	var all []Release
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&all); err != nil {
		return nil, nil, fmt.Errorf("upgrade: releases of %s: %w", repo, err)
	}
	for _, r := range all {
		v, ok := ParseVersion(r.Tag)
		switch {
		case r.Draft:
			skipped = append(skipped, Skip{r.Tag, "draft"})
		case r.Prerelease:
			skipped = append(skipped, Skip{r.Tag, "marked as a pre-release"})
		case !ok:
			skipped = append(skipped, Skip{r.Tag, "not a version"})
		case !v.Stable():
			skipped = append(skipped, Skip{r.Tag, "pre-release tag"})
		default:
			stable = append(stable, r)
		}
	}
	return stable, skipped, nil
}

// LatestStable is the highest stable release of a repo.
func (o *Options) LatestStable(ctx context.Context, repo string) (Release, Version, []Skip, error) {
	stable, skipped, err := o.Releases(ctx, repo)
	if err != nil {
		return Release{}, Version{}, nil, err
	}
	var best Release
	var bestV Version
	found := false
	for _, r := range stable {
		v, _ := ParseVersion(r.Tag)
		if !found || v.Compare(bestV) > 0 {
			best, bestV, found = r, v, true
		}
	}
	if !found {
		return Release{}, Version{}, skipped, fmt.Errorf("upgrade: %s has no stable release (skipped %d)", repo, len(skipped))
	}
	return best, bestV, skipped, nil
}

var errNoAsset = errors.New("no matching asset")

func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Host)
}
