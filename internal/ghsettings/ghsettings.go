// Package ghsettings is layer 3, GitHub's own secret scanning. It audits whether secret
// scanning and push protection are on, switches them on for public repos and reads the repo
// again to see that they are, and imports the open alerts as hits so GitHub's findings land in
// the same database as keyguard's.
//
// What a free plan can do is a fact, not something to find out by trying (STEAL P0-18): public
// repos get secret scanning and push protection, private repos get nothing, and so a private
// repo is classified from the GET alone, through one sample per owner (Survey), is never written
// to, and has no alerts to poll. What GitHub reported is kept in state/ghsettings.json, which is
// how a feature that went from on to off shows up as drift.
//
// Alerts are always asked for with hide_secret=true, so the raw value never reaches this
// process (P0-20). Every stamp and every age is GitHub's clock (P0-16).
//
// Every call runs as the account that owns the repo (core.Source.Account), through ghcli, so
// the active gh account is never touched.
package ghsettings

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"keyguard/internal/core"
	"keyguard/internal/inventory/ghcli"
)

// Feature names one field of a repo's security_and_analysis object.
type Feature string

const (
	SecretScanning      Feature = "secret_scanning"
	PushProtection      Feature = "secret_scanning_push_protection"
	NonProviderPatterns Feature = "secret_scanning_non_provider_patterns"
	ValidityChecks      Feature = "secret_scanning_validity_checks"
)

// Features lists them in the order they can be switched on: the others need the first.
var Features = []Feature{SecretScanning, PushProtection, NonProviderPatterns, ValidityChecks}

// State is a feature's status as GitHub reports it.
type State string

const (
	Enabled    State = "enabled"
	Disabled   State = "disabled"
	Unreported State = "" // GitHub did not say: the token lacks admin rights, or the feature does not exist here
)

// Config wires a Settings.
type Config struct {
	Client  *ghcli.Client      // nil means real gh
	FP      core.Fingerprinter // required: alert secrets are fingerprinted here and dropped
	Workers int                // concurrent reads for Audit and AlertsAll; 0 means 6. Writes are always serial.
	PerPage int                // alerts per request, at most 100; 0 means 100

	// StatePath is the file that keeps what GitHub reported between runs (core.Paths.GHSettings,
	// STEAL P0-17). "" keeps nothing, which also turns off drift detection and the monthly
	// re-probe: both need a yesterday to compare against.
	StatePath string
	// Gap is the pause between two writes to GitHub, whichever repos they go to; 0 means a second
	// (P0-17). GitHub treats a burst of mutating requests as abuse.
	Gap time.Duration
	// Sleep waits for d or until ctx ends and returns ctx's error in that case. Nil sleeps for
	// real. Tests record the pauses instead of waiting them out.
	Sleep func(ctx context.Context, d time.Duration) error
	// Now is this Mac's clock, used only to measure how long ago the last write was. Every stamp
	// and every re-probe date is GitHub's clock, from the Date header (P0-16).
	Now func() time.Time
	// PrivateAlerts lets Alerts ask about private repos. Off, they are answered without a
	// request: a free plan cannot scan a private repo, so GitHub has no alerts for it (P0-18).
	PrivateAlerts bool
	// ReprobeEvery is how long a plan probe is believed; 0 means 30 days (P0-18, "re-probe monthly").
	ReprobeEvery time.Duration
}

// Settings audits and changes repos' secret scanning settings and reads their alerts.
type Settings struct {
	cl            *ghcli.Client
	fp            core.Fingerprinter
	workers       int
	perPage       int
	statePath     string
	gap           time.Duration
	sleep         func(context.Context, time.Duration) error
	now           func() time.Time
	privateAlerts bool
	reprobe       time.Duration

	stMu sync.Mutex // one reader-writer of the state file at a time
}

// New checks cfg and fills defaults.
func New(cfg Config) (*Settings, error) {
	if cfg.FP == nil {
		return nil, errors.New("ghsettings: a fingerprinter is required")
	}
	if cfg.PerPage < 0 || cfg.PerPage > 100 || cfg.Workers < 0 {
		return nil, fmt.Errorf("ghsettings: per-page %d and workers %d are out of range", cfg.PerPage, cfg.Workers)
	}
	if cfg.Gap < 0 || cfg.ReprobeEvery < 0 {
		return nil, fmt.Errorf("ghsettings: gap %v and re-probe interval %v cannot be negative", cfg.Gap, cfg.ReprobeEvery)
	}
	s := &Settings{
		cl: cfg.Client, fp: cfg.FP, workers: cmp.Or(cfg.Workers, 6), perPage: cmp.Or(cfg.PerPage, 100),
		statePath: cfg.StatePath, gap: cmp.Or(cfg.Gap, time.Second), sleep: cfg.Sleep, now: cfg.Now,
		privateAlerts: cfg.PrivateAlerts, reprobe: cmp.Or(cfg.ReprobeEvery, 30*24*time.Hour),
	}
	if s.cl == nil {
		s.cl = ghcli.New(nil)
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.sleep == nil {
		s.sleep = sleepFor
	}
	return s, nil
}

// sleepFor is the real pause: d, cut short by ctx.
func sleepFor(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// githubNow is GitHub's time now, from the Date header of the last response (P0-16). Every
// stamp this package writes and every age it judges uses it, never this Mac's clock.
func (s *Settings) githubNow() time.Time { return s.cl.Clock().Now() }

var (
	// ErrNotRepo is the reason for a source that has no settings or alerts: wikis and gists.
	ErrNotRepo = errors.New("not a repository")
	// ErrDisabled means secret scanning is off, or not available on the plan, for that repo.
	ErrDisabled = errors.New("secret scanning is disabled or unavailable")
)

// repoPath builds "repos/<owner>/<name>" for a repo source. Owner and name come from
// GitHub or a state file and are spliced into a URL path, so they are validated, not escaped.
func repoPath(src core.Source) (string, error) {
	if src.Kind != "repo" {
		return "", fmt.Errorf("ghsettings: %s: %w", src.ID, ErrNotRepo)
	}
	if !ghcli.ValidLogin(src.Owner) || !ghcli.ValidName(src.Name) {
		return "", fmt.Errorf("ghsettings: %s has an unusable owner or name", src.ID)
	}
	return "repos/" + src.Owner + "/" + src.Name, nil
}

// AuditResult is one repo's settings as GitHub reports them.
type AuditResult struct {
	Source   core.Source
	Reported bool // security_and_analysis was in the reply; GitHub omits it without admin rights
	State    map[Feature]State
	Err      error
}

// saReply is the part of a repo object and of a PATCH reply this package reads.
type saReply struct {
	SecurityAndAnalysis map[string]struct {
		Status string `json:"status"`
	} `json:"security_and_analysis"`
}

func (r saReply) states() (map[Feature]State, bool) {
	out := map[Feature]State{}
	if r.SecurityAndAnalysis == nil {
		return out, false
	}
	for _, f := range Features {
		out[f] = State(r.SecurityAndAnalysis[string(f)].Status)
	}
	return out, true
}

// Audit reads the settings of every repo in sources, in parallel, and returns one result per
// source in the same order. A source that cannot be read carries its own Err; nothing else
// is lost to it.
func (s *Settings) Audit(ctx context.Context, sources []core.Source) []AuditResult {
	out := make([]AuditResult, len(sources))
	s.each(len(sources), func(i int) { out[i] = s.audit1(ctx, sources[i]) })
	return out
}

func (s *Settings) audit1(ctx context.Context, src core.Source) AuditResult {
	res := AuditResult{Source: src}
	path, err := repoPath(src)
	if err != nil {
		res.Err = err
		return res
	}
	resp, err := s.cl.Do(ctx, src.Account, ghcli.Request{Path: path})
	if err != nil {
		res.Err = err
		return res
	}
	if err := resp.Err(); err != nil {
		res.Err = fmt.Errorf("ghsettings: %s: %w", src.ID, err)
		return res
	}
	var body saReply
	if err := json.Unmarshal(resp.Body, &body); err != nil {
		res.Err = fmt.Errorf("ghsettings: %s: reply is not a repository object", src.ID)
		return res
	}
	res.State, res.Reported = body.states()
	return res
}

// each runs fn(0..n-1) on a bounded pool.
func (s *Settings) each(n int, fn func(i int)) {
	sem := make(chan struct{}, s.workers)
	var wg sync.WaitGroup
	for i := range n {
		sem <- struct{}{}
		wg.Go(func() {
			defer func() { <-sem }()
			fn(i)
		})
	}
	wg.Wait()
}

// Plain strings for the reasons a field was left alone, so a report can show them.
const (
	reasonEnabled    = "already enabled"
	reasonNeedsScan  = "secret scanning is not enabled, so this cannot be"
	reasonNotPublic  = "not public: a free plan cannot scan a private repo and enabling it elsewhere can cost money; Probe reads the repo to tell"
	reasonUnreported = "GitHub did not report the repo's settings (the token lacks admin rights there), so nothing was changed"
)

// quoteForLog keeps GitHub's refusal text on one line.
func quoteForLog(s string) string { return strings.Join(strings.Fields(s), " ") }
