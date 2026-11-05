package ghsettings

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"strings"
	"time"

	"keyguard/internal/core"
	"keyguard/internal/inventory/ghcli"
)

// FieldResult is what happened to one feature of one repo.
type FieldResult struct {
	Feature Feature
	Before  State
	// After is what GitHub says when the repo is read again once the writes are done (STEAL
	// P0-17: never trust the 200). When nothing was sent it is Before. It is empty when the repo
	// could not be read again, and then the field is not Done: an unconfirmed write is not a
	// switched-on feature.
	After State
	// Reply is what the PATCH reply claimed. It is kept apart from After so that a 200 that did
	// not stick shows as the disagreement it is.
	Reply   State
	Sent    bool   // a PATCH went out
	Status  int    // its HTTP status
	Message string // GitHub's own words when it refused (the 422 text), or why nothing was sent
}

// Done reports whether the feature ended up on, as the re-read says.
func (f FieldResult) Done() bool { return f.After == Enabled || (!f.Sent && f.Before == Enabled) }

// ApplyResult is the outcome for one repo.
type ApplyResult struct {
	Source core.Source
	Fields []FieldResult
	Err    error // the repo could not be read or written at all
	// StateErr is set when the state file could not be written. The result itself stands; what
	// is lost is the memory of it that drift detection would have used next time.
	StateErr error
}

// required are the features Apply switches on, in the order they can be: push protection needs
// secret scanning. The other two are asked once on one public repo (ProbePlan, P0-18).
var required = []Feature{SecretScanning, PushProtection}

// Apply switches secret scanning and push protection on for every public repo in sources
// (STEAL P0-17). Per repo it reads the settings, sends one PATCH for each of the two that are
// off, and reads the repo again to compare: the reply to a PATCH is a claim, and what counts is
// what GitHub reports afterwards. Each feature is its own PATCH so a refusal of one never costs
// the other and every field carries GitHub's own text. A feature already on is not touched; push
// protection is not tried while secret scanning is off.
//
// Writes are serial, with Config.Gap (a second) between any two of them, across repos too:
// GitHub treats a burst of mutating requests as abuse. A rate limit ends the call; the repos not
// reached carry it as their Err, and ghcli's RateLimitError.Wait says how long to stay quiet on
// GitHub's clock.
//
// Private repos are skipped: a free plan cannot scan them and enabling it elsewhere can cost
// money (P0-18). What GitHub reported is written to the state file once the call is done.
func (s *Settings) Apply(ctx context.Context, sources []core.Source) []ApplyResult {
	out := make([]ApplyResult, len(sources))
	audits := make([]*AuditResult, len(sources))
	w := &pacer{s: s}
	var stopped error
	for i, src := range sources {
		if stopped != nil {
			out[i] = ApplyResult{Source: src, Err: stopped}
			continue
		}
		out[i], audits[i] = s.apply1(ctx, src, w)
		var rl *ghcli.RateLimitError
		if errors.As(out[i].Err, &rl) {
			stopped = out[i].Err
		}
	}
	s.remember(out, audits)
	return out
}

// remember writes what GitHub reported to the state file, once for the whole call, and puts a
// failure to do so on the results it concerns.
func (s *Settings) remember(out []ApplyResult, audits []*AuditResult) {
	var seen []int
	for i, a := range audits {
		if a != nil {
			seen = append(seen, i)
		}
	}
	if len(seen) == 0 {
		return
	}
	at := s.githubStamp()
	err := s.update(func(st *Saved) {
		for _, i := range seen {
			st.Repos[audits[i].Source.ID] = s.repoState(*audits[i], at)
		}
	})
	for _, i := range seen {
		out[i].StateErr = err
	}
}

// apply1 handles one repo and returns the last read of it, for the state file.
func (s *Settings) apply1(ctx context.Context, src core.Source, w *pacer) (ApplyResult, *AuditResult) {
	res := ApplyResult{Source: src}
	if err := ctx.Err(); err != nil {
		res.Err = err
		return res, nil
	}
	path, err := repoPath(src)
	if err != nil {
		res.Err = err
		return res, nil
	}
	if src.Visibility != core.Public {
		res.Err = fmt.Errorf("ghsettings: %s is %s: %s", src.ID, src.Visibility, reasonNotPublic)
		return res, nil
	}
	read := s.audit1(ctx, src)
	if read.Err != nil {
		res.Err = read.Err
		return res, nil
	}
	if !read.Reported {
		// Without admin rights GitHub leaves security_and_analysis out, and a PATCH would be
		// refused for the same reason: not worth a write.
		for _, f := range required {
			res.Fields = append(res.Fields, FieldResult{Feature: f, Message: reasonUnreported})
		}
		return res, &read
	}

	scanning := read.State[SecretScanning] == Enabled
	wrote := false
fields:
	for i, f := range required {
		fr := FieldResult{Feature: f, Before: read.State[f], After: read.State[f]}
		var stop error
		switch {
		case fr.Before == Enabled:
			fr.Message = reasonEnabled
		case f != SecretScanning && !scanning:
			fr.Message = reasonNeedsScan
		default:
			stop = s.enable(ctx, src, path, &fr, w)
			wrote = wrote || fr.Sent
			if f == SecretScanning {
				scanning = fr.Reply == Enabled
			}
		}
		if stop != nil {
			// The call ends here, and the features not reached say so instead of vanishing.
			res.Err = stop
			fr.After = Unreported
			res.Fields = append(res.Fields, fr)
			for _, rest := range required[i+1:] {
				res.Fields = append(res.Fields, FieldResult{Feature: rest, Before: read.State[rest], After: read.State[rest], Message: "not tried: " + stop.Error()})
			}
			break fields
		}
		res.Fields = append(res.Fields, fr)
	}
	if !wrote {
		return res, &read
	}

	// Read the repo again and judge each write by it, not by the reply that came with it.
	again := s.audit1(ctx, src)
	for i := range res.Fields {
		fr := &res.Fields[i]
		if !fr.Sent {
			continue
		}
		if again.Err != nil || !again.Reported {
			fr.After = Unreported
			fr.Message = joinNotes(fr.Message, "the repo could not be read again, so the write is unconfirmed")
			continue
		}
		fr.After = again.State[fr.Feature]
		if fr.After != Enabled && fr.Status >= 200 && fr.Status < 300 {
			fr.Message = joinNotes(fr.Message, fmt.Sprintf("GitHub answered %d but the repo reads %q afterwards: the setting did not stick", fr.Status, fr.After))
		}
	}
	if again.Err == nil && again.Reported {
		return res, &again
	}
	return res, &read
}

// joinNotes joins two notes about one field, the first being GitHub's own.
func joinNotes(first, second string) string {
	if first == "" {
		return second
	}
	return first + "; " + second
}

// pacer keeps GitHub from seeing two writes closer together than Config.Gap.
type pacer struct {
	s     *Settings
	last  time.Time
	wrote bool
}

// before waits out what is left of the gap since the last write. The first write waits for
// nothing, and nothing waits after the last.
func (p *pacer) before(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !p.wrote {
		return nil
	}
	if d := p.s.gap - p.s.now().Sub(p.last); d > 0 {
		return p.s.sleep(ctx, d)
	}
	return nil
}

// after marks a write as made, whatever came of it: a request that failed in transit may still
// have reached GitHub.
func (p *pacer) after() { p.wrote, p.last = true, p.s.now() }

// enable sends one PATCH and records the outcome in fr. It returns an error only when the call
// must end: the context is done, or GitHub says to stop.
func (s *Settings) enable(ctx context.Context, src core.Source, path string, fr *FieldResult, w *pacer) error {
	body, err := json.Marshal(map[string]any{"security_and_analysis": map[string]any{string(fr.Feature): map[string]string{"status": "enabled"}}})
	if err != nil {
		fr.Message = err.Error()
		return nil
	}
	if err := w.before(ctx); err != nil {
		fr.Message = "not tried: " + err.Error()
		return err
	}
	resp, err := s.cl.Do(ctx, src.Account, ghcli.Request{Method: http.MethodPatch, Path: path, Body: body})
	w.after()
	if err != nil {
		fr.Message = quoteForLog(err.Error())
		return ctx.Err()
	}
	fr.Sent, fr.Status = true, resp.Status
	if !resp.OK() {
		var rl *ghcli.RateLimitError
		if errors.As(resp.Err(), &rl) {
			wait := rl.Wait(s.githubNow()).Round(time.Second)
			fr.Message = fmt.Sprintf("rate limited; GitHub's clock says wait %s", wait)
			return rl
		}
		fr.Message = quoteForLog(resp.Message())
		return nil
	}
	var reply saReply
	if json.Unmarshal(resp.Body, &reply) == nil {
		fr.Reply = State(reply.SecurityAndAnalysis[string(fr.Feature)].Status)
	}
	if fr.Reply != Enabled {
		fr.Message = "GitHub accepted the request but did not report the feature as enabled"
	}
	return nil
}

// ProbeResult says whether secret scanning can be enabled on private repos on this plan.
type ProbeResult struct {
	Source    core.Source
	Available bool
	Status    int
	Message   string // why it is not, in words
	Err       error
}

// Probe reads one private repo and says whether the plan has secret scanning for it. It writes
// nothing: the answer is already in the GET, which for a private repo on a free plan reads
// `security_and_analysis: null` (STEAL P0-18), and a write to learn it could switch on a paid
// feature. Public repos belong to Apply and are refused here.
func (s *Settings) Probe(ctx context.Context, src core.Source) ProbeResult {
	res := ProbeResult{Source: src}
	path, err := repoPath(src)
	if err != nil {
		res.Err = err
		return res
	}
	if src.Visibility == core.Public {
		res.Err = errors.New("ghsettings: Probe is for private repos; Apply handles public ones")
		return res
	}
	resp, err := s.cl.Do(ctx, src.Account, ghcli.Request{Path: path})
	if err != nil {
		res.Err = fmt.Errorf("ghsettings: probe of %s did not reach GitHub: %s", src.ID, quoteForLog(err.Error()))
		return res
	}
	res.Status = resp.Status
	if !resp.OK() {
		res.Message = quoteForLog(resp.Message())
		return res
	}
	var body saReply
	if json.Unmarshal(resp.Body, &body) != nil {
		res.Err = fmt.Errorf("ghsettings: probe of %s: the reply is not a repository object", src.ID)
		return res
	}
	if states, reported := body.states(); reported && states[SecretScanning] != Unreported {
		res.Available = true
		return res
	}
	res.Message = "secret scanning is not available for private repositories on this plan: GitHub reports no security_and_analysis for " + src.ID
	return res
}

// ProbePlan asks, once, on one public repo of an owner, whether the two optional features can be
// switched on (STEAL P0-18): non-provider patterns and validity checks. It sends one PATCH for
// each and remembers the answer in the state file, for that owner, for a month, so a later call
// within that time sends nothing unless force is set. A 422 or 403 says the plan lacks the
// feature; anything else is inconclusive and recorded as nothing. A feature that is available
// stays on for the repo it was asked of, which is what the caller wants anyway.
//
// The returned map is everything known about the owner's optional features, not only what this
// call asked.
func (s *Settings) ProbePlan(ctx context.Context, src core.Source, force bool) (map[Feature]PlanState, error) {
	path, err := repoPath(src)
	if err != nil {
		return nil, err
	}
	if src.Visibility != core.Public {
		return nil, fmt.Errorf("ghsettings: ProbePlan asks a public repo; %s is %s", src.ID, src.Visibility)
	}
	// How old a probe is must be judged on GitHub's clock, so GitHub has to have spoken first.
	if err := s.prime(ctx, src.Account); err != nil {
		return nil, err
	}
	owner := strings.ToLower(src.Owner)
	st, loadErr := s.Saved()
	errs := []error{loadErr}
	got := map[Feature]PlanState{}
	w := &pacer{s: s}
probing:
	for _, f := range Features {
		if PlanSupport(src.Visibility, f) != Probe {
			continue
		}
		if p, known := st.Plan[owner][string(f)]; known && !force && !s.planStale(p, s.githubNow()) {
			continue
		}
		fr := FieldResult{Feature: f}
		if stop := s.enable(ctx, src, path, &fr, w); stop != nil {
			errs = append(errs, stop)
			break probing
		}
		at := stamp(s.githubNow()) // after the answer, so it is the time GitHub gave it
		switch {
		case !fr.Sent:
			errs = append(errs, fmt.Errorf("ghsettings: probing %s on %s did not reach GitHub: %s", f, src.ID, fr.Message))
		case fr.Status >= 200 && fr.Status < 300:
			got[f] = PlanState{Probed: at}
		case fr.Status == http.StatusUnprocessableEntity || fr.Status == http.StatusForbidden:
			got[f] = PlanState{Unavailable: true, Probed: at, Message: fr.Message}
		default:
			errs = append(errs, fmt.Errorf("ghsettings: probing %s on %s was inconclusive (HTTP %d: %s)", f, src.ID, fr.Status, fr.Message))
		}
	}
	if len(got) > 0 {
		errs = append(errs, s.update(func(st *Saved) {
			if st.Plan[owner] == nil {
				st.Plan[owner] = map[string]PlanState{}
			}
			for f, p := range got {
				st.Plan[owner][string(f)] = p
			}
		}))
	}
	plan := planOf(st.Plan[owner])
	maps.Copy(plan, got)
	return plan, errors.Join(errs...)
}

// prime makes sure the clock has heard GitHub, with one request that costs no quota. Most calls
// have by then, from the read that came first; ProbePlan is the one that must know the time
// before it asks anything.
func (s *Settings) prime(ctx context.Context, acct string) error {
	if s.cl.Clock().Known() {
		return nil
	}
	if _, err := s.cl.Do(ctx, acct, ghcli.Request{Path: "rate_limit"}); err != nil {
		return fmt.Errorf("ghsettings: could not learn GitHub's time: %w", err)
	}
	if !s.cl.Clock().Known() {
		return errors.New("ghsettings: GitHub's answer carried no Date header, so its clock is unknown")
	}
	return nil
}

// planStale reports whether a probe is old enough to be asked again. The age is GitHub's clock
// against GitHub's clock, so this Mac's error cannot make it too young or too old.
func (s *Settings) planStale(p PlanState, now time.Time) bool {
	at, err := time.Parse(time.RFC3339, p.Probed)
	return err != nil || now.Sub(at) >= s.reprobe
}
