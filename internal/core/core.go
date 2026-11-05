// Package core holds the types and contracts every keyguard package shares, so each
// package can be built and tested on its own and wired together only in cmd/keyguard.
// PLAN.md is the spec; this file is the part of it the compiler checks.
package core

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Visibility is who can read a location.
type Visibility string

const (
	Public     Visibility = "public"      // public repo/wiki/issue/release/actions, public gist
	SecretGist Visibility = "secret-gist" // unlisted gist: anyone holding the URL
	Private    Visibility = "private"
	Local      Visibility = "local" // only on this Mac: staged or unpushed
	Unknown    Visibility = "unknown"
)

// Exposed reports whether a stranger could read it. Unknown counts as exposed: the
// cautious answer is the one that gets a key rotated.
func (v Visibility) Exposed() bool { return v == Public || v == SecretGist || v == Unknown }

// Verified is the result of checking a secret against its provider (STEAL P0-09).
//
// Only Live and Dead are verdicts, and only an answer from the provider earns one. Verifying
// is the biggest precision lever there is, but roughly one in ten "verified" credential-URL
// hits was wrong, and a key whose endpoint could not be reached is not a dead key. So a
// failed check is VerifyError with a VerifyReason, never Dead, and neither Unverified nor
// VerifyError lowers anything a verdict already said. RecordVerification holds the rules.
type Verified string

const (
	Live        Verified = "live"
	Dead        Verified = "dead"       // the provider answered and rejected it: revoked, rotated, or never valid
	Unverified  Verified = "unverified" // no verifier for this type, or verification not run: not an attempt
	VerifyError Verified = "error"      // a verifier ran but could not decide; the VerifyReason says why
)

// Decisive reports whether v is a verdict from the provider.
func (v Verified) Decisive() bool { return v == Live || v == Dead }

// VerifyReason says why a verification could not decide. It travels with VerifyError only:
// a verdict means the provider answered, so there is nothing to explain. The classes decide
// how a retry is judged (a 429 wants patience, a bad status wants a look), not whether the
// secret is real: none of them says anything about the key.
type VerifyReason string

const (
	ReasonNone        VerifyReason = ""
	ReasonTimeout     VerifyReason = "timeout" // no answer in time
	ReasonRateLimited VerifyReason = "429"     // the provider is throttling us
	ReasonDNS         VerifyReason = "dns"     // the host did not resolve
	ReasonDial        VerifyReason = "dial"    // the host did not take the connection: refused, TLS failure, unreachable
	ReasonStatus      VerifyReason = "status"  // an HTTP status that is neither accept nor reject (5xx, a WAF page)
	ReasonOverlap     VerifyReason = "overlap" // several detectors claim the value, so the engine would not pick a verifier
)

// Class returns r when it is one of the classes above and ReasonNone for anything else. A
// reason is a class and never text: a verifier's own error can quote the credential it was
// checking (a connection URL with its password in it), so RecordVerification and the triage
// text keep the class only, and no raw value reaches findings.json through here (PLAN
// invariant 1; STEAL P0-04 "keep a class only").
func (r VerifyReason) Class() VerifyReason {
	switch r {
	case ReasonTimeout, ReasonRateLimited, ReasonDNS, ReasonDial, ReasonStatus, ReasonOverlap:
		return r
	}
	return ReasonNone
}

// verifyBackoff is the wait before the next attempt after n undecided attempts in a row: a
// short first wait rides out a blip, the long last one keeps a dead endpoint from being
// asked every sweep. Attempts past the table wait as long as its last entry.
var verifyBackoff = [...]time.Duration{time.Minute, 5 * time.Minute, 30 * time.Minute, 6 * time.Hour}

// VerifyBackoff is how long to wait after the n-th undecided attempt in a row (n < 1 counts as 1).
func VerifyBackoff(n int) time.Duration {
	return verifyBackoff[min(max(n, 1), len(verifyBackoff))-1]
}

// How long a verdict is believed before the provider is asked again. A live key is re-asked
// often because rotation is what resolves it and the report should notice; a dead one only
// weekly, in case the first answer was wrong.
const (
	LiveTTL = 6 * time.Hour
	DeadTTL = 7 * 24 * time.Hour
)

// VerdictTTL is the lifetime of a verdict; 0 for anything that is not one.
func VerdictTTL(v Verified) time.Duration {
	switch v {
	case Live:
		return LiveTTL
	case Dead:
		return DeadTTL
	}
	return 0
}

// Severity orders what the user must act on. None means "not yet assessed / never notified".
type Severity int

const (
	None Severity = iota
	Info
	Low
	Medium
	High
	Critical
)

var severityNames = [...]string{"none", "info", "low", "medium", "high", "critical"}

// String names a severity. A value outside the scale, such as one read from a damaged
// findings.json, is "none" rather than a panic in whichever caller formats it.
func (s Severity) String() string {
	if s < None || int(s) >= len(severityNames) {
		return severityNames[None]
	}
	return severityNames[s]
}

func ParseSeverity(s string) Severity {
	for i, n := range severityNames {
		if strings.EqualFold(s, n) {
			return Severity(i)
		}
	}
	return None
}

// Location is one place a secret was seen. Source ids look like
// "github.com/hangryclaude/foo", "github.com/hangryclaude/foo.wiki",
// "gist.github.com/hangryclaude/<id>", or "local:/Users/me/dev/foo".
type Location struct {
	Source string `json:"source"`
	// Kind: repo|wiki|gist|issue|pr|comment|release|actions|staged|unpushed|file, or alert for
	// a GitHub secret-scanning alert (its Source is still the repo it belongs to).
	Kind       string     `json:"kind"`
	Visibility Visibility `json:"visibility"`
	Ref        string     `json:"ref,omitempty"`
	Commit     string     `json:"commit,omitempty"`
	// Blob is the git object id of the content, for a hit that no commit places: an engine
	// that scans objects (titus) finds blobs kept alive only by a tag, and without it two
	// such hits on one line number would be the same location.
	Blob string `json:"blob,omitempty"`
	// Path is repo-relative. A hit inside an archive is "<archive path>!<member path>", the
	// way betterleaks writes it; an engine that cannot name the member reports the archive.
	Path   string `json:"path,omitempty"`
	Line   int    `json:"line,omitempty"`
	Author string `json:"author,omitempty"`
	Date   string `json:"date,omitempty"`
	URL    string `json:"url,omitempty"`
}

// Key identifies a location for dedup across engines that report the same line.
func (l Location) Key() string {
	k := l.Source + "|" + l.Commit + "|" + l.Path + "|" + strconv.Itoa(l.Line)
	if l.Commit == "" && l.Blob != "" {
		k += "|" + l.Blob
	}
	return k
}

// Hit is one detection by one engine, already fingerprinted. The raw value is gone by the
// time a Hit exists; Context has the secret replaced by its Shape.
//
// Detections that are not an engine's report follow one convention, so db and triage treat
// them alike. A filename-rule hit has Engine "filename", Rule = Type = the rule id
// (env-file, ssh-key, pem-key, ...), Context = the reason in words, FP = an HMAC of the path
// and blob id (one file can be allowed per content), and no Shape or Len. A learned-secret
// hit has Engine "known" and Known set. Consumers must accept an empty Shape.
type Hit struct {
	Engine       string       `json:"engine"` // betterleaks|gitleaks|trufflehog|titus|known|filename|github-alerts
	Rule         string       `json:"rule"`
	Type         string       `json:"type"` // normalized provider: openai, anthropic, github, aws, ...
	FP           string       `json:"fp"`
	Shape        string       `json:"shape"`
	Len          int          `json:"len"`
	Entropy      float64      `json:"entropy"`
	Verified     Verified     `json:"verified"`
	VerifyReason VerifyReason `json:"verify_reason,omitempty"` // with VerifyError only: why the check could not decide
	Context      string       `json:"context,omitempty"`       // ≤ 200 runes, secret already replaced
	Known        string       `json:"known,omitempty"`         // "<entry id> <name>" when this is a learned local secret
	// Tags are facts the normalizer worked out from the raw value before dropping it:
	// placeholder, jwt.role=anon, test-mode. Shape, Len and Context cannot carry them (a
	// Supabase anon key and a service_role key look the same), so triage reads them here.
	// A tag is one of a fixed vocabulary, never a piece of the value.
	Tags []string `json:"tags,omitempty"`
	Loc  Location `json:"loc"`
}

// Secret is the dedup unit: one distinct value, every place it was seen.
type Secret struct {
	FP        string     `json:"fp"`
	ID        string     `json:"id"` // "kg" + first 6 hex of FP; what a human types
	Type      string     `json:"type"`
	Shape     string     `json:"shape"`
	Len       int        `json:"len"`
	Engines   []string   `json:"engines"`
	Rules     []string   `json:"rules"`
	Locations []Location `json:"locations"`
	Tags      []string   `json:"tags,omitempty"` // union of the hits' tags
	// ExposedEver latches once a location has been public or a secret gist. A key a stranger
	// could read is compromised for good: cloned, cached, scraped. Exposed() looks at now,
	// so without this a key that went private again would fall from critical to high.
	ExposedEver bool `json:"exposed_ever,omitempty"`

	// The validity model (STEAL P0-09). Verified and VerifiedAt are the standing verdict;
	// the rest is the bookkeeping of asking again. RecordVerification maintains all of it.
	Verified        Verified     `json:"verified"`
	VerifiedAt      string       `json:"verified_at,omitempty"`      // when the standing verdict (live or dead) was recorded
	VerifyReason    VerifyReason `json:"verify_reason,omitempty"`    // why the latest attempt could not decide; empty after a verdict
	VerifyAttempted string       `json:"verify_attempted,omitempty"` // when verification last ran, whatever came of it
	VerifyErrors    int          `json:"verify_errors,omitempty"`    // undecided attempts in a row: the backoff step
	NextVerifyAt    string       `json:"next_verify_at,omitempty"`   // when to ask again; empty = nothing scheduled

	Known     string   `json:"known,omitempty"`
	Triage    string   `json:"triage"`              // TriageReal|TriageTest|TriagePlaceholder|TriagePublicByDesign|TriageFalsePositive|TriageUnreviewed
	TriageBy  string   `json:"triage_by,omitempty"` // TriageByRule|TriageByClaude|TriageByCodex|TriageByHuman
	TriageWhy string   `json:"triage_why,omitempty"`
	Severity  Severity `json:"severity"`
	Status    string   `json:"status"` // StatusOpen|StatusResolved|StatusIgnored
	FirstSeen string   `json:"first_seen"`
	LastSeen  string   `json:"last_seen"`
	Notified  Severity `json:"notified"` // highest severity already sent to the user
}

// Values of Secret.Status. A reader treats an empty or unknown status as open, so a
// forgotten field never hides a secret.
const (
	StatusOpen     = "open"
	StatusResolved = "resolved"
	StatusIgnored  = "ignored"
)

// Values of Secret.Triage.
const (
	TriageReal           = "real"
	TriageTest           = "test"
	TriagePlaceholder    = "placeholder"
	TriagePublicByDesign = "public-by-design"
	TriageFalsePositive  = "false-positive"
	TriageUnreviewed     = "unreviewed"
)

// Values of Secret.TriageBy, the judge list. Claude Opus 5.5 is the only judge in use
// (Codex is off by default); the list stays claude|codex|human so
// labels already stored keep reading and a second reviewer can come back without a format change.
const (
	TriageByRule   = "rule"
	TriageByClaude = "claude"
	TriageByCodex  = "codex"
	TriageByHuman  = "human"
)

// Exposed reports whether any location is readable by a stranger right now.
func (s Secret) Exposed() bool {
	for _, l := range s.Locations {
		if l.Visibility.Exposed() {
			return true
		}
	}
	return false
}

// WasExposed reports whether a stranger can read it now or ever could. Severity follows
// this, not Exposed.
func (s Secret) WasExposed() bool { return s.ExposedEver || s.Exposed() }

// NoteExposure latches ExposedEver. Writers call it after every change to Locations or to a
// location's visibility. Only a place known to be open counts: Unknown is exposed for
// severity while it lasts, but must not become permanent when the visibility turns out private.
func (s *Secret) NoteExposure() {
	for _, l := range s.Locations {
		if l.Visibility == Public || l.Visibility == SecretGist {
			s.ExposedEver = true
			return
		}
	}
}

// RecordVerification folds one verification outcome into s and reports whether anything
// changed. Every writer of verdicts goes through it (the store's Merge, the re-verify loop),
// so these are the merge rules, in full:
//
//   - Live and Dead are verdicts. A verdict replaces the standing one unless it is older than
//     it; at equal instants the later call wins. Taking a verdict clears the reason and the
//     error count, and schedules the next check VerdictTTL away.
//   - VerifyError never replaces a verdict. On a secret with none it becomes the state; either
//     way it records the reason, counts the failure and schedules a retry on the backoff
//     (VerifyBackoff). An unreachable endpoint (timeout, 429, dns, dial), a status the
//     verifier cannot read and a detector overlap are all this: never Dead.
//   - Dead with a reason is a contradiction (a failed check cannot reject a key), so it is
//     taken as VerifyError. Dead is the one verdict that retires an alert; it has to be clean.
//   - Unverified (no verifier, or verification not run) changes nothing but an empty state. It
//     is not an attempt, so it neither counts as one nor schedules one.
//   - The reason is kept as a class (VerifyReason.Class); any other text is dropped.
//   - One instant is one round. An error at the instant that already holds an attempt, a
//     verdict or an earlier error, changes nothing: betterleaks checks every occurrence of a
//     key, so six copies of it are six outcomes, and they must not walk the backoff six steps.
//     A verdict at that instant still replaces an error, in either order.
//
// A caller that has several outcomes for one secret from one round reduces them first and
// records the strongest: Live over Dead over VerifyError over Unverified, because the cautious
// answer is the one that gets a key rotated.
//
// at is the caller's clock, GitHub's when the sweep has it (this Mac's runs two hours fast).
func (s *Secret) RecordVerification(v Verified, why VerifyReason, at time.Time) bool {
	was := *s
	if v == "" {
		v = Unverified
	}
	if v == Dead && why != ReasonNone {
		v = VerifyError
	}
	why = why.Class()
	stamp := at.UTC().Format(time.RFC3339)
	switch v {
	case Live, Dead:
		if held, ok := parseStamp(s.VerifiedAt); ok && s.Verified.Decisive() && at.Before(held) {
			return false
		}
		s.Verified, s.VerifiedAt = v, stamp
		s.VerifyReason, s.VerifyErrors = ReasonNone, 0
		s.VerifyAttempted = stamp
		s.NextVerifyAt = at.Add(VerdictTTL(v)).UTC().Format(time.RFC3339)
	case VerifyError:
		if s.VerifyAttempted == stamp {
			return false // this round already has its answer
		}
		if !s.Verified.Decisive() {
			s.Verified = VerifyError
		}
		s.VerifyReason = why
		s.VerifyErrors++
		s.VerifyAttempted = stamp
		s.NextVerifyAt = at.Add(VerifyBackoff(s.VerifyErrors)).UTC().Format(time.RFC3339)
	default:
		if s.Verified == "" {
			s.Verified = Unverified
		}
	}
	return s.Verified != was.Verified || s.VerifiedAt != was.VerifiedAt || s.VerifyReason != was.VerifyReason ||
		s.VerifyAttempted != was.VerifyAttempted || s.VerifyErrors != was.VerifyErrors || s.NextVerifyAt != was.NextVerifyAt
}

// VerifyDue reports whether a check was scheduled and its time has come.
func (s Secret) VerifyDue(now time.Time) bool {
	t, ok := parseStamp(s.NextVerifyAt)
	return ok && !now.Before(t)
}

func parseStamp(s string) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339, s)
	return t, err == nil
}

// Emit receives normalized hits. Engines call it from their parsing goroutine.
type Emit func(Hit)

// Range selects git history for an engine scan. At least one field must be set: an empty
// Range is an error, and one that selects no commits starts no engine.
//
// Since holds tips that were already scanned. Whichever ref a tip was recorded for, the
// commits it reaches are excluded; so All+Since is every ref minus those tips, and Since
// alone scans only the refs it names, from their old tips to where they are now. Revs go to
// git verbatim: one "--not" flips the sign of everything after it, so a second flips it back.
type Range struct {
	All   bool              // every ref, refs/pull/* included (mirrors are cloned with --mirror)
	Revs  []string          // rev-list style args, e.g. ["<new>", "^<old>"] or ["--all", "--not", "<tip>"...]
	Since map[string]string // ref -> previously scanned tip, for engines that scan per ref (trufflehog)
}

// ScanOpts carries per-scan settings. Loc is a template: engines copy Source, Kind and
// Visibility into each hit and fill in Ref/Commit/Path/Line/Author/Date/URL themselves.
type ScanOpts struct {
	Verify  bool
	Threads int    // engine-internal concurrency cap; 0 = engine default
	Rules   string // extra rules config (betterleaks/gitleaks); "" = defaults only
	// Env is extra KEY=VALUE for the engine's child process, for what the engine can only be
	// given that way (GITHUB_TOKEN for an API scan). A credential goes here and never in argv,
	// where `ps` and the engine's own logs would show it.
	Env []string
	// ReleaseAssets asks ScanAPI to open the files attached to a release too. They are big and
	// rarely hold a key, so only the weekly deep run sets it (STEAL P0-22). Other scans ignore it.
	ReleaseAssets bool
	Loc           Location
}

// ErrUnsupported is returned by engines for scan modes they do not have.
var ErrUnsupported = errors.New("unsupported by this engine")

// Fingerprinter turns raw values into salted fingerprints (fp.Keyring implements it).
type Fingerprinter interface {
	FP(raw string) string
}

// Engine is one external scanner behind a normalizer. Implementations stream the engine's
// stdout through a pipe, fingerprint each finding and drop the raw value immediately.
//
// ScanDir takes a directory or a single file: known.Learn hands it one file at a time, with
// an engine built on the keyring of the root it is learning into (a hit's FP is only
// comparable to the store's when both used one salt).
// Hits already emitted when a scan fails are valid; the error says the scan is incomplete,
// and a caller must never read an engine error as a clean scan.
type Engine interface {
	Name() string
	Version() string // "" when the binary is missing
	Available() bool
	ScanGit(ctx context.Context, repo string, r Range, o ScanOpts, emit Emit) error
	ScanStaged(ctx context.Context, worktree string, o ScanOpts, emit Emit) error
	ScanDir(ctx context.Context, dir string, o ScanOpts, emit Emit) error
}

// APIScanner is an optional capability of an Engine: it scans one part of GitHub that is not
// git, named by its exact URL (STEAL P0-22). Listing a repository's issues with --since stops
// at the first item created before the cursor, so a new comment on an old issue is never seen,
// and it costs about 6 GraphQL points a page even when nothing matches; one URL costs about 1.
// url is the page of an issue, a pull request, a release or an Actions run, such as
// https://github.com/<owner>/<repo>/issues/<N>, /pull/<N>, /releases/tag/<tag> or
// /actions/runs/<id>. The token goes in o.Env as GITHUB_TOKEN, never in argv. o.Loc is the
// template, as for any scan, and the scanner sets Kind (issue|pr|comment|release|actions) and
// URL on each hit. A caller type-asserts for it and, when no engine has it, says in
// RunStats.Notes that the event was not scanned. It replaces the since/kinds shape the v1
// sweep package declared for itself, which nothing implemented.
type APIScanner interface {
	ScanAPI(ctx context.Context, url string, o ScanOpts, emit Emit) error
}

// NoteTaker is implemented by an Engine or a Store that sometimes drops, caps or widens
// work and says so (PLAN: no silent caps): a ranged scan that placed a hit on no commit, a
// blob that reported only its first paths, a scan widened past a tip it no longer has, a
// location list that was capped. TakeNotes returns what happened since the last call and
// forgets it; the sweep appends the lines to RunStats.Notes. Notes name counts and kinds,
// never values.
type NoteTaker interface {
	TakeNotes() []string
}

// KnownMatch is a learned local secret found in content.
type KnownMatch struct {
	EntryID string // "kg" id of the learned entry
	Name    string // e.g. "OPENAI_API_KEY"
	Source  string // where it was learned, e.g. "/Users/me/dev/x/.env"
	Variant string // raw|base64|base64url|urlenc|json (a value that needs escaping inside a JSON string)|utf16le|utf16be (a file saved as UTF-16)
	Offset  int    // byte offset of the match in the scanned data
	Len     int    // length of the matched bytes
	FP      string // fingerprint of the RAW value, whatever variant matched
	Shape   string
}

// KnownMatcher finds learned secrets (and encoded variants) in content. Zero false
// positives by construction: every candidate is confirmed by HMAC.
type KnownMatcher interface {
	Match(data []byte) []KnownMatch
	Len() int // number of learned entries (variants included)
}

// LimitedMatcher is a KnownMatcher that says when it stopped early. Match keeps the first
// matches of a huge blob and drops the rest; a caller that reports coverage (PLAN: no silent
// caps) asks through MatchLimit instead and counts the blobs it truncated. limit <= 0 means
// the matcher's own default. Optional, so a plain KnownMatcher (a test double) still fits.
type LimitedMatcher interface {
	KnownMatcher
	MatchLimit(data []byte, limit int) (matches []KnownMatch, truncated bool)
}

// VersionedMatcher is a KnownMatcher that can name its learned set exactly, for example a
// hash of the entry ids. The sweep rescans all history when the version changes; without
// one it can only compare Len, which notices an added secret but not one swapped for another.
type VersionedMatcher interface {
	KnownMatcher
	Version() string
}

// Source is one thing keyguard mirrors and scans.
type Source struct {
	ID            string     `json:"id"`   // "github.com/<owner>/<name>", "...<name>.wiki", "gist.github.com/<owner>/<id>"
	Kind          string     `json:"kind"` // repo|wiki|gist
	Owner         string     `json:"owner"`
	Name          string     `json:"name"`
	Account       string     `json:"account"` // gh login whose token reads it
	CloneURL      string     `json:"clone_url"`
	Visibility    Visibility `json:"visibility"`
	PushedAt      string     `json:"pushed_at"`
	DefaultBranch string     `json:"default_branch,omitempty"`
	Fork          bool       `json:"fork,omitempty"`
	Archived      bool       `json:"archived,omitempty"`
	SizeKB        int        `json:"size_kb,omitempty"`
}

// Event is GitHub activity that does not move pushedAt (issues, comments, visibility).
type Event struct {
	Source string `json:"source"`
	Type   string `json:"type"` // IssuesEvent, IssueCommentEvent, PullRequestEvent, PublicEvent, ReleaseEvent, GistEvent, ...
	At     string `json:"at"`
}

// Inventory lists everything keyguard watches.
type Inventory interface {
	List(ctx context.Context) ([]Source, error)
	// Changed is the cheap poll: the lists that reveal a push to, or a flip of, an exposed
	// source (public repos, gists) plus each account's events, all read with conditional
	// requests, so an idle poll is a handful of 304s that cost no quota. A quiet Changed reports
	// only exposed sources; the metadata of private repos is refreshed every RefreshEvery (30 min).
	// prev is the last full inventory keyed by Source.ID. Results from the scopes that worked
	// come back together with an error joining those that failed. Events are delivered at most
	// once (their ETag and high-water mark are saved as they are read). A changed Source never
	// has DefaultBranch filled in beyond what prev held, and a wiki Source has no PushedAt.
	Changed(ctx context.Context, prev map[string]Source) (changed []Source, events []Event, err error)
}

// Mirror keeps bare mirrors fresh. Tips are every ref under refs/ (refs/pull/* included).
// A wiki that upstream never created comes back as two empty maps and no error, the same as
// an empty repo; the concrete mirror's Result says which it was (Absent, Cloned).
type Mirror interface {
	Path(s Source) string
	Sync(ctx context.Context, s Source) (before, after map[string]string, err error)
}

// Store is the findings DB, deduplicated by FP.
type Store interface {
	// Merge folds hits in and returns FPs never seen before. A newer live/dead result
	// replaces an older one; unverified/error never overwrite live or dead. An unreachable
	// endpoint is an error, never dead. The whole rule set, with the retry schedule, is
	// Secret.RecordVerification; a Store applies it rather than keeping its own copy.
	Merge(hits []Hit, now string) (newFPs []string, err error)
	RefreshVisibility(vis map[string]Visibility) // Source.ID -> current visibility
	Secrets() []Secret
	Get(fp string) (Secret, bool)
	Put(s Secret) error
	Ignore(idOrFP, reason string) error
	Save() error
}

// Triager sets Triage, TriageBy, TriageWhy and Severity on a secret.
type Triager interface {
	Classify(s *Secret)
}

// RunStats is written to state/runs/<ts>.json after every run. Notes says out loud any
// work that was dropped, capped or skipped.
type RunStats struct {
	Kind     string `json:"kind"` // poll|full|deep|publish-check|bench|selftest
	Started  string `json:"started"`
	Finished string `json:"finished"`
	Sources  int    `json:"sources"`
	Scanned  int    `json:"scanned"`
	Skipped  int    `json:"skipped"` // not processed on purpose: unchanged, or private and out of scope
	// Failed is sources that should have been processed and were not, because a sync or an
	// engine failed. A launchd wrapper needs it apart from Skipped to tell "nothing new"
	// from "something broke".
	Failed  int                    `json:"failed,omitempty"`
	NewFPs  int                    `json:"new_fps"`
	Alerts  int                    `json:"alerts,omitempty"` // GitHub secret-scanning alerts imported
	Engines map[string]EngineStats `json:"engines"`
	// Coverage, so a report can state what a run looked at instead of leaving dashes. Zero
	// means not counted.
	Refs         int      `json:"refs,omitempty"`
	Commits      int      `json:"commits,omitempty"`
	Blobs        int      `json:"blobs,omitempty"`
	Gists        int      `json:"gists,omitempty"`
	Wikis        int      `json:"wikis,omitempty"`
	APIResources int      `json:"api_resources,omitempty"` // issues, PRs, comments, releases, Actions runs
	Notes        []string `json:"notes,omitempty"`
}

type EngineStats struct {
	Seconds float64 `json:"seconds"`
	Hits    int     `json:"hits"`
	Errors  int     `json:"errors"`
}

// LayerStatus is one protection layer's health for the report and doctor.
type LayerStatus struct {
	Name      string `json:"name"`
	OK        bool   `json:"ok"`
	Detail    string `json:"detail"`
	Fix       string `json:"fix,omitempty"` // the command that repairs a layer that is down, e.g. "keyguard install"
	CheckedAt string `json:"checked_at"`
}

type Reporter interface {
	Write(secrets []Secret, run RunStats, layers []LayerStatus) (path string, err error)
}

// Notifier tells the user. Notify returns nil when at least one channel probably reached them
// (an imsg that exited non-zero counts as sent, since the text may have gone). A caller
// records "notified" only on nil and does not retry on an error within the same run.
type Notifier interface {
	Notify(title, body string, sev Severity) error
}

// Paths is the on-disk layout under one data root. PLAN.md draws the same tree. A package
// that needs a file under it takes the name from here, so install, doctor and the writer of
// that file cannot disagree about where it is.
type Paths struct {
	Root, Bin, State, Known, Findings, Ignore, Sources, Inventory, Runs, Config, Mirrors, Report, Logs, Lock string

	// Names that had no home in v1; each package kept its own copy of the string.
	Events     string // state/events.json: per-account ETags and event high-water marks (inventory), and under the reserved keys _watch, _refreshed and _delivered the cheap poll's conditional-request entries (no GitHub login starts with an underscore)
	KnownStore string // state/known/known.json: the learned secret hashes
	KnownLock  string // state/known/.learn.lock: learn's read-merge-write
	Install    string // state/install.json: what the installer put where
	Selftest   string // state/selftest.json: the last selftest result
	Blocked    string // state/blocked.jsonl: what the hooks refused, display fields only
	Rules      string // rules/keyguard.toml: the extra rules the installed binary scans with

	// Names the P0 rows of docs/STEAL.md fix.
	BinDir     string // bin/: pinned engine copies named <engine>-<version> (P0-01); Bin lives here too
	Tmp        string // tmp/: TMPDIR for engine children, mode 0700 (P0-04)
	TitusCache string // cache/titus: Hyperscan rule cache, TITUS_CACHE_DIR (P0-06)
	Ledger     string // state/ledger/: OID ledgers of blobs already scanned, one file per rules version (P0-06, P1-08)
	GHSettings string // state/ghsettings.json: per repo and feature, what GitHub reported (P0-17)
}

// RealRoot is the data dir hooks always protect with, whatever the environment says.
func RealRoot() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".keyguard")
}

// Root is $KEYGUARD_HOME when set (tests, selftest), else RealRoot.
func Root() string {
	if r := os.Getenv("KEYGUARD_HOME"); r != "" {
		return r
	}
	return RealRoot()
}

// KnownRoots lists every known-store root a hook must load: the real one always, plus
// $KEYGUARD_HOME when set. The environment can add protection, never remove it.
func KnownRoots() []string {
	roots := []string{RealRoot()}
	if r := os.Getenv("KEYGUARD_HOME"); r != "" && r != roots[0] {
		roots = append(roots, r)
	}
	return roots
}

func PathsAt(root string) Paths {
	st := filepath.Join(root, "state")
	return Paths{
		Root:      root,
		Bin:       filepath.Join(root, "bin", "keyguard"),
		State:     st,
		Known:     filepath.Join(st, "known"),
		Findings:  filepath.Join(st, "findings.json"),
		Ignore:    filepath.Join(st, "ignore.json"),
		Sources:   filepath.Join(st, "sources"),
		Inventory: filepath.Join(st, "inventory.json"),
		Runs:      filepath.Join(st, "runs"),
		Config:    filepath.Join(st, "config.json"),
		Mirrors:   filepath.Join(root, "cache", "mirrors"),
		Report:    filepath.Join(root, "report", "index.html"),
		Logs:      filepath.Join(root, "logs"),
		Lock:      filepath.Join(st, "lock"),

		Events:     filepath.Join(st, "events.json"),
		KnownStore: filepath.Join(st, "known", "known.json"),
		KnownLock:  filepath.Join(st, "known", ".learn.lock"),
		Install:    filepath.Join(st, "install.json"),
		Selftest:   filepath.Join(st, "selftest.json"),
		Blocked:    filepath.Join(st, "blocked.jsonl"),
		Rules:      filepath.Join(root, "rules", "keyguard.toml"),

		BinDir:     filepath.Join(root, "bin"),
		Tmp:        filepath.Join(root, "tmp"),
		TitusCache: filepath.Join(root, "cache", "titus"),
		Ledger:     filepath.Join(st, "ledger"),
		GHSettings: filepath.Join(st, "ghsettings.json"),
	}
}
