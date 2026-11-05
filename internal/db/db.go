// Package db is keyguard's findings store: Secrets deduplicated by fingerprint in one JSON
// file, the human ignore list beside it, and the run lock that keeps two writers apart.
//
// Nothing here ever sees a raw secret. A Hit arrives already fingerprinted with its Context
// redacted, and everything persisted is derived from those fields. Because this is the last
// stop before disk, the store still refuses what could not be a display form: a Shape that
// is not an ellipsis-bearing shape is blanked, a Context is scrubbed again, and the only
// free text a human supplies (an ignore reason) is scrubbed on the way in.
//
// Merge rules (core.Store has the one-line version):
//   - one Secret per FP; engines, rules and locations are unions, and locations are keyed by
//     Location.Key, so three engines reporting one line leave one location;
//   - verification follows the validity model (core.Secret.RecordVerification, STEAL P0-09): a
//     live or dead verdict is replaced by a newer verdict of either kind; on a tie the later
//     Merge call wins, and within one call live wins, because the cautious answer is the one
//     that gets a key rotated; unverified and error results never overwrite a verdict. An error
//     keeps the reason class (never the verifier's text), counts the failure and schedules the
//     retry on the backoff (1 m, 5 m, 30 m, 6 h); a verdict is believed for a TTL (live 6 h, dead 7 d);
//   - the hits' tags (placeholder, jwt.role=anon, test-mode) are facts the normalizer worked out
//     before it dropped the value; a secret carries their union and triage reads them;
//   - dead means resolved, live reopens, ignored is sticky and comes from the ignore list;
//   - Known is sticky: once a secret has matched a learned local key it always has;
//   - FirstSeen only moves earlier and LastSeen only later.
//
// Files (core.Paths): Findings is {"version","updated","secrets":[...],"evidence",
// "locations_dropped"}; Ignore is {"version","ignored":{"<fp>":{"id","reason","at"}}}. Both
// are written atomically at 0600. A writer must hold the run lock (AcquireLock) from Open
// to Save: Save replaces the file and does not merge with a concurrent writer.
package db

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"keyguard/internal/core"
	"keyguard/internal/fp"
)

// Values of Secret.Status and the human triage fields this package sets. core.go lists them
// in comments only, so the strings live here once.
const (
	StatusOpen     = "open"
	StatusResolved = "resolved"
	StatusIgnored  = "ignored"

	TriageUnreviewed    = "unreviewed"
	TriageFalsePositive = "false-positive"
	TriageByHuman       = "human"
)

const (
	// DefaultMaxLocations bounds one secret's location list. A token pasted into a log file
	// can be reported on a million lines; keeping them all would make every later run slower
	// for no extra insight. Exposed places are never traded for private ones (see addLocation).
	DefaultMaxLocations = 2000

	fileVersion    = 1
	maxContexts    = 4 // distinct redacted lines kept per secret as triage evidence
	maxContextRune = 200
	maxShapeRunes  = 40 // fp.Shape output is a short prefix, an ellipsis and at most four characters
	maxReasonRunes = 200
)

type fileDoc struct {
	Version  int                    `json:"version"`
	Updated  string                 `json:"updated,omitempty"`
	Secrets  []core.Secret          `json:"secrets"`
	Evidence map[string]evidenceRec `json:"evidence,omitempty"`
	Dropped  map[string]int         `json:"locations_dropped,omitempty"`
}

// evidenceRec is what triage needs from Hits but core.Secret has no field for: the
// redacted lines a secret was seen on and its entropy. Both are display-safe by the Hit
// contract.
type evidenceRec struct {
	Entropy  float64  `json:"entropy,omitempty"`
	Contexts []string `json:"contexts,omitempty"`
	Tags     []string `json:"tags,omitempty"`
}

// rec is a stored secret plus the lookup state Merge keeps beside it.
type rec struct {
	core.Secret
	idx       map[string]int // Location.Key -> index in Locations; built on first merge
	unexposed int            // locations a stranger cannot read; lets a full list make room for an exposed one
}

func (r *rec) index() map[string]int {
	if r.idx == nil {
		r.idx = make(map[string]int, len(r.Locations))
		r.unexposed = 0
		for i, l := range r.Locations {
			r.idx[l.Key()] = i
			if !l.Visibility.Exposed() {
				r.unexposed++
			}
		}
	}
	return r.idx
}

// Store implements core.Store over one findings file.
type Store struct {
	mu       sync.RWMutex
	paths    core.Paths
	memory   bool // a scratch store: nothing is written, the ignore list is read-only
	maxLoc   int
	now      func() time.Time
	secrets  map[string]*rec
	evidence map[string]*evidenceRec
	dropped  map[string]int // fp -> locations seen but not stored
	ignored  map[string]IgnoreEntry
	seen     ignoreStamp // ignore.json as last read, so a `keyguard allow` made mid-run is noticed
	notes    []string
	noted    map[string]bool
	dirty    bool
	onDisk   bool
}

var _ core.Store = (*Store)(nil)

type ignoreStamp struct {
	mtime  time.Time
	size   int64
	exists bool
}

// Option tunes a Store.
type Option func(*Store)

// WithMaxLocations caps the locations kept per secret; n <= 0 keeps the default.
func WithMaxLocations(n int) Option {
	return func(st *Store) {
		if n > 0 {
			st.maxLoc = n
		}
	}
}

// WithClock replaces time.Now, for the timestamps the store makes itself (ignore entries,
// the file's updated stamp).
func WithClock(now func() time.Time) Option { return func(st *Store) { st.now = now } }

func newStore(p core.Paths, opts []Option) *Store {
	st := &Store{
		paths:    p,
		maxLoc:   DefaultMaxLocations,
		now:      time.Now,
		secrets:  map[string]*rec{},
		evidence: map[string]*evidenceRec{},
		dropped:  map[string]int{},
		ignored:  map[string]IgnoreEntry{},
		noted:    map[string]bool{},
	}
	for _, o := range opts {
		o(st)
	}
	return st
}

// Open loads the findings and the ignore list. Missing files are the empty first-run state.
// A file that exists but cannot be parsed is an error and is left untouched: overwriting it
// would destroy the one copy of whatever is wrong with it.
func Open(p core.Paths, opts ...Option) (*Store, error) {
	st := newStore(p, opts)
	if err := st.loadIgnore(); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(p.Findings)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return st, nil
	case err != nil:
		return nil, fmt.Errorf("db: read findings: %w", err)
	}
	var doc fileDoc
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("db: %s is not valid findings JSON (move it aside and the next full scan refinds everything): %w", p.Findings, err)
	}
	if doc.Version > fileVersion {
		return nil, fmt.Errorf("db: %s is version %d, this build reads up to %d", p.Findings, doc.Version, fileVersion)
	}
	for i := range doc.Secrets {
		s := doc.Secrets[i]
		if s.FP == "" {
			return nil, fmt.Errorf("db: %s: secret #%d has no fingerprint", p.Findings, i)
		}
		if st.secrets[s.FP] != nil {
			return nil, fmt.Errorf("db: %s: fingerprint %s appears twice", p.Findings, fp.ID(s.FP))
		}
		normalize(&s)
		st.secrets[s.FP] = &rec{Secret: s}
	}
	for k, e := range doc.Evidence {
		st.evidence[k] = &e
	}
	maps.Copy(st.dropped, doc.Dropped)
	st.onDisk = true
	st.applyIgnores()
	return st, nil
}

// NewScratch is a store that lives in memory: Merge, Put and triage work as usual, Save
// does nothing, and the real ignore list is honored but never written. Publish checks use
// it so a what-if scan of a repo that is not public yet cannot leave findings behind.
func NewScratch(p core.Paths, opts ...Option) (*Store, error) {
	st := newStore(p, opts)
	st.memory = true
	if err := st.loadIgnore(); err != nil {
		return nil, err
	}
	return st, nil
}

func (st *Store) loadIgnore() error {
	m, err := readIgnore(st.paths.Ignore)
	if err != nil {
		return err
	}
	st.ignored = m
	st.seen = statIgnore(st.paths.Ignore)
	return nil
}

func statIgnore(path string) ignoreStamp {
	fi, err := os.Stat(path)
	if err != nil {
		return ignoreStamp{}
	}
	return ignoreStamp{mtime: fi.ModTime(), size: fi.Size(), exists: true}
}

// syncIgnore picks up changes another process made to ignore.json, so `keyguard allow`
// takes effect inside a sweep that is already running. The caller holds mu.
func (st *Store) syncIgnore() {
	if st.paths.Ignore == "" {
		return
	}
	cur := statIgnore(st.paths.Ignore)
	if cur == st.seen {
		return
	}
	m, err := readIgnore(st.paths.Ignore)
	if err != nil {
		st.noteOnce("ignore list is unreadable; keeping the copy loaded at start")
		st.seen = cur
		return
	}
	st.ignored, st.seen = m, cur
	st.applyIgnores()
}

// applyIgnores makes the secrets agree with the ignore list, in both directions: a new entry
// ignores, a removed entry releases what only it was holding. The caller holds mu.
func (st *Store) applyIgnores() {
	for k, r := range st.secrets {
		if e, ok := st.ignored[k]; ok {
			if applyIgnore(&r.Secret, e) {
				st.dirty = true
			}
		} else if r.Status == StatusIgnored {
			unignore(&r.Secret)
			st.dirty = true
		}
	}
}

func applyIgnore(s *core.Secret, e IgnoreEntry) bool {
	why := "ignored by a human"
	if e.Reason != "" {
		why += ": " + e.Reason
	}
	if s.Status == StatusIgnored && s.Triage == TriageFalsePositive && s.TriageBy == TriageByHuman &&
		s.TriageWhy == why && s.Severity == core.Info {
		return false
	}
	s.Status, s.Triage, s.TriageBy, s.TriageWhy, s.Severity = StatusIgnored, TriageFalsePositive, TriageByHuman, why, core.Info
	return true
}

// unignore returns a secret to the state it would have had without the ignore: open unless
// the provider already said dead, and unreviewed so the next triage pass judges it afresh.
func unignore(s *core.Secret) {
	s.Status = StatusOpen
	if s.Verified == core.Dead {
		s.Status = StatusResolved
	}
	s.Triage, s.TriageBy, s.TriageWhy, s.Severity = TriageUnreviewed, "", "", core.None
}

// normalize fills the defaults a Secret must have before it is stored or served, so every
// reader sees the same shape whoever wrote the record.
func normalize(s *core.Secret) {
	if s.ID == "" {
		s.ID = fp.ID(s.FP)
	}
	s.Shape = safeShape(s.Shape)
	s.Verified = cmp.Or(s.Verified, core.Unverified)
	s.Status = cmp.Or(s.Status, StatusOpen)
	s.Triage = cmp.Or(s.Triage, TriageUnreviewed)
	slices.Sort(s.Engines)
	s.Engines = slices.Compact(s.Engines)
	slices.Sort(s.Rules)
	s.Rules = slices.Compact(s.Rules)
	slices.Sort(s.Tags)
	s.Tags = slices.Compact(s.Tags)
	s.VerifyReason = s.VerifyReason.Class() // a class and never text, whatever a file on disk says
	seen := make(map[string]bool, len(s.Locations))
	locs := s.Locations[:0:0]
	for _, l := range s.Locations {
		if l.Visibility == "" {
			l.Visibility = core.Unknown // the cautious reading: Unknown counts as exposed
		}
		if k := l.Key(); !seen[k] {
			seen[k] = true
			locs = append(locs, l)
		}
	}
	slices.SortFunc(locs, cmpLocation)
	s.Locations = locs
	if s.Engines == nil {
		s.Engines = []string{}
	}
	if s.Rules == nil {
		s.Rules = []string{}
	}
	if s.Locations == nil {
		s.Locations = []core.Location{}
	}
}

func cmpLocation(a, b core.Location) int {
	return cmp.Or(
		cmp.Compare(a.Source, b.Source), cmp.Compare(a.Commit, b.Commit),
		cmp.Compare(a.Path, b.Path), cmp.Compare(a.Line, b.Line), cmp.Compare(a.Kind, b.Kind))
}

// safeShape keeps only what could be a display shape. fp.Shape always contains an ellipsis
// and never exceeds a prefix plus four characters, so a "shape" without one, or a long one,
// is a raw value in the wrong field and is blanked rather than written.
func safeShape(s string) string {
	if strings.Contains(s, "…") && utf8.RuneCountInString(s) <= maxShapeRunes {
		return s
	}
	return "…"
}

func isBlankShape(s string) bool { return s == "" || s == "…" }

func clip(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n-1]) + "…"
}

func stamp(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// newer reports whether a is strictly later than b. Timestamps are RFC 3339; when both
// parse they are compared as times, otherwise as strings, and an empty b is older than
// anything.
func newer(a, b string) bool {
	if b == "" {
		return a != ""
	}
	if a == "" {
		return false
	}
	ta, ea := time.Parse(time.RFC3339, a)
	tb, eb := time.Parse(time.RFC3339, b)
	if ea == nil && eb == nil {
		return ta.After(tb)
	}
	return a > b
}

func earliest(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	case newer(a, b):
		return b
	}
	return a
}

func latest(a, b string) string {
	if newer(b, a) {
		return b
	}
	return cmp.Or(a, b)
}

func insertSorted(list []string, v string) []string {
	if v == "" {
		return list
	}
	i, found := slices.BinarySearch(list, v)
	if found {
		return list
	}
	return slices.Insert(list, i, v)
}

func (st *Store) noteOnce(msg string) {
	if !st.noted[msg] {
		st.noted[msg] = true
		st.notes = append(st.notes, msg)
	}
}

// TakeNotes returns what the store dropped or blanked since the last call, for the run's
// Notes. Each message is a count or an id, never a value.
func (st *Store) TakeNotes() []string {
	st.mu.Lock()
	defer st.mu.Unlock()
	n := st.notes
	st.notes = nil
	return n
}

// Merge folds hits in and returns the FPs this store had never seen, in order of first
// appearance. Hits without a fingerprint are dropped and reported in the error; the valid
// ones are still merged, so one broken normalizer cannot cost a whole scan.
//
// Verification is recorded once per secret per call, as the strongest outcome the call brought
// (live over dead over error over unverified): betterleaks checks every occurrence of a key, so
// six copies of one are six outcomes of one round, and two engines can disagree about it. The
// cautious answer is the one that gets a key rotated.
func (st *Store) Merge(hits []core.Hit, now string) ([]string, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if now == "" {
		now = stamp(st.now())
	}
	st.syncIgnore()
	var (
		fresh   []string
		bad     int
		badFrom []string
		round   = map[string]outcome{}
		order   []string // fingerprints in order of first appearance, for a stable result
	)
	for i := range hits {
		h := &hits[i]
		if h.FP == "" {
			bad++
			badFrom = insertSorted(badFrom, cmp.Or(h.Engine, "unknown"))
			continue
		}
		r := st.secrets[h.FP]
		if r == nil {
			r = st.create(h.FP, now)
			fresh = append(fresh, h.FP)
		}
		st.fold(r, h, now)
		if _, seen := round[h.FP]; !seen {
			order = append(order, h.FP)
		}
		round[h.FP] = round[h.FP].with(h.Verified, h.VerifyReason)
		st.dirty = true
	}
	at := st.instant(now)
	for _, f := range order {
		r := st.secrets[f]
		o := round[f]
		r.Secret.RecordVerification(o.v, o.why, at)
		deriveStatus(&r.Secret)
	}
	if bad > 0 {
		return fresh, fmt.Errorf("db: dropped %d hit(s) with no fingerprint from engine(s) %s", bad, strings.Join(badFrom, ", "))
	}
	return fresh, nil
}

// outcome is what the hits of one secret in one Merge call said about it.
type outcome struct {
	v   core.Verified
	why core.VerifyReason
}

func (o outcome) rank() int {
	switch o.v {
	case core.Live:
		return 3
	case core.Dead:
		return 2
	case core.VerifyError:
		return 1
	}
	return 0
}

// with folds one more hit's answer in, keeping the stronger. An error keeps the first reason
// it was given: the reason is a class, and which of two classes is "the" reason has no right answer.
func (o outcome) with(v core.Verified, why core.VerifyReason) outcome {
	n := outcome{v: cmp.Or(v, core.Unverified), why: why}
	if n.rank() > o.rank() {
		return n
	}
	return o
}

// instant is the call's time as a time. A stamp that does not parse (a test's "t1") is this
// store's own clock, which keeps the order of calls at least.
func (st *Store) instant(now string) time.Time {
	if t, err := time.Parse(time.RFC3339, now); err == nil {
		return t
	}
	return st.now()
}

func (st *Store) create(f, now string) *rec {
	r := &rec{Secret: core.Secret{
		FP: f, ID: fp.ID(f), Verified: core.Unverified, Triage: TriageUnreviewed, Status: StatusOpen,
		Engines: []string{}, Rules: []string{}, Locations: []core.Location{}, FirstSeen: now, LastSeen: now,
	}}
	if e, ok := st.ignored[f]; ok {
		applyIgnore(&r.Secret, e)
	}
	st.secrets[f] = r
	return r
}

func (st *Store) fold(r *rec, h *core.Hit, now string) {
	s := &r.Secret
	shape := safeShape(h.Shape)
	if shape == "…" && h.Shape != "" && h.Shape != "…" {
		st.noteOnce("a hit from engine " + cmp.Or(h.Engine, "unknown") + " carried a shape that was not a shape; it was blanked")
	}
	if isBlankShape(s.Shape) && (!isBlankShape(shape) || s.Shape == "") {
		s.Shape = shape
	}
	if s.Len == 0 {
		s.Len = h.Len
	}
	mergeType(s, h)
	s.Engines = insertSorted(s.Engines, h.Engine)
	s.Rules = insertSorted(s.Rules, h.Rule)
	st.addLocation(r, h.Loc)
	if s.Known == "" {
		s.Known = h.Known
	}
	st.mergeTags(r, h)
	s.FirstSeen = earliest(s.FirstSeen, now)
	s.LastSeen = latest(s.LastSeen, now)
	deriveStatus(s)
	st.learn(h)
}

// isGeneric reports types that say nothing about the provider. Engines normalize rule ids
// to a provider type; the high-entropy catch-alls come out as "generic".
func isGeneric(t string) bool {
	return t == "" || t == "generic" || t == "unknown" || t == "other" || strings.HasPrefix(t, "generic-")
}

// mergeType keeps the most specific provider seen. A provider that accepted the key is the
// authority on what the key is, so a live-verified type also replaces a different guess.
func mergeType(s *core.Secret, h *core.Hit) {
	switch {
	case h.Type == "":
	case isGeneric(s.Type):
		s.Type = h.Type
	case !isGeneric(h.Type) && h.Type != s.Type && h.Verified == core.Live:
		s.Type = h.Type
	}
}

// deriveStatus ties Status to verification: dead is resolved, live reopens. Ignored is
// sticky, and anything else keeps what a person or an earlier run set.
func deriveStatus(s *core.Secret) {
	switch {
	case s.Status == StatusIgnored:
	case s.Verified == core.Dead:
		s.Status = StatusResolved
	case s.Verified == core.Live:
		s.Status = StatusOpen
	default:
		s.Status = cmp.Or(s.Status, StatusOpen)
	}
}

// addLocation unions one sighting into the secret. The same place seen again refreshes its
// visibility (the newest sighting knows best) and fills fields the first one lacked. When
// the list is full, an exposed sighting takes the slot of an unexposed one rather than being
// dropped: what a stranger can read matters more than what is private.
func (st *Store) addLocation(r *rec, l core.Location) {
	if l.Visibility == "" {
		l.Visibility = core.Unknown
	}
	l.Ref = scrubRef(l.Ref)
	idx := r.index()
	k := l.Key()
	if i, ok := idx[k]; ok {
		cur := &r.Locations[i]
		if cur.Visibility.Exposed() != l.Visibility.Exposed() {
			if l.Visibility.Exposed() {
				r.unexposed--
			} else {
				r.unexposed++
			}
		}
		cur.Visibility = l.Visibility
		cur.Kind = cmp.Or(cur.Kind, l.Kind)
		cur.Ref = cmp.Or(cur.Ref, l.Ref)
		cur.Author = cmp.Or(cur.Author, l.Author)
		cur.Date = cmp.Or(cur.Date, l.Date)
		cur.URL = cmp.Or(cur.URL, l.URL)
		return
	}
	if len(r.Locations) >= st.maxLoc {
		slot := -1
		if l.Visibility.Exposed() && r.unexposed > 0 {
			for i := len(r.Locations) - 1; i >= 0; i-- {
				if !r.Locations[i].Visibility.Exposed() {
					slot = i
					break
				}
			}
		}
		st.dropped[r.FP]++
		st.noteOnce(fmt.Sprintf("secret %s has more than %d locations; the extra sightings are counted, not stored", r.ID, st.maxLoc))
		if slot < 0 {
			return
		}
		delete(idx, r.Locations[slot].Key())
		r.Locations[slot] = l
		idx[k] = slot
		r.unexposed--
		return
	}
	idx[k] = len(r.Locations)
	r.Locations = append(r.Locations, l)
	if !l.Visibility.Exposed() {
		r.unexposed++
	}
}

// scrubRef keeps a ref name that is a key off the disk. An engine names the ref a hit was found
// on, and a branch or tag can be called anything, a key included (that is how a key is hidden
// from content scans, STEAL P0-13). A segment of the name that is long and random-looking is
// replaced by a mask; ordinary names, dates and version numbers have neither the length nor the
// entropy and are left as they are.
func scrubRef(ref string) string {
	if len(ref) < 32 {
		return ref
	}
	segs := strings.Split(ref, "/")
	for i, seg := range segs {
		if len(seg) >= 32 && fp.Entropy(seg) >= 4.3 {
			segs[i] = "«…»"
		}
	}
	return strings.Join(segs, "/")
}

// maxTags bounds a secret's tags: the vocabulary is a handful of words.
const maxTags = 8

var (
	tagRE   = regexp.MustCompile(`^[a-z0-9][a-z0-9_.=-]{0,31}$`)
	longRun = regexp.MustCompile(`[a-z0-9]{16}`)
)

// mergeTags unions the hit's tags into the secret and its evidence. A tag is one of a fixed
// vocabulary of short lower-case words, never a piece of the value; this is the last stop before
// disk, so one that looks like it could be a piece of a value (a long run of letters and digits,
// anything that is not a plain word) is dropped and said once, like a shape that is not a shape.
func (st *Store) mergeTags(r *rec, h *core.Hit) {
	for _, t := range h.Tags {
		if !tagRE.MatchString(t) || longRun.MatchString(t) {
			st.noteOnce("a hit from engine " + cmp.Or(h.Engine, "unknown") + " carried a tag that was not a tag; it was dropped")
			continue
		}
		if len(r.Tags) >= maxTags && !slices.Contains(r.Tags, t) {
			continue
		}
		r.Tags = insertSorted(r.Tags, t)
		e := st.evidence[h.FP]
		if e == nil {
			e = &evidenceRec{}
			st.evidence[h.FP] = e
		}
		e.Tags = insertSorted(e.Tags, t)
	}
}

// learn keeps the display-safe evidence triage reads: the highest entropy seen and a few
// distinct redacted lines. The context is scrubbed again here because this is where it
// reaches disk.
func (st *Store) learn(h *core.Hit) {
	ctx := strings.TrimSpace(fp.Scrub(clip(h.Context, maxContextRune)))
	if h.Entropy == 0 && ctx == "" {
		return
	}
	e := st.evidence[h.FP]
	if e == nil {
		e = &evidenceRec{}
		st.evidence[h.FP] = e
	}
	e.Entropy = max(e.Entropy, h.Entropy)
	if ctx != "" && len(e.Contexts) < maxContexts && !slices.Contains(e.Contexts, ctx) {
		e.Contexts = append(e.Contexts, ctx)
	}
}

// Evidence returns what triage can use beyond the Secret itself: redacted context lines, the
// entropy of the value, and the tags the normalizer computed from the value before it was dropped.
func (st *Store) Evidence(f string) (contexts []string, entropy float64, tags []string, ok bool) {
	st.mu.RLock()
	defer st.mu.RUnlock()
	e := st.evidence[f]
	if e == nil {
		return nil, 0, nil, false
	}
	return slices.Clone(e.Contexts), e.Entropy, slices.Clone(e.Tags), true
}

// Dropped is how many sightings of a secret were counted but not stored.
func (st *Store) Dropped(f string) int {
	st.mu.RLock()
	defer st.mu.RUnlock()
	return st.dropped[f]
}

// RefreshVisibility rewrites each location's visibility from the current inventory. It does
// not touch severity: the caller re-triages, so one code path decides what a visibility
// change means.
func (st *Store) RefreshVisibility(vis map[string]core.Visibility) {
	st.mu.Lock()
	defer st.mu.Unlock()
	for _, r := range st.secrets {
		changed := false
		for i := range r.Locations {
			if v, ok := vis[r.Locations[i].Source]; ok && v != "" && r.Locations[i].Visibility != v {
				r.Locations[i].Visibility = v
				changed = true
			}
		}
		if changed {
			r.idx = nil // exposed/unexposed counts are stale
			st.dirty = true
		}
	}
}

func clone(s core.Secret) core.Secret {
	s.Engines = slices.Clone(s.Engines)
	s.Rules = slices.Clone(s.Rules)
	s.Tags = slices.Clone(s.Tags)
	s.Locations = slices.Clone(s.Locations)
	return s
}

// canonical is a copy with every slice non-nil and sorted, so the file and the API are
// stable whatever order hits arrived in.
func canonical(s core.Secret) core.Secret {
	s = clone(s)
	normalize(&s)
	return s
}

// Secrets returns copies of every secret, ordered by fingerprint.
func (st *Store) Secrets() []core.Secret {
	st.mu.RLock()
	defer st.mu.RUnlock()
	out := make([]core.Secret, 0, len(st.secrets))
	for _, f := range slices.Sorted(maps.Keys(st.secrets)) {
		out = append(out, canonical(st.secrets[f].Secret))
	}
	return out
}

// Len is the number of distinct secrets.
func (st *Store) Len() int {
	st.mu.RLock()
	defer st.mu.RUnlock()
	return len(st.secrets)
}

// Get returns a copy of the secret with this fingerprint.
func (st *Store) Get(f string) (core.Secret, bool) {
	st.mu.RLock()
	defer st.mu.RUnlock()
	r := st.secrets[f]
	if r == nil {
		return core.Secret{}, false
	}
	return canonical(r.Secret), true
}

var (
	fpRE = regexp.MustCompile(`^[0-9a-f]{32}$`)
	idRE = regexp.MustCompile(`^kg[0-9a-f]{6}$`)
)

// Find resolves what a human types: a fingerprint or a "kg" id.
func (st *Store) Find(idOrFP string) (core.Secret, bool) {
	st.mu.RLock()
	defer st.mu.RUnlock()
	if f, err := st.resolve(idOrFP); err == nil && st.secrets[f] != nil {
		return canonical(st.secrets[f].Secret), true
	}
	return core.Secret{}, false
}

// resolve maps an id or fingerprint to a fingerprint. A fingerprint need not be stored yet:
// ignoring a value before it is ever found is legitimate. An id must match exactly one
// stored secret, since six hex digits are not unique across a large store. The caller holds mu.
func (st *Store) resolve(idOrFP string) (string, error) {
	arg := strings.TrimSpace(idOrFP)
	if st.secrets[arg] != nil {
		return arg, nil
	}
	if id := strings.ToLower(arg); idRE.MatchString(id) {
		// Stored secrets and ignore entries both count: a value can be on the ignore list
		// before it is ever found.
		found := map[string]bool{}
		for f := range st.secrets {
			if fp.ID(f) == id {
				found[f] = true
			}
		}
		for f := range st.ignored {
			if fp.ID(f) == id {
				found[f] = true
			}
		}
		hits := slices.Sorted(maps.Keys(found))
		switch len(hits) {
		case 1:
			return hits[0], nil
		case 0:
			return "", fmt.Errorf("db: no stored secret has id %s; pass the full fingerprint", id)
		}
		return "", fmt.Errorf("db: id %s matches %d stored secrets; pass the full fingerprint", id, len(hits))
	}
	if f := strings.ToLower(arg); fpRE.MatchString(f) {
		return f, nil
	}
	return "", fmt.Errorf("db: %q is neither a kg id nor a 32-character fingerprint", clip(arg, 40))
}

// Put replaces the stored secret with s. It exists for triage and for imports of outside
// verdicts; it neither merges nor re-derives status. The ignore list still wins: a put can
// not un-ignore a fingerprint a human ignored.
func (st *Store) Put(s core.Secret) error {
	if s.FP == "" {
		return errors.New("db: put: secret has no fingerprint")
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	st.syncIgnore()
	s = clone(s)
	normalize(&s)
	if e, ok := st.ignored[s.FP]; ok {
		applyIgnore(&s, e)
	}
	st.secrets[s.FP] = &rec{Secret: s}
	st.dirty = true
	return nil
}

// Ignore marks a secret a human-confirmed false positive and records it in ignore.json
// before anything else, so the decision survives a lost or rebuilt findings file. idOrFP
// may be a full fingerprint (the secret need not be stored yet) or a kg id of a stored one.
func (st *Store) Ignore(idOrFP, reason string) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	if !st.memory {
		unlock, err := lockIgnore(st.paths.Ignore)
		if err != nil {
			return err
		}
		defer unlock()
	}
	st.syncIgnore()
	f, err := st.resolve(idOrFP)
	if err != nil {
		return err
	}
	e := IgnoreEntry{ID: fp.ID(f), Reason: strings.TrimSpace(fp.Scrub(clip(reason, maxReasonRunes))), At: stamp(st.now())}
	next := maps.Clone(st.ignored)
	next[f] = e
	if err := st.writeIgnore(next); err != nil {
		return err
	}
	st.ignored = next
	if r := st.secrets[f]; r != nil {
		applyIgnore(&r.Secret, e)
		st.dirty = true
	}
	return nil
}

// Unignore takes a fingerprint off the ignore list and returns its secret, if stored, to
// open/unreviewed so the next pass judges it again.
func (st *Store) Unignore(idOrFP string) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	if !st.memory {
		unlock, err := lockIgnore(st.paths.Ignore)
		if err != nil {
			return err
		}
		defer unlock()
	}
	st.syncIgnore()
	arg := strings.TrimSpace(idOrFP)
	f := arg
	if _, ok := st.ignored[f]; !ok {
		var err error
		if f, err = st.resolve(arg); err != nil {
			return err
		}
	}
	if _, ok := st.ignored[f]; !ok {
		return fmt.Errorf("db: %s is not on the ignore list", fp.ID(f))
	}
	next := maps.Clone(st.ignored)
	delete(next, f)
	if err := st.writeIgnore(next); err != nil {
		return err
	}
	st.ignored = next
	if r := st.secrets[f]; r != nil && r.Status == StatusIgnored {
		unignore(&r.Secret)
		st.dirty = true
	}
	return nil
}

// Ignored reports whether fp is on the ignore list.
func (st *Store) Ignored(f string) bool {
	st.mu.RLock()
	defer st.mu.RUnlock()
	_, ok := st.ignored[f]
	return ok
}

func (st *Store) writeIgnore(m map[string]IgnoreEntry) error {
	if st.memory {
		return nil
	}
	b, err := marshalIgnore(m)
	if err != nil {
		return err
	}
	if err := WriteFileAtomic(st.paths.Ignore, b, 0o600); err != nil {
		return fmt.Errorf("db: write ignore list: %w", err)
	}
	st.seen = statIgnore(st.paths.Ignore) // our own write is not news
	return nil
}

// Save writes the findings atomically if anything changed since the last Save (or if the
// file does not exist yet, so a first run leaves an honest empty file).
func (st *Store) Save() error {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.memory || (!st.dirty && st.onDisk) {
		return nil
	}
	doc := fileDoc{Version: fileVersion, Updated: stamp(st.now()), Secrets: make([]core.Secret, 0, len(st.secrets))}
	for _, f := range slices.Sorted(maps.Keys(st.secrets)) {
		doc.Secrets = append(doc.Secrets, canonical(st.secrets[f].Secret))
		if e := st.evidence[f]; e != nil {
			if doc.Evidence == nil {
				doc.Evidence = map[string]evidenceRec{}
			}
			doc.Evidence[f] = *e
		}
		if n := st.dropped[f]; n > 0 {
			if doc.Dropped == nil {
				doc.Dropped = map[string]int{}
			}
			doc.Dropped[f] = n
		}
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	if err := WriteFileAtomic(st.paths.Findings, append(b, '\n'), 0o600); err != nil {
		return fmt.Errorf("db: write findings: %w", err)
	}
	st.dirty, st.onDisk = false, true
	return nil
}
