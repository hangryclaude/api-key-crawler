package report

import (
	"cmp"
	"html/template"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"keyguard/internal/core"
	"keyguard/internal/fp"
)

// The page is built in two steps: this file turns secrets, run stats and layer states into
// plain, already-formatted strings and flags; page.html only lays them out. All judgement
// (what is urgent, what is stale, what to hide) lives here where tests can reach it.

// Coverage carries the counts of what is watched (the inventory's), and, for a caller that
// has them but did not put them in the RunStats, what the engines walked. A run's own RunStats
// fields win when they are set. Zero means "not reported" and the page prints a dash, never 0:
// a missing count must not read as "nothing there".
type Coverage struct {
	Repos, Wikis, Gists, Public int // sources by kind, and how many of them are public
	Refs, Commits, Blobs        int // what the engines walked
	APIItems                    int // issues, PRs, comments, releases, actions logs
}

// CoverageFromSources counts an inventory by kind, so callers need not tally it themselves.
func CoverageFromSources(srcs []core.Source) Coverage {
	var c Coverage
	for _, s := range srcs {
		switch s.Kind {
		case "repo":
			c.Repos++
		case "wiki":
			c.Wikis++
		case "gist":
			c.Gists++
		}
		if s.Visibility == core.Public {
			c.Public++
		}
	}
	return c
}

type input struct {
	secrets []core.Secret
	run     core.RunStats
	layers  []core.LayerStatus
	cov     Coverage
	now     time.Time
	zone    *time.Location
	stale   time.Duration
}

type view struct {
	Title    string
	CSS      template.CSS
	Hero     heroView
	Strips   []stripView
	Levels   []levelView
	RotateN  int
	Rotate   []groupView
	Empty    emptyView // what the Rotate now section says when it has no rows
	Layers   layersView
	Coverage coverageView
	Engines  enginesView
	Lower    listView
	Ignored  listView
	Written  string
}

type heroView struct {
	Kind     string // alert|warn|ok|unknown: picks colours; the words carry the meaning
	Headline string
	Sub      string
	Fresh    string
}

type stripView struct{ Kind, Text, Href, Link string }

// emptyView keeps an empty list from reading as good news the hero does not give: after a
// stale or missing scan, "nothing to rotate" is only what the last look found.
type emptyView struct{ Kind, Text string }

type levelView struct {
	Name, Class, Meaning, N string
	Zero                    bool
}

type groupView struct {
	Heading, Note string
	Rows          []rowView
}

type rowView struct {
	ID, Allow               string // Allow is the command that marks a false positive; "" for keys known to be real
	Type, Shape, Len, Known string
	Level, LevelClass       string
	Where                   whereView
	More                    []whereView
	MoreN                   string
	MoreHidden              string
	Places                  string
	FirstN, FirstWord       string
	FirstDay                string
	Verified, VerifiedClass string
	VerifiedOn              string
	Rotate                  rotateView
	Why                     string
	Status                  string
}

type whereView struct {
	Badge, Class string
	Name, Href   string
	Place, Meta  string
}

type rotateView struct{ Name, URL, Hint string }

type layersView struct {
	Summary, Class string
	Rows           []layerRow
}

type layerRow struct{ Name, State, Class, Detail, Fix, Checked string }

type coverageView struct {
	Rows   []covRow
	Notes  []string
	NotesN string
}

type covRow struct {
	Label, Value, Note string
	Missing, Warn      bool
}

type enginesView struct {
	Rows  []engineRow
	Empty bool
}

type engineRow struct {
	Name, Time, Hits, Errors string
	Warn                     bool
}

type listView struct {
	Summary string
	Empty   bool
	Rows    []rowView
	Capped  string // set when rows were cut, so the cut is never silent
}

// A cap on table length keeps a first deep scan with tens of thousands of findings from
// producing a page that is slow to open; the cut is announced on the page.
const rowCap = 2000

type bucket int

const (
	bRotate bucket = iota
	bLower
	bIgnored
)

// isOpen treats an unknown or empty status as open: hiding a secret because a writer forgot
// to set a field is the wrong way to fail.
func isOpen(s core.Secret) bool { return s.Status != "resolved" && s.Status != "ignored" }

// sev clamps a corrupt severity so it can never index outside core's names or hide a secret.
func sev(s core.Severity) core.Severity {
	switch {
	case s < core.None:
		return core.None
	case s > core.Critical:
		return core.Critical
	}
	return s
}

func bucketOf(s core.Secret) bucket {
	switch {
	case !isOpen(s) || sev(s.Severity) == core.Info:
		return bIgnored
	case sev(s.Severity) >= core.High:
		return bRotate
	}
	return bLower
}

// split sorts secrets into the piles the page shows: critical and high are the rotate-now
// list, low is the review queue, ign is everything that needs no action.
func split(ss []core.Secret) (crit, high, low, ign []core.Secret) {
	for _, s := range ss {
		switch bucketOf(s) {
		case bLower:
			low = append(low, s)
		case bIgnored:
			ign = append(ign, s)
		default:
			if sev(s.Severity) == core.Critical {
				crit = append(crit, s)
			} else {
				high = append(high, s)
			}
		}
	}
	return crit, high, low, ign
}

func build(in input) view {
	crit, high, low, ign := split(in.secrets)
	sortSecrets(crit, urgentFirst)
	sortSecrets(high, urgentFirst)
	sortSecrets(low, reviewFirst)
	sortSecrets(ign, ignoredFirst)

	v := view{CSS: template.CSS(styleCSS), RotateN: len(crit) + len(high)}

	v.Hero, v.Strips = in.hero(crit, high)
	v.Title = v.Hero.Headline + " · keyguard"
	switch v.Hero.Kind {
	case "ok":
		v.Empty = emptyView{"ok", "Nothing to rotate."}
	case "warn":
		v.Empty = emptyView{"warn", "Nothing to rotate at the last scan."}
	default:
		v.Empty = emptyView{"unknown", "No result yet. Nothing has been scanned."}
	}
	v.Levels = levels(crit, high, low, ign)

	if len(crit) > 0 {
		v.Rotate = append(v.Rotate, groupView{
			Heading: "Critical: strangers can read these",
			Note:    "The key works, or it is one of yours. Rotate first.",
			Rows:    in.rows(crit, true),
		})
	}
	if len(high) > 0 {
		v.Rotate = append(v.Rotate, groupView{
			Heading: "High: private, but still yours",
			Note:    "Nobody outside can read these today.",
			Rows:    in.rows(high, true),
		})
	}

	v.Layers = in.layersView()
	v.Coverage = in.coverageView()
	v.Engines = in.enginesView()
	v.Lower = in.list(low, lowerSummary(low))
	v.Ignored = in.list(ign, ignoredSummary(ign))
	v.Written = stamp(in.now, in.zone)
	return v
}

// --- ordering -------------------------------------------------------------------------

func sortSecrets(ss []core.Secret, less func(a, b core.Secret) bool) {
	sort.SliceStable(ss, func(i, j int) bool {
		if less(ss[i], ss[j]) {
			return true
		}
		if less(ss[j], ss[i]) {
			return false
		}
		return ss[i].ID+ss[i].FP < ss[j].ID+ss[j].FP
	})
}

// urgentFirst orders one severity group: working keys before unconfirmed ones, and among
// equals the one that has been out the longest.
func urgentFirst(a, b core.Secret) bool {
	if (a.Verified == core.Live) != (b.Verified == core.Live) {
		return a.Verified == core.Live
	}
	return a.FirstSeen < b.FirstSeen
}

// reviewFirst: the review queue reads best newest first, exposed before private.
func reviewFirst(a, b core.Secret) bool {
	if sev(a.Severity) != sev(b.Severity) {
		return sev(a.Severity) > sev(b.Severity)
	}
	if a.Exposed() != b.Exposed() {
		return a.Exposed()
	}
	return a.FirstSeen > b.FirstSeen
}

func ignoredFirst(a, b core.Secret) bool {
	if ra, rb := ignoredRank(a), ignoredRank(b); ra != rb {
		return ra < rb
	}
	return a.Type < b.Type
}

func ignoredRank(s core.Secret) int {
	switch s.Status {
	case "ignored":
		return 0
	case "resolved":
		return 1
	}
	return 2
}

func exposureRank(v core.Visibility) int {
	switch v {
	case core.Public:
		return 0
	case core.SecretGist:
		return 1
	case core.Unknown:
		return 2
	case core.Private:
		return 3
	case core.Local:
		return 4
	}
	return 2 // an unrecognised value is treated as unknown, which counts as exposed
}

// --- hero, strips, levels -------------------------------------------------------------

func (in input) hero(crit, high []core.Secret) (heroView, []stripView) {
	finished, finOK := parseTime(in.run.Finished, in.zone)
	started, startOK := parseTime(in.run.Started, in.zone)
	age := time.Duration(0)
	if finOK {
		age = in.now.Sub(finished)
	}
	stale := finOK && age > in.stale

	var h heroView
	switch {
	case len(crit) > 0:
		h = heroView{Kind: "alert",
			Headline: critHeadline(crit),
			Sub:      "Anyone could read " + itThem(len(crit)) + ". Rotate " + itEach(len(crit)) + " below."}
	case len(high) > 0:
		h = heroView{Kind: "warn",
			Headline: highHeadline(high),
			Sub:      "Nobody outside can read " + itThem(len(high)) + " today. Rotate before that changes."}
	case in.run.Finished == "":
		h = heroView{Kind: "unknown",
			Headline: "Not scanned yet",
			Sub:      "No scan has finished, so this page cannot clear anything. This is not an all-clear."}
		if startOK {
			h.Sub = "A scan started " + ago(in.now.Sub(started)) + " and has not finished. This is not an all-clear."
		}
	case stale:
		h = heroView{Kind: "warn",
			Headline: "No live keys exposed at the last scan",
			Sub:      "That scan finished " + ago(age) + ". Check that the poller is running."}
	default:
		sub := "Nothing to rotate."
		if in.run.Sources > 0 {
			sub = plural(in.run.Sources, "source", "sources") + " checked. Nothing to rotate."
		}
		h = heroView{Kind: "ok", Headline: "No live keys exposed", Sub: sub}
	}

	switch {
	case finOK:
		h.Fresh = "Last scan " + stamp(finished, in.zone) + " · " + ago(age)
		if startOK && !finished.Before(started) { // a run that ends before it starts has bad stamps; say nothing rather than "took —"
			h.Fresh += " · " + runKind(in.run.Kind) + " took " + dur(finished.Sub(started))
		}
	case in.run.Finished != "":
		h.Fresh = "Last scan " + ident(in.run.Finished)
	}

	var strips []stripView
	if down := downLayers(in.layers); down > 0 {
		strips = append(strips, stripView{Kind: "warn",
			Text: plural(down, "protection layer", "protection layers") + " of " + num(len(in.layers)) +
				" " + isAre(down) + " down.",
			Href: "#layers", Link: "See which"})
	}
	if n := engineErrors(in.run); n > 0 {
		strips = append(strips, stripView{Kind: "warn",
			Text: plural(n, "engine error", "engine errors") + " in the last run. Some code may not have been checked.",
			Href: "#engines", Link: "See engines"})
	}
	// Failed is a source that should have been scanned and was not, because a sync or an engine
	// did not finish. Skipped is not that: a source with nothing new is skipped by design, and a
	// warm full run skips nearly all of them. The notes of a run, informational ones included,
	// are listed under Coverage and are not a headline.
	if in.run.Failed > 0 {
		strips = append(strips, stripView{Kind: "warn",
			Text: plural(in.run.Failed, "source", "sources") + " failed in the last run and " + isWere(in.run.Failed) + " not scanned.",
			Href: "#coverage", Link: "See coverage"})
	}
	if stale && len(crit)+len(high) > 0 {
		strips = append(strips, stripView{Kind: "warn",
			Text: "The last scan finished " + ago(age) + ".", Href: "#coverage", Link: "See coverage"})
	}
	return h, strips
}

// The notification shares the hero's sentences, so the banner and the page never disagree.
func critHeadline(ss []core.Secret) string { return keys(ss) + " exposed — rotate now" }
func highHeadline(ss []core.Secret) string { return keys(ss) + " in private places — rotate now" }

// keys counts "live" only when every one of them is verified live; a learned local key
// found in public is critical without a verifier, and saying "live" there would be a guess.
func keys(ss []core.Secret) string {
	live := true
	for _, s := range ss {
		live = live && s.Verified == core.Live
	}
	if live {
		return plural(len(ss), "live key", "live keys")
	}
	return plural(len(ss), "key", "keys")
}

func itThem(n int) string {
	if n == 1 {
		return "it"
	}
	return "them"
}

func itEach(n int) string {
	if n == 1 {
		return "it"
	}
	return "each one"
}

func isAre(n int) string {
	if n == 1 {
		return "is"
	}
	return "are"
}

func isWere(n int) string {
	if n == 1 {
		return "was"
	}
	return "were"
}

func downLayers(ls []core.LayerStatus) (n int) {
	for _, l := range ls {
		if !l.OK {
			n++
		}
	}
	return n
}

func engineErrors(r core.RunStats) (n int) {
	for _, e := range r.Engines {
		n += e.Errors
	}
	return n
}

func runKind(k string) string {
	switch k {
	case "poll":
		return "Quick check"
	case "deep":
		return "Deep scan"
	case "full":
		return "Full scan"
	case "publish-check":
		return "Publish check"
	case "bench":
		return "Benchmark"
	case "selftest":
		return "Self-test"
	case "":
		return "Scan"
	}
	return ident(k)
}

func levels(crit, high, low, ign []core.Secret) []levelView {
	var med, lo, unrated int
	for _, s := range low {
		switch sev(s.Severity) {
		case core.Medium:
			med++
		case core.Low:
			lo++
		default:
			unrated++
		}
	}
	mk := func(name, class, meaning string, n int) levelView {
		return levelView{Name: name, Class: class, Meaning: meaning, N: num(n), Zero: n == 0}
	}
	out := []levelView{
		mk("Critical", "crit", "Your key, and strangers can read it", len(crit)),
		mk("High", "high", "Your key, in a private place", len(high)),
		mk("Medium", "med", "Maybe a key, and strangers can read it", med),
		mk("Low", "low", "Maybe a key, in a private place", lo),
	}
	if unrated > 0 {
		out = append(out, mk("Not rated", "none", "Waiting for triage", unrated))
	}
	return append(out, mk("Ignored", "ign", "Dead, resolved, placeholder, or marked by you", len(ign)))
}

// --- secret rows ----------------------------------------------------------------------

func (in input) rows(ss []core.Secret, withRotate bool) []rowView {
	out := make([]rowView, 0, len(ss))
	for _, s := range ss {
		out = append(out, in.row(s, withRotate))
	}
	return out
}

func (in input) row(s core.Secret, withRotate bool) rowView {
	id := ident(s.ID)
	if !validID(id) {
		id = ident(fp.ID(s.FP))
	}
	r := rowView{
		ID:    id,
		Shape: safeShape(s.Shape),
		Level: levelName(sev(s.Severity)), LevelClass: levelClass(sev(s.Severity)),
	}
	if r.Shape == "" {
		r.Shape = "…"
	}
	if s.Len > 0 {
		r.Len = plural(s.Len, "character", "characters")
	}
	// A key verified live, or one learned from the user's own files, is real by definition:
	// offering the command that hides it would be offering the wrong fix.
	if s.Verified != core.Live && s.Known == "" {
		r.Allow = "keyguard allow " + id
	}
	if p, ok := Rotation(s.Type); ok {
		r.Type = p.Name
		if withRotate {
			r.Rotate = rotateView{Name: p.Name, URL: p.URL, Hint: p.Hint}
		}
	} else {
		r.Type = ident(s.Type)
		if r.Type == "" {
			r.Type = "Unknown type"
		}
		if withRotate {
			r.Rotate = rotateView{Hint: "Rotate it where it was issued."}
		}
	}
	if name := knownName(s.Known); name != "" {
		r.Known = name
	}

	locs := append([]core.Location(nil), s.Locations...)
	sort.SliceStable(locs, func(i, j int) bool {
		if a, b := exposureRank(locs[i].Visibility), exposureRank(locs[j].Visibility); a != b {
			return a < b
		}
		return locs[i].Key() < locs[j].Key()
	})
	r.Places = num(len(locs))
	if len(locs) > 0 {
		r.Where = in.where(locs[0])
		const showMore = 8
		rest := locs[1:]
		if len(rest) > showMore {
			r.MoreHidden = plural(len(rest)-showMore, "more place", "more places") + " not listed here"
			rest = rest[:showMore]
		}
		for _, l := range rest {
			r.More = append(r.More, in.where(l))
		}
		if n := len(locs) - 1; n > 0 {
			r.MoreN = plural(n, "more place", "more places")
		}
	} else {
		r.Where = whereView{Badge: "Unknown", Class: "vis-unknown", Name: "no location recorded"}
	}

	if t, ok := parseTime(s.FirstSeen, in.zone); ok {
		n, word := days(in.now.Sub(t))
		if word == "today" {
			r.FirstN = "today"
		} else {
			r.FirstN, r.FirstWord = num(n), word
		}
		r.FirstDay = day(t, in.zone)
	} else if s.FirstSeen != "" {
		r.FirstDay = ident(s.FirstSeen)
	}

	r.Verified, r.VerifiedClass = verifiedName(s.Verified)
	if t, ok := parseTime(s.VerifiedAt, in.zone); ok && s.Verified != core.Unverified {
		r.VerifiedOn = "checked " + day(t, in.zone)
	}

	r.Why = why(s)
	r.Status = statusName(s)
	return r
}

var idRe = regexp.MustCompile(`^kg[0-9a-f]{6}$`)

func validID(id string) bool { return idRe.MatchString(id) }

// knownName pulls the variable name out of "<entry id> <name>".
func knownName(k string) string {
	k = strings.TrimSpace(clean(k))
	if _, name, ok := strings.Cut(k, " "); ok {
		k = name
	}
	return maskRuns(strings.TrimSpace(k))
}

func levelName(s core.Severity) string {
	switch s {
	case core.Critical:
		return "Critical"
	case core.High:
		return "High"
	case core.Medium:
		return "Medium"
	case core.Low:
		return "Low"
	case core.Info:
		return "Info"
	}
	return "Not rated"
}

func levelClass(s core.Severity) string {
	switch s {
	case core.Critical:
		return "crit"
	case core.High:
		return "high"
	case core.Medium:
		return "med"
	case core.Low:
		return "low"
	}
	return "none"
}

func verifiedName(v core.Verified) (text, class string) {
	switch v {
	case core.Live:
		return "Live", "v-live"
	case core.Dead:
		return "Dead", "v-dead"
	case core.VerifyError:
		return "Check failed", "v-err"
	}
	return "Not checked", "v-none"
}

func statusName(s core.Secret) string {
	switch {
	case s.Status == "ignored":
		return "Marked by you"
	case s.Status == "resolved":
		return "Resolved"
	}
	return "No action needed"
}

var triageNames = map[string]string{
	"real":             "Looks real",
	"test":             "Test or fixture",
	"placeholder":      "Placeholder",
	"public-by-design": "Public by design",
	"false-positive":   "False positive",
	"unreviewed":       "Not reviewed yet",
}

var triageBy = map[string]string{"rule": "rule", "claude": "Claude", "codex": "Codex", "human": "you"}

func why(s core.Secret) string {
	label, ok := triageNames[s.Triage]
	if !ok {
		label = "Not reviewed yet"
	}
	if by := triageBy[s.TriageBy]; by != "" {
		label += " (" + by + ")"
	}
	if w := strings.TrimSpace(prose(s.TriageWhy)); w != "" {
		return label + ": " + w
	}
	return label
}

// --- locations ------------------------------------------------------------------------

func (in input) where(l core.Location) whereView {
	v := whereView{Badge: "Unknown", Class: "vis-unknown"}
	switch l.Visibility {
	case core.Public:
		v.Badge, v.Class = "Public", "vis-public"
	case core.SecretGist:
		v.Badge, v.Class = "Secret gist", "vis-gist"
	case core.Private:
		v.Badge, v.Class = "Private", "vis-private"
	case core.Local:
		v.Badge, v.Class = "This Mac", "vis-local"
	}
	v.Name = sourceName(l.Source)
	v.Href = locHref(l)
	if p := ident(l.Path); p != "" {
		v.Place = p
		if l.Line > 0 {
			v.Place += ":" + num(l.Line)
		}
	}
	var meta []string
	if k := kindName(l.Kind); k != "" {
		meta = append(meta, k)
	}
	if r := refName(l.Ref); r != "" {
		meta = append(meta, r)
	}
	if c := shortSHA(l.Commit); c != "" {
		meta = append(meta, c)
	}
	if t, ok := parseTime(l.Date, in.zone); ok {
		meta = append(meta, day(t, in.zone))
	}
	v.Meta = strings.Join(meta, " · ")
	return v
}

func kindName(k string) string {
	switch k {
	case "pr":
		return "pull request"
	case "actions":
		return "actions log"
	case "":
		return ""
	}
	return ident(k)
}

func refName(r string) string {
	r = ident(r)
	switch {
	case strings.HasPrefix(r, "refs/heads/"):
		return strings.TrimPrefix(r, "refs/heads/")
	case strings.HasPrefix(r, "refs/tags/"):
		return "tag " + strings.TrimPrefix(r, "refs/tags/")
	case strings.HasPrefix(r, "refs/pull/"):
		return "pull " + strings.TrimSuffix(strings.TrimPrefix(r, "refs/pull/"), "/head")
	}
	return r
}

var homeRe = regexp.MustCompile(`^/Users/[^/]+`)

func sourceName(src string) string {
	src = clean(src)
	var name string
	switch {
	case strings.HasPrefix(src, "github.com/"):
		name = strings.TrimPrefix(src, "github.com/")
		if strings.HasSuffix(name, ".wiki") {
			name = strings.TrimSuffix(name, ".wiki") + " (wiki)"
		}
	case strings.HasPrefix(src, "gist.github.com/"):
		// A gist id is 32 hex characters; eight are enough to find it on the owner's list.
		owner, id, _ := strings.Cut(strings.TrimPrefix(src, "gist.github.com/"), "/")
		if len(id) > 8 {
			id = id[:8] + "…"
		}
		name = "gist " + owner + "/" + id
	case strings.HasPrefix(src, "local:"):
		name = "this Mac: " + homeRe.ReplaceAllString(strings.TrimPrefix(src, "local:"), "~")
	default:
		name = src
	}
	if name == "" {
		return "unknown source"
	}
	return maskRuns(name)
}

var nameRe = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

// locHref prefers the URL an engine gave, then builds one from the parts it can trust.
// Gists link to the owner's list: their id is long and key-like, and the page shows
// eight characters of it to look for.
func locHref(l core.Location) string {
	if h := safeLink(l.URL); h != "" {
		return h
	}
	src := clean(l.Source)
	switch {
	case strings.HasPrefix(src, "gist.github.com/"):
		owner, _, _ := strings.Cut(strings.TrimPrefix(src, "gist.github.com/"), "/")
		if nameRe.MatchString(owner) {
			return safeLink("https://gist.github.com/" + owner)
		}
	case strings.HasPrefix(src, "github.com/"):
		owner, name, ok := strings.Cut(strings.TrimPrefix(src, "github.com/"), "/")
		wiki := strings.HasSuffix(name, ".wiki")
		name = strings.TrimSuffix(name, ".wiki")
		if !ok || !nameRe.MatchString(owner) || !nameRe.MatchString(name) {
			return ""
		}
		base := "https://github.com/" + owner + "/" + name
		sha := shortSHA(l.Commit)
		switch {
		case wiki:
			return safeLink(base + "/wiki")
		case sha != "" && l.Path != "":
			segs := strings.Split(clean(l.Path), "/")
			for i, sg := range segs {
				segs[i] = url.PathEscape(sg)
			}
			h := base + "/blob/" + sha + "/" + strings.Join(segs, "/")
			if l.Line > 0 {
				h += "#L" + strconv.Itoa(l.Line)
			}
			return safeLink(h)
		case sha != "":
			return safeLink(base + "/commit/" + sha)
		}
		return safeLink(base)
	}
	return ""
}

// --- lists ----------------------------------------------------------------------------

func (in input) list(ss []core.Secret, summary string) listView {
	lv := listView{Summary: summary, Empty: len(ss) == 0}
	if len(ss) > rowCap {
		lv.Capped = "Showing " + num(rowCap) + " of " + num(len(ss)) + ". The rest are in findings.json."
		ss = ss[:rowCap]
	}
	lv.Rows = in.rows(ss, false)
	return lv
}

func lowerSummary(low []core.Secret) string {
	if len(low) == 0 {
		return "Lower severity: none"
	}
	var med, lo, unrated int
	for _, s := range low {
		switch sev(s.Severity) {
		case core.Medium:
			med++
		case core.Low:
			lo++
		default:
			unrated++
		}
	}
	parts := []string{}
	if med > 0 {
		parts = append(parts, num(med)+" medium")
	}
	if lo > 0 {
		parts = append(parts, num(lo)+" low")
	}
	if unrated > 0 {
		parts = append(parts, num(unrated)+" not rated")
	}
	return "Lower severity: " + num(len(low)) + " to review (" + strings.Join(parts, ", ") + ")"
}

func ignoredSummary(ign []core.Secret) string {
	if len(ign) == 0 {
		return "Ignored: none"
	}
	var you, done, rest int
	for _, s := range ign {
		switch s.Status {
		case "ignored":
			you++
		case "resolved":
			done++
		default:
			rest++
		}
	}
	parts := []string{}
	if you > 0 {
		parts = append(parts, num(you)+" marked by you")
	}
	if done > 0 {
		parts = append(parts, num(done)+" resolved")
	}
	if rest > 0 {
		parts = append(parts, num(rest)+" need no action")
	}
	return "Ignored: " + num(len(ign)) + " (" + strings.Join(parts, ", ") + ")"
}

// --- layers, coverage, engines --------------------------------------------------------

func (in input) layersView() layersView {
	lv := layersView{}
	down := downLayers(in.layers)
	switch {
	case len(in.layers) == 0:
		lv.Summary, lv.Class = "No layer check has run yet.", "unknown"
	case down == 0:
		lv.Summary, lv.Class = "All "+plural(len(in.layers), "layer", "layers")+" working.", "ok"
		if len(in.layers) == 1 {
			lv.Summary = "The 1 layer is working."
		}
	default:
		lv.Summary, lv.Class = plural(down, "layer is", "layers are")+" down.", "alert"
	}
	// Broken layers first: the reader should not have to scan for the red one.
	order := append([]core.LayerStatus(nil), in.layers...)
	sort.SliceStable(order, func(i, j int) bool { return !order[i].OK && order[j].OK })
	for _, l := range order {
		r := layerRow{Name: ident(l.Name), Detail: prose(l.Detail)}
		if !l.OK || l.Detail != "ok" {
			r.Fix = prose(l.Fix) // what to run, for a layer that is down or has something to say
		}
		if l.OK {
			r.State, r.Class = "Working", "ok"
		} else {
			r.State, r.Class = "Down", "alert"
		}
		if t, ok := parseTime(l.CheckedAt, in.zone); ok {
			r.Checked = stamp(t, in.zone) + " · " + ago(in.now.Sub(t))
		} else if l.CheckedAt != "" {
			r.Checked = ident(l.CheckedAt)
		} else {
			r.Checked = "—"
		}
		lv.Rows = append(lv.Rows, r)
	}
	return lv
}

func (in input) coverageView() coverageView {
	r, c := in.run, in.cov
	count := func(label string, n int, note string) covRow {
		if n == 0 {
			return covRow{Label: label, Value: "—", Missing: true, Note: "not reported"}
		}
		return covRow{Label: label, Value: num(n), Note: note}
	}
	rows := []covRow{{Label: "Sources watched", Value: num(r.Sources)}}
	if c.Repos+c.Wikis+c.Gists > 0 {
		rows = append(rows,
			covRow{Label: "Repos", Value: num(c.Repos)},
			covRow{Label: "Wikis", Value: num(cmp.Or(c.Wikis, r.Wikis))},
			covRow{Label: "Gists", Value: num(cmp.Or(c.Gists, r.Gists))},
			covRow{Label: "Public sources", Value: num(c.Public), Note: "anyone can read these"})
	} else {
		rows = append(rows, covRow{Label: "Repos, wikis, gists", Value: "—", Missing: true, Note: "not reported"})
	}
	rows = append(rows,
		covRow{Label: "Scanned this run", Value: num(r.Scanned)},
		covRow{Label: "Skipped", Value: num(r.Skipped), Note: "nothing new in them, or private and out of scope"},
		covRow{Label: "Failed", Value: num(r.Failed), Warn: r.Failed > 0, Note: failedNote(r.Failed)},
		count("Refs", cmp.Or(r.Refs, c.Refs), "branches, tags, pull refs"),
		count("Commits scanned", cmp.Or(r.Commits, c.Commits), ""),
		count("Files scanned", cmp.Or(r.Blobs, c.Blobs), "git blobs"),
		count("API items scanned", cmp.Or(r.APIResources, c.APIItems), "issues, PRs, comments, releases"),
		covRow{Label: "New secrets this run", Value: num(r.NewFPs)})
	if r.Alerts > 0 {
		rows = append(rows, covRow{Label: "GitHub alerts imported", Value: num(r.Alerts)})
	}
	if t, ok := parseTime(r.Finished, in.zone); ok {
		rows = append(rows, covRow{Label: "Last run", Value: stamp(t, in.zone), Note: runKind(r.Kind)})
		if s, ok := parseTime(r.Started, in.zone); ok && !t.Before(s) {
			rows = append(rows, covRow{Label: "Run time", Value: dur(t.Sub(s))})
		}
	} else {
		rows = append(rows, covRow{Label: "Last run", Value: "—", Missing: true, Note: "no scan has finished"})
	}
	cv := coverageView{Rows: rows}
	for _, n := range r.Notes {
		if n = strings.TrimSpace(prose(n)); n != "" {
			cv.Notes = append(cv.Notes, n)
		}
	}
	cv.NotesN = num(len(cv.Notes))
	return cv
}

func failedNote(n int) string {
	if n == 0 {
		return ""
	}
	return "a sync or an engine did not finish; they are tried again next run"
}

func (in input) enginesView() enginesView {
	names := make([]string, 0, len(in.run.Engines))
	for n := range in.run.Engines {
		names = append(names, n)
	}
	sort.Strings(names)
	ev := enginesView{Empty: len(names) == 0}
	for _, n := range names {
		e := in.run.Engines[n]
		ev.Rows = append(ev.Rows, engineRow{
			Name: ident(n), Time: secs(e.Seconds), Hits: num(e.Hits), Errors: num(e.Errors), Warn: e.Errors > 0,
		})
	}
	return ev
}
