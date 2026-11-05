// Package upgrade decides, once a week, whether an engine may move to a newer release. It is a
// library: it reads GitHub's releases API anonymously, downloads the darwin/arm64 build and the
// project's checksums file into a temporary directory, verifies them, runs the bench on the pinned
// engine and the candidate, and returns what it found and what it would do. It never installs
// anything and never touches the engine that is in use. The CLI command and the launchd job that
// call it live in cmd/keyguard.
//
// Why it is gated: engines are pinned (docs/STEAL.md P0-01) because an upgrade can silently change
// what is found. betterleaks 2.0 candidates drop the flags the hooks use, and a Discord-shaped
// fake that titus 1.2.10 reports is not reported by 1.3.0. A candidate is accepted only if the
// bench says it is no worse: recall and precision both at least the pinned engine's, and one scan
// no more than 1.10 times as slow.
package upgrade

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

// Source is where one engine's releases are published.
type Source struct {
	Name   string // the engine's name in keyguard
	Repo   string // owner/name on GitHub
	Binary string // the engine's file name inside an archive
}

// Sources are the four engines keyguard runs.
var Sources = []Source{
	{"betterleaks", "betterleaks/betterleaks", "betterleaks"},
	{"gitleaks", "gitleaks/gitleaks", "gitleaks"},
	{"trufflehog", "trufflesecurity/trufflehog", "trufflehog"},
	{"titus", "praetorian-inc/titus", "titus"},
}

// Pinned is the engine keyguard runs today.
type Pinned struct {
	Path    string // the pinned copy, which is only ever read
	Version string // as the engine reports it
}

// Row is how one engine binary scored on the bench corpus.
type Row struct {
	Version   string  `json:"version"`
	Recall    float64 `json:"recall"`     // over the plants an engine's rules cover by design
	RecallAll float64 `json:"recall_all"` // over every planted secret
	Precision float64 `json:"precision"`
	Seconds   float64 `json:"seconds"` // one scan of the corpus: the fastest of the timed runs
}

// Scorer runs the bench on one engine binary.
type Scorer interface {
	Score(ctx context.Context, engine, bin string) (Row, error)
}

// ScorerFunc adapts a function to Scorer.
type ScorerFunc func(ctx context.Context, engine, bin string) (Row, error)

func (f ScorerFunc) Score(ctx context.Context, engine, bin string) (Row, error) {
	return f(ctx, engine, bin)
}

// Options tunes a check. The zero value reads api.github.com, stages under the system temp
// directory and times each binary three times; Scorer is required.
type Options struct {
	API    string // base URL of the releases API; tests point it at a local server
	Client *http.Client
	// Dir is where staging directories are made. The library never removes them: a candidate that
	// is accepted is installed from one, and the caller clears the rest.
	Dir    string
	Scorer Scorer
	// Runs is how many times each binary is scored (5). Accuracy is the same every time. The wall
	// time is the fastest run: load only ever adds time, so the fastest is the best estimate of what a
	// scan costs, where a median swings with whatever else the machine is doing. The two binaries take
	// turns, so a load that comes and goes meets both.
	Runs int
	// SlowLimit is how many times as long as the pinned engine a candidate may take (1.10).
	SlowLimit float64
	// MaxDownload and MaxBinary cap the bytes of a download and of an unpacked engine.
	MaxDownload, MaxBinary int64
}

func (o *Options) api() string {
	if o.API != "" {
		return strings.TrimRight(o.API, "/")
	}
	return "https://api.github.com"
}

func (o *Options) client() *http.Client {
	base := o.Client
	if base == nil {
		base = &http.Client{Timeout: 10 * time.Minute}
	}
	c := *base
	// a redirect may go to GitHub's storage hosts and nowhere else
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("upgrade: too many redirects")
		}
		if !o.hostOK(strings.ToLower(req.URL.Host)) {
			return fmt.Errorf("upgrade: redirected to %s, which is not GitHub", req.URL.Host)
		}
		return nil
	}
	return &c
}

func (o *Options) userAgent() string { return "keyguard-upgrade" }
func (o *Options) tempRoot() string {
	if o.Dir != "" {
		return o.Dir
	}
	return os.TempDir()
}
func (o *Options) runs() int {
	if o.Runs > 0 {
		return o.Runs
	}
	return 5
}
func (o *Options) slowLimit() float64 {
	if o.SlowLimit > 0 {
		return o.SlowLimit
	}
	return 1.10
}
func (o *Options) maxDownload() int64 {
	if o.MaxDownload > 0 {
		return o.MaxDownload
	}
	return 400 << 20
}
func (o *Options) maxBinary() int64 {
	if o.MaxBinary > 0 {
		return o.MaxBinary
	}
	return 600 << 20
}

// Candidate is a release that was downloaded, verified and scored.
type Candidate struct {
	Version     string `json:"version"`
	Tag         string `json:"tag"`
	Path        string `json:"path"`   // the staged binary, mode 0755, in Decision.Dir
	SHA256      string `json:"sha256"` // of the binary: the hash to pin
	Asset       string `json:"asset"`
	AssetSHA256 string `json:"asset_sha256"` // of the download, which matched the checksums file
	Row         Row    `json:"row"`
}

// Decision is what a check found for one engine and what it would do. Nothing has been installed.
type Decision struct {
	Engine string `json:"engine"`
	Pinned Pinned `json:"pinned"`
	// Latest is the highest stable release; Skipped are the releases passed over and why
	// (betterleaks has only 2.0 release candidates past 1.9.0).
	Latest  string `json:"latest"`
	Skipped []Skip `json:"skipped,omitempty"`
	// PinnedRow and Candidate carry the two score rows; both are zero when nothing newer exists.
	PinnedRow *Row       `json:"pinned_row,omitempty"`
	Candidate *Candidate `json:"candidate,omitempty"`
	// Switch is the decision. Reasons list every test, passed or failed.
	Switch  bool     `json:"switch"`
	Reasons []string `json:"reasons"`
	Dir     string   `json:"dir,omitempty"` // the staging directory, when one was made
	Err     string   `json:"error,omitempty"`
}

// Decide applies the rule: the candidate's recall (over the detectable plants and over all of
// them) and its precision are each at least the pinned engine's, and one scan takes no more than
// limit times as long. Both recalls are required because "recall" is one of them in the bench's
// headline and the other in its table, and a candidate that is better by one reading and worse by
// the other has changed what is found. Every test is listed in the reasons.
func Decide(pinned, cand Row, limit float64) (bool, []string) {
	ok := true
	var why []string
	const eps = 1e-9
	test := func(name string, passed bool, format string, a ...any) {
		mark := "ok"
		if !passed {
			mark, ok = "FAIL", false
		}
		why = append(why, fmt.Sprintf("%s: %s: %s", mark, name, fmt.Sprintf(format, a...)))
	}
	test("recall", cand.Recall >= pinned.Recall-eps, "%.1f%% against %.1f%% pinned", 100*cand.Recall, 100*pinned.Recall)
	test("recall (all plants)", cand.RecallAll >= pinned.RecallAll-eps, "%.1f%% against %.1f%% pinned", 100*cand.RecallAll, 100*pinned.RecallAll)
	test("precision", cand.Precision >= pinned.Precision-eps, "%.1f%% against %.1f%% pinned", 100*cand.Precision, 100*pinned.Precision)
	test("speed", cand.Seconds <= limit*pinned.Seconds+eps, "%.2f s against %.2f s pinned, limit %.2fx = %.2f s", cand.Seconds, pinned.Seconds, limit, limit*pinned.Seconds)
	return ok, why
}

// Check looks for a newer stable release of one engine and, if there is one, stages it and
// scores it against the pinned engine. With nothing newer it makes no download and no score.
func (o *Options) Check(ctx context.Context, src Source, pin Pinned) (Decision, error) {
	d := Decision{Engine: src.Name, Pinned: pin}
	if o.Scorer == nil {
		return d, errors.New("upgrade: no scorer")
	}
	pv, ok := ParseVersion(pin.Version)
	if !ok {
		return d, fmt.Errorf("upgrade: the pinned %s reports no version (%q)", src.Name, pin.Version)
	}
	rel, ver, skipped, err := o.LatestStable(ctx, src.Repo)
	d.Skipped = skipped
	if err != nil {
		return d, err
	}
	d.Latest = ver.String()
	if ver.Compare(pv) <= 0 {
		d.Reasons = []string{fmt.Sprintf("the pinned %s is the latest stable release (%s)", pv, ver)}
		return d, nil
	}

	st, err := o.Stage(ctx, src, rel, ver)
	d.Dir = st.Dir
	if err != nil {
		return d, err
	}
	pinnedRow, candRow, err := o.score(ctx, src.Name, pin.Path, st.Binary)
	if err != nil {
		return d, err
	}
	d.PinnedRow = &pinnedRow
	d.Candidate = &Candidate{Version: ver.String(), Tag: rel.Tag, Path: st.Binary, SHA256: st.SHA256, Asset: st.Asset, AssetSHA256: st.AssetSHA256, Row: candRow}
	// the binary has to be what the release says it is
	if rv, ok := ParseVersion(candRow.Version); !ok || rv.Compare(ver) != 0 {
		d.Candidate = nil // a binary that is not what its release says is offered to nobody
		d.Reasons = []string{fmt.Sprintf("the staged binary reports version %q, the release is %s", candRow.Version, ver)}
		return d, fmt.Errorf("upgrade: the staged %s reports %q, not %s", src.Name, candRow.Version, ver)
	}
	d.Switch, d.Reasons = Decide(pinnedRow, candRow, o.slowLimit())
	return d, nil
}

// score runs the pinned binary and the candidate, taking turns, and returns one row each. The
// accuracy figures are the pinned engine's best against the candidate's worst, so noise cannot
// let a candidate through; the seconds are each binary's fastest run.
func (o *Options) score(ctx context.Context, engine, pinnedBin, candBin string) (Row, Row, error) {
	var ps, cs []Row
	for i := 0; i < o.runs(); i++ {
		p, err := o.Scorer.Score(ctx, engine, pinnedBin)
		if err != nil {
			return Row{}, Row{}, fmt.Errorf("upgrade: scoring the pinned %s: %w", engine, err)
		}
		c, err := o.Scorer.Score(ctx, engine, candBin)
		if err != nil {
			return Row{}, Row{}, fmt.Errorf("upgrade: scoring the candidate %s: %w", engine, err)
		}
		ps, cs = append(ps, p), append(cs, c)
	}
	return aggregate(ps, true), aggregate(cs, false), nil
}

func aggregate(rows []Row, best bool) Row {
	out := rows[0]
	secs := make([]float64, len(rows))
	for i, r := range rows {
		secs[i] = r.Seconds
		pick := func(cur, v float64) float64 {
			if best == (v > cur) {
				return v
			}
			return cur
		}
		out.Recall, out.RecallAll, out.Precision = pick(out.Recall, r.Recall), pick(out.RecallAll, r.RecallAll), pick(out.Precision, r.Precision)
	}
	sort.Float64s(secs)
	out.Seconds = secs[0]
	return out
}

// CheckAll checks every engine in pins, in the order of Sources. One engine failing does not stop
// the others, except that a spent rate limit ends the round: the rest are marked as not checked.
func (o *Options) CheckAll(ctx context.Context, pins map[string]Pinned) []Decision {
	var out []Decision
	limited := ""
	for _, src := range Sources {
		pin, ok := pins[src.Name]
		if !ok {
			continue
		}
		if limited != "" {
			out = append(out, Decision{Engine: src.Name, Pinned: pin, Err: "not checked: " + limited})
			continue
		}
		d, err := o.Check(ctx, src, pin)
		if err != nil {
			d.Err = err.Error()
			var rl *RateLimitError
			if errors.As(err, &rl) {
				limited = err.Error()
			}
		}
		out = append(out, d)
	}
	return out
}
