package known

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"keyguard/internal/core"
	"keyguard/internal/fp"
)

// Runner runs an external command and returns its stdout. Learn uses it for `gh auth
// token`; tests inject a fake so no real credential is ever asked for.
type Runner func(ctx context.Context, name string, args ...string) ([]byte, error)

// Options configures one Learn run. The zero value learns from the places PLAN.md lists,
// under the real home directory, into core.Root(). Tests point Home and Root at temp dirs;
// everything else follows from Home.
type Options struct {
	Ctx  context.Context // nil means context.Background()
	Root string          // data root; "" means core.Root()
	Home string          // "" means the user's home directory

	// EnvRoots are walked for .env* files; nil means ~/dev ~/projects ~/Tools ~/sec.
	EnvRoots []string
	// SkipDirs are never entered; nil means ~/sec/tools ~/sec/targets ~/sec/practice
	// ~/sec/ctf. node_modules, .git and the usual dependency and cache directories are
	// always skipped.
	SkipDirs []string
	// Files are extra files to read, parsed by their names like any other source.
	Files []string
	// GHUsers are the gh accounts whose tokens are learned, the config's accounts. nil or
	// empty learns none.
	GHUsers []string
	Run     Runner // nil means os/exec with a timeout

	// Engines are the second opinion on values whose names do not look secret: a value
	// that passes the value filters but sits under a harmless name is learned if an
	// engine flags it when scanning the file it came from. ScanDir is called with that
	// FILE's path, and the engine must fingerprint with the keyring of Root (Hit.FP is
	// compared with this run's own fingerprints). Unavailable engines are skipped, up to
	// four files are scanned at once per engine, and files with no unnamed candidate are
	// never handed over, so the cost is one engine start-up per file that needs a second
	// opinion.
	Engines []core.Engine

	// Env is a process environment ("NAME=value", as os.Environ returns). nil learns none,
	// which is what tests want; the CLI passes its own so exports computed at shell start
	// are learned too.
	Env []string

	// KeepPublic also learns values issuers publish on purpose (Stripe publishable keys,
	// PostHog project keys, Supabase anon JWTs and the like). By default they are skipped:
	// they belong in client code, and learning them would block ordinary commits.
	KeepPublic bool

	// Prune drops entries whose value was not found this run. Without it a store only
	// grows: sources get moved into ~/Archive all the time, and a key that is still live
	// must stay protected after its file is gone.
	Prune bool

	// Log receives one line per file read and per decision to skip: counts and paths,
	// never values. nil is silent.
	Log io.Writer
}

// Report says what a Learn run did, without any value in it.
type Report struct {
	Root       string
	Store      string // path of known.json
	Files      int    // source files read
	Candidates int    // values looked at, before filters
	Learned    []Learned
	Added      int            // secrets new to the store
	Refreshed  int            // secrets already in the store and found again
	Retained   int            // secrets in the store, not found this run, kept
	Pruned     int            // secrets in the store, not found this run, dropped (Prune)
	Entries    int            // forms in the store after this run
	Rejected   map[string]int // by reason; occurrences, except "name", which counts distinct values
	Skipped    []string       // "path: reason"
	Notes      []string       // anything dropped, capped or unavailable
}

// Learned is one secret this run found, in display form only.
type Learned struct {
	ID     string
	Name   string
	Source string
	Shape  string
	Len    int
	Forms  int
	New    bool
}

// Summary renders the report as plain text for the CLI.
func (r *Report) Summary() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "learned %d secrets (%d new, %d refreshed), %d retained, %d pruned; %d forms in %s\n",
		len(r.Learned), r.Added, r.Refreshed, r.Retained, r.Pruned, r.Entries, r.Store)
	fmt.Fprintf(&sb, "read %d files, looked at %d values", r.Files, r.Candidates)
	keys := make([]string, 0, len(r.Rejected))
	for k := range r.Rejected {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&sb, ", %d %s", r.Rejected[k], k)
	}
	sb.WriteString(" rejected\n")
	for _, s := range r.Learned {
		mark := " "
		if s.New {
			mark = "+"
		}
		fmt.Fprintf(&sb, "%s %s  %-28s %-24s len %-4d %2d forms  %s\n", mark, s.ID, s.Name, s.Shape, s.Len, s.Forms, s.Source)
	}
	for _, s := range r.Skipped {
		fmt.Fprintf(&sb, "skipped %s\n", s)
	}
	for _, n := range r.Notes {
		fmt.Fprintf(&sb, "note: %s\n", n)
	}
	return sb.String()
}

func (o Options) withDefaults() (Options, error) {
	if o.Ctx == nil {
		o.Ctx = context.Background()
	}
	if o.Root == "" {
		o.Root = core.Root()
	}
	if o.Home == "" {
		h, err := os.UserHomeDir()
		if err != nil {
			return o, err
		}
		o.Home = h
	}
	join := func(rel ...string) []string {
		out := make([]string, len(rel))
		for i, r := range rel {
			out[i] = home(o.Home, r)
		}
		return out
	}
	if o.EnvRoots == nil {
		o.EnvRoots = join("dev", "projects", "Tools", "sec")
	}
	if o.SkipDirs == nil {
		o.SkipDirs = join("sec/tools", "sec/targets", "sec/practice", "sec/ctf")
	}
	if o.Run == nil {
		o.Run = runCommand
	}
	return o, nil
}

// runCommand runs gh. GH_TOKEN and GITHUB_TOKEN are removed so `--user X` answers with
// X's stored login rather than echoing an environment token for every account.
func runCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "GH_TOKEN=") && !strings.HasPrefix(kv, "GITHUB_TOKEN=") {
			cmd.Env = append(cmd.Env, kv)
		}
	}
	cmd.Env = append(cmd.Env, "GH_PROMPT_DISABLED=1", "NO_COLOR=1")
	return cmd.Output()
}

// cand is one distinct value seen during the harvest. The value is the map key in
// learner.cands and stays in memory; nothing here is written anywhere.
type cand struct {
	name, source string
	ok           bool // the name filter passed, or the position makes it a credential
	files        []string
}

type learner struct {
	o          Options
	rep        *Report
	cands      map[string]*cand
	read       map[string]bool // files already harvested, so a sourced file is read once
	unreadable int             // sources that exist but could not be read: they veto Prune
}

// Learn harvests the secrets on this machine and merges their hashes into the store under
// Options.Root. Raw values live in this function's memory and nowhere else: not in the
// store, the Report, the Log, or any error.
func Learn(opts Options) (*Report, error) {
	o, err := opts.withDefaults()
	if err != nil {
		return nil, err
	}
	paths := core.PathsAt(o.Root)
	kr, err := fp.Load(paths.Known)
	if err != nil {
		return nil, err
	}
	rep := &Report{Root: o.Root, Store: filepath.Join(paths.Known, storeFile), Rejected: map[string]int{}}
	l := &learner{o: o, rep: rep, cands: map[string]*cand{}, read: map[string]bool{}}
	l.harvest()
	if err := o.Ctx.Err(); err != nil {
		return rep, err
	}
	detected := l.detect(kr)

	type secret struct {
		value string
		*cand
		fp string
	}
	var found []secret
	for v, c := range l.cands {
		fpv := kr.FP(v)
		// The engines fingerprint the canonical form of what they report (STEAL P0-08): the
		// password of a connection URI, a private key unwrapped to one line. A value that is one of
		// those is corroborated under that form, not under the raw one.
		if !c.ok && !detected[fpv] && !detected[kr.FP(fp.Canonical(v))] {
			rep.Rejected[rejName]++
			continue
		}
		found = append(found, secret{v, c, fpv})
	}
	sort.Slice(found, func(i, j int) bool {
		a, b := found[i], found[j]
		if a.name != b.name {
			return a.name < b.name
		}
		return a.fp < b.fp
	})

	// The harvest above can take a while and needs no lock; the read-merge-write below does,
	// or two runs (the weekly deep job and a manual one) could each write a store that lacks
	// what the other just learned.
	unlock, err := lockStore(paths.Known)
	if err != nil {
		return rep, err
	}
	defer unlock()

	old, err := readStore(paths.Known)
	if errors.Is(err, errNotJSON) {
		// A store nothing can read protects nothing. Move it aside (never delete: it may
		// be a hand edit worth recovering) and start a fresh one.
		bad := fmt.Sprintf("%s.bad-%d", filepath.Join(paths.Known, storeFile), time.Now().Unix())
		if rerr := os.Rename(filepath.Join(paths.Known, storeFile), bad); rerr != nil {
			return rep, err
		}
		rep.Notes = append(rep.Notes, "the previous store was unreadable and was moved to "+bad)
		old, err = nil, nil
	}
	if err != nil {
		return rep, err
	}
	var kept []Entry
	if old != nil {
		if old.SaltCheck == saltCheck(kr) {
			kept = old.Entries
		} else if len(old.Entries) > 0 {
			rep.Notes = append(rep.Notes, fmt.Sprintf("the previous store was keyed by a different salt and cannot be matched: %d forms dropped", len(old.Entries)))
		}
	}
	had := map[string]bool{}
	for _, e := range kept {
		had[e.FP] = true
	}

	h := newHasher(kr.Base())
	type group struct {
		name, fp string
		entries  []Entry
	}
	var groups []group
	fresh := map[string]bool{}
	for _, s := range found {
		es := newEntries(kr, h, s.name, s.source, []byte(s.value))
		if len(es) == 0 {
			continue
		}
		fresh[s.fp] = true
		groups = append(groups, group{s.name, s.fp, es})
		isNew := !had[s.fp]
		if isNew {
			rep.Added++
		} else {
			rep.Refreshed++
		}
		rep.Learned = append(rep.Learned, Learned{
			ID: es[0].ID, Name: s.name, Source: s.source, Shape: es[0].Shape, Len: len(s.value), Forms: len(es), New: isNew,
		})
	}
	prune := o.Prune
	if prune && (rep.Files == 0 || l.unreadable > 0) {
		// A secret is gone only if its place was read and it was not there.
		prune = false
		rep.Notes = append(rep.Notes, "prune skipped: some sources could not be read, so nothing proves the old secrets are gone")
	}
	oldGroups := map[string]*group{}
	var oldOrder []string
	for _, e := range kept {
		if fresh[e.FP] {
			continue
		}
		g := oldGroups[e.FP]
		if g == nil {
			g = &group{name: e.Name, fp: e.FP}
			oldGroups[e.FP] = g
			oldOrder = append(oldOrder, e.FP)
		}
		g.entries = append(g.entries, e)
	}
	for _, f := range oldOrder {
		if prune {
			rep.Pruned++
			continue
		}
		rep.Retained++
		groups = append(groups, *oldGroups[f])
	}
	sort.SliceStable(groups, func(i, j int) bool {
		if groups[i].name != groups[j].name {
			return groups[i].name < groups[j].name
		}
		return groups[i].fp < groups[j].fp
	})
	var entries []Entry
	for _, g := range groups {
		entries = append(entries, g.entries...)
	}
	rep.Entries = len(entries)
	if err := writeStore(paths.Known, &Store{Version: storeVersion, SaltCheck: saltCheck(kr), Updated: now(), Entries: entries}); err != nil {
		return rep, err
	}
	l.logf("learn: wrote %d forms of %d secrets", len(entries), len(groups))
	return rep, nil
}

func (l *learner) logf(format string, args ...any) {
	if l.o.Log != nil {
		fmt.Fprintf(l.o.Log, format+"\n", args...)
	}
}

func (l *learner) skip(path, reason string) {
	l.rep.Skipped = append(l.rep.Skipped, path+": "+reason)
	l.logf("learn: skipped %s: %s", path, reason)
}

// ingest takes one name/value pair from a parser. Values that carry other secrets are
// unpacked first: private keys become their lines, URLs their passwords, base64 blobs
// the key they wrap, and an Authorization value its credential without the scheme word.
func (l *learner) ingest(name, value, source string, trusted bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	l.rep.Candidates++
	if strings.Contains(value, "PRIVATE KEY-----") {
		l.privateKeys(source, baseName(source)+" "+name, value)
		return
	}
	for _, pw := range urlPasswords(value) {
		l.consider(name+" (url password)", pw, source, true)
	}
	if len(value) >= 100 {
		if dec, ok := decodeBase64(value); ok && strings.Contains(dec, "PRIVATE KEY-----") {
			l.privateKeys(source, baseName(source)+" "+name+" (base64)", dec)
		}
	}
	for _, scheme := range []string{"bearer ", "basic ", "token "} {
		if len(value) > len(scheme) && strings.EqualFold(value[:len(scheme)], scheme) {
			cred := strings.TrimSpace(value[len(scheme):])
			l.consider(name, cred, source, trusted)
			if scheme == "basic " { // base64(user:password)
				if pair, ok := decodeBase64(cred); ok {
					if _, pw, ok := strings.Cut(pair, ":"); ok {
						l.consider(name+" (basic auth password)", pw, source, true)
					}
				}
			}
		}
	}
	l.consider(name, value, source, trusted)
}

// ingestTrusted is ingest for values whose position already says credential (a netrc
// password, an npm auth token, the body of a private key): the name filter is skipped, the
// value filters are not.
func (l *learner) ingestTrusted(name, value, source string) {
	l.ingest(name, value, source, true)
}

func (l *learner) consider(name, v, source string, trusted bool) {
	if why := reject(v, trusted); why != "" {
		l.rep.Rejected[why]++
		return
	}
	if !l.o.KeepPublic && publicByDesign(v) {
		l.rep.Rejected[rejPublic]++
		return
	}
	ok := trusted || nameLooksSecret(name)
	if c := l.cands[v]; c == nil {
		l.cands[v] = &cand{name: name, source: source, ok: ok, files: []string{source}}
	} else {
		if len(c.files) < 64 && !contains(c.files, source) {
			c.files = append(c.files, source)
		}
		if !c.ok && ok { // the same value under a name that says what it is
			c.name, c.source, c.ok = name, source, true
		}
	}
	if d, isCard := cardNumber(v); isCard && d != v {
		l.consider(name, d, source, trusted)
	}
}

func contains(s []string, x string) bool {
	for _, y := range s {
		if y == x {
			return true
		}
	}
	return false
}

// detect asks the engines about the values nothing else vouches for, by scanning the files
// those values came from, and returns the fingerprints they flagged.
func (l *learner) detect(kr *fp.Keyring) map[string]bool {
	flagged := map[string]bool{}
	seen := map[string]bool{}
	var files []string
	for _, c := range l.cands {
		if c.ok {
			continue
		}
		for _, f := range c.files {
			if !seen[f] {
				seen[f] = true
				files = append(files, f)
			}
		}
	}
	sort.Strings(files)
	if len(files) == 0 {
		return flagged
	}
	var mu sync.Mutex
	for _, eng := range l.o.Engines {
		if !eng.Available() {
			l.rep.Notes = append(l.rep.Notes, "engine "+eng.Name()+" is not installed: skipped for unnamed values")
			continue
		}
		failed := 0
		var wg sync.WaitGroup
		sem := make(chan struct{}, 4)
		for _, f := range files {
			wg.Add(1)
			sem <- struct{}{}
			go func(f string) {
				defer wg.Done()
				defer func() { <-sem }()
				err := eng.ScanDir(l.o.Ctx, f, core.ScanOpts{Threads: 1, Loc: core.Location{Source: "local:" + f, Kind: "file", Visibility: core.Local}}, func(h core.Hit) {
					mu.Lock()
					flagged[h.FP] = true
					mu.Unlock()
				})
				if err != nil {
					mu.Lock()
					failed++
					mu.Unlock()
				}
			}(f)
		}
		wg.Wait()
		if failed > 0 {
			l.rep.Notes = append(l.rep.Notes, fmt.Sprintf("engine %s could not scan %d of %d files", eng.Name(), failed, len(files)))
		}
		l.logf("learn: engine %s scanned %d files", eng.Name(), len(files))
	}
	return flagged
}
