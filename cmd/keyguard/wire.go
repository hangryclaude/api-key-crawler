package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"keyguard/internal/core"
	"keyguard/internal/db"
	"keyguard/internal/engines"
	"keyguard/internal/fp"
	"keyguard/internal/install"
	"keyguard/internal/inventory"
	"keyguard/internal/inventory/ghcli"
	"keyguard/internal/known"
	"keyguard/internal/mirror"
	"keyguard/internal/notify"
	"keyguard/internal/report"
	"keyguard/internal/sweep"
	"keyguard/internal/triage"
)

// lazyStore is the findings store, opened on first use. The sweep takes the run lock before
// its first touch of the store, and a store opened any earlier could be a copy that another
// process has since changed: saving it would write that other process's work away.
type lazyStore struct {
	paths core.Paths
	once  sync.Once
	st    *db.Store
	err   error
}

var (
	_ core.Store = (*lazyStore)(nil)
	_ interface {
		Evidence(string) ([]string, float64, []string, bool)
	} = (*lazyStore)(nil)
)

func (l *lazyStore) open() *db.Store {
	l.once.Do(func() { l.st, l.err = db.Open(l.paths) })
	return l.st
}

func (l *lazyStore) Merge(hits []core.Hit, now string) ([]string, error) {
	if s := l.open(); s != nil {
		return s.Merge(hits, now)
	}
	return nil, l.err
}

func (l *lazyStore) RefreshVisibility(vis map[string]core.Visibility) {
	if s := l.open(); s != nil {
		s.RefreshVisibility(vis)
	}
}

func (l *lazyStore) Secrets() []core.Secret {
	if s := l.open(); s != nil {
		return s.Secrets()
	}
	return nil
}

func (l *lazyStore) Get(f string) (core.Secret, bool) {
	if s := l.open(); s != nil {
		return s.Get(f)
	}
	return core.Secret{}, false
}

func (l *lazyStore) Put(s core.Secret) error {
	if st := l.open(); st != nil {
		return st.Put(s)
	}
	return l.err
}

func (l *lazyStore) Ignore(idOrFP, reason string) error {
	if s := l.open(); s != nil {
		return s.Ignore(idOrFP, reason)
	}
	return l.err
}

func (l *lazyStore) Save() error {
	if s := l.open(); s != nil {
		return s.Save()
	}
	return l.err
}

func (l *lazyStore) TakeNotes() []string {
	if s := l.open(); s != nil {
		return s.TakeNotes()
	}
	return nil
}

func (l *lazyStore) Evidence(f string) ([]string, float64, []string, bool) {
	if s := l.open(); s != nil {
		return s.Evidence(f)
	}
	return nil, 0, nil, false
}

// staleAfter is when the dashboard calls itself stale: the poll runs every minute, so a page
// whose last scan is half an hour old means the poller has stopped.
const staleAfter = 30 * time.Minute

// coverageReporter writes the dashboard with the inventory's counts, read when it writes:
// a sweep finishes after it has updated the snapshot, so the page shows the new one. What the
// run itself covered (refs, commits, blobs, API pages) is in its RunStats.
type coverageReporter struct{ paths core.Paths }

func (r coverageReporter) Write(secrets []core.Secret, run core.RunStats, layers []core.LayerStatus) (string, error) {
	rep := report.New(r.paths.Report)
	rep.StaleAfter = staleAfter
	if srcs, err := inventory.LoadSnapshot(r.paths.Inventory); err == nil {
		rep.Coverage = report.CoverageFromSources(srcs)
	}
	return rep.Write(secrets, run, layers)
}

// stack is everything a sweep command needs, built once per invocation.
type stack struct {
	c     *cli
	paths core.Paths
	cfg   install.Config
	kr    *fp.Keyring
	store *lazyStore
	known core.KnownMatcher // nil when nothing is learned
	notif core.Notifier
	inv   core.Inventory
	mir   mirrorAPI
	engs  []core.Engine
}

// stackOpts picks what a command scans with.
type stackOpts struct {
	tier    string   // which engines: a tier from config.json
	engines []string // overrides the tier when set
	noNet   bool     // do not build the inventory and the mirror (the command never needs GitHub)
	noFetch bool     // serve the mirrors already on disk and never clone or fetch
}

func (c *cli) buildStack(o stackOpts) (*stack, error) {
	p := c.paths()
	cfg := c.config(p)
	kr, err := openKeyring(p)
	if err != nil {
		return nil, err
	}
	s := &stack{c: c, paths: p, cfg: cfg, kr: kr, store: &lazyStore{paths: p}}

	names := o.engines
	if len(names) == 0 {
		names = cfg.Tier(o.tier)
	}
	for _, n := range names {
		if !contains(engines.Names, n) {
			return nil, fmt.Errorf("%q is not an engine keyguard has (%s)", n, strings.Join(engines.Names, ", "))
		}
		// Every scanner is checked against its pin each time it starts: a binary that is not the
		// pinned one does not run, and the sweep counts that source as failed, never as clean.
		e, err := engines.New(n, cfg.EnginePaths()[n], kr, cfg.EngineOptions(p)...)
		if err != nil {
			return nil, err
		}
		s.engs = append(s.engs, e)
	}

	if m, merr := known.LoadMatcher(core.KnownRoots()); merr != nil {
		c.warnf("the learned-secret store did not fully load: %s", safeErr(merr))
		if m != nil && m.Len() > 0 {
			s.known = m
		}
	} else if m != nil && m.Len() > 0 {
		s.known = m
	}

	s.notif = c.notifier(cfg)
	if o.noNet {
		return s, nil
	}
	switch {
	case c.seams.inventory != nil:
		s.inv, err = c.seams.inventory(cfg, p)
	case len(cfg.Accounts) == 0 && len(cfg.Orgs) == 0:
		s.inv = noInventory{p.Config}
	default:
		s.inv, err = inventory.New(cfg.InventoryConfig(p))
	}
	if err != nil {
		return nil, err
	}
	if c.seams.mirror != nil {
		s.mir, err = c.seams.mirror(p)
	} else {
		s.mir, err = mirror.New(mirrorConfig(cfg, p, o.noFetch))
	}
	if err != nil {
		return nil, err
	}
	return s, nil
}

// mirrorConfig is the mirror every command shares. ExposedOnly puts the sweep scope at the one place
// every fetch passes through: a private source is refused before git starts (a publish check hands
// over a what-if public one).
func mirrorConfig(cfg install.Config, p core.Paths, noFetch bool) mirror.Config {
	return mirror.Config{Root: cfg.MirrorRoot(p), NoFetch: noFetch, ExposedOnly: true}
}

func contains(list []string, x string) bool {
	for _, v := range list {
		if v == x {
			return true
		}
	}
	return false
}

// notifier builds the banner + iMessage notifier. A target that is not a phone number or an
// email is said out loud and iMessage is left off: the banner still works.
func (c *cli) notifier(cfg install.Config) core.Notifier {
	if c.seams.notifier != nil {
		return c.seams.notifier
	}
	n, err := notify.New(notify.Config{IMessageTo: cfg.Notify.IMessageTo})
	if err != nil {
		c.warnf("notify.imessage_to is not usable (%s); banners only", safeErr(err))
		n, err = notify.New(notify.Config{})
		if err != nil {
			return nil
		}
	}
	return n
}

// rulesFile is the installed rules path when the file is there, else "" (engine defaults).
// An engine given a rules path that does not exist fails the scan; a missing optional file
// should cost the extra rules, not the scan.
func (s *stack) rulesFile() string {
	if s.cfg.Rules != "" {
		if _, err := os.Stat(s.cfg.Rules); err == nil {
			return s.cfg.Rules
		}
	}
	return ""
}

// runnerOpts are the per-command knobs of a sweep.
type runnerOpts struct {
	jobs     int
	noVerify bool
	fresh    bool // read every blob again, still feeding the ledger
	noLedger bool // read every blob again and keep no ledger
}

func (s *stack) runner(o runnerOpts) (*sweep.Runner, error) {
	jobs := o.jobs
	if jobs <= 0 {
		jobs = s.cfg.Jobs
	}
	cfg := sweep.Config{
		Paths: s.paths, Inventory: s.inv, Mirror: s.mir, Engines: s.engs, Store: s.store,
		Triage:   triage.New(triage.WithStoreEvidence(s.store), triage.WithFingerprinter(s.kr)),
		Reporter: coverageReporter{s.paths}, Notifier: s.notif,
		Layers: s.c.layersFunc(s.paths), Jobs: jobs, NoVerify: o.noVerify, Rules: s.rulesFile(),
		Fresh: o.fresh, NoLedger: o.noLedger,
		// The pages the inventory names (an issue, a pull request, a release) are scanned by exact
		// URL with the token of the account that can read them; it goes to the scanner in its
		// environment and nowhere else (STEAL P0-22).
		Token: s.c.ghClient().Token,
		// PLAN.md "Sweep scope": only what a stranger can read is fetched and scanned. The rest
		// stay in the inventory, so the day one turns public it is scanned from the start.
		ExposedOnly: true,
	}
	if s.known != nil {
		cfg.Known = s.known
	}
	return sweep.New(cfg)
}

// ghClient is the GitHub client the commands that read tokens or settings share.
func (c *cli) ghClient() *ghcli.Client {
	if c.seams.gh != nil {
		return c.seams.gh
	}
	return ghcli.New(nil)
}

// doctorOptions builds the doctor's view of the machine from the CLI's environment. The full
// doctor also asks GitHub what time it is (one request that costs no quota) when there is an
// inventory to ask through.
func (c *cli) doctorOptions(p core.Paths, quick bool) install.DoctorOptions {
	o := install.DoctorOptions{
		Options: install.Options{Paths: p, Run: c.seams.run, Now: c.seams.now},
		Quick:   quick,
	}
	if quick {
		return o
	}
	cfg := c.config(p)
	var inv core.Inventory
	var err error
	if c.seams.inventory != nil {
		inv, err = c.seams.inventory(cfg, p)
	} else {
		ic := cfg.InventoryConfig(p)
		ic.Client = c.seams.gh // nil is the real gh
		inv, err = inventory.New(ic)
	}
	if sk, ok := inv.(interface {
		Skew(context.Context) (time.Duration, error)
	}); ok && err == nil {
		o.Skew = sk.Skew
	}
	return o
}

// layersFunc is the sweep's Config.Layers: the doctor's quick pass, folded into layers.
func (c *cli) layersFunc(p core.Paths) func() []core.LayerStatus {
	return func() []core.LayerStatus {
		r, err := install.Doctor(c.ctx, c.doctorOptions(p, true))
		if err != nil {
			return nil
		}
		return r.Layers()
	}
}

// noInventory stands in while config.json names no account or org, before the first install
// or without a gh login. A check of a local repo or of the saved inventory never asks it
// anything; whatever has to list GitHub gets the reason, not a crawl of nothing.
type noInventory struct{ config string }

func (n noInventory) err() error {
	return fmt.Errorf("no GitHub account to watch: run `keyguard install` with gh logged in, or add yours under \"accounts\" in %s", n.config)
}

func (n noInventory) List(context.Context) ([]core.Source, error) { return nil, n.err() }

func (n noInventory) Changed(context.Context, map[string]core.Source) ([]core.Source, []core.Event, error) {
	return nil, nil, n.err()
}

// lockedMessage turns the run lock's error into words the user can act on.
func lockedMessage(err error) (string, bool) {
	var le *db.LockedError
	if errors.As(err, &le) {
		who := "another keyguard run"
		if le.PID > 0 {
			who = fmt.Sprintf("keyguard pid %d", le.PID)
		}
		since := ""
		if le.Started != "" {
			since = " since " + le.Started
		}
		return who + " is running" + since + "; wait for it to finish", true
	}
	if errors.Is(err, db.ErrLocked) {
		return "another keyguard run is in progress; wait for it to finish", true
	}
	return "", false
}

// withStore opens the findings under the run lock, hands them to fn, and saves. A lock held
// by a scan is the usual reason for ErrLocked and is reported as such.
func (c *cli) withStore(p core.Paths, fn func(*db.Store) error) error {
	lock, err := db.AcquireLock(p.Lock)
	if err != nil {
		return err
	}
	defer lock.Release()
	st, err := db.Open(p)
	if err != nil {
		return err
	}
	if err := fn(st); err != nil {
		return err
	}
	if !lock.Held() {
		return sweep.ErrLockLost
	}
	return st.Save()
}
