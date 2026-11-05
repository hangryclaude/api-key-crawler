// Package install puts keyguard on this Mac and keeps it honest: the global git hooks, the
// installed binary and its rules, the two launchd jobs, the config file, and the doctor
// that says which of them has quietly stopped working.
//
// Everything here is idempotent and reversible. Install records what it changed in
// state/install.json, Uninstall reads that record and undoes exactly that, and neither
// ever deletes: what comes out is moved aside.
package install

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"

	"keyguard/internal/core"
	"keyguard/internal/db"
	"keyguard/internal/engines"
	"keyguard/internal/inventory"
	"keyguard/internal/inventory/ghcli"
)

// ConfigVersion is bumped when config.json changes shape in a way an old file cannot express.
const ConfigVersion = 1

// Tier names. A tier is the list of engines one job may use. The hook tiers run the first
// engine in the list that is installed (a hook has a latency budget and one regex engine
// is enough); the sweep tiers run every one that is.
const (
	TierPreCommit = "precommit"
	TierPrePush   = "prepush"
	TierVerify    = "verify" // the verifying pass for pushes to public or unknown remotes
	TierLearn     = "learn"  // the engine that vouches for values whose names do not look secret
	TierPoll      = "poll"
	TierDeep      = "deep"
)

// Config is state/config.json: whose GitHub to watch, which engine binaries to run and how
// wide, and where to tell the user.
type Config struct {
	Version  int                 `json:"version"`
	Accounts []string            `json:"accounts"`
	Orgs     []inventory.Org     `json:"orgs"`
	Engines  map[string]string   `json:"engines"`        // engine name -> absolute path of its binary
	Pins     map[string]Pin      `json:"pins,omitempty"` // what each engine was when Install last looked
	Tiers    map[string][]string `json:"tiers"`
	Jobs     int                 `json:"jobs"` // sources scanned at once
	Rules    string              `json:"rules"`
	Notify   Notify              `json:"notify"`
	// Mirrors is where the bare mirrors live. Empty, the usual case, means <root>/cache/mirrors.
	// Pointing it at another data root's cache lets a scan read mirrors that are already there
	// (with scan --no-fetch it changes nothing in them) without cloning fifteen gigabytes again.
	Mirrors string `json:"mirrors,omitempty"`
}

// MirrorRoot is the directory the bare mirrors are under.
func (c Config) MirrorRoot(p core.Paths) string {
	if c.Mirrors != "" {
		return c.Mirrors
	}
	return p.Mirrors
}

// Pin is an engine binary as Install found it. A hook that fails open on an engine that
// changed its flags protects nothing, so doctor compares the binary on disk with the pin.
type Pin struct {
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}

// Notify says where alerts go. iMessage is off until a target is set.
type Notify struct {
	IMessageTo string `json:"imessage_to"`
}

// DefaultJobs is the -j the sweep runs with: the box has 18 cores and most of a scan is
// waiting on engine processes and git.
const DefaultJobs = 8

// DefaultTiers is the engine assignment: the fastest engine at the gates, the three precise
// engines in the sweeps. `keyguard bench` is how this is tuned, and it says to leave titus
// out for now: with the real triage, betterleaks + gitleaks + trufflehog + the learned-secret
// matcher score recall 100% and precision 98.3% on the bench corpus, and adding titus keeps
// recall at 100% but takes precision to 86.2%, because titus reports fragments of credentials
// another engine already reported whole, under a different fingerprint (54 of its 65 false
// positives). The store does not yet fold such fragments into the secret they belong to.
// Add "titus" to the poll and deep tiers in config.json to run it anyway; it is the one engine
// that reads blobs, so it also sees a secret that exists only in a merge's conflict resolution.
func DefaultTiers() map[string][]string {
	sweep := []string{"betterleaks", "gitleaks", "trufflehog"}
	return map[string][]string{
		TierPreCommit: {"betterleaks", "gitleaks"},
		TierPrePush:   {"betterleaks", "gitleaks"},
		TierVerify:    {"trufflehog"},
		TierLearn:     {"betterleaks"},
		TierPoll:      slices.Clone(sweep),
		TierDeep:      slices.Clone(sweep),
	}
}

// discoverAccounts fills in the accounts of a first config: every github.com account gh is
// logged in to, and the orgs of the active one, read through it. Without gh or a login the
// config starts with none, and the warning says where to add them.
func (in *installer) discoverAccounts(cfg *Config) {
	out, err := in.o.Run(in.ctx, "gh", ghcli.AuthStatusArgs...)
	accts := ghcli.Logins(out)
	if err != nil || len(accts) == 0 {
		in.warn("gh is logged in to no GitHub account, so the crawl has none to watch: run gh auth login, or list yours under \"accounts\" in %s", in.o.Paths.Config)
		return
	}
	cfg.Accounts = accts
	out, err = in.o.Run(in.ctx, "gh", ghcli.OrgsArgs...)
	if err != nil {
		in.warn("could not list the orgs of %s, so none is watched: add them under \"orgs\" in %s", accts[0], in.o.Paths.Config)
		return
	}
	for _, o := range ghcli.Logins(out) {
		cfg.Orgs = append(cfg.Orgs, inventory.Org{Login: o, Via: accts[0]})
	}
}

// RulesPath is where the installed copy of rules/keyguard.toml lives.
func RulesPath(p core.Paths) string { return filepath.Join(p.Root, "rules", "keyguard.toml") }

// DefaultConfig is a working config for this Mac: no account yet (a first install asks gh,
// see discoverAccounts), the engines found on this machine, the PLAN.md tiers, and no
// notification target.
func DefaultConfig(p core.Paths, home string) Config {
	inv := inventory.DefaultConfig(p.State)
	return Config{
		Version:  ConfigVersion,
		Accounts: inv.Accounts,
		Orgs:     inv.Orgs,
		Engines:  DiscoverEngines(home),
		Tiers:    DefaultTiers(),
		Jobs:     DefaultJobs,
		Rules:    RulesPath(p),
	}
}

// DiscoverEngines finds each engine binary: on PATH first, then where this Mac keeps them.
// The result holds absolute paths of the engines it found; a missing one is left out, so
// doctor can say so instead of the config naming a path that never existed. Symlinks are
// kept as they are (titus is one, repointed on upgrade); Pins hash what they resolve to.
func DiscoverEngines(home string) map[string]string {
	found := map[string]string{}
	for _, name := range engines.Names {
		cands := []string{}
		if p, err := exec.LookPath(name); err == nil {
			cands = append(cands, p)
		}
		cands = append(cands,
			filepath.Join("/opt/homebrew/bin", name),
			filepath.Join(home, ".local", "bin", name),
			filepath.Join("/usr/local/bin", name),
		)
		for _, c := range cands {
			if abs, err := filepath.Abs(c); err == nil && isExecutable(abs) {
				found[name] = abs
				break
			}
		}
	}
	return found
}

func isExecutable(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&0o111 != 0
}

// LoadConfig reads state/config.json over the defaults: a key the file does not have keeps
// its default, and an engine the file does not name is looked for on this machine. A missing
// file is the first-run state and is not an error. A file that does not parse is: the
// returned Config is still the defaults, so a hook can fail open and keep protecting.
func LoadConfig(p core.Paths, home string) (Config, error) {
	def := DefaultConfig(p, home)
	b, err := os.ReadFile(p.Config)
	if errors.Is(err, fs.ErrNotExist) {
		return def, nil
	}
	if err != nil {
		return def, err
	}
	cfg := def
	// Decoding over the defaults would merge maps key by key, which would keep a tier the
	// file deliberately shortened, and would write through slices shared with def. Start
	// those from empty so the file wins whole and def stays what it was.
	cfg.Accounts, cfg.Orgs = slices.Clone(def.Accounts), slices.Clone(def.Orgs)
	cfg.Engines, cfg.Tiers = map[string]string{}, map[string][]string{}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return def, fmt.Errorf("install: %s is not valid config: %w", p.Config, errNoValue(err))
	}
	if cfg.Engines == nil {
		cfg.Engines = map[string]string{}
	}
	if cfg.Tiers == nil {
		cfg.Tiers = map[string][]string{}
	}
	for name, path := range def.Engines {
		if _, ok := cfg.Engines[name]; !ok {
			cfg.Engines[name] = path
		}
	}
	for tier, list := range def.Tiers {
		if _, ok := cfg.Tiers[tier]; !ok {
			cfg.Tiers[tier] = list
		}
	}
	if cfg.Jobs <= 0 {
		cfg.Jobs = DefaultJobs
	}
	if cfg.Rules == "" {
		cfg.Rules = def.Rules
	}
	return cfg, nil
}

// errNoValue keeps a decode error from quoting the bytes it choked on; config.json holds a
// phone number, which is not a secret but is not for logs either.
func errNoValue(err error) error {
	var se *json.SyntaxError
	if errors.As(err, &se) {
		return fmt.Errorf("syntax error at byte %d", se.Offset)
	}
	var te *json.UnmarshalTypeError
	if errors.As(err, &te) {
		return fmt.Errorf("field %q has the wrong type", te.Field)
	}
	return errors.New("unreadable")
}

// Save writes config.json atomically at 0600.
func (c Config) Save(p core.Paths) error {
	b, err := c.marshal()
	if err != nil {
		return err
	}
	return db.WriteFileAtomic(p.Config, b, 0o600)
}

func (c Config) marshal() ([]byte, error) {
	c.Version = ConfigVersion
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// Tier returns the engine names a job may use, in order, keeping only engines keyguard
// knows. An unknown tier is empty.
func (c Config) Tier(name string) []string {
	var out []string
	for _, e := range c.Tiers[name] {
		if slices.Contains(engines.Names, e) && !slices.Contains(out, e) {
			out = append(out, e)
		}
	}
	return out
}

// UsesEngine reports whether any tier names the engine.
func (c Config) UsesEngine(name string) bool {
	for tier := range c.Tiers {
		if slices.Contains(c.Tier(tier), name) {
			return true
		}
	}
	return false
}

// Problems lists what is wrong with the config in words, without touching anything. An
// empty list is a usable config.
func (c Config) Problems() []string {
	var out []string
	for name, p := range c.Engines {
		switch {
		case !slices.Contains(engines.Names, name):
			out = append(out, fmt.Sprintf("engines: %q is not an engine keyguard has", name))
		case !filepath.IsAbs(p):
			// A relative path would resolve against whatever repo a hook runs in.
			out = append(out, fmt.Sprintf("engines.%s: %q is not an absolute path", name, p))
		}
	}
	for tier, list := range c.Tiers {
		for _, e := range list {
			if !slices.Contains(engines.Names, e) {
				out = append(out, fmt.Sprintf("tiers.%s: %q is not an engine keyguard has", tier, e))
			}
		}
	}
	if c.Jobs < 1 || c.Jobs > 64 {
		out = append(out, fmt.Sprintf("jobs: %d is outside 1..64", c.Jobs))
	}
	if len(c.Accounts) == 0 && len(c.Orgs) == 0 {
		out = append(out, "accounts: nothing to watch")
	}
	if c.Rules != "" && !filepath.IsAbs(c.Rules) {
		out = append(out, fmt.Sprintf("rules: %q is not an absolute path", c.Rules))
	}
	if c.Mirrors != "" && !filepath.IsAbs(c.Mirrors) {
		out = append(out, fmt.Sprintf("mirrors: %q is not an absolute path", c.Mirrors))
	}
	sort.Strings(out)
	return out
}

// EnginePaths is the map engines.NewAll takes: only absolute paths, so a hand-edited
// relative one is ignored (and flagged by Problems) instead of being run from a repo.
func (c Config) EnginePaths() map[string]string {
	out := map[string]string{}
	for name, p := range c.Engines {
		if filepath.IsAbs(p) {
			out[name] = p
		}
	}
	return out
}

// InventoryConfig converts to what inventory.New takes. Nothing in the scan path reads a
// repo's default branch and it costs 19 of every 26 seconds of a listing, so it is skipped.
func (c Config) InventoryConfig(p core.Paths) inventory.Config {
	return inventory.Config{Accounts: c.Accounts, Orgs: c.Orgs, StateDir: p.State, NoDefaultBranch: true}
}

// PinEngines records each installed engine's version and the hash of the file its path
// resolves to. Hashing a 170 MB binary costs about 0.15 s, which is why this runs at
// install and in the full doctor, never in a hook.
func PinEngines(c Config) map[string]Pin {
	pins := map[string]Pin{}
	for name, path := range c.EnginePaths() {
		if !isExecutable(path) {
			continue
		}
		e, err := engines.New(name, path, nopFP{})
		if err != nil {
			continue
		}
		sum, _ := hashFile(path)
		pins[name] = Pin{Version: e.Version(), SHA256: sum}
	}
	return pins
}

// nopFP satisfies engines.New for callers that only ask a binary for its version.
type nopFP struct{}

func (nopFP) FP(string) string { return "" }
