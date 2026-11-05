package install

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"time"

	"keyguard/internal/core"
	"keyguard/internal/engines"
)

// Engine pins (STEAL P0-01). An engine that updates itself, or that a package manager upgrades,
// can change what is found or drop a flag a hook relies on, and a hook that fails open on an
// engine it cannot drive protects nothing. So install copies each engine into the data root as
// <root>/bin/<name>-<version>, records the hash of that copy, and from then on every start of
// the engine is checked against the hash (engines.WithPins): a binary that is not the one that
// was pinned does not run. Moving to a newer engine is a deliberate act: `keyguard engines pin`
// for a binary the user has looked at, `keyguard engines check-upgrade --apply` for one the bench
// has vetted.

// EnginePath is where the pinned copy of an engine at a version lives.
func EnginePath(p core.Paths, name, version string) string {
	return filepath.Join(p.BinDir, name+"-"+version)
}

// HashCachePath is the advisory file engines remember binary hashes in, so that a git hook,
// which is a new process every time and has 150 ms, does not read a 170 MB engine to learn
// what it already knew.
func HashCachePath(p core.Paths) string { return filepath.Join(p.State, "engine-hashes.json") }

// SupersededDir is where a pinned copy goes when a different binary takes its name: moved, never
// deleted.
func SupersededDir(p core.Paths, at time.Time) string {
	return filepath.Join(p.Root, ".superseded", at.UTC().Format("20060102T150405Z"))
}

// EnginePins is the pins in the shape engines.WithPins takes. engines.Pin has Pin's fields.
func (c Config) EnginePins() map[string]engines.Pin {
	out := make(map[string]engines.Pin, len(c.Pins))
	for name, p := range c.Pins {
		out[name] = engines.Pin(p)
	}
	return out
}

// EngineOptions is what every engine built from this config is given: the pin its binary must
// match and the file its hash is remembered in. An engine built without them is not checked,
// which is right for a tool that only asks a binary its version (PinEngines, the doctor's probe
// of an unpinned engine) and wrong for anything that scans.
func (c Config) EngineOptions(p core.Paths) []engines.Option {
	return []engines.Option{engines.WithPins(c.EnginePins()), engines.WithHashCache(HashCachePath(p))}
}

// engineVersion is what the binary at path says its version is, "" when it will not say. An
// engine is started for it, with the flags that keep trufflehog from replacing itself.
func engineVersion(name, path string) string {
	e, err := engines.New(name, path, nopFP{})
	if err != nil {
		return ""
	}
	if v := e.Version(); v != "unknown" {
		return v
	}
	return ""
}

// inBinDir reports whether path is one of the copies this install keeps.
func inBinDir(p core.Paths, path string) bool {
	dir := filepath.Clean(p.BinDir) + string(filepath.Separator)
	return strings.HasPrefix(filepath.Clean(path), dir)
}

// PinEngine copies the engine binary at src to <root>/bin/<name>-<version>, checks the copy
// byte for byte against its source by hash, and returns where it is and the pin for it. A copy
// already there with the same bytes is reused; a different binary under that name is moved
// aside first, never overwritten. src is only read, symlinks followed (titus is one), so it can
// be a Homebrew binary or a candidate the upgrade check staged.
//
// created is false when the copy was already there with those bytes.
func PinEngine(p core.Paths, name, src string, now time.Time) (path string, pin Pin, created bool, err error) {
	if !isExecutable(src) {
		return "", Pin{}, false, fmt.Errorf("install: %s is not an executable file", src)
	}
	ver := engineVersion(name, src)
	if ver == "" {
		return "", Pin{}, false, fmt.Errorf("install: %s at %s does not say its version, so there is nothing to name its copy after", name, src)
	}
	sum, err := hashFile(src)
	if err != nil {
		return "", Pin{}, false, fmt.Errorf("install: reading %s: %w", src, err)
	}
	dst := EnginePath(p, name, ver)
	if sameFile(src, dst) {
		return dst, Pin{Version: ver, SHA256: sum}, false, nil
	}
	if have, herr := hashFile(dst); herr == nil {
		if have == sum {
			return dst, Pin{Version: ver, SHA256: sum}, false, nil
		}
		if _, err := moveAside(dst, SupersededDir(p, now)); err != nil {
			return "", Pin{}, false, fmt.Errorf("install: another %s is already pinned as %s and could not be moved aside: %w", name, filepath.Base(dst), err)
		}
	} else if !errors.Is(herr, fs.ErrNotExist) {
		return "", Pin{}, false, herr
	}
	if err := copyFileAtomic(src, dst, 0o755); err != nil {
		return "", Pin{}, false, fmt.Errorf("install: copying %s to %s: %w", name, dst, err)
	}
	got, err := hashFile(dst)
	if err != nil || got != sum {
		_, _ = moveAside(dst, SupersededDir(p, now))
		return "", Pin{}, false, fmt.Errorf("install: the copy of %s at %s is not the bytes of %s; it was moved aside", name, dst, src)
	}
	return dst, Pin{Version: ver, SHA256: sum}, true, nil
}

// SavePin points config.json at a pinned copy and records its pin, in one write.
func SavePin(p core.Paths, home, name, path string, pin Pin) error {
	cfg, err := LoadConfig(p, home)
	if err != nil {
		return fmt.Errorf("install: %w; fix or move %s first", err, p.Config)
	}
	if cfg.Pins == nil {
		cfg.Pins = map[string]Pin{}
	}
	cfg.Engines[name], cfg.Pins[name] = path, pin
	return cfg.Save(p)
}

// engineCopies is the install step: each engine found on this Mac becomes a pinned copy in the
// data root. It returns the engines whose existing copy no longer matches its pin; those are
// left exactly as they are and keep the pin they had, because installing again must not be a way
// to accept a binary nobody looked at (the doctor fails them, and `keyguard engines pin` is the
// deliberate way out). An engine that is already a copy of the right bytes is a no-op.
func (in *installer) engineCopies(cfg *Config) (drifted map[string]bool) {
	p := in.o.Paths
	drifted = map[string]bool{}
	if in.o.InPlace {
		return drifted
	}
	discovered := DiscoverEngines(in.o.Home)
	for _, name := range engines.Names {
		path := cfg.Engines[name]
		if path == "" || !isExecutable(path) {
			path = discovered[name]
		}
		if path == "" || !isExecutable(path) {
			continue
		}
		old, wasPinned := cfg.Pins[name]
		if inBinDir(p, path) {
			// Already one of ours. Its bytes either are the pin or they are not.
			if sum, herr := hashFile(path); wasPinned && old.SHA256 != "" && herr == nil && sum != old.SHA256 {
				drifted[name] = true
				in.warn("%s: the pinned copy %s is not the binary that was pinned; it was left alone and keeps its old pin. Look at what changed, then run: keyguard engines pin %s <path>", name, filepath.Base(path), name)
				in.act("engine", path, "skipped", "differs from its pin")
				cfg.Engines[name] = path
				continue
			}
			in.act("engine", path, "unchanged", "")
			cfg.Engines[name] = path
			continue
		}
		if in.o.DryRun {
			ver := engineVersion(name, path)
			in.act("engine", EnginePath(p, name, ver), "created", "would copy "+path)
			continue
		}
		dst, pin, created, perr := PinEngine(p, name, path, in.o.Now())
		if perr != nil {
			// The engine stays where it is and is pinned there: unpinned would be worse.
			in.warn("%s: %s; it is pinned where it is", name, perr)
			continue
		}
		change := "created"
		if !created {
			change = "unchanged"
		}
		cfg.Engines[name] = dst
		if in.m.Engines == nil {
			in.m.Engines = map[string]FileRecord{}
		}
		in.m.Engines[name] = FileRecord{Path: dst, SHA256: pin.SHA256}
		in.act("engine", dst, change, fmt.Sprintf("%s %s, copied from %s", name, pin.Version, path))
	}
	return drifted
}

// prewarm builds the rule cache titus keeps (2.7 s the first time, 30 ms after), so the first
// hook or scan that uses it does not pay. It goes under the data root (TITUS_CACHE_DIR). A
// failure is a warning: titus still works, only slower once.
func (in *installer) prewarm(cfg Config) {
	if in.o.NoPrewarm || in.o.DryRun {
		return
	}
	const name = "titus"
	path := cfg.EnginePaths()[name]
	if path == "" || !isExecutable(path) || !cfg.UsesEngine(name) {
		return
	}
	e, err := engines.New(name, path, nopFP{}, cfg.EngineOptions(in.o.Paths)...)
	if err != nil {
		return
	}
	if err := engines.Prewarm(in.ctx, e); err != nil {
		if ctxErr := in.ctx.Err(); ctxErr != nil {
			return
		}
		in.warn("%s did not build its rule cache (%s); its first scan will", name, firstLine(err.Error()))
		return
	}
	in.act("engine", in.o.Paths.TitusCache, "created", name+" rule cache built")
}

// PrewarmEngine is prewarm for the command that pins one engine on its own.
func PrewarmEngine(ctx context.Context, cfg Config, p core.Paths, name string) error {
	path := cfg.EnginePaths()[name]
	if path == "" || !isExecutable(path) {
		return fmt.Errorf("install: %s is not installed", name)
	}
	e, err := engines.New(name, path, nopFP{}, cfg.EngineOptions(p)...)
	if err != nil {
		return err
	}
	return engines.Prewarm(ctx, e)
}
