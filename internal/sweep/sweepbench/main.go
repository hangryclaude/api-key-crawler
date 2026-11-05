// Command sweepbench times the sweep over a set of mirrors that are already on disk: a cold
// full scan, the same scan warm (with the blob ledger the first one built), a poll with nothing
// new, and a poll after one new commit. It reads mirrors and never fetches (mirror.NoFetch), so
// pass it clones made for the purpose, never the real cache. All state goes to a temp dir.
//
//	sweepbench -mirrors /tmp/m -list repos.txt -engines betterleaks,trufflehog -jobs 8
//
// Verification is off unless -verify is given: a timing run must not send anything to a provider.
// Every number it prints is measured by this run, with the load average at the time, since an
// unrelated job on this Mac can load the CPU.
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"keyguard/internal/core"
	"keyguard/internal/db"
	"keyguard/internal/engines"
	"keyguard/internal/fp"
	"keyguard/internal/known"
	"keyguard/internal/mirror"
	"keyguard/internal/sweep"
	"keyguard/internal/triage"
)

func main() {
	var (
		mirrors  = flag.String("mirrors", "", "root of the mirrors: <root>/github.com/<owner>/<name>.git (read only)")
		list     = flag.String("list", "", "file with one owner/name per line")
		engList  = flag.String("engines", "betterleaks", "comma-separated engines to run")
		jobs     = flag.Int("jobs", 8, "sources scanned at once")
		nKnown   = flag.Int("known", 8, "random learned keys for the known pass (0 turns the pass off)")
		verify   = flag.Bool("verify", false, "let the engines verify what they find (sends it to providers)")
		noLedger = flag.Bool("no-ledger", false, "keep no blob ledger, as before it existed")
		work     = flag.String("work", "", "state directory (default: a new temp dir)")
		huge     = flag.Int64("huge-bytes", 0, "pack size at which a full scan runs alone (0 = the sweep's default, negative = never)")
		hugeThr  = flag.Int("huge-threads", 0, "threads per engine for a source that runs alone (0 = the sweep's default)")
		runs     = flag.String("runs", "cold,warm,poll,push,lost", "which runs to time, in order")
	)
	flag.Parse()
	if *mirrors == "" || *list == "" {
		fmt.Fprintln(os.Stderr, "sweepbench: -mirrors and -list are required")
		os.Exit(2)
	}
	if err := run(*mirrors, *list, *engList, *jobs, *nKnown, *verify, *noLedger, *huge, *hugeThr, *work, strings.Split(*runs, ",")); err != nil {
		fmt.Fprintln(os.Stderr, "sweepbench:", err)
		os.Exit(1)
	}
}

// inventory is a fixed list of sources. Changed reports what was pushed since prev, the way
// the real one compares pushedAt.
type inventory struct {
	mu   sync.Mutex
	list []core.Source
}

func (i *inventory) List(context.Context) ([]core.Source, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	return slices.Clone(i.list), nil
}

func (i *inventory) Changed(_ context.Context, prev map[string]core.Source) ([]core.Source, []core.Event, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	var out []core.Source
	for _, s := range i.list {
		if p, ok := prev[s.ID]; !ok || p.Visibility != s.Visibility || s.PushedAt > p.PushedAt {
			out = append(out, s)
		}
	}
	return out, nil, nil
}

func (i *inventory) push(id string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	for k := range i.list {
		if i.list[k].ID == id {
			i.list[k].PushedAt = time.Now().UTC().Format(time.RFC3339)
		}
	}
}

func load() string {
	out, err := exec.Command("sysctl", "-n", "vm.loadavg").Output()
	if err != nil {
		return "?"
	}
	return strings.Trim(strings.TrimSpace(string(out)), "{} ")
}

func run(mirrorRoot, listFile, engList string, jobs, nKnown int, verify, noLedger bool, huge int64, hugeThreads int, workDir string, which []string) error {
	// The run writes to its mirrors (the "push" step adds a commit), so it must never be pointed at the real ones.
	abs, err := filepath.Abs(mirrorRoot)
	if err != nil {
		return err
	}
	if home, _ := os.UserHomeDir(); home != "" && strings.HasPrefix(abs, filepath.Join(home, ".keyguard")) {
		return fmt.Errorf("%s is under ~/.keyguard: pass a clone of the mirrors, made with git clone --mirror --local", abs)
	}
	f, err := os.Open(listFile)
	if err != nil {
		return err
	}
	var srcs []core.Source
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		owner, name, ok := strings.Cut(strings.TrimSpace(sc.Text()), "/")
		if !ok {
			continue
		}
		srcs = append(srcs, core.Source{
			ID: "github.com/" + owner + "/" + name, Kind: "repo", Owner: owner, Name: name, Account: owner,
			Visibility: core.Public, PushedAt: "2026-11-04T00:00:00Z",
		})
	}
	f.Close()
	if len(srcs) == 0 {
		return fmt.Errorf("%s names no repository", listFile)
	}
	if workDir == "" {
		if workDir, err = os.MkdirTemp("", "sweepbench-"); err != nil {
			return err
		}
	}
	paths := core.PathsAt(workDir)
	store, err := db.Open(paths)
	if err != nil {
		return err
	}
	kr := fp.NewEphemeral()
	var engs []core.Engine
	var versions []string
	for _, n := range strings.Split(engList, ",") {
		e, err := engines.New(strings.TrimSpace(n), "", kr)
		if err != nil {
			return err
		}
		if !e.Available() {
			return fmt.Errorf("engine %s is not installed", n)
		}
		engs = append(engs, e)
		versions = append(versions, e.Name()+" "+e.Version())
	}
	mir, err := mirror.New(mirror.Config{Root: mirrorRoot, NoFetch: true})
	if err != nil {
		return err
	}
	cfg := sweep.Config{
		Paths: paths, Inventory: &inventory{list: srcs}, Mirror: mir, Engines: engs, Store: store,
		Triage: triage.New(triage.WithStoreEvidence(store), triage.WithFingerprinter(kr)),
		Jobs:   jobs, NoVerify: !verify, NoLedger: noLedger, ExposedOnly: true, HugeBytes: huge, HugeThreads: hugeThreads,
	}
	inv := cfg.Inventory.(*inventory)
	if nKnown > 0 {
		var entries []known.Entry
		for range nKnown {
			b := make([]byte, 36)
			if _, err := rand.Read(b); err != nil {
				return err
			}
			entries = append(entries, known.EntriesFor(kr, "OPENAI_API_KEY", "bench", []byte("sk-"+base64.RawURLEncoding.EncodeToString(b)))...)
		}
		m, err := known.NewMatcher(kr, entries)
		if err != nil {
			return err
		}
		cfg.Known = m
	}
	r, err := sweep.New(cfg)
	if err != nil {
		return err
	}
	fmt.Printf("%d sources, jobs %d, %d cpus, engines %s, known keys %d, verification %v, ledger %v\n",
		len(srcs), jobs, runtime.NumCPU(), strings.Join(versions, ", "), nKnown, verify, !noLedger)
	fmt.Printf("%-6s %8s  %-26s %5s %7s %7s %6s %9s  %s\n", "run", "wall s", "load before -> after", "scan", "skipped", "failed", "blobs", "ledger B", "engine seconds (summed over workers)")

	ctx := context.Background()
	for _, name := range which {
		switch strings.TrimSpace(name) {
		case "push":
			if err := pushOneCommit(mirrorRoot, srcs, inv); err != nil {
				return err
			}
		case "lost":
			// The tips are lost; the ledger is not. The poll scans from the start and reads only what is new.
			if err := os.RemoveAll(paths.Sources); err != nil {
				return err
			}
		}
		before := load()
		t0 := time.Now()
		var st core.RunStats
		switch strings.TrimSpace(name) {
		case "cold", "warm":
			st, err = r.Full(ctx)
		case "poll", "push", "lost":
			st, err = r.Poll(ctx)
		default:
			return fmt.Errorf("unknown run %q", name)
		}
		wall := time.Since(t0)
		if err != nil {
			return fmt.Errorf("%s: %w (notes: %v)", name, err, st.Notes)
		}
		var eng []string
		for _, n := range slices.Sorted(mapKeys(st.Engines)) {
			eng = append(eng, fmt.Sprintf("%s %.2f", n, st.Engines[n].Seconds))
		}
		fmt.Printf("%-6s %8.2f  %-26s %5d %7d %7d %6d %9d  %s\n", name, wall.Seconds(), before+" -> "+load(), st.Scanned, st.Skipped, st.Failed, st.Blobs, ledgerBytes(paths.Ledger), strings.Join(eng, ", "))
		for _, n := range st.Notes {
			if strings.HasPrefix(n, "blob ledger") || strings.Contains(n, "alone") {
				fmt.Printf("       note: %s\n", n)
			}
		}
	}
	return nil
}

func mapKeys[V any](m map[string]V) func(func(string) bool) {
	return func(yield func(string) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}

func ledgerBytes(dir string) int64 {
	var n int64
	filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(p, ".bin") && !strings.Contains(p, "superseded") {
			if fi, err := d.Info(); err == nil {
				n += fi.Size()
			}
		}
		return nil
	})
	return n
}

// pushOneCommit adds an empty-change commit to the largest mirror, in the clone it was given,
// and tells the inventory it was pushed. It only ever runs git against the mirror root it was told.
func pushOneCommit(root string, srcs []core.Source, inv *inventory) error {
	var best string
	var bestSize int64
	for _, s := range srcs {
		dir := filepath.Join(root, filepath.FromSlash(s.ID)+".git")
		var n int64
		packs, _ := filepath.Glob(filepath.Join(dir, "objects", "pack", "*.pack"))
		for _, p := range packs {
			if fi, err := os.Stat(p); err == nil {
				n += fi.Size()
			}
		}
		if n > bestSize {
			best, bestSize = dir, n
		}
	}
	if best == "" {
		return fmt.Errorf("no mirror with a pack to push to")
	}
	git := func(args ...string) (string, error) {
		cmd := exec.Command("git", append([]string{"--git-dir=" + best}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1",
			"GIT_AUTHOR_NAME=bench", "GIT_AUTHOR_EMAIL=bench@example.com", "GIT_COMMITTER_NAME=bench", "GIT_COMMITTER_EMAIL=bench@example.com")
		out, err := cmd.CombinedOutput()
		return strings.TrimSpace(string(out)), err
	}
	head, err := git("symbolic-ref", "HEAD")
	if err != nil {
		return fmt.Errorf("symbolic-ref: %s", head)
	}
	tip, err := git("rev-parse", head)
	if err != nil {
		return fmt.Errorf("rev-parse: %s", tip)
	}
	blob := exec.Command("git", "--git-dir="+best, "hash-object", "-w", "--stdin")
	blob.Stdin = strings.NewReader("a line added by sweepbench\n")
	bo, err := blob.Output()
	if err != nil {
		return err
	}
	tree := exec.Command("git", "--git-dir="+best, "mktree")
	tree.Stdin = strings.NewReader("100644 blob " + strings.TrimSpace(string(bo)) + "\tsweepbench.txt\n")
	to, err := tree.Output()
	if err != nil {
		return err
	}
	// A commit whose tree is only the new file: not a descendant's state of the repo, but a
	// commit with one new blob, which is all a timing of "one new commit" needs.
	c, err := git("commit-tree", strings.TrimSpace(string(to)), "-p", tip, "-m", "sweepbench")
	if err != nil {
		return fmt.Errorf("commit-tree: %s", c)
	}
	if out, err := git("update-ref", head, c); err != nil {
		return fmt.Errorf("update-ref: %s", out)
	}
	id := "github.com/" + strings.TrimSuffix(strings.TrimPrefix(best, filepath.Join(root, "github.com")+"/"), ".git")
	inv.push(id)
	return nil
}
