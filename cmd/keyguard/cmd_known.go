package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"keyguard/internal/core"
	"keyguard/internal/db"
	"keyguard/internal/fp"
	"keyguard/internal/known"
)

func (c *cli) cmdLearn(args []string) int {
	f := c.flagSet("learn", "learn [flags]\n\nReads the secrets on this Mac (.env files, shell exports, launchd plists, ~/.config, gh tokens, ssh key bodies)\nand stores only keyed hashes of them. Prints ids, names and shapes; never a value.")
	prune := f.Bool("prune", false, "forget learned secrets whose source no longer holds them (never with an unreadable source)")
	keepPublic := f.Bool("keep-public", false, "also learn keys that are public by design (publishable keys, anon JWTs)")
	noEngine := f.Bool("no-engine", false, "do not ask an engine for a second opinion (faster; names alone decide)")
	noGH := f.Bool("no-gh", false, "do not read the gh CLI's tokens")
	verbose := f.Bool("v", false, "log one line per file read: paths and counts, never values")
	if _, code, ok := c.parse(f, args); !ok {
		return code
	}
	p := c.paths()
	cfg := c.config(p)
	opts, err := c.learnOptions(p, cfg, *noEngine)
	if err != nil {
		return c.failf("%s", safeErr(err))
	}
	opts.Prune, opts.KeepPublic = *prune, *keepPublic
	if *noGH {
		opts.GHUsers = []string{}
	}
	if *verbose {
		opts.Log = c.err
	}
	rep, err := known.Learn(opts)
	if rep != nil {
		fmt.Fprint(c.out, rep.Summary())
	}
	if err != nil {
		return c.failf("learn: %s", safeErr(err))
	}
	if rep.Added > 0 {
		fmt.Fprintln(c.out, "\nThe next poll looks for the new keys in every repo's whole history.")
	}
	return exitOK
}

func (c *cli) cmdKnown(args []string) int {
	if len(args) == 0 || args[0] != "list" && args[0] != "forget" {
		fmt.Fprintln(c.err, "usage: keyguard known list [--json] | keyguard known forget <id|fingerprint>")
		return exitUsage
	}
	switch args[0] {
	case "forget":
		f := c.flagSet("known forget", "known forget <id|fingerprint>")
		pos, code, ok := c.parse(f, args[1:])
		if !ok {
			return code
		}
		if len(pos) != 1 {
			return c.usageErr(f, "forget takes exactly one id")
		}
		root := core.Root()
		gone, err := known.Forget(root, pos[0])
		if err != nil {
			if errors.Is(err, known.ErrNotLearned) {
				fmt.Fprintf(c.err, "keyguard: %s\n", safeErr(err))
				return exitFound
			}
			return c.failf("%s", safeErr(err))
		}
		for _, g := range gone {
			fmt.Fprintf(c.out, "forgot %s  %s  %s  (%s)\n", g.ID, g.Name, g.Shape, plural(g.Forms, "form", "forms"))
		}
		fmt.Fprintln(c.out, "Hooks stop matching it at once. A key you still use is no longer protected: relearn it with `keyguard learn`.")
		return exitOK
	}

	f := c.flagSet("known list", "known list [--json] [--fp]")
	asJSON := f.Bool("json", false, "machine-readable output")
	withFP := f.Bool("fp", false, "also show the full fingerprint (needed when two ids collide)")
	if _, code, ok := c.parse(f, args[1:]); !ok {
		return code
	}
	type row struct {
		Root   string `json:"root"`
		ID     string `json:"id"`
		Name   string `json:"name"`
		Shape  string `json:"shape"`
		Len    int    `json:"len"`
		Forms  int    `json:"forms"`
		Source string `json:"source"`
		FP     string `json:"fp,omitempty"`
	}
	var rows []row
	for _, root := range core.KnownRoots() {
		st, err := known.ReadStore(root)
		if err != nil {
			return c.failf("%s", safeErr(err))
		}
		if st == nil {
			continue
		}
		at := map[string]int{}
		first := len(rows)
		for _, e := range st.Entries {
			i, seen := at[e.FP]
			if !seen {
				i = len(rows)
				at[e.FP] = i
				r := row{Root: root, ID: e.ID, Name: e.Name, Shape: e.Shape, Source: e.Source}
				if *asJSON || *withFP {
					r.FP = e.FP
				}
				rows = append(rows, r)
			}
			rows[i].Forms++
			if e.Variant == "raw" {
				rows[i].Len = e.Len
			}
		}
		_ = first
	}
	if *asJSON {
		enc := json.NewEncoder(c.out)
		enc.SetIndent("", "  ")
		if rows == nil {
			rows = []row{}
		}
		_ = enc.Encode(rows)
		return exitOK
	}
	if len(rows) == 0 {
		fmt.Fprintln(c.out, "nothing is learned yet. Run `keyguard learn`.")
		return exitOK
	}
	head := []string{"ID", "NAME", "SHAPE", "LEN", "FORMS"}
	if *withFP {
		head = append(head, "FINGERPRINT")
	}
	head = append(head, "LEARNED FROM")
	out := [][]string{head}
	for _, r := range rows {
		line := []string{r.ID, r.Name, r.Shape, fmt.Sprint(r.Len), fmt.Sprint(r.Forms)}
		if *withFP {
			line = append(line, r.FP)
		}
		out = append(out, append(line, r.Source))
	}
	table(c.out, "", out, 3, 4)
	fmt.Fprintf(c.out, "\n%s learned.\n", plural(len(rows), "secret", "secrets"))
	return exitOK
}

// ----- match -----

const maxMatchInput = 512 << 20

func (c *cli) cmdMatch(args []string) int {
	f := c.flagSet("match", "match [--json] [--quiet] [file...]\n\nExit 0 when no learned secret appears, 1 when one does. With no file, reads stdin.\nPrints where (file:line), which learned secret and its shape; never the value.")
	asJSON := f.Bool("json", false, "machine-readable output")
	quiet := f.Bool("quiet", false, "print nothing; the exit code says it")
	pos, code, ok := c.parse(f, args)
	if !ok {
		return code
	}
	m, err := known.LoadMatcher(core.KnownRoots())
	if err != nil {
		c.warnf("the learned-secret store did not fully load: %s", safeErr(err))
	}
	if m == nil || m.Len() == 0 {
		// "Nothing found" from a matcher that knows nothing would be a lie.
		return c.failf("nothing is learned, so nothing can be matched. Run `keyguard learn`.")
	}
	if len(pos) == 0 {
		pos = []string{"-"}
	}
	type hit struct {
		File    string `json:"file"`
		Line    int    `json:"line"`
		ID      string `json:"id"`
		Name    string `json:"name"`
		Variant string `json:"variant"`
		Shape   string `json:"shape"`
		Offset  int    `json:"offset"`
	}
	var hits []hit
	for _, name := range pos {
		var r io.Reader = c.in
		label := "stdin"
		if name != "-" {
			fh, err := os.Open(name)
			if err != nil {
				return c.failf("%s", safeErr(err))
			}
			defer fh.Close()
			r, label = fh, name
		}
		data, err := io.ReadAll(io.LimitReader(r, maxMatchInput+1))
		if err != nil {
			return c.failf("reading %s: %s", label, safeErr(err))
		}
		if len(data) > maxMatchInput {
			return c.failf("%s is over %d MiB; match it in pieces", label, maxMatchInput>>20)
		}
		line, last := 1, 0
		for _, km := range m.Match(data) {
			line += bytes.Count(data[last:km.Offset], []byte{'\n'})
			last = km.Offset
			hits = append(hits, hit{label, line, km.EntryID, km.Name, km.Variant, km.Shape, km.Offset})
		}
	}
	if !*quiet {
		if *asJSON {
			if hits == nil {
				hits = []hit{}
			}
			enc := json.NewEncoder(c.out)
			enc.SetIndent("", "  ")
			_ = enc.Encode(hits)
		} else {
			for _, h := range hits {
				fmt.Fprintf(c.out, "%s:%d  %s  %s  %s  (%s)\n", h.File, h.Line, h.ID, h.Name, h.Shape, h.Variant)
			}
		}
	}
	if len(hits) > 0 {
		return exitFound
	}
	return exitOK
}

// ----- allow -----

func (c *cli) cmdAllow(args []string) int {
	f := c.flagSet("allow", "allow <id|fingerprint> [--reason TEXT]\n       allow --list\n       allow --remove <id|fingerprint>\n\nMarks a finding a false positive, for good: hooks stop blocking it and sweeps stop alerting on it.\nThe id is the kg... a block message or the report printed.")
	reason := f.String("reason", "", "why it is not a secret (kept with the entry)")
	list := f.Bool("list", false, "show what is ignored")
	remove := f.Bool("remove", false, "take the id off the ignore list instead")
	pos, code, ok := c.parse(f, args)
	if !ok {
		return code
	}
	p := c.paths()
	if *list {
		return c.allowList(p)
	}
	if len(pos) != 1 {
		return c.usageErr(f, "allow takes exactly one id")
	}
	id := pos[0]

	// The run lock keeps this edit from interleaving with a sweep's save. A sweep that holds
	// it for an hour must not make `allow` impossible, though: ignore.json is written whole
	// and atomically on its own, so without the lock the entry still lands, and the sweep
	// notices the file changed. Only the findings are left for that sweep to save.
	lock, lerr := db.AcquireLock(p.Lock)
	if lerr == nil {
		defer lock.Release()
	} else if _, locked := lockedMessage(lerr); !locked {
		return c.failf("%s", safeErr(lerr))
	}
	st, err := db.Open(p)
	if err != nil {
		return c.failf("%s", safeErr(err))
	}
	if *remove {
		if err := st.Unignore(id); err != nil {
			return c.failf("%s", safeErr(err))
		}
		fmt.Fprintf(c.out, "%s is no longer ignored. The next scan judges it again.\n", id)
		return c.saveAllow(st, lock)
	}

	target := id
	err = st.Ignore(target, *reason)
	if err != nil && strings.Contains(err.Error(), "pass the full fingerprint") {
		// The id is not in the findings: a block that was never merged. The journal knows it.
		if fpv, jerr := c.resolveBlocked(p, id); jerr == nil {
			target = fpv
			err = st.Ignore(target, *reason)
		} else {
			return c.failf("%s", safeErr(jerr))
		}
	}
	if err != nil {
		return c.failf("%s", safeErr(err))
	}
	desc := ""
	if s, found := st.Find(target); found {
		desc = fmt.Sprintf("  (%s %s)", orGeneric(s.Type), s.Shape)
	} else if recs, _ := readBlocked(p); len(recs) > 0 {
		for _, r := range recs {
			if r.FP == target {
				desc = fmt.Sprintf("  (%s %s in %s)", orGeneric(r.Type), r.Shape, r.Path)
			}
		}
	}
	fmt.Fprintf(c.out, "ignored %s%s\n", fp.ID(target), desc)
	if lerr != nil {
		fmt.Fprintln(c.out, "A scan is running; the findings page catches up when it finishes.")
		return exitOK
	}
	return c.saveAllow(st, lock)
}

func (c *cli) saveAllow(st *db.Store, lock *db.Lock) int {
	if lock == nil {
		return exitOK
	}
	if err := st.Save(); err != nil {
		return c.failf("%s", safeErr(err))
	}
	return exitOK
}

func orGeneric(t string) string {
	if t == "" {
		return "generic"
	}
	return t
}

// resolveBlocked finds the one fingerprint in the block journal that has this kg id.
func (c *cli) resolveBlocked(p core.Paths, id string) (string, error) {
	recs, err := readBlocked(p)
	if err != nil {
		return "", err
	}
	want := strings.ToLower(id)
	seen := map[string]blockedRec{}
	for _, r := range recs {
		if r.ID == want {
			seen[r.FP] = r
		}
	}
	switch len(seen) {
	case 1:
		for f := range seen {
			return f, nil
		}
	case 0:
		return "", fmt.Errorf("no finding or recent block has id %s; pass the full fingerprint", id)
	}
	return "", fmt.Errorf("id %s matches %d recent blocks; pass the full fingerprint", id, len(seen))
}

func (c *cli) allowList(p core.Paths) int {
	b, err := os.ReadFile(p.Ignore)
	if errors.Is(err, os.ErrNotExist) {
		fmt.Fprintln(c.out, "nothing is ignored.")
		return exitOK
	}
	if err != nil {
		return c.failf("%s", safeErr(err))
	}
	var doc struct {
		Ignored map[string]db.IgnoreEntry `json:"ignored"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return c.failf("ignore.json does not parse")
	}
	if len(doc.Ignored) == 0 {
		fmt.Fprintln(c.out, "nothing is ignored.")
		return exitOK
	}
	rows := [][]string{{"ID", "WHEN", "REASON"}}
	for _, e := range sortedIgnores(doc.Ignored) {
		rows = append(rows, []string{e.ID, e.At, e.Reason})
	}
	table(c.out, "", rows)
	return exitOK
}

func sortedIgnores(m map[string]db.IgnoreEntry) []db.IgnoreEntry {
	out := make([]db.IgnoreEntry, 0, len(m))
	for f, e := range m {
		if e.ID == "" {
			e.ID = fp.ID(f)
		}
		out = append(out, e)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].At < out[j-1].At; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}
