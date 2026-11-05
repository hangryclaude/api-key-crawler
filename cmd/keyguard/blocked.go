package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"keyguard/internal/core"
	"keyguard/internal/fp"
)

// blockedRec is one finding a hook blocked, in display form only: ids, shapes, places.
type blockedRec struct {
	At     string `json:"at"`
	Layer  string `json:"layer"`
	ID     string `json:"id"`
	FP     string `json:"fp"`
	Type   string `json:"type,omitempty"`
	Rule   string `json:"rule,omitempty"`
	Engine string `json:"engine,omitempty"`
	Shape  string `json:"shape,omitempty"`
	Source string `json:"source,omitempty"`
	Path   string `json:"path,omitempty"`
	Line   int    `json:"line,omitempty"`
}

// maxBlockedBytes is when the journal is moved aside and started afresh: a journal that
// grows forever is a log nobody reads, and `allow` only needs the recent ones.
const maxBlockedBytes = 1 << 20

func blockedPath(p core.Paths) string { return filepath.Join(p.State, "blocked.jsonl") }

// appendBlocked adds one line per blocking hit. Every line is one Write on an O_APPEND file,
// which the kernel keeps whole even when two hooks block at once, so no lock is needed.
func appendBlocked(p core.Paths, layer string, hits []core.Hit, now time.Time) error {
	if len(hits) == 0 {
		return nil
	}
	path := blockedPath(p)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if fi, err := os.Stat(path); err == nil && fi.Size() > maxBlockedBytes {
		aside := fmt.Sprintf("%s.%s", path, now.UTC().Format("20060102T150405Z"))
		if err := os.Rename(path, aside); err != nil {
			return err
		}
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, h := range hits {
		if h.FP == "" {
			continue // a finding with no fingerprint cannot be allowed by id anyway
		}
		b, err := json.Marshal(blockedRec{
			At: now.UTC().Format(time.RFC3339), Layer: layer, ID: fp.ID(h.FP), FP: h.FP, Type: h.Type, Rule: h.Rule,
			Engine: h.Engine, Shape: h.Shape, Source: h.Loc.Source, Path: h.Loc.Path, Line: h.Loc.Line,
		})
		if err != nil {
			return err
		}
		if _, err := f.Write(append(b, '\n')); err != nil {
			return err
		}
	}
	return nil
}

// journalSecrets records the findings of a publish check the same way, so the id its report
// prints resolves for "keyguard allow": a publish check scans into a scratch store that is
// thrown away, and the id would otherwise lead nowhere.
func journalSecrets(p core.Paths, layer string, secrets []core.Secret, now time.Time) error {
	hits := make([]core.Hit, 0, len(secrets))
	for _, s := range secrets {
		h := core.Hit{FP: s.FP, Type: s.Type, Shape: s.Shape}
		if len(s.Rules) > 0 {
			h.Rule = s.Rules[0]
		}
		if len(s.Engines) > 0 {
			h.Engine = s.Engines[0]
		}
		if len(s.Locations) > 0 {
			h.Loc = s.Locations[0]
		}
		hits = append(hits, h)
	}
	return appendBlocked(p, layer, hits, now)
}

// readBlocked returns the journal's records, oldest first. A line that does not parse is
// skipped: the journal is a convenience, not a record.
func readBlocked(p core.Paths) ([]blockedRec, error) {
	b, err := os.ReadFile(blockedPath(p))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []blockedRec
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		var r blockedRec
		if json.Unmarshal(sc.Bytes(), &r) == nil && r.FP != "" {
			out = append(out, r)
		}
	}
	return out, nil
}
