// Package report renders the keyguard dashboard: one self-contained HTML file, light theme
// only, written for a reader who is dyslexic. The page leads with one sentence of status,
// keeps lines short, puts numbers right-aligned in columns, and shows a secret only as its
// shape. It runs no script and makes no request; a Content-Security-Policy in the page
// makes the browser enforce that, so a markup-injection bug could not turn it into either.
//
// From the sweep, after a run:
//
//	rep := report.New(paths.Report)
//	rep.Coverage = report.CoverageFromSources(inventory) // plus Refs, Commits, Blobs, APIItems
//	path, err := rep.Write(store.Secrets(), runStats, layers)
//
// and for the notification, in the report's own words:
//
//	s := report.Summarize(newSecrets)
//	err = notifier.Notify(s.Title, s.Body, s.Sev)
package report

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"time"

	"keyguard/internal/core"
)

//go:embed page.html
var pageHTML string

//go:embed style.css
var styleCSS string

// html/template escapes by output context, so a path or branch name holding markup arrives
// as text. Parsing at init makes a broken template fail the first test, not the first run.
var page = template.Must(template.New("page").Parse(pageHTML))

// Reporter implements core.Reporter. Only Path is required; the rest default.
type Reporter struct {
	Path       string
	Now        func() time.Time // default time.Now
	Zone       *time.Location   // default time.Local: the user reads times on this Mac's clock
	StaleAfter time.Duration    // default 2h; the CLI passes 30 minutes, since it polls every minute
	Coverage   Coverage         // counts RunStats has no field for; see Coverage
}

var _ core.Reporter = (*Reporter)(nil)

// New returns a Reporter that writes to path (core.Paths.Report in production).
func New(path string) *Reporter { return &Reporter{Path: path} }

// Write renders the page and replaces the file at Path atomically, so a browser reload
// during a poll sees the old report or the new one, never half of either.
func (r *Reporter) Write(secrets []core.Secret, run core.RunStats, layers []core.LayerStatus) (string, error) {
	if r.Path == "" {
		return "", errors.New("report: no output path")
	}
	b, err := r.Render(secrets, run, layers)
	if err != nil {
		return "", err
	}
	if err := writeAtomic(r.Path, b); err != nil {
		return "", fmt.Errorf("report: %w", err)
	}
	return r.Path, nil
}

// Render returns the page without touching disk.
func (r *Reporter) Render(secrets []core.Secret, run core.RunStats, layers []core.LayerStatus) ([]byte, error) {
	in := input{secrets: secrets, run: run, layers: layers, cov: r.Coverage,
		now: time.Now(), zone: time.Local, stale: r.StaleAfter}
	if r.Now != nil {
		in.now = r.Now()
	}
	if r.Zone != nil {
		in.zone = r.Zone
	}
	if in.stale <= 0 {
		in.stale = 2 * time.Hour
	}
	var buf bytes.Buffer
	if err := page.Execute(&buf, build(in)); err != nil {
		return nil, fmt.Errorf("report: render: %w", err)
	}
	return buf.Bytes(), nil
}

// writeAtomic follows fp's salt writer: temp file in the same directory, private mode set
// before any content lands, rename into place.
func writeAtomic(path string, b []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".report-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
