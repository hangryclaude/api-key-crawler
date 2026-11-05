package engines

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"keyguard/internal/core"
)

// leaks is betterleaks and gitleaks: same report, same flags, except that betterleaks adds
// validation, a git worker pool, the full source line in its report and the GitHub API source.
type leaks struct {
	*base
	better bool
}

var _ core.APIScanner = (*leaks)(nil)

// leakRec is the part of a betterleaks/gitleaks finding keyguard reads.
type leakRec struct {
	RuleID           string
	File             string
	Commit           string
	Author           string
	Date             string
	StartLine        int
	EndLine          int
	Secret           string
	Match            string
	MatchContext     string         // betterleaks, with --match-context 0L: the whole line
	ValidationStatus string         // betterleaks, with --validation
	ValidationReason string         // betterleaks, with --validation: the verifier's words, which are never kept
	Attributes       map[string]any // betterleaks: url, path, resource, git.*
}

// config picks the rules the scan runs with and gives them to the engine as -c: always, never
// left to discovery, because a .betterleaks.toml or .gitleaks.toml in a directory with an
// allowlist of ".*" silences the scan of it completely (measured). Without ScanOpts.Rules the
// defaults are written into the run's scratch dir.
func config(o core.ScanOpts, scratch string) (string, error) {
	if o.Rules == "" {
		p := filepath.Join(scratch, "default.toml")
		return p, os.WriteFile(p, []byte(defaultConfigTOML), 0o600)
	}
	p, err := filepath.Abs(o.Rules)
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(p); err != nil {
		return "", fmt.Errorf("engines: rules file: %w", err)
	}
	return p, nil
}

// flags are the options every mode shares.
//   - -i points at an empty directory so a .gitleaksignore or .betterleaksignore in the
//     directory being scanned (or the one the engine runs in) cannot hide findings;
//   - --ignore-gitleaks-allow, in every mode, pre-commit included: "gitleaks:allow" and
//     "betterleaks:allow" are not evidence that a key is safe, and a blocked agent can add the
//     comment itself (STEAL P0-12, K9). The only allowlist is ignore.json;
//   - gitleaks gets decode depth 0 and archive depth 3 (STEAL K2): its default decode depth of
//     five burned 63.8 CPU-seconds in 4.3 of wall time, and betterleaks and trufflehog decode.
func (e *leaks) flags(o core.ScanOpts, cfg, empty string) []string {
	args := []string{"--no-banner", "--no-color", "-l", "error", "-f", "json", "-r", "-", "--exit-code", "0",
		"-i", empty, "-c", cfg, "--ignore-gitleaks-allow"}
	if !e.better {
		return append(args, "--max-decode-depth", "0", "--max-archive-depth", "3")
	}
	args = append(args, "--match-context", "0L")
	if o.Verify {
		// betterleaks validates every occurrence, not every distinct secret (measured: six copies
		// of one key, six requests), and providers rate-limit rejected keys hard, so the pace and the
		// number of requests per provider are capped.
		args = append(args, "--validation", "--validation-timeout", "10s", "--validation-max-requests", "200",
			"--validation-rps", "10", "--validation-workers", "10")
	}
	return args
}

func (e *leaks) gitArgs(o core.ScanOpts, cfg, empty, target string, revs []string) []string {
	args := append([]string{"git"}, e.flags(o, cfg, empty)...)
	if e.better && o.Threads > 0 {
		// One huge repository scanned alone; pooled scans start no workers of their own.
		args = append(args, "--git-workers", strconv.Itoa(o.Threads))
	}
	return append(args, "--log-opts="+strings.Join(revs, " "), target)
}

// stagedArgs names no repository: GIT_DIR, GIT_WORK_TREE and GIT_INDEX_FILE do, as absolute
// paths, and the engine runs from an empty directory (see stagedRepo). generic-password is off
// at the gate only (STEAL K10): it is the engine's noisiest rule, and the sweeps keep it.
func (e *leaks) stagedArgs(o core.ScanOpts, cfg, empty, regex string) []string {
	args := append([]string{"git", "--pre-commit", "--staged"}, e.flags(o, cfg, empty)...)
	if e.better {
		args = append(args, "--regex-engine", regex, "--disable-rule", "generic-password")
	}
	return args
}

func (e *leaks) dirArgs(o core.ScanOpts, cfg, empty, dir string) []string {
	return append(append([]string{"dir"}, e.flags(o, cfg, empty)...), dir)
}

// setup makes what every mode needs inside the run's scratch dir: the empty directory the
// engine runs in and is pointed at for ignore files, and its config.
func (e *leaks) setup(o core.ScanOpts, scratch string) (cwd, cfg string, err error) {
	if cwd, err = subdir(scratch, "cwd"); err != nil {
		return "", "", err
	}
	cfg, err = config(o, scratch)
	return cwd, cfg, err
}

func (e *leaks) ScanGit(ctx context.Context, repo string, r core.Range, o core.ScanOpts, emit core.Emit) error {
	g, err := e.openGit(ctx, repo, r)
	if err != nil || len(g.args) == 0 {
		return err
	}
	var lr lineReader
	if !e.better {
		gl := newGitLines(ctx, g.dir)
		defer gl.close()
		lr = gl
	}
	sk := &sink{emit: emit, namer: newRefNamer(ctx, g.dir)}
	err = e.run(ctx, func(scratch string) (job, error) {
		cwd, cfg, err := e.setup(o, scratch)
		if err != nil {
			return job{}, err
		}
		return job{args: e.gitArgs(o, cfg, cwd, g.dir, g.args), dir: cwd, env: jobEnv(o, diffEnv...)}, nil
	}, e.decode(o, "", lr, sk))
	sk.flush() // what was found before a failure is still valid
	return err
}

func (e *leaks) ScanStaged(ctx context.Context, worktree string, o core.ScanOpts, emit core.Emit) error {
	wt, err := filepath.Abs(worktree)
	if err != nil {
		return err
	}
	st, err := resolveStaged(ctx, wt)
	if err != nil {
		return err
	}
	lines, anything, err := st.stagedSize(ctx)
	if err != nil || !anything {
		return err // an empty index is the cheap exit; anything unclear means scan anyway, and that failed
	}
	var lr lineReader
	if !e.better {
		gl := newStagedLines(ctx, st)
		defer gl.close()
		lr = gl
	}
	sk := &sink{emit: emit}
	err = e.run(ctx, func(scratch string) (job, error) {
		cwd, cfg, err := e.setup(o, scratch)
		if err != nil {
			return job{}, err
		}
		return job{args: e.stagedArgs(o, cfg, cwd, regexEngine(lines)), dir: cwd, env: jobEnv(o, slices.Concat(st.env(), diffEnv)...)}, nil
	}, e.decode(o, "", lr, sk))
	sk.flush()
	return err
}

func (e *leaks) ScanDir(ctx context.Context, dir string, o core.ScanOpts, emit core.Emit) error {
	d, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	fi, err := os.Stat(d)
	if err != nil {
		return fmt.Errorf("engines: %w", err)
	}
	root := d
	if !fi.IsDir() {
		root = filepath.Dir(d)
	}
	var lr lineReader
	if !e.better {
		lr = newFSLines()
	}
	sk := &sink{emit: emit}
	err = e.run(ctx, func(scratch string) (job, error) {
		cwd, cfg, err := e.setup(o, scratch)
		if err != nil {
			return job{}, err
		}
		return job{args: e.dirArgs(o, cfg, cwd, d), dir: cwd, env: jobEnv(o)}, nil
	}, e.decode(o, root, lr, sk))
	sk.flush()
	return err
}

// decode turns the report stream into hits. root is set in dir mode, where engines report
// absolute paths and locations are relative to the scanned directory.
func (e *leaks) decode(o core.ScanOpts, root string, lr lineReader, sk *sink) func(io.Reader) error {
	return func(rd io.Reader) error {
		return streamArray(rd, func(rec *leakRec) error {
			raw := strings.TrimSpace(rec.Secret)
			if raw == "" {
				return nil
			}
			path := rec.File
			line := rec.MatchContext
			if line == "" && lr != nil {
				line = lr.line(rec.Commit, path, rec.StartLine)
			}
			if line == "" {
				line = rec.Match
			}
			if root != "" {
				if rel, err := filepath.Rel(root, path); err == nil {
					path = rel
				}
			}
			v, why := leakVerified(rec.ValidationStatus, rec.ValidationReason)
			sk.add(e.newCand(o, found{
				raw: raw, line: line, rule: rec.RuleID, verified: v, reasonText: why,
				commit: rec.Commit, path: path, lineNo: rec.StartLine, endLine: rec.EndLine, author: rec.Author, date: rec.Date,
			}))
			return nil
		})
	}
}

// leakVerified maps betterleaks's validation status. "unknown" and "error" mean the check ran
// and could not decide, which is not the provider rejecting the key; the reason text is the
// verifier's own words and is returned only to be classified.
func leakVerified(status, reason string) (core.Verified, string) {
	switch status {
	case "valid":
		return core.Live, ""
	case "invalid", "revoked":
		return core.Dead, ""
	case "error", "unknown":
		return core.VerifyError, reason
	}
	return core.Unverified, "" // no status: no validator for this rule, or validation not requested
}

// ----- GitHub API resources, by exact URL (STEAL P0-22) -----

// ScanAPI scans one issue, pull request, release or Actions run of a GitHub repository, named
// by its page URL. `--since` on a repository's issues stops at the first item created before
// the cursor, so a new comment on an old issue is never seen, and costs about six GraphQL
// points a page when nothing matches; one URL costs about one. The token comes from
// ScanOpts.Env as GITHUB_TOKEN and is given to the child by environment, never as --token,
// where `ps` and the engine's own logs would show it. The files attached to a release are
// skipped unless ScanOpts.ReleaseAssets: they are big and rarely hold a key.
func (e *leaks) ScanAPI(ctx context.Context, target string, o core.ScanOpts, emit core.Emit) error {
	if !e.better {
		return core.ErrUnsupported // gitleaks has no GitHub source
	}
	kind, err := apiKind(target)
	if err != nil {
		return err
	}
	sk := &sink{emit: emit}
	err = e.run(ctx, func(scratch string) (job, error) {
		cwd, cfg, err := e.setup(o, scratch)
		if err != nil {
			return job{}, err
		}
		args := append([]string{"github", target}, e.flags(o, cfg, cwd)...)
		if !o.ReleaseAssets {
			args = append(args, "--exclude=release-assets")
		}
		return job{args: args, dir: cwd, env: jobEnv(o)}, nil
	}, func(rd io.Reader) error {
		return streamArray(rd, func(rec *leakRec) error {
			raw := strings.TrimSpace(rec.Secret)
			if raw == "" {
				return nil
			}
			v, why := leakVerified(rec.ValidationStatus, rec.ValidationReason)
			where := attr(rec, "url")
			c := e.newCand(o, found{
				raw: raw, line: orElse(rec.MatchContext, rec.Match), rule: rec.RuleID, verified: v, reasonText: why,
				path: rec.File, lineNo: rec.StartLine, endLine: rec.EndLine, date: rec.Date, group: orElse(where, target) + "\x00" + rec.File,
			})
			c.hit.Loc.Kind = apiItemKind(attr(rec, "resource"), kind)
			c.hit.Loc.URL = orElse(where, target)
			sk.add(c)
			return nil
		})
	})
	sk.flush()
	return err
}

func orElse(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func attr(rec *leakRec, key string) string {
	s, _ := rec.Attributes[key].(string)
	return s
}

// apiKind validates the URL and says what it names. Anything else (a user, an organization, a
// whole repository) would make betterleaks list and scan everything below it.
func apiKind(target string) (string, error) {
	u, err := url.Parse(target)
	if err != nil || u.Scheme != "https" || u.Host != "github.com" || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("engines: ScanAPI takes the https://github.com URL of one issue, pull request, release or Actions run")
	}
	seg := strings.Split(strings.Trim(u.Path, "/"), "/")
	switch {
	case len(seg) == 4 && seg[2] == "issues" && isDigits(seg[3]):
		return "issue", nil
	case len(seg) == 4 && seg[2] == "pull" && isDigits(seg[3]):
		return "pr", nil
	case len(seg) >= 5 && seg[2] == "releases" && seg[3] == "tag" && seg[4] != "":
		return "release", nil
	case len(seg) == 5 && seg[2] == "actions" && seg[3] == "runs" && isDigits(seg[4]):
		return "actions", nil
	}
	return "", fmt.Errorf("engines: ScanAPI takes the URL of one issue, pull request, release or Actions run, not %s", u.Path)
}

// apiItemKind refines the kind of the URL with what the engine says it read: the comments of an
// issue are comments, not the issue.
func apiItemKind(resource, fallback string) string {
	if strings.Contains(strings.ToLower(resource), "comment") {
		return "comment"
	}
	return fallback
}
