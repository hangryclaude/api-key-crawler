package engines

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"keyguard/internal/core"
)

// truffle is trufflehog: provider-specific detectors that can check a key against its
// provider, and decoders that undo base64 and friends before matching.
type truffle struct{ *base }

// truffleRec is the part of a trufflehog result keyguard reads. SecretParts, StructuredData,
// ExtraData and Redacted are deliberately not declared: they carry the credential in pieces,
// and what is not decoded cannot be kept (STEAL P0-04).
type truffleRec struct {
	DetectorName      string
	Verified          bool
	VerificationError string
	Raw               string
	RawV2             string
	SourceMetadata    struct {
		Data struct {
			Git *struct {
				Commit    string `json:"commit"`
				File      string `json:"file"`
				Email     string `json:"email"`
				Timestamp string `json:"timestamp"`
				Line      int    `json:"line"`
			}
			Filesystem *struct {
				File string `json:"file"`
				Line int    `json:"line"`
			}
		}
	}
}

// truffleResults asks for every class of result. By default trufflehog drops an unverified
// result whose body contains a dictionary word (0.5% of random Anthropic keys, 3 to 6 in 1500
// for Groq, SendGrid, Replicate, xAI, GitHub and HuggingFace; "password" and "business" in a key
// always, measured on 3.99.8): filtered_unverified brings them back. Never --filter-unverified,
// --filter-entropy, --allow-verification-overlap or --skip-additional-refs (STEAL P0-03).
const truffleResults = "--results=verified,unknown,unverified,filtered_unverified"

// verifyAllowlist is the set of detectors a run with verification on may use, as protobuf
// enum numbers, which are stable and which the installed binary rejects when it does not know
// them (TestVerificationAllowlist asks it). They are the detectors that check a credential
// against its own provider's API: STEAL Appendix C tiers A and B, minus 30 SlackWebhook, which
// POSTs. Read against 3.99.8 by decoding the DetectorType enum out of the binary.
//
// What is not here, and why (STEAL P0-10). The URI, JDBC, Postgres, MongoDB, Redis, FTP and LDAP
// detectors verify a credential by dialling the host written next to it in the scanned text: a
// stranger's server receives the password (24 connections to a loopback port in one run, 48 in
// another). PrivateKey tries SSH to github.com and gitlab.com and sends a fingerprint to
// Truffle Security. SlackWebhook POSTs a message. JWT and CustomRegex verify against whatever
// the token or the config names.
var verifyAllowlist = []struct {
	id   int
	name string
}{
	// tier A
	{933, "Anthropic"}, {201, "OpenAI"}, {1040, "OpenAIAdmin"}, {8, "Github"}, {988, "Groq"}, {1023, "XAI"},
	{1057, "OpenRouter"}, {967, "Replicate"}, {926, "HuggingFace"}, {16, "Stripe"}, {994, "ElevenLabs"},
	{12, "SendGrid"}, {100, "CloudflareApiToken"}, {58, "CloudflareGlobalApiKey"}, {13, "Slack"},
	{66, "DiscordWebhook"}, {2, "AWS"}, {959, "AWSSessionKey"}, {915, "SupabaseToken"},
	{1041, "GoogleGeminiAPIKey"}, {6, "GCP"},
	// tier B
	{160, "Vercel"}, {144, "Zerobounce"}, {91, "TelegramBotToken"}, {65, "DiscordBotToken"},
	{26, "Twilio"}, {1011, "TwilioApiKey"},
}

func verifyFlag() string {
	ids := make([]string, len(verifyAllowlist))
	for i, d := range verifyAllowlist {
		ids[i] = strconv.Itoa(d.id)
	}
	return "--include-detectors=" + strings.Join(ids, ",")
}

// flags are shared by every mode.
//   - --no-update: trufflehog replaces its own binary on startup otherwise (3.97.5 to 3.99.8,
//     mid-session). The pinned copy is the one that runs;
//   - --no-ignore-tag because a "trufflehog:ignore" comment is not evidence a key is safe;
//   - --fail-on-scan-errors so a scan that partly failed is an error here instead of a quiet success;
//   - --log-level=0, the lowest level that prints the scan summary, whose byte count is how a scan
//     that read nothing is told from one that found nothing. The log is filtered as it is read
//     (thLog), never kept;
//   - verification is either off or restricted to verifyAllowlist, and --concurrency is also its
//     request rate: trufflehog has no global limiter, so a verifying run is two requests at a time.
func (e *truffle) flags(o core.ScanOpts) []string {
	args := []string{"--json", "--no-update", "--no-color", "--log-level=0", "--fail-on-scan-errors", "--no-ignore-tag", truffleResults}
	conc := threads(o)
	if o.Verify {
		args = append(args, verifyFlag())
		conc = min(conc, 2)
	} else {
		args = append(args, "--no-verification")
	}
	return append(args, "--concurrency="+strconv.Itoa(conc))
}

func fileURL(path string) string { return (&url.URL{Scheme: "file", Path: path}).String() }

// gitArgs scans a git dir in place. --bare tells trufflehog the directory is a git dir, and
// --trust-local-git-config tells it to use it where it is: with --bare alone it still clones the
// mirror into TMPDIR first, a second copy of whatever leaked that fails outright when the
// directory cannot be written (reproduced on 3.99.8). Without --bare, --trust-local-git-config
// skips any directory whose name ends in "git" and exits 0 having read nothing (STEAL P0-02).
func (e *truffle) gitArgs(o core.ScanOpts, gitDir string, p trufflePass) []string {
	args := append([]string{"git", fileURL(gitDir), "--bare", "--trust-local-git-config"}, e.flags(o)...)
	if p.branch != "" {
		args = append(args, "--branch="+p.branch)
	}
	if p.since != "" {
		args = append(args, "--since-commit="+p.since)
	}
	return args
}

// dirArgs scans a directory without its .git, as betterleaks and gitleaks do: the history is
// ScanGit's job and git's object files are compressed noise.
func (e *truffle) dirArgs(o core.ScanOpts, dir, exclude string) []string {
	args := append([]string{"filesystem"}, e.flags(o)...)
	if exclude != "" {
		args = append(args, "--exclude-paths="+exclude)
	}
	return append(args, dir)
}

func writeExclude(scratch string) string {
	p := filepath.Join(scratch, "exclude-paths.txt")
	if os.WriteFile(p, []byte("(^|/)\\.git(/|$)\n"), 0o600) != nil {
		return "" // scanning .git too is noisier, not unsafe
	}
	return p
}

// trufflePass is one trufflehog invocation: the commits of branch after since.
type trufflePass struct{ branch, since string }

// revs is the pass as git writes it.
func (p trufflePass) revs() []string {
	switch {
	case p.branch == "" && p.since == "":
		return []string{"--all"}
	case p.since == "":
		return []string{p.branch}
	}
	return []string{p.branch, "^" + p.since}
}

// maxTrufflePasses bounds the process spawns for a range with many new heads (a flood of new
// pull refs). Past it one pass over everything runs and the results are filtered to the range.
const maxTrufflePasses = 12

// passes decides how to cover a range with trufflehog, which can only scan "<branch> after
// <commit>". A whole-repo scan is one pass. Anything narrower is one pass per head of the
// new commits, each starting after an excluded commit; that can be wider than the range, so
// the second return is the exact set of commits to keep (nil = keep everything).
func (e *truffle) passes(ctx context.Context, g gitScan, r core.Range) ([]trufflePass, map[string]struct{}, error) {
	if r.All && len(r.Revs) == 0 && len(r.Since) == 0 {
		return []trufflePass{{}}, nil, nil
	}
	nc, err := listNewCommits(ctx, g.dir, g.args)
	if err != nil || len(nc.set) == 0 {
		return nil, nil, err
	}
	if len(nc.heads) > maxTrufflePasses {
		e.note("trufflehog: the range has %d new heads, so it scanned the whole repository once and kept the range's commits", len(nc.heads))
		return []trufflePass{{}}, nc.set, nil
	}
	var ps []trufflePass
	for _, h := range nc.heads {
		ps = append(ps, trufflePass{branch: h, since: nc.since(h)})
	}
	return ps, nc.set, nil
}

func (e *truffle) ScanGit(ctx context.Context, repo string, r core.Range, o core.ScanOpts, emit core.Emit) error {
	g, err := e.openGit(ctx, repo, r)
	if err != nil || len(g.args) == 0 {
		return err
	}
	passes, keep, err := e.passes(ctx, g, r)
	if err != nil {
		return err
	}
	lr := newGitLines(ctx, g.dir)
	defer lr.close()
	sk := &sink{emit: emit, namer: newRefNamer(ctx, g.dir)}
	seen := map[string]struct{}{} // passes overlap when heads share history
	for _, p := range passes {
		log := &thLog{}
		err := e.run(ctx, func(string) (job, error) {
			return job{args: e.gitArgs(o, g.dir, p), env: jobEnv(o, diffEnv...), stderr: log}, nil
		}, func(rd io.Reader) error {
			return streamValues(rd, func(rec *truffleRec) error {
				gm := rec.SourceMetadata.Data.Git
				if gm == nil {
					return nil
				}
				if keep != nil {
					if _, in := keep[gm.Commit]; !in {
						return nil
					}
				}
				c, ok := e.cand(o, rec, gm.Commit, gm.File, gm.Line, authorName(gm.Email), gm.Timestamp, lr)
				if !ok {
					return nil
				}
				k := c.hit.Loc.Key() + "|" + c.hit.FP + "|" + c.hit.Rule
				if _, dup := seen[k]; dup {
					return nil
				}
				seen[k] = struct{}{}
				sk.add(c)
				return nil
			})
		})
		if err == nil {
			err = e.checkRead(ctx, g, p, log)
		}
		if err != nil {
			sk.flush()
			return err
		}
	}
	sk.flush()
	return nil
}

// checkRead is the check that trufflehog read something. A scan that read nothing exits 0 and
// prints no results, exactly like a clean one, and the ways to get one are silent (a directory
// it skipped, a repository it could not open). Its summary line says how many bytes it read. Zero
// is only a failure where there was text to read: a commit that only deletes files, adds an empty
// file or a binary is zero bytes to read, and git, asked what the pass adds, says which it was.
// A summary that did not come proves nothing either way.
func (e *truffle) checkRead(ctx context.Context, g gitScan, p trufflePass, log *thLog) error {
	seen, _, read := log.summary()
	if !seen || read > 0 {
		return nil
	}
	adds, err := rangeAddsText(ctx, g.dir, p.revs())
	if err != nil {
		return err
	}
	if adds {
		return fmt.Errorf("engines: trufflehog: scanned 0 bytes of a range that adds text; the repository was not read")
	}
	return nil
}

// rangeAddsText says whether any non-merge commit of the range adds or changes lines of text,
// which is what trufflehog scans (it diffs with --diff-filter=AM). git writes "-" for the line
// counts of a binary file, so those do not count.
func rangeAddsText(ctx context.Context, gitDir string, revs []string) (bool, error) {
	args := append([]string{"--git-dir=" + gitDir, "log", "--no-renames", "--diff-filter=AM", "--numstat", "--format="}, revs...)
	cmd := gitCmd(ctx, gitDir, nil, append(args, "--")...)
	out, err := cmd.StdoutPipe()
	if err != nil {
		return false, err
	}
	var stderr tailBuf
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return false, err
	}
	found := false
	sc := bufio.NewScanner(out)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	for sc.Scan() {
		added, _, _ := strings.Cut(sc.Text(), "\t")
		if n, err := strconv.Atoi(added); err == nil && n > 0 {
			found = true
			break
		}
	}
	if found {
		cmd.Process.Kill() // one added line answers it
	}
	io.Copy(io.Discard, out)
	werr := cmd.Wait()
	if found {
		return true, nil
	}
	if err := sc.Err(); err != nil {
		return false, err
	}
	if werr != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		return false, fmt.Errorf("engines: git log: %v; stderr: %s", werr, stderr.text())
	}
	return false, nil
}

func (e *truffle) ScanStaged(context.Context, string, core.ScanOpts, core.Emit) error {
	return core.ErrUnsupported
}

func (e *truffle) ScanDir(ctx context.Context, dir string, o core.ScanOpts, emit core.Emit) error {
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
	lr := newFSLines()
	sk := &sink{emit: emit}
	err = e.run(ctx, func(scratch string) (job, error) {
		return job{args: e.dirArgs(o, d, writeExclude(scratch)), env: jobEnv(o), stderr: &thLog{}}, nil
	}, func(rd io.Reader) error {
		return streamValues(rd, func(rec *truffleRec) error {
			fs := rec.SourceMetadata.Data.Filesystem
			if fs == nil {
				return nil
			}
			path := fs.File
			if !filepath.IsAbs(path) {
				path = filepath.Join(d, path)
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				rel = path
			}
			c, ok := e.cand(o, rec, "", path, fs.Line, "", "", lr)
			if !ok {
				return nil
			}
			c.hit.Loc.Path = rel
			sk.add(c)
			return nil
		})
	})
	sk.flush()
	return err
}

// cand builds the candidate for one record; path is what the line reader opens, which for
// directory scans is the absolute file.
func (e *truffle) cand(o core.ScanOpts, rec *truffleRec, commit, path string, line int, author, date string, lr lineReader) (cand, bool) {
	raw := truffleRaw(rec)
	if raw == "" {
		return cand{}, false
	}
	v, why := truffleVerified(rec)
	return e.newCand(o, found{
		raw: raw, line: lr.line(commit, path, line), rule: rec.DetectorName, verified: v, reasonText: why,
		commit: commit, path: path, lineNo: line, author: author, date: date,
	}), true
}

// truffleRaw is the value to fingerprint. Raw, unless the detector is AWS and found a pair:
// Raw is then the key id and RawV2 the id with the secret key after it, and the secret key is
// the credential. It is also what titus's AWS secret rule and a learned ~/.aws/credentials
// entry have, so the three agree.
func truffleRaw(rec *truffleRec) string {
	raw, v2 := strings.TrimSpace(rec.Raw), strings.TrimSpace(rec.RawV2)
	if rec.DetectorName == "AWS" && raw != "" && strings.HasPrefix(v2, raw) && len(v2) == len(raw)+awsSecretLen {
		return v2[len(raw):]
	}
	if raw != "" {
		return raw
	}
	return v2
}

const awsSecretLen = 40

// truffleVerified: a detector that was rejected by its provider and one that has no verifier
// look the same in trufflehog's report (Verified false, no error), so "not verified" is
// Unverified, never Dead. Calling an unverifiable live key dead would let it be auto-resolved.
// A verification error is returned as its text, to be classified and dropped.
func truffleVerified(rec *truffleRec) (core.Verified, string) {
	switch {
	case rec.Verified:
		return core.Live, ""
	case rec.VerificationError != "":
		return core.VerifyError, rec.VerificationError
	}
	return core.Unverified, ""
}
