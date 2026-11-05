package engines

import (
	"encoding/base64"
	"encoding/json"
	"regexp"
	"slices"
	"strings"

	"keyguard/internal/core"
	"keyguard/internal/fp"
)

// found is one finding as an engine reported it. raw is the only field that must never
// outlive the scan: newCand fingerprints it and the sink drops it.
type found struct {
	raw          string // the extent the engine reported; fp.Canonical decides what is fingerprinted
	line         string // source line when the engine or a line reader has it
	rule         string
	verified     core.Verified
	reasonText   string // the verifier's own words for VerifyError; only their class is kept
	commit, path string
	lineNo       int
	endLine      int // last line of a value that spans several; 0 = the value's own line count
	author, date string
	group        string // what makes two hits share a text: "" = commit and path
}

// cand is a hit that is not yet emitted. It still holds the canonical value, in memory only,
// so the sink can tell a fragment from the credential it is part of before either is stored.
type cand struct {
	hit         core.Hit
	val         string
	group       string
	first, last int
}

// newCand turns a finding into a Hit. This is the one place a raw value is read: the
// fingerprint, the display shape, the length, the entropy, the tags and the redacted context
// are all computed here, from what fp.Canonical makes of the extent, so that every engine's
// report of one credential is the same Secret (STEAL P0-08).
func (b *base) newCand(o core.ScanOpts, f found) cand {
	canon := fp.Canonical(f.raw)
	line := fp.Redact(clip(f.line, f.raw), canon)
	h := core.Hit{
		Engine:   b.name,
		Rule:     f.rule,
		Type:     NormalizeType(b.name, f.rule),
		FP:       b.fp.FP(canon),
		Shape:    fp.Shape(canon),
		Len:      len(canon),
		Entropy:  fp.Entropy(canon),
		Verified: f.verified,
		Context:  fp.Context(line, f.raw),
		Tags:     tagsFor(canon),
		Loc:      o.Loc,
	}
	if f.verified == core.VerifyError {
		h.VerifyReason = classifyReason(f.reasonText)
	}
	h.Loc.Commit, h.Loc.Path, h.Loc.Line = f.commit, f.path, f.lineNo
	h.Loc.Author, h.Loc.Date = f.author, isoDate(f.date)
	h.Loc.URL = blobURL(h.Loc)
	group := f.group
	if group == "" {
		group = f.commit + "\x00" + f.path
	}
	last := max(f.endLine, f.lineNo+strings.Count(strings.TrimRight(f.raw, "\r\n"), "\n"))
	return cand{hit: h, val: canon, group: group, first: f.lineNo, last: last}
}

// ----- one leak is one secret -----

// maxContainSpan bounds how many lines below its first a value is searched for fragments in.
const maxContainSpan = 4096

// dropContained removes the hits that are part of another hit on the same text (STEAL P0-08).
// A specific hit swallows a hit on the same lines whose value is a proper substring of its own:
// titus's np.generic.2 matched 47 characters inside an Anthropic key, np.mailgun.1 the hex
// after "key-", np.pem.1 the body of a key whose armor another rule reported. It also swallows
// a generic hit of the same value, the less specific label for one thing. What it never does:
// swallow a hit because of a generic one (a generic rule is the least specific), swallow two
// equally specific hits of one value (they are two witnesses), or discard a verdict, which is
// evidence whatever it is a fragment of.
func dropContained(cs []cand) []cand {
	if len(cs) < 2 {
		return cs
	}
	type at struct {
		group string
		line  int
	}
	starts := make(map[at][]int, len(cs))
	for i, c := range cs {
		k := at{c.group, c.first}
		starts[k] = append(starts[k], i)
	}
	gone := make([]bool, len(cs))
	for j, outer := range cs {
		if outer.hit.Type == Generic {
			continue
		}
		for l := outer.first; l <= min(outer.last, outer.first+maxContainSpan); l++ {
			for _, i := range starts[at{outer.group, l}] {
				if i != j && covers(outer, cs[i]) {
					gone[i] = true
				}
			}
		}
	}
	kept := cs[:0:0]
	for i, c := range cs {
		if !gone[i] {
			kept = append(kept, c)
		}
	}
	return kept
}

func covers(outer, in cand) bool {
	if in.hit.Verified.Decisive() || in.val == "" {
		return false
	}
	a, b := outer.val, in.val
	if len(b) > len(a) {
		return false
	}
	// A value that spans lines is compared without its line breaks and indentation: titus's
	// np.pem.1 reports the body wrapped as it is in the file (or with the two characters \n that
	// a JSON string or a .env file has instead of a break), another engine's canonical key has
	// it on one line.
	if spans(a) || spans(b) {
		a, b = squeeze(a), squeeze(b)
	}
	switch {
	case b == "" || len(b) > len(a):
		return false
	case len(b) == len(a):
		return a == b && in.hit.Type == Generic
	}
	return strings.Contains(a, b)
}

func spans(s string) bool {
	return strings.ContainsAny(s, " \t\r\n") || strings.Contains(s, `\n`) || strings.Contains(s, `\r`)
}

var escapedBreaks = strings.NewReplacer(`\r`, "", `\n`, "")

// squeeze removes everything a line wrapper adds: white space, and the escaped line breaks.
func squeeze(s string) string { return strings.Join(strings.Fields(escapedBreaks.Replace(s)), "") }

// ----- why a check could not decide -----

// reasonRules are tried in order. The order matters: "dial tcp 10.0.0.1:443: i/o timeout" is a
// timeout, and "dial tcp: lookup x: no such host" is a DNS failure, before either is a failed dial.
var reasonRules = []struct {
	class core.VerifyReason
	re    *regexp.Regexp
}{
	{core.ReasonOverlap, regexp.MustCompile(`overlap`)},
	{core.ReasonRateLimited, regexp.MustCompile(`\b429\b|rate.?limit|too many requests`)},
	{core.ReasonTimeout, regexp.MustCompile(`deadline exceeded|timed? ?out|timeout`)},
	{core.ReasonDNS, regexp.MustCompile(`no such host|\bdns\b|server misbehaving|lookup \S+ on `)},
	{core.ReasonDial, regexp.MustCompile(`\beof\b|connection (refused|reset)|dial tcp|\btls\b|x509|certificate|handshake|unreachable|no route to host|broken pipe|egress blocked|connect:`)},
	{core.ReasonStatus, regexp.MustCompile(`\bstatus\b|(?:http|code|response)\D{0,12}\b[45]\d\d\b|bad gateway|service unavailable|internal server error`)},
}

// quoted and userinfo are the parts of an error that can hold the credential being checked: a
// request URL in quotes, the user:password of a connection string.
var (
	quoted   = regexp.MustCompile(`"[^"]*"|'[^']*'`)
	userinfo = regexp.MustCompile(`://[^\s/@]*@`)
)

// classifyReason maps a verifier's error text to one of core's six classes and drops the text.
// A verifier's error can quote the credential it was checking (a connection URL with its
// password in it), so nothing of it is kept, and what is looked at is the text with its
// quoted and userinfo parts removed. Text no rule knows is ReasonNone: the check could not
// decide, and why is unknown.
func classifyReason(text string) core.VerifyReason {
	if text == "" {
		return core.ReasonNone
	}
	if len(text) > 1<<10 {
		text = text[:1<<10]
	}
	text = userinfo.ReplaceAllString(quoted.ReplaceAllString(strings.ToLower(text), " "), "://")
	for _, r := range reasonRules {
		if r.re.MatchString(text) {
			return r.class
		}
	}
	return core.ReasonNone
}

// ----- tags -----

// Tags are facts about a value that Shape, Len and Context cannot carry. They are a fixed
// vocabulary, shared with internal/triage (TestTagsMatchTriage keeps the two equal), and
// never a piece of the value.
const (
	tagPlaceholder    = "placeholder"
	tagJWTAnon        = "jwt.role=anon"
	tagJWTServiceRole = "jwt.role=service_role"
	tagTestMode       = "test-mode"
)

func tagsFor(v string) []string {
	var tags []string
	if isPlaceholder(v) {
		tags = append(tags, tagPlaceholder)
	}
	switch jwtRole(v) {
	case "anon":
		tags = append(tags, tagJWTAnon)
	case "service_role":
		tags = append(tags, tagJWTServiceRole)
	}
	if isTestMode(v) {
		tags = append(tags, tagTestMode)
	}
	return tags
}

// placeholderWords are what a value says about itself. Each is long enough that a random key
// does not contain it: a 40 character base62 key holds "dummy" about once in 10^8.
var placeholderWords = []string{
	"your_", "your-", "yourkey", "changeme", "change_me", "change-me", "replace_me", "replace-me", "replaceme",
	"placeholder", "redacted", "dummy", "example", "insert_", "insert-",
}

var placeholderShape = regexp.MustCompile(`[xX*#]{6,}|^<[^<>]+>$|\$\{[^}]*\}|\{\{[^}]*\}\}|%\([a-z_]+\)s`)

func isPlaceholder(v string) bool {
	if placeholderShape.MatchString(v) {
		return true
	}
	l := strings.ToLower(v)
	return slices.ContainsFunc(placeholderWords, func(w string) bool { return strings.Contains(l, w) })
}

func isTestMode(v string) bool {
	return strings.HasPrefix(v, "sk_test_") || strings.HasPrefix(v, "pk_test_") || strings.HasPrefix(v, "rk_test_")
}

// jwtRole is the role claim of a JWT: "anon" and "service_role" are the two that mean
// something to triage (Supabase's public key, and the one that bypasses row-level security).
func jwtRole(v string) string {
	if !strings.HasPrefix(v, "eyJ") {
		return ""
	}
	parts := strings.Split(v, ".")
	if len(parts) < 2 || len(parts[1]) > 4<<10 {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return ""
	}
	var claims struct {
		Role string `json:"role"`
	}
	if json.Unmarshal(raw, &claims) != nil {
		return ""
	}
	switch claims.Role {
	case "anon", "service_role":
		return claims.Role
	}
	return ""
}

// ----- the sink -----

// sink holds a scan's hits until the scan has seen all of them, then drops fragments (see
// dropContained), has the refs containing their commits resolved with one git call instead of
// one per hit, and hands them on.
type sink struct {
	emit  core.Emit
	namer *refNamer
	buf   []cand
}

// flushAt bounds the batch held back. A variable so a test can force batching.
var flushAt = 20000

func (s *sink) add(c cand) {
	s.buf = append(s.buf, c)
	if len(s.buf) >= flushAt {
		s.flush()
	}
}

func (s *sink) flush() {
	if len(s.buf) == 0 {
		return
	}
	kept := dropContained(s.buf)
	hits := make([]core.Hit, len(kept))
	for i, c := range kept {
		hits[i] = c.hit
	}
	clear(s.buf) // the canonical values go with it
	s.buf = s.buf[:0]
	if s.namer != nil {
		s.namer.fill(hits)
	}
	for _, h := range hits {
		s.emit(h)
	}
}
