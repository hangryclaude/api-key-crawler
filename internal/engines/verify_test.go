package engines

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"keyguard/internal/core"
	"keyguard/internal/triage"
)

// ----- P0-04, P0-09: an error is a class, never the verifier's own words -----

// A verifier's error can quote what it was checking: a connection URL with its password in it.
// The hit keeps one of six classes and nothing else, so no credential reaches findings.json
// through the reason of a failed check.
func TestVerifyErrorsBecomeClasses(t *testing.T) {
	f := getFixture(t)
	pw := register(tok(alnumCS, 14)) // short enough that fp.Scrub would not mask it
	root := t.TempDir()
	texts := map[core.VerifyReason][]string{
		core.ReasonTimeout:     {"context deadline exceeded", `Get "https://api.example.invalid/v1": net/http: request canceled (Client.Timeout exceeded while awaiting headers)`, "dial tcp 10.0.0.1:443: i/o timeout"},
		core.ReasonRateLimited: {"unexpected HTTP status 429 Too Many Requests", "rate limited, retry later"},
		core.ReasonDNS:         {"lookup api.example.invalid on 192.0.2.1:53: no such host"},
		core.ReasonDial: {"dial tcp 127.0.0.1:9: connect: connection refused", "EOF", `Post "https://u:` + pw + `@db.example.invalid/": tls: failed to verify certificate: x509: certificate signed by unknown authority`,
			"egress blocked: non-public address"},
		core.ReasonStatus:  {"unexpected response status 503", "unexpected HTTP status 502"},
		core.ReasonOverlap: {"verification skipped: the credential matches several detectors (overlap)"},
		core.ReasonNone:    {"something no table has seen before " + pw},
	}
	var stream strings.Builder
	want := map[int]core.VerifyReason{}
	line := 0
	for class, ts := range texts {
		for _, text := range ts {
			line++
			raw := register("sk_live_" + tok(alnumCS, 24))
			b, _ := json.Marshal(map[string]any{
				"DetectorName": "Stripe", "Verified": false, "Raw": raw, "VerificationError": text,
				"SourceMetadata": map[string]any{"Data": map[string]any{"Filesystem": map[string]any{"file": filepath.Join(root, "a.txt"), "line": line}}},
			})
			stream.Write(b)
			stream.WriteString("\n")
			want[line] = class
		}
	}
	e := scriptEngine(t, "trufflehog", f.kr, stream.String(), "", 0)
	var hits []core.Hit
	if err := e.ScanDir(context.Background(), root, testOpts(), func(h core.Hit) { hits = append(hits, h) }); err != nil {
		t.Fatal(err)
	}
	assertSafe(t, "trufflehog", hits)
	if len(hits) != len(want) {
		t.Fatalf("%d hits, want %d", len(hits), len(want))
	}
	for _, h := range hits {
		if h.Verified != core.VerifyError {
			t.Errorf("line %d: verified %q, want error", h.Loc.Line, h.Verified)
		}
		if h.VerifyReason != want[h.Loc.Line] {
			t.Errorf("line %d: reason %q, want %q", h.Loc.Line, h.VerifyReason, want[h.Loc.Line])
		}
		if h.VerifyReason != h.VerifyReason.Class() {
			t.Errorf("line %d: reason %q is not one of the classes", h.Loc.Line, h.VerifyReason)
		}
	}
	b, _ := json.Marshal(hits)
	assertNoRaw(t, "hits", b)
	if strings.Contains(string(b), pw) {
		t.Error("a verifier's error text reached a hit")
	}

	// betterleaks: error and unknown are undecided checks with a reason; a clean verdict has none.
	recs := []map[string]any{
		rec(root, "github-pat", fake("github"), 1, 1, [2]string{"ValidationStatus", "error"}, [2]string{"ValidationReason", "Get \"https://api.github.com/user\": context deadline exceeded"}),
		rec(root, "github-pat", fake("github"), 2, 2, [2]string{"ValidationStatus", "unknown"}, [2]string{"ValidationReason", "HTTP 503 from the provider " + pw}),
		rec(root, "github-pat", fake("github"), 3, 3, [2]string{"ValidationStatus", "invalid"}, [2]string{"ValidationReason", "HTTP 401 bad credentials " + pw}),
		rec(root, "github-pat", fake("github"), 4, 4, [2]string{"ValidationStatus", "valid"}),
	}
	bl := scriptEngine(t, "betterleaks", f.kr, leakJSON(t, recs...), "", 0)
	hits = nil
	if err := bl.ScanDir(context.Background(), root, testOpts(), func(h core.Hit) { hits = append(hits, h) }); err != nil {
		t.Fatal(err)
	}
	assertSafe(t, "betterleaks", hits)
	b, _ = json.Marshal(hits)
	if strings.Contains(string(b), pw) {
		t.Error("a validation reason reached a hit")
	}
	wantBL := map[int]struct {
		v core.Verified
		r core.VerifyReason
	}{1: {core.VerifyError, core.ReasonTimeout}, 2: {core.VerifyError, core.ReasonStatus}, 3: {core.Dead, core.ReasonNone}, 4: {core.Live, core.ReasonNone}}
	for _, h := range hits {
		if w := wantBL[h.Loc.Line]; h.Verified != w.v || h.VerifyReason != w.r {
			t.Errorf("betterleaks line %d: %q/%q, want %q/%q", h.Loc.Line, h.Verified, h.VerifyReason, w.v, w.r)
		}
	}
}

// ----- P0-09: tags, computed while the value is still in hand -----

func jwtOf(payload string) string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"HS256","typ":"JWT"}`)) + "." + enc([]byte(payload)) + "." + enc([]byte("signature-bytes-"+tok(alnumCS, 8)))
}

// Shape, Len and Context cannot tell a Supabase anon key from a service_role key, or a Stripe
// test key from a live one; triage needs to. The tags are a fixed vocabulary and never a piece
// of the value.
func TestHitsCarryTagsComputedFromTheRawValue(t *testing.T) {
	f := getFixture(t)
	root := t.TempDir()
	anon := register(jwtOf(`{"iss":"supabase","ref":"abcdefghijklmnop","role":"anon","iat":1700000000,"exp":2000000000}`))
	service := register(jwtOf(`{"iss":"supabase","ref":"abcdefghijklmnop","role":"service_role","iat":1700000000,"exp":2000000000}`))
	other := register(jwtOf(`{"sub":"1234567890","name":"Someone"}`))
	testKey := register("sk_test_" + tok(alnumCS, 24))
	liveKey := register("sk_live_" + tok(alnumCS, 24))
	placeholderKey := register("sk_live_" + strings.Repeat("x", 24))
	yourKey := register("your_api_key_" + tok(alnumCS, 10))
	plain := register(tok(alnumCS, 32))

	cases := []struct {
		raw  string
		line int
		want []string
	}{
		{anon, 1, []string{triage.TagJWTAnon}},
		{service, 2, []string{triage.TagJWTServiceRole}},
		{other, 3, nil},
		{testKey, 4, []string{triage.TagTestMode}},
		{liveKey, 5, nil},
		{placeholderKey, 6, []string{triage.TagPlaceholder}},
		{yourKey, 7, []string{triage.TagPlaceholder}},
		{plain, 8, nil},
	}
	var recs []map[string]any
	for _, c := range cases {
		recs = append(recs, rec(root, "generic-api-key", c.raw, c.line, c.line))
	}
	e := scriptEngine(t, "betterleaks", f.kr, leakJSON(t, recs...), "", 0)
	var hits []core.Hit
	if err := e.ScanDir(context.Background(), root, testOpts(), func(h core.Hit) { hits = append(hits, h) }); err != nil {
		t.Fatal(err)
	}
	assertSafe(t, "betterleaks", hits)
	if len(hits) != len(cases) {
		t.Fatalf("%d hits, want %d", len(hits), len(cases))
	}
	for _, h := range hits {
		want := cases[h.Loc.Line-1].want
		got := slices.Clone(h.Tags)
		slices.Sort(got)
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Errorf("line %d: tags %v, want %v", h.Loc.Line, got, want)
		}
	}
}
