package engines

import (
	"context"
	"encoding/json"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"keyguard/internal/core"
	"keyguard/internal/fp"
)

// ----- P0-08: one fingerprint per credential -----

// Engines report different stretches of one credential: betterleaks the password of a
// connection URI (generic-credential-uri) or the whole URI (mongodb-connection-string),
// trufflehog the URI up to the port, titus every capture group, which put the user name where
// the secret should be. Their fingerprints differed, so nothing deduplicated and no agreement
// between engines could be counted. The fingerprint is of fp.Canonical of the extent.
func TestOneCredentialIsOneFingerprint(t *testing.T) {
	f := getFixture(t)
	root := t.TempDir()
	pgPW, mongoPW := register(tok(alnumCS, 18)), register(tok(alnumCS, 18))
	writeLines(t, root, "app.env",
		"DATABASE_URL="+uriOf("postgres", "appuser", pgPW, "db.example.invalid:5432/app"),
		"MONGO_URL="+uriOf("mongodb", "appuser", mongoPW, "db.example.invalid:27017/app"))
	key := realKeys(t)["rsa"]
	writeLines(t, root, "id_rsa", strings.Split(key, "\n")...)
	writeLines(t, root, "key.json", `{"private_key": "`+strings.ReplaceAll(key, "\n", `\n`)+`"}`)
	canonKey := fp.Canonical(key)

	byLine := map[string]map[string][]string{} // "path:line" -> engine -> rules per FP
	perFP := map[string]map[string]bool{}      // "path:line" -> FP -> true
	seenBy := map[string][]string{}            // credential -> engines that reported it
	for _, name := range Names {
		e := newEngine(t, name, f.kr)
		resetAudit()
		var hits []core.Hit
		o := core.ScanOpts{Loc: core.Location{Source: "local:" + root, Kind: "file", Visibility: core.Local}}
		if err := e.ScanDir(context.Background(), root, o, func(h core.Hit) { hits = append(hits, h) }); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		assertSafe(t, name, hits)
		for _, h := range hits {
			k := h.Loc.Path + ":" + strconv.Itoa(h.Loc.Line)
			if perFP[k] == nil {
				perFP[k] = map[string]bool{}
				byLine[k] = map[string][]string{}
			}
			perFP[k][h.FP] = true
			byLine[k][name] = append(byLine[k][name], h.Rule)
			switch {
			case h.Loc.Path == "app.env" && h.Loc.Line == 1 && h.FP == f.kr.FP(pgPW):
				seenBy["postgres"] = appendOnce(seenBy["postgres"], name)
			case h.Loc.Path == "app.env" && h.Loc.Line == 2 && h.FP == f.kr.FP(mongoPW):
				seenBy["mongodb"] = appendOnce(seenBy["mongodb"], name)
			case h.Loc.Path == "id_rsa" && h.FP == f.kr.FP(canonKey):
				seenBy["pem"] = appendOnce(seenBy["pem"], name)
			case h.Loc.Path == "key.json" && h.FP == f.kr.FP(canonKey):
				seenBy["pem as json"] = appendOnce(seenBy["pem as json"], name)
			}
			if h.Type == "private-key" && (h.Len != len(canonKey) || h.Shape != fp.Shape(canonKey)) {
				t.Errorf("%s %s: private key has len %d shape %q, want the canonical form's %d %q", name, h.Rule, h.Len, h.Shape, len(canonKey), fp.Shape(canonKey))
			}
			// Whatever line an engine starts the key on (titus's np.pem.1 starts at the body),
			// nothing about the key may come out under another fingerprint.
			if (h.Loc.Path == "id_rsa" || h.Loc.Path == "key.json") && h.FP != f.kr.FP(canonKey) {
				t.Errorf("%s %s: a hit inside the private key file has its own fingerprint (line %d, %d bytes)", name, h.Rule, h.Loc.Line, h.Len)
			}
		}
	}
	// One credential on a line is one fingerprint, whoever reported it and however much of it.
	want := map[string]string{"app.env:1": f.kr.FP(pgPW), "app.env:2": f.kr.FP(mongoPW), "id_rsa:1": f.kr.FP(canonKey)}
	for k, fps := range perFP {
		w, tracked := want[k]
		if !tracked {
			continue
		}
		if len(fps) != 1 || !fps[w] {
			t.Errorf("%s: %d distinct fingerprints from %v, want exactly the credential's", k, len(fps), byLine[k])
		}
	}
	// ... and the claim is not vacuous: several engines saw each of them.
	for cred, who := range seenBy {
		t.Logf("%s reported by %v", cred, who)
	}
	for _, cred := range []string{"postgres", "mongodb", "pem"} {
		if len(seenBy[cred]) < 2 {
			t.Errorf("%s was reported (under its canonical fingerprint) by only %v", cred, seenBy[cred])
		}
	}
	if len(seenBy["pem as json"]) < 1 {
		t.Errorf("no engine reported the key written as one JSON string under the same fingerprint as the wrapped file")
	}
}

func appendOnce(s []string, v string) []string {
	if slices.Contains(s, v) {
		return s
	}
	return append(s, v)
}

// leakJSON is a betterleaks report with one finding per record.
func leakJSON(t *testing.T, recs ...map[string]any) string {
	t.Helper()
	b, err := json.Marshal(recs)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func rec(root, rule, secret string, line, endLine int, extra ...[2]string) map[string]any {
	r := map[string]any{
		"RuleID": rule, "File": filepath.Join(root, "a.txt"), "StartLine": line, "EndLine": endLine,
		"Secret": secret, "Match": secret, "MatchContext": secret,
	}
	for _, kv := range extra {
		r[kv[0]] = kv[1]
	}
	return r
}

// A hit whose value is a proper substring of a specific hit's on the same line is a fragment of
// it (titus np.generic.2 matched 47 characters inside an Anthropic key; np.mailgun.1 the hex
// after "key-"): it is dropped, so one leak is one secret. A generic hit does not swallow a
// specific one, a different line or file does not count, and a verdict is never discarded.
func TestHitsInsideAnotherHitAreDropped(t *testing.T) {
	f := getFixture(t)
	root := t.TempDir()
	long := register(fake("anthropic"))
	frag := register(long[12:50])
	hexOnly := register(tok(hexCS, 32))
	mailgun := "key-" + hexOnly
	register(mailgun)
	keep := register(tok(alnumCS, 30))
	other := register(tok(alnumCS, 30))

	pem := register(realKeys(t)["ec"])
	body := strings.Split(pem, "\n")[2]

	report := leakJSON(t,
		rec(root, "anthropic-api-key", long, 3, 3),
		rec(root, "generic-api-key", frag, 3, 3),              // a fragment of the above: dropped
		rec(root, "generic-api-key", frag, 4, 4),              // the same text on another line: kept
		rec(root, "generic-api-key", long, 3, 3),              // the same value, less specific: dropped
		rec(root, "mailgun-private-api-token", hexOnly, 6, 6), // a specific fragment ...
		rec(root, "mailgun-pub-key", mailgun, 6, 6),           // ... of a longer specific hit: dropped
		rec(root, "generic-api-key", keep, 7, 7),              // generic, alone: kept
		rec(root, "stripe-access-token", other, 8, 8),         // unrelated: kept
		rec(root, "private-key", pem, 10, 10+strings.Count(pem, "\n")),
		rec(root, "generic-api-key", body, 12, 12),                                  // a body line of the key: dropped
		rec(root, "generic-api-key", body, 40, 40),                                  // not within the key's lines: kept
		rec(root, "github-pat", frag, 3, 3, [2]string{"ValidationStatus", "valid"}), // has a verdict: kept
	)
	e := scriptEngine(t, "betterleaks", f.kr, report, "", 0)
	var hits []core.Hit
	if err := e.ScanDir(context.Background(), root, testOpts(), func(h core.Hit) { hits = append(hits, h) }); err != nil {
		t.Fatal(err)
	}
	assertSafe(t, "betterleaks", hits)
	type key struct {
		rule string
		line int
	}
	got := map[key]bool{}
	for _, h := range hits {
		got[key{h.Rule, h.Loc.Line}] = true
	}
	for _, c := range []struct {
		k    key
		want bool
		why  string
	}{
		{key{"anthropic-api-key", 3}, true, "the whole key"},
		{key{"generic-api-key", 4}, true, "a fragment on a line where the whole key is not"},
		{key{"mailgun-pub-key", 6}, true, "the longer specific hit"},
		{key{"mailgun-private-api-token", 6}, false, "a specific fragment of a longer specific hit"},
		{key{"generic-api-key", 7}, true, "a generic hit with nothing to be a fragment of"},
		{key{"stripe-access-token", 8}, true, "unrelated"},
		{key{"private-key", 10}, true, "the whole PEM block"},
		{key{"generic-api-key", 12}, false, "a body line inside the PEM block's lines"},
		{key{"generic-api-key", 40}, true, "the same text outside the block's lines"},
		{key{"github-pat", 3}, true, "a verified hit is evidence, never a fragment"},
	} {
		if got[c.k] != c.want {
			t.Errorf("%s at line %d: kept=%v, want %v (%s)", c.k.rule, c.k.line, got[c.k], c.want, c.why)
		}
	}
	// generic-api-key on line 3 appears twice in the report (a fragment, and the whole value);
	// both are covered by the specific hit.
	n3 := 0
	for _, h := range hits {
		if h.Loc.Line == 3 && h.Rule == "generic-api-key" {
			n3++
		}
	}
	if n3 != 0 {
		t.Errorf("%d generic hits survive on the line of the whole key", n3)
	}
}

// Titus reports every capture group of a rule, and a rule's secret is not always the first:
// np.postgres.1 captures the user name before the password. The group that is the secret is the
// one named for it.
func TestTitusFingerprintsTheGroupThatIsTheSecret(t *testing.T) {
	f := getFixture(t)
	root := t.TempDir()
	pw, user, host := register(tok(alnumCS, 18)), "appuser", "db.example.invalid"
	tokenV, keyV, plain := register(tok(alnumCS, 30)), register("sk_live_"+tok(alnumCS, 24)), register(tok(alnumCS, 26))
	idV, secretV := "AKIA"+tok(upperCS+digitCS, 16), register(tok(alnumCS, 40))
	writeLines(t, root, "a.txt", "x")
	blob, ok := gitBlobID(filepath.Join(root, "a.txt"))
	if !ok {
		t.Fatal("cannot hash the file")
	}
	g := func(vs ...string) [][]byte {
		var out [][]byte
		for _, v := range vs {
			out = append(out, []byte(v))
		}
		return out
	}
	r := func(rule string, groups [][]byte, named map[string][]byte, line int) map[string]any {
		return map[string]any{
			"BlobID": blob, "RuleID": rule, "Groups": groups, "NamedGroups": named,
			"Location": map[string]any{"Source": map[string]any{"Start": map[string]any{"Line": line}}},
			"Snippet":  map[string]any{"Before": []byte(""), "Matching": []byte("m"), "After": []byte("")},
		}
	}
	recs := []map[string]any{
		r("np.postgres.1", g(user, pw, host, "5432"), map[string][]byte{"username": []byte(user), "password": []byte(pw), "host": []byte(host), "port": []byte("5432")}, 1),
		r("np.stripe.1", g(keyV), map[string][]byte{"key": []byte(keyV)}, 2),
		r("kingfisher.vendor.1", g("client-id-123456", tokenV), map[string][]byte{"client_id": []byte("client-id-123456"), "token": []byte(tokenV)}, 3),
		r("np.aws.6", g(idV, secretV), map[string][]byte{"key_id": []byte(idV), "secret": []byte(secretV)}, 4),
		r("np.generic.1", g(plain), nil, 5),
	}
	b, _ := json.Marshal(recs)
	e := scriptEngine(t, "titus", f.kr, string(b), "", 0)
	var hits []core.Hit
	if err := e.ScanDir(context.Background(), root, testOpts(), func(h core.Hit) { hits = append(hits, h) }); err != nil {
		t.Fatal(err)
	}
	assertSafe(t, "titus", hits)
	want := map[int]string{1: pw, 2: keyV, 3: tokenV, 4: secretV, 5: plain}
	if len(hits) != len(want) {
		t.Fatalf("%d hits, want %d", len(hits), len(want))
	}
	for _, h := range hits {
		if w := want[h.Loc.Line]; h.FP != f.kr.FP(w) || h.Len != len(w) {
			t.Errorf("line %d (%s): fingerprinted the wrong group", h.Loc.Line, h.Rule)
		}
	}
}

// trufflehog's AWS detector reports the key id as Raw and id+secret as RawV2. The id alone is
// not the secret: with the pair, the secret key is what gets fingerprinted, the same bytes
// titus's secret rule and the learned ~/.aws/credentials entry have.
func TestTrufflehogAWSPairIsFingerprintedByItsSecretKey(t *testing.T) {
	f := getFixture(t)
	root := t.TempDir()
	id := "AKIA" + tok(upperCS+digitCS, 16)
	secret := register(tok(alnumCS, 40))
	idOnly := "AKIA" + tok(upperCS+digitCS, 16)
	rec := func(raw, v2 string, line int) string {
		b, _ := json.Marshal(map[string]any{
			"DetectorName": "AWS", "Raw": raw, "RawV2": v2,
			"SourceMetadata": map[string]any{"Data": map[string]any{"Filesystem": map[string]any{"file": filepath.Join(root, "a.txt"), "line": line}}},
		})
		return string(b) + "\n"
	}
	e := scriptEngine(t, "trufflehog", f.kr, rec(id, id+secret, 1)+rec(idOnly, "", 2), "", 0)
	var hits []core.Hit
	if err := e.ScanDir(context.Background(), root, testOpts(), func(h core.Hit) { hits = append(hits, h) }); err != nil {
		t.Fatal(err)
	}
	if len(hits) != 2 {
		t.Fatalf("%d hits", len(hits))
	}
	for _, h := range hits {
		switch h.Loc.Line {
		case 1:
			if h.FP != f.kr.FP(secret) || h.Len != 40 {
				t.Errorf("an id+secret pair is not fingerprinted by its secret key (len %d)", h.Len)
			}
		case 2:
			if h.FP != f.kr.FP(idOnly) {
				t.Errorf("a lone key id lost its own fingerprint")
			}
		}
	}
}
