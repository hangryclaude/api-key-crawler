package bench

import (
	"context"
	"encoding/base64"
	"fmt"
	"hash/crc32"
	"slices"
	"strings"
	"testing"

	"keyguard/internal/fp"
)

// docs/STEAL.md 4.3 lists the placements the corpus must plant. Each one is a variant with a
// path that says what it is.
func TestEveryAgentEraPlacementIsPlanted(t *testing.T) {
	c := sharedCorpus(t)
	want := []struct {
		variant string
		path    string // a suffix every plant's file has, or "" for git metadata
		where   string
	}{
		{vMCP, ".mcp.json", ""},
		{vClaudeEnv, ".claude/settings.json", ""},
		{vCodex, ".codex/config.toml", ""},
		{vHAR, "trace.har", ""},
		{vPWState, "playwright/.auth/user.json", ""},
		{vCookies, "cookies.txt", ""},
		{vPostman, ".postman_environment.json", ""},
		{vNbOut, ".ipynb", ""},
		{vTFState, "terraform.tfstate", ""},
		{vWPConfig, "wp-config.php", ""},
		{vCast, "session.cast", ""},
		{vCastTyped, "typed.cast", ""},
		{vB64Basic, ".dockerconfigjson", ""},
		{vUTF16, "settings.env", ""},
		{vTGZ, ".tgz", ""},
		{vJAR, ".jar", ""},
		{vRename, "renamed.env", ""},
		{vCommitMsg, "", "message"},
		{vTagMsg, "", "tag"},
		{vBranchName, "", "ref"},
		{vTwin, ".env", ""},
	}
	n := map[string]int{}
	for _, p := range c.Truth.Plants {
		if !p.Positive {
			continue
		}
		for _, w := range want {
			if p.Variant != w.variant {
				continue
			}
			n[w.variant]++
			if w.path != "" && !strings.HasSuffix(p.Location.Path, w.path) {
				t.Errorf("%s is planted at %s, want a path ending %s", p.ID, p.Location.Path, w.path)
			}
			if p.Location.Where != w.where {
				t.Errorf("%s: where = %q, want %q", p.ID, p.Location.Where, w.where)
			}
			if w.where != "" && p.Location.Path != "" {
				t.Errorf("%s: a value in git metadata has the path %s", p.ID, p.Location.Path)
			}
		}
	}
	for _, w := range want {
		if n[w.variant] < 4 {
			t.Errorf("placement %s has %d plants, want at least 4", w.variant, n[w.variant])
		}
	}
}

// A recording of a typed secret holds it one character per event: no engine can read it, and it
// is the one placement no matcher finds in the file either. The same secret pasted is whole.
func TestTypedAndPastedRecordings(t *testing.T) {
	c := sharedCorpus(t)
	typed, pasted := 0, 0
	for _, rec := range c.recs {
		if !rec.positive {
			continue
		}
		switch rec.variant {
		case vCastTyped:
			typed++
			if strings.Contains(rec.file.rend.content, rec.fake.Value) {
				t.Errorf("%s: the typed recording holds the value in one piece", rec.id)
			}
			p := c.Truth.Plants[slices.IndexFunc(c.Truth.Plants, func(p Plant) bool { return p.ID == rec.id })]
			if p.Detectable || p.Known {
				t.Errorf("%s: a typed secret is detectable=%v known=%v, want neither", rec.id, p.Detectable, p.Known)
			}
		case vCast:
			pasted++
			if !strings.Contains(rec.file.rend.content, rec.file.rend.esc(rec.fake.Value)) {
				t.Errorf("%s: the pasted recording lacks the value", rec.id)
			}
		}
	}
	if typed < 4 || pasted < 4 {
		t.Errorf("typed %d, pasted %d recordings: want both", typed, pasted)
	}
}

// The placements that hide a value from the regex engines say why, hold it where a known-secret
// matcher can find it, and (checked against the live engines) really are invisible to them.
func TestBlindPlacementsAreUndetectableByDesign(t *testing.T) {
	c := sharedCorpus(t)
	blind := []string{vUTF16, vTGZ, vJAR, vCastTyped, vCommitMsg, vTagMsg, vBranchName}
	for _, p := range c.Truth.Plants {
		if !p.Positive || !slices.Contains(blind, p.Variant) {
			continue
		}
		if p.Detectable || len(p.DetectableBy) != 0 {
			t.Errorf("%s: a %s plant is marked detectable", p.ID, p.Variant)
		}
		if !strings.Contains(p.Note, "undetected by design") {
			t.Errorf("%s: no reason is given", p.ID)
		}
		// a value that is written as itself must be findable; one the file escapes or encodes
		// differently (a PEM's newlines, a URL's password) has no registered spelling in it
		if rec := recOf(c, p.ID); p.Variant != vCastTyped && rec.fake.Raw == rec.fake.Value && !rec.prov.Multi && !p.Known {
			t.Errorf("%s: a matcher holding the value should find it in a %s", p.ID, p.Variant)
		}
	}
}

func TestLiveEnginesAreBlindWhereTheCorpusSaysTheyAre(t *testing.T) {
	c := sharedCorpus(t)
	res, err := ScoreWith(context.Background(), realEngines(t, c, "betterleaks", "gitleaks"), nil, c.Dir, ScoreOptions{OutDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range res.Engines {
		if e.Error != "" {
			t.Fatalf("%s: %s", e.Name, e.Error)
		}
		for _, v := range []string{vUTF16, vTGZ, vJAR, vCastTyped, vCommitMsg, vTagMsg, vBranchName} {
			if r := e.ByVariant[v]; r == nil || r.Total < 4 {
				t.Fatalf("%s: variant %s has %+v", e.Name, v, r)
			} else if r.Found != 0 {
				t.Errorf("%s found %d of %d %s plants, which the corpus says no engine can read", e.Name, r.Found, r.Total, v)
			}
		}
	}
}

// The rename plant is added in the same commit that renames the file: git shows a rename, and
// the engines that read the patch still see the added line.
func TestRenamePlantsAreFoundByThePatchReaders(t *testing.T) {
	c := sharedCorpus(t)
	res, err := ScoreWith(context.Background(), realEngines(t, c, "betterleaks"), nil, c.Dir, ScoreOptions{OutDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	r := res.Engines[0].ByVariant[vRename]
	if r == nil || r.Detectable < 4 || r.FoundDetectable != r.Detectable {
		t.Errorf("betterleaks on the rename plants: %+v", r)
	}
}

// Every format has near-misses beside a valid plant, in one file, on lines of their own.
func TestTwinsSitBesideTheirValidPlant(t *testing.T) {
	c := sharedCorpus(t)
	byID := map[string]Plant{}
	invalid := map[string][]Plant{}
	for _, p := range c.Truth.Plants {
		byID[p.ID] = p
		if p.Twin == "invalid" {
			invalid[p.TwinOf] = append(invalid[p.TwinOf], p)
		}
	}
	valid := 0
	types := map[string]bool{}
	for _, p := range c.Truth.Plants {
		if p.Twin != "valid" {
			continue
		}
		valid++
		if !p.Positive {
			t.Errorf("%s: a valid twin is a negative", p.ID)
		}
		if len(invalid[p.ID]) == 0 {
			t.Errorf("%s: a valid twin with nothing beside it", p.ID)
		}
		for _, q := range invalid[p.ID] {
			if q.Positive || q.Variant != vTwin || !strings.HasPrefix(q.Kind, "twin-") {
				t.Errorf("%s: an invalid twin must be a negative twin plant: %+v", q.ID, q)
			}
			if q.Location.Path != p.Location.Path || q.Location.Commit != p.Location.Commit || q.Format != p.Format {
				t.Errorf("%s is not in the file of %s", q.ID, p.ID)
			}
			if q.Location.Line == p.Location.Line {
				t.Errorf("%s shares a line with %s", q.ID, p.ID)
			}
			if q.FP == "" || q.FP == p.FP {
				t.Errorf("%s: the invalid twin must have a fingerprint of its own", q.ID)
			}
			types[q.Type] = true
		}
	}
	if valid < 40 {
		t.Errorf("only %d formats have a valid twin", valid)
	}
	if len(types) < 40 {
		t.Errorf("only %d types have an invalid twin, want at least 40", len(types))
	}
	if c.Truth.Stats.Twins < 80 {
		t.Errorf("%d invalid twins", c.Truth.Stats.Twins)
	}
}

// An invalid twin is invalid in the one way a pattern can tell: the format's own rules refuse it.
// The check runs for three seeds, since the values differ and the structure must not.
func TestInvalidTwinsAreRefusedByTheirFormatsRules(t *testing.T) {
	checked := 0
	for _, p := range Providers {
		if p.Twins == nil || p.Multi {
			continue
		}
		kinds := twinKinds(&p)
		for seed := uint64(1); seed <= 3; seed++ {
			for _, tw := range p.Twins(&Gen{r: newRand(seed, "twin/"+p.ID)}) {
				if !kinds[tw.Kind] {
					continue
				}
				checked++
				content := "NAME=" + tw.Fake.Value + "\n"
				if tw.Kind != "checksum" {
					by, err := coveredBy(p.Rules, ".env", []string{content}, []string{tw.Fake.Value})
					if err != nil {
						t.Fatal(err)
					}
					if len(by) != 0 {
						t.Errorf("%s: the %s twin is taken for a valid value by %v (seed %d)", p.ID, tw.Kind, by, seed)
					}
				}
				if tw.Kind == "floor" {
					if fl := ruleFloor(p.Rules); fp.Entropy(tw.Fake.Value) > fl-0.3 {
						t.Errorf("%s: the floor twin has entropy %.2f against a floor of %.2f", p.ID, fp.Entropy(tw.Fake.Value), fl)
					}
				}
			}
		}
	}
	if checked < 150 {
		t.Errorf("only %d twins checked", checked)
	}
}

// A checksum twin is wrong in the checksum and nowhere else.
func TestChecksumTwinsAreWrongOnlyInTheChecksum(t *testing.T) {
	crcOK := func(tok string, prefix string) bool {
		body := tok[len(prefix) : len(tok)-6]
		return tok[len(tok)-6:] == base62(crc32.ChecksumIEEE([]byte(body)), 6)
	}
	n := 0
	for _, p := range Providers {
		if p.Twins == nil {
			continue
		}
		g := &Gen{r: newRand(5, "crc/"+p.ID)}
		for _, tw := range p.Twins(g) {
			if tw.Kind != "checksum" {
				continue
			}
			n++
			prefix := tw.Fake.Value[:strings.IndexByte(tw.Fake.Value, '_')+1]
			valid := p.Gen(&Gen{r: newRand(5, "crc-valid/"+p.ID)}).Raw
			if !crcOK(valid, prefix) {
				t.Errorf("%s: the valid fake does not carry a correct checksum", p.ID)
			}
			if crcOK(tw.Fake.Value, prefix) {
				t.Errorf("%s: the checksum twin's checksum is correct", p.ID)
			}
			if len(tw.Fake.Value) != len(valid) {
				t.Errorf("%s: the checksum twin is %d long, the valid value %d", p.ID, len(tw.Fake.Value), len(valid))
			}
		}
	}
	if n != 4 {
		t.Errorf("%d checksum twins, want the 4 formats that end in GitHub's checksum", n)
	}
}

// A fake has to clear its rule's entropy floor by 0.3 or the engine's own filter drops it and
// the plant tests the filter, not the rule (STEAL P0-26; K8: a floor of 3.5 rejects 18% of random hex).
func TestFakesClearTheirRuleFloorsByAMargin(t *testing.T) {
	checked := 0
	for _, p := range Providers {
		floor := ruleFloor(p.Rules)
		if floor == 0 || p.Multi {
			continue
		}
		for k := 0; k < 40; k++ {
			f := p.Gen(&Gen{r: newRand(7, fmt.Sprintf("floor/%s/%d", p.ID, k))})
			if e := fp.Entropy(f.Raw); e < floor+0.3 {
				t.Errorf("%s draw %d: entropy %.2f is under the rule's floor %.1f plus 0.3", p.ID, k, e, floor)
				break
			}
		}
		checked++
	}
	if checked < 40 {
		t.Errorf("only %d formats have an entropy floor to clear", checked)
	}
}

// The floor twin carries the tag that says an engine is expected to drop it.
func TestFloorTwinsAreTaggedAsExpectedNegatives(t *testing.T) {
	c := sharedCorpus(t)
	n := 0
	for _, p := range c.Truth.Plants {
		if p.Kind != "twin-floor" {
			continue
		}
		n++
		if !slices.Contains(p.Tags, "floor-rejected") || p.Positive {
			t.Errorf("%s: %+v", p.ID, p)
		}
	}
	if n < 30 {
		t.Errorf("%d floor twins", n)
	}
}

// What the known matcher registers must be in the bytes of the placements that need it: UTF-16
// in the UTF-16 file, base64 of user:secret (one byte off the three-byte groups) in the basic
// auth config, and each spelling a substring of what it should be a part of.
func TestRegisteredFormsMatchTheirPlacements(t *testing.T) {
	g := &Gen{r: newRand(3, "forms")}
	for i := 0; i < 50; i++ {
		raw := g.token(4.0, lit("ghp_"), rnd(alnum, 36))
		for _, prefix := range []string{"svc:", "user:", "x", "ab", "admin:"} {
			enc := base64.StdEncoding.EncodeToString([]byte(prefix + raw))
			k := len(prefix) % 3
			if k == 0 {
				if !strings.Contains(enc, stdB64(raw)) {
					t.Fatalf("prefix %q: base64 of the bare value is not inside base64 of %q+value", prefix, prefix)
				}
				continue
			}
			a := alignedB64(raw, k)
			if a == "" || !strings.Contains(enc, a) {
				t.Fatalf("prefix %q: the alignment-%d form is not inside base64 of %q+value", prefix, k, prefix)
			}
		}
		for _, f := range registeredForms(raw) {
			if f.Pattern == "" || len(f.Pattern) < 12 {
				t.Errorf("form %s is too short to register: %d", f.Variant, len(f.Pattern))
			}
		}
	}
	c := sharedCorpus(t)
	for _, rec := range c.recs {
		if !rec.positive {
			continue
		}
		var form string
		if rec.fake.Raw != rec.fake.Value || rec.prov.Multi {
			continue // the file spells it differently from the value that was registered
		}
		switch rec.variant {
		case vUTF16:
			form = utf16Form(rec.fake.Raw, false)
		case vB64Basic:
			form = alignedB64(rec.fake.Raw, 1)
			if len(basicUser+":")%3 != 1 {
				t.Fatal("the basic-auth user no longer leaves the secret one byte off the groups")
			}
		default:
			continue
		}
		if form == "" || !strings.Contains(rec.file.rend.content, form) {
			t.Errorf("%s: the form a matcher registers for a %s is not in the file", rec.id, rec.variant)
		}
	}
}
