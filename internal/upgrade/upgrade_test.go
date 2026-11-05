package upgrade

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// A fake GitHub: a releases API for one repo and the downloads behind it, on a local server.
// Nothing in these tests reaches the network.

type rel struct {
	tag        string
	prerelease bool
	draft      bool
	label      string // what the engine inside is: the scorer reads it
	tamper     bool   // the download is not what the checksums file says it is
	badDigest  bool   // GitHub's digest of the asset disagrees with the checksums file
	noSums     bool
	raw        bool        // a bare binary, as titus ships, and not a tarball
	members    []tarMember // extra archive members
	twoBuilds  bool        // a second darwin/arm64 asset
}

type tarMember struct {
	name     string
	body     string
	symlink  string
	typeflag byte
}

type fakeGitHub struct {
	t     *testing.T
	srv   *httptest.Server
	mu    sync.Mutex
	rels  []rel
	files map[string][]byte // download path -> bytes
	hits  map[string]int
	// rate limiting
	limit      bool
	date       time.Time
	reset      time.Time
	retryAfter string
}

func newFakeGitHub(t *testing.T) *fakeGitHub {
	g := &fakeGitHub{t: t, files: map[string][]byte{}, hits: map[string]int{}}
	g.srv = httptest.NewServer(http.HandlerFunc(g.serve))
	t.Cleanup(g.srv.Close)
	return g
}

func (g *fakeGitHub) count(prefix string) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	n := 0
	for p, c := range g.hits {
		if strings.HasPrefix(p, prefix) {
			n += c
		}
	}
	return n
}

func (g *fakeGitHub) serve(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	g.hits[r.URL.Path]++
	limit, date, reset, retry := g.limit, g.date, g.reset, g.retryAfter
	body, isFile := g.files[r.URL.Path]
	g.mu.Unlock()
	if limit && strings.HasPrefix(r.URL.Path, "/repos/") {
		w.Header().Set("Date", date.UTC().Format(http.TimeFormat))
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.Header().Set("X-RateLimit-Reset", fmt.Sprint(reset.Unix()))
		if retry != "" {
			w.Header().Set("Retry-After", retry)
		}
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if isFile {
		w.Write(body)
		return
	}
	if r.URL.Path == "/repos/o/fakeeng/releases" {
		g.mu.Lock()
		defer g.mu.Unlock()
		var out []map[string]any
		for _, rl := range g.rels {
			out = append(out, map[string]any{"tag_name": rl.tag, "draft": rl.draft, "prerelease": rl.prerelease, "assets": g.assets(rl)})
		}
		json.NewEncoder(w).Encode(out)
		return
	}
	http.NotFound(w, r)
}

func hexSHA(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func makeTarball(t *testing.T, binary, label string, extra []tarMember) []byte {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	add := func(name, body string, flag byte, link string) {
		h := &tar.Header{Name: name, Mode: 0o755, Size: int64(len(body)), Typeflag: flag, Linkname: link}
		if flag != tar.TypeReg {
			h.Size = 0
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if flag == tar.TypeReg {
			tw.Write([]byte(body))
		}
	}
	add("LICENSE", "MIT\n", tar.TypeReg, "")
	for _, m := range extra {
		flag := m.typeflag
		if flag == 0 {
			flag = tar.TypeReg
		}
		add(m.name, m.body, flag, m.symlink)
	}
	add(binary, "#!/bin/sh\n# engine "+label+"\n", tar.TypeReg, "")
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

// assets names the files of a release as the API would list them, and records the downloads.
func (g *fakeGitHub) assets(rl rel) []map[string]any {
	ver := strings.TrimPrefix(rl.tag, "v")
	var out []map[string]any
	add := func(name string, data []byte, digest string) {
		path := "/dl/" + rl.tag + "/" + name
		g.files[path] = data
		a := map[string]any{"name": name, "browser_download_url": g.srv.URL + path, "size": len(data)}
		if digest != "" {
			a["digest"] = "sha256:" + digest
		}
		out = append(out, a)
	}
	var data []byte
	name := "fakeeng_" + ver + "_darwin_arm64.tar.gz"
	if rl.raw {
		name = "fakeeng-darwin-arm64"
		data = []byte("#!/bin/sh\n# engine " + rl.label + "\n")
	} else {
		data = makeTarball(g.t, "fakeeng", rl.label, rl.members)
	}
	want := hexSHA(data)
	served := data
	if rl.tamper {
		served = append(append([]byte(nil), data...), []byte("# tampered\n")...)
	}
	digest := want
	if rl.badDigest {
		digest = strings.Repeat("0", 64)
	}
	add(name, served, digest)
	add("fakeeng_"+ver+"_darwin_x64.tar.gz", []byte("other arch"), "")
	add("fakeeng_"+ver+"_linux_arm64.tar.gz", []byte("other os"), "")
	if rl.twoBuilds {
		add("fakeeng_"+ver+"_darwin_arm64_extra.tar.gz", []byte("a second build"), "")
	}
	if !rl.noSums {
		sums := fmt.Sprintf("%s  %s\n%s  fakeeng_%s_darwin_x64.tar.gz\n", want, name, hexSHA([]byte("other arch")), ver)
		add("fakeeng_"+ver+"_checksums.txt", []byte(sums), "")
		add("fakeeng_"+ver+"_checksums.txt.sig", []byte("signature"), "")
	}
	return out
}

func (g *fakeGitHub) publish(rs ...rel) {
	g.mu.Lock()
	g.rels = append(g.rels, rs...)
	g.mu.Unlock()
}

var src = Source{Name: "fakeeng", Repo: "o/fakeeng", Binary: "fakeeng"}

// rowsByLabel is what the stand-in scorer says about an engine, by the label inside the file.
type scoreBook map[string]Row

func (b scoreBook) scorer(calls *[]string) Scorer {
	var mu sync.Mutex
	return ScorerFunc(func(_ context.Context, _ string, bin string) (Row, error) {
		data, err := os.ReadFile(bin)
		if err != nil {
			return Row{}, err
		}
		_, label, _ := strings.Cut(strings.TrimSpace(strings.SplitN(string(data), "\n", 3)[1]), "engine ")
		mu.Lock()
		defer mu.Unlock()
		if calls != nil {
			*calls = append(*calls, label)
		}
		r, ok := b[label]
		if !ok {
			return Row{}, fmt.Errorf("no row for %q", label)
		}
		return r, nil
	})
}

// pinnedEngine writes the pinned binary read-only, and returns a check that it was left alone.
func pinnedEngine(t *testing.T, label string) (Pinned, func()) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "fakeeng-1.0.0")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n# engine "+label+"\n"), 0o555); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Stat(p)
	sum, _ := fileSHA256(p)
	return Pinned{Path: p, Version: "1.0.0"}, func() {
		t.Helper()
		after, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if got, _ := fileSHA256(p); got != sum || after.ModTime() != before.ModTime() || after.Mode() != before.Mode() {
			t.Error("the pinned engine was touched")
		}
	}
}

func good() Row {
	return Row{Version: "1.0.0", Recall: 0.95, RecallAll: 0.80, Precision: 0.97, Seconds: 1.0}
}

func opts(g *fakeGitHub, book scoreBook, calls *[]string, t *testing.T) *Options {
	return &Options{API: g.srv.URL, Dir: t.TempDir(), Scorer: book.scorer(calls), Runs: 3}
}

func TestCheckAcceptsABetterCandidateAndStagesItWithoutInstalling(t *testing.T) {
	g := newFakeGitHub(t)
	g.publish(rel{tag: "v1.1.0", label: "new"}, rel{tag: "v1.0.0", label: "old"})
	pin, untouched := pinnedEngine(t, "old")
	better := Row{Version: "1.1.0", Recall: 0.96, RecallAll: 0.82, Precision: 0.98, Seconds: 1.05}
	var calls []string
	o := opts(g, scoreBook{"old": good(), "new": better}, &calls, t)

	d, err := o.Check(context.Background(), src, pin)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Switch || d.Candidate == nil || d.PinnedRow == nil || d.Latest != "1.1.0" || d.Err != "" {
		t.Fatalf("decision: %+v", d)
	}
	c := d.Candidate
	if c.Version != "1.1.0" || c.Tag != "v1.1.0" || c.Row != better || *d.PinnedRow != good() {
		t.Errorf("candidate: %+v pinned row %+v", c, d.PinnedRow)
	}
	// staged in a directory of its own, named for the engine and version, executable, hashed
	if filepath.Dir(c.Path) != d.Dir || filepath.Base(c.Path) != "fakeeng-1.1.0" || !strings.HasPrefix(d.Dir, o.Dir) {
		t.Errorf("staged at %s in %s", c.Path, d.Dir)
	}
	st, err := os.Stat(c.Path)
	if err != nil || st.Mode().Perm() != 0o755 {
		t.Errorf("the staged binary: %v %v", st, err)
	}
	body, _ := os.ReadFile(c.Path)
	if c.SHA256 != hexSHA(body) || !strings.Contains(string(body), "engine new") {
		t.Errorf("sha256 %s does not describe the staged binary", c.SHA256)
	}
	if c.Asset != "fakeeng_1.1.0_darwin_arm64.tar.gz" || c.AssetSHA256 == "" || c.AssetSHA256 == c.SHA256 {
		t.Errorf("asset %s %s", c.Asset, c.AssetSHA256)
	}
	// the pinned engine and the candidate took turns, three times each, and the pinned one is untouched
	if strings.Join(calls, " ") != "old new old new old new" {
		t.Errorf("scored in this order: %v", calls)
	}
	untouched()
	// every test is listed, and all passed
	if len(d.Reasons) != 4 {
		t.Errorf("reasons: %v", d.Reasons)
	}
	for _, r := range d.Reasons {
		if !strings.HasPrefix(r, "ok:") {
			t.Errorf("a passing decision lists a failure: %s", r)
		}
	}
	// nothing outside the staging directory was written
	ents, _ := os.ReadDir(o.Dir)
	if len(ents) != 1 || ents[0].Name() != filepath.Base(d.Dir) {
		t.Errorf("the staging root holds %v", ents)
	}
}

func TestCheckRefusesATamperedAsset(t *testing.T) {
	g := newFakeGitHub(t)
	g.publish(rel{tag: "v1.1.0", label: "new", tamper: true})
	pin, untouched := pinnedEngine(t, "old")
	var calls []string
	o := opts(g, scoreBook{"old": good(), "new": good()}, &calls, t)

	d, err := o.Check(context.Background(), src, pin)
	if !errors.Is(err, ErrChecksum) {
		t.Fatalf("a tampered download was accepted: %v", err)
	}
	if d.Switch || d.Candidate != nil || len(calls) != 0 {
		t.Errorf("nothing may be scored or offered after a checksum failure: %+v, scored %v", d, calls)
	}
	// the staging directory holds the download and no executable
	entries, _ := os.ReadDir(d.Dir)
	for _, e := range entries {
		if info, _ := e.Info(); info.Mode().Perm()&0o111 != 0 {
			t.Errorf("%s is executable", e.Name())
		}
		if strings.HasPrefix(e.Name(), "fakeeng-") {
			t.Errorf("an engine was unpacked from a failed download: %s", e.Name())
		}
	}
	untouched()
}

func TestCheckRefusesWhenGitHubsDigestAndTheChecksumsFileDisagree(t *testing.T) {
	g := newFakeGitHub(t)
	g.publish(rel{tag: "v1.1.0", label: "new", badDigest: true})
	pin, _ := pinnedEngine(t, "old")
	o := opts(g, scoreBook{"old": good(), "new": good()}, nil, t)
	d, err := o.Check(context.Background(), src, pin)
	if !errors.Is(err, ErrChecksum) || d.Switch {
		t.Fatalf("two witnesses disagreed and the release was accepted: %v", err)
	}
	// the asset itself was never downloaded
	if n := g.count("/dl/v1.1.0/fakeeng_1.1.0_darwin_arm64.tar.gz"); n != 0 {
		t.Errorf("the asset was downloaded %d times before the witnesses were compared", n)
	}
}

func TestCheckRefusesAReleaseThatPublishesNoChecksums(t *testing.T) {
	g := newFakeGitHub(t)
	g.publish(rel{tag: "v1.1.0", label: "new", noSums: true})
	pin, _ := pinnedEngine(t, "old")
	_, err := opts(g, scoreBook{"old": good(), "new": good()}, nil, t).Check(context.Background(), src, pin)
	if err == nil || !strings.Contains(err.Error(), "checksums") {
		t.Errorf("a release nothing vouches for was accepted: %v", err)
	}
}

func TestCheckSkipsPrereleases(t *testing.T) {
	g := newFakeGitHub(t)
	g.publish(
		rel{tag: "v2.0.0-rc.6", prerelease: true, label: "rc6"}, // flagged by GitHub
		rel{tag: "v2.0.0-rc.5", label: "rc5"},                   // not flagged, but the tag says so
		rel{tag: "v1.9.5", draft: true, label: "draft"},         // unpublished
		rel{tag: "v1.9.0", label: "stable"},
		rel{tag: "v1.8.0", label: "older"},
	)
	pin := Pinned{Path: "/does/not/matter", Version: "1.9.0"}
	var calls []string
	o := opts(g, scoreBook{}, &calls, t)
	d, err := o.Check(context.Background(), src, pin)
	if err != nil {
		t.Fatal(err)
	}
	if d.Latest != "1.9.0" || d.Switch || d.Candidate != nil || len(calls) != 0 || d.Dir != "" {
		t.Errorf("the pinned 1.9.0 is the newest stable release: %+v", d)
	}
	why := map[string]string{}
	for _, s := range d.Skipped {
		why[s.Tag] = s.Why
	}
	if len(why) != 3 || why["v2.0.0-rc.6"] != "marked as a pre-release" || why["v2.0.0-rc.5"] != "pre-release tag" || why["v1.9.5"] != "draft" {
		t.Errorf("skipped: %v", why)
	}
	// nothing newer: no asset was fetched and no engine was scored
	if g.count("/dl/") != 0 {
		t.Errorf("%d downloads for a pinned engine that is current", g.count("/dl/"))
	}
	if len(d.Reasons) != 1 || !strings.Contains(d.Reasons[0], "latest stable release") {
		t.Errorf("reasons: %v", d.Reasons)
	}
}

func TestCheckPicksTheHighestStableAndNotTheNewestListed(t *testing.T) {
	g := newFakeGitHub(t)
	// the API lists by date: a patch to an old line comes after the newest line
	g.publish(rel{tag: "v1.2.1", label: "patch"}, rel{tag: "v1.10.0", label: "new"}, rel{tag: "v1.9.0", label: "old"})
	pin, _ := pinnedEngine(t, "old")
	d, err := opts(g, scoreBook{"old": good(), "new": Row{Version: "1.10.0", Recall: 0.95, RecallAll: 0.8, Precision: 0.97, Seconds: 1}}, nil, t).Check(context.Background(), src, pin)
	if err != nil || d.Latest != "1.10.0" || d.Candidate == nil || d.Candidate.Tag != "v1.10.0" {
		t.Errorf("the highest version is 1.10.0, not the first listed or the highest string: %+v %v", d, err)
	}
}

func TestCheckRefusesACandidateThatIsSlowerOrLessAccurate(t *testing.T) {
	cases := []struct {
		name string
		row  Row
		ok   bool
		fail string // the test that must be reported failed
	}{
		{"identical", Row{Recall: 0.95, RecallAll: 0.80, Precision: 0.97, Seconds: 1.0}, true, ""},
		{"exactly at the speed limit", Row{Recall: 0.95, RecallAll: 0.80, Precision: 0.97, Seconds: 1.10}, true, ""},
		{"just over the speed limit", Row{Recall: 0.95, RecallAll: 0.80, Precision: 0.97, Seconds: 1.1001}, false, "speed"},
		{"twice as slow", Row{Recall: 0.99, RecallAll: 0.90, Precision: 0.99, Seconds: 2.0}, false, "speed"},
		{"faster and better", Row{Recall: 0.99, RecallAll: 0.90, Precision: 0.99, Seconds: 0.5}, true, ""},
		{"lower recall", Row{Recall: 0.94, RecallAll: 0.80, Precision: 0.99, Seconds: 0.9}, false, "recall"},
		{"lower recall over all plants", Row{Recall: 0.95, RecallAll: 0.79, Precision: 0.99, Seconds: 0.9}, false, "recall (all plants)"},
		{"lower precision", Row{Recall: 0.99, RecallAll: 0.90, Precision: 0.96, Seconds: 0.9}, false, "precision"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := newFakeGitHub(t)
			g.publish(rel{tag: "v1.1.0", label: "new"})
			pin, untouched := pinnedEngine(t, "old")
			tc.row.Version = "1.1.0"
			d, err := opts(g, scoreBook{"old": good(), "new": tc.row}, nil, t).Check(context.Background(), src, pin)
			if err != nil {
				t.Fatal(err)
			}
			if d.Switch != tc.ok {
				t.Errorf("switch = %v, want %v: %v", d.Switch, tc.ok, d.Reasons)
			}
			// the candidate is staged and scored either way, so the caller can see both rows
			if d.Candidate == nil || d.Candidate.Row != tc.row || d.PinnedRow == nil || *d.PinnedRow != good() {
				t.Errorf("rows: %+v %+v", d.Candidate, d.PinnedRow)
			}
			failed := ""
			for _, r := range d.Reasons {
				if strings.HasPrefix(r, "FAIL: ") {
					failed += r + "\n"
				}
			}
			if tc.fail == "" && failed != "" || tc.fail != "" && !strings.Contains(failed, "FAIL: "+tc.fail+":") {
				t.Errorf("failed tests %q, want %q", failed, tc.fail)
			}
			untouched()
		})
	}
}

func TestCheckRefusesABinaryThatIsNotTheReleaseItClaimsToBe(t *testing.T) {
	g := newFakeGitHub(t)
	g.publish(rel{tag: "v1.1.0", label: "new"})
	pin, _ := pinnedEngine(t, "old")
	// the staged binary says 1.0.0: a stale build in a new tarball
	stale := Row{Version: "fakeeng 1.0.0", Recall: 0.99, RecallAll: 0.99, Precision: 0.99, Seconds: 0.5}
	d, err := opts(g, scoreBook{"old": good(), "new": stale}, nil, t).Check(context.Background(), src, pin)
	if err == nil || d.Switch || d.Candidate != nil || !strings.Contains(err.Error(), "reports") {
		t.Errorf("a binary of the wrong version was accepted: %v %+v", err, d)
	}
}

func TestCheckDownloadsNothingWhenThePinnedEngineIsCurrent(t *testing.T) {
	g := newFakeGitHub(t)
	g.publish(rel{tag: "v1.0.0", label: "old"})
	pin, untouched := pinnedEngine(t, "old")
	var calls []string
	d, err := opts(g, scoreBook{"old": good()}, &calls, t).Check(context.Background(), src, pin)
	if err != nil || d.Switch || d.Candidate != nil || g.count("/dl/") != 0 || len(calls) != 0 {
		t.Errorf("%+v %v downloads %d scores %v", d, err, g.count("/dl/"), calls)
	}
	// a pinned engine newer than the latest release (a local build) is no upgrade either
	pin.Version = "fakeeng version 1.0.1"
	if d, err := opts(g, scoreBook{"old": good()}, &calls, t).Check(context.Background(), src, pin); err != nil || d.Candidate != nil {
		t.Errorf("an older release was offered over a newer pin: %+v %v", d, err)
	}
	untouched()
}

func TestStageUnpacksTheEngineAndNothingElse(t *testing.T) {
	g := newFakeGitHub(t)
	g.publish(rel{tag: "v1.1.0", label: "new", members: []tarMember{
		{name: "../../evil", body: "escape"},                                 // a path that climbs out
		{name: "/etc/passwd", body: "absolute"},                              // an absolute one
		{name: "bin/fakeeng", typeflag: tar.TypeSymlink, symlink: "/bin/sh"}, // a link with the engine's name
	}})
	root := t.TempDir()
	o := &Options{API: g.srv.URL, Dir: filepath.Join(root, "stage")}
	if err := os.Mkdir(o.Dir, 0o755); err != nil {
		t.Fatal(err)
	}
	rels, _, err := o.Releases(context.Background(), "o/fakeeng")
	if err != nil || len(rels) != 1 {
		t.Fatal(err, rels)
	}
	v, _ := ParseVersion(rels[0].Tag)
	st, err := o.Stage(context.Background(), src, rels[0], v)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := os.ReadFile(st.Binary)
	if !strings.Contains(string(body), "engine new") {
		t.Errorf("the staged binary is %q: the symlink member was taken for the engine", body)
	}
	var names []string
	filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		rel, _ := filepath.Rel(root, p)
		names = append(names, rel)
		return nil
	})
	for _, n := range names {
		if strings.Contains(n, "evil") || strings.Contains(n, "passwd") || strings.Contains(n, "..") {
			t.Errorf("an archive member escaped or was written: %s", n)
		}
	}
	// the staging dir holds exactly: the checksums file, the download and the engine
	ents, _ := os.ReadDir(st.Dir)
	if len(ents) != 3 {
		t.Errorf("staging dir holds %d files: %v", len(ents), ents)
	}
}

func TestPickAssets(t *testing.T) {
	mk := func(names ...string) Release {
		r := Release{Tag: "v1.0.0"}
		for _, n := range names {
			r.Assets = append(r.Assets, Asset{Name: n})
		}
		return r
	}
	b, s, err := pickAssets(mk("betterleaks_1.9.0_darwin_arm64.tar.gz", "betterleaks_1.9.0_darwin_x64.tar.gz", "checksums.txt", "checksums.txt.sigstore.json"))
	if err != nil || b.Name != "betterleaks_1.9.0_darwin_arm64.tar.gz" || s.Name != "checksums.txt" {
		t.Errorf("betterleaks layout: %v %v %v", b.Name, s.Name, err)
	}
	b, s, err = pickAssets(mk("titus-darwin-amd64", "titus-darwin-arm64", "checksums.txt", "titus-burp-v1.3.0.jar"))
	if err != nil || b.Name != "titus-darwin-arm64" || s.Name != "checksums.txt" {
		t.Errorf("titus layout: %v %v %v", b.Name, s.Name, err)
	}
	b, s, err = pickAssets(mk("trufflehog_3.99.8_checksums.txt", "trufflehog_3.99.8_checksums.txt.pem", "trufflehog_3.99.8_checksums.txt.sig", "trufflehog_3.99.8_darwin_arm64.tar.gz", "trufflehog_3.99.8_darwin_amd64.tar.gz"))
	if err != nil || b.Name != "trufflehog_3.99.8_darwin_arm64.tar.gz" || s.Name != "trufflehog_3.99.8_checksums.txt" {
		t.Errorf("trufflehog layout: %v %v %v", b.Name, s.Name, err)
	}
	for name, as := range map[string][]string{
		"no darwin build":    {"x_linux_arm64.tar.gz", "checksums.txt"},
		"two darwin builds":  {"x_darwin_arm64.tar.gz", "x_darwin_arm64_fips.tar.gz", "checksums.txt"},
		"no checksums":       {"x_darwin_arm64.tar.gz", "x_darwin_arm64.tar.gz.sig"},
		"two checksum files": {"x_darwin_arm64.tar.gz", "checksums.txt", "x_checksums.txt"},
	} {
		if _, _, err := pickAssets(mk(as...)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestParseChecksums(t *testing.T) {
	text := "AA" + strings.Repeat("0", 62) + "  one.tar.gz\r\n" +
		strings.Repeat("b", 64) + " *dist/two.zip\n" +
		"not a checksum line\n" +
		strings.Repeat("c", 63) + "  too-short\n"
	got := parseChecksums(text)
	if len(got) != 2 || got["one.tar.gz"] != "aa"+strings.Repeat("0", 62) || got["two.zip"] != strings.Repeat("b", 64) {
		t.Errorf("%v", got)
	}
}

func TestAssetsComeFromGitHubHostsOnly(t *testing.T) {
	o := &Options{API: "http://127.0.0.1:9999"}
	for host, want := range map[string]bool{
		"github.com": true, "api.github.com": true, "objects.githubusercontent.com": true, "release-assets.githubusercontent.com": true,
		"127.0.0.1:9999": true, "evil.example": false, "github.com.evil.example": false, "githubusercontent.com.evil.example": false, "": false,
	} {
		if got := o.hostOK(host); got != want {
			t.Errorf("hostOK(%q) = %v, want %v", host, got, want)
		}
	}
	g := newFakeGitHub(t)
	g.publish(rel{tag: "v1.1.0", label: "new"})
	g.mu.Lock()
	g.files["/dl/v1.1.0/elsewhere"] = []byte("x")
	g.mu.Unlock()
	o = &Options{API: g.srv.URL, Dir: t.TempDir()}
	if _, err := o.download(context.Background(), Asset{Name: "x", URL: "https://evil.example/x"}, filepath.Join(o.Dir, "x"), 10); err == nil || !strings.Contains(err.Error(), "not GitHub") {
		t.Errorf("a download from a stranger's host went ahead: %v", err)
	}
	// a redirect away from GitHub is refused too
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://evil.example/payload", http.StatusFound)
	}))
	defer redirect.Close()
	o = &Options{API: redirect.URL, Dir: t.TempDir()}
	if _, err := o.download(context.Background(), Asset{Name: "x", URL: redirect.URL + "/x"}, filepath.Join(o.Dir, "x"), 10); err == nil || !strings.Contains(err.Error(), "not GitHub") {
		t.Errorf("a redirect to a stranger's host was followed: %v", err)
	}
}

// The rate limit is worked out on GitHub's clock. The local clock here is not consulted: the
// Date header says it is ten minutes past noon, the quota resets at a quarter past, and the
// wait is five minutes and two seconds whatever this machine thinks the time is.
func TestRateLimitWaitUsesGitHubsClock(t *testing.T) {
	g := newFakeGitHub(t)
	noon := time.Date(2026, 11, 3, 12, 10, 0, 0, time.UTC)
	g.limit, g.date, g.reset = true, noon, noon.Add(5*time.Minute)
	o := &Options{API: g.srv.URL, Dir: t.TempDir(), Scorer: scoreBook{}.scorer(nil)}
	_, err := o.Check(context.Background(), src, Pinned{Path: "x", Version: "1.0.0"})
	var rl *RateLimitError
	if !errors.As(err, &rl) {
		t.Fatalf("a spent quota was not reported as one: %v", err)
	}
	if rl.Wait != 5*time.Minute+2*time.Second || !rl.Reset.Equal(noon.Add(5*time.Minute)) {
		t.Errorf("wait %v, reset %v", rl.Wait, rl.Reset)
	}
	// Retry-After wins
	g.retryAfter = "17"
	_, err = o.Check(context.Background(), src, Pinned{Path: "x", Version: "1.0.0"})
	if !errors.As(err, &rl) || rl.Wait != 17*time.Second {
		t.Errorf("retry-after should win: %v", err)
	}
	// a plain 403 is not a rate limit
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusForbidden) }))
	defer plain.Close()
	o.API = plain.URL
	if _, err := o.Check(context.Background(), src, Pinned{Path: "x", Version: "1.0.0"}); err == nil || errors.As(err, &rl) {
		t.Errorf("a forbidden request that is not about the quota: %v", err)
	}
}

func TestCheckAllKeepsGoingAfterOneFailureButStopsAtTheRateLimit(t *testing.T) {
	g := newFakeGitHub(t)
	g.publish(rel{tag: "v1.0.0", label: "old"})
	// route every Source to the one fake repo
	o := &Options{API: g.srv.URL, Dir: t.TempDir(), Scorer: scoreBook{"old": good()}.scorer(nil)}
	old := Sources
	defer func() { Sources = old }()
	Sources = []Source{{"a", "o/fakeeng", "fakeeng"}, {"b", "o/missing", "b"}, {"c", "o/fakeeng", "fakeeng"}}
	pins := map[string]Pinned{
		"a": {Path: "x", Version: "1.0.0"}, "b": {Path: "x", Version: "1.0.0"}, "c": {Path: "x", Version: "1.0.0"},
	}
	out := o.CheckAll(context.Background(), pins)
	if len(out) != 3 || out[0].Err != "" || out[1].Err == "" || out[2].Err != "" {
		t.Fatalf("a failure should not stop the round: %+v", out)
	}
	g.limit, g.date, g.reset = true, time.Now(), time.Now().Add(time.Minute)
	out = o.CheckAll(context.Background(), pins)
	if len(out) != 3 || !strings.Contains(out[0].Err, "rate limit") || !strings.Contains(out[1].Err, "not checked") || !strings.Contains(out[2].Err, "not checked") {
		t.Errorf("a spent quota should end the round: %+v", out)
	}
	// an engine with no pin is left out
	delete(pins, "b")
	g.limit = false
	if out := o.CheckAll(context.Background(), pins); len(out) != 2 {
		t.Errorf("%d decisions for two pins", len(out))
	}
}

func TestACandidateThatIsABareBinaryIsStagedLikeAnArchive(t *testing.T) {
	g := newFakeGitHub(t)
	g.publish(rel{tag: "v1.1.0", label: "new", raw: true})
	pin, untouched := pinnedEngine(t, "old")
	better := Row{Version: "1.1.0", Recall: 0.96, RecallAll: 0.82, Precision: 0.98, Seconds: 1.0}
	d, err := opts(g, scoreBook{"old": good(), "new": better}, nil, t).Check(context.Background(), src, pin)
	if err != nil || !d.Switch || d.Candidate == nil {
		t.Fatalf("%v %+v", err, d)
	}
	body, _ := os.ReadFile(d.Candidate.Path)
	if d.Candidate.SHA256 != hexSHA(body) || d.Candidate.SHA256 != d.Candidate.AssetSHA256 || filepath.Base(d.Candidate.Path) != "fakeeng-1.1.0" {
		t.Errorf("a bare binary: %+v", d.Candidate)
	}
	untouched()
}

func TestDecideAndAggregate(t *testing.T) {
	ok, why := Decide(good(), good(), 1.10)
	if !ok || len(why) != 4 {
		t.Errorf("an identical engine: %v %v", ok, why)
	}
	// noise cannot let a candidate through: the pinned engine's best against the candidate's worst
	a := aggregate([]Row{{Recall: 0.90, Seconds: 3}, {Recall: 0.95, Seconds: 2}, {Recall: 0.93, Seconds: 1.5}}, true)
	if a.Recall != 0.95 || a.Seconds != 1.5 {
		t.Errorf("best of three: %+v", a)
	}
	b := aggregate([]Row{{Recall: 0.90, Seconds: 3}, {Recall: 0.95, Seconds: 2}, {Recall: 0.93, Seconds: 1.5}}, false)
	if b.Recall != 0.90 || b.Seconds != 1.5 {
		t.Errorf("worst of three: %+v", b)
	}
	// the time is the fastest run on either side: a load spike in one run is not the engine's cost
	if e := aggregate([]Row{{Seconds: 9}, {Seconds: 1}, {Seconds: 40}}, false); e.Seconds != 1 {
		t.Errorf("fastest of three: %v", e.Seconds)
	}
}

func TestVersionParsingAndOrder(t *testing.T) {
	for in, want := range map[string]string{
		"v3.99.8": "3.99.8", "1.9.0": "1.9.0", "trufflehog 3.99.8": "3.99.8", "titus version 1.2.10": "1.2.10",
		"v2.0.0-rc.6": "2.0.0-rc.6", "gitleaks version 8.30.1\n": "8.30.1", "1.2.3+build.5": "1.2.3",
	} {
		v, ok := ParseVersion(in)
		if !ok || v.String() != want {
			t.Errorf("ParseVersion(%q) = %v %v, want %s", in, v, ok, want)
		}
	}
	for _, bad := range []string{"", "latest", "1.2", "v1"} {
		if _, ok := ParseVersion(bad); ok {
			t.Errorf("%q parsed as a version", bad)
		}
	}
	order := []string{"1.2.3-alpha", "1.2.3-alpha.1", "1.2.3-alpha.beta", "1.2.3-beta", "1.2.3-rc.2", "1.2.3-rc.10", "1.2.3", "1.2.4", "1.10.0", "2.0.0-rc.1", "2.0.0"}
	for i := range order {
		for j := range order {
			a, _ := ParseVersion(order[i])
			b, _ := ParseVersion(order[j])
			want := 0
			if i < j {
				want = -1
			} else if i > j {
				want = 1
			}
			if got := a.Compare(b); got != want {
				t.Errorf("Compare(%s, %s) = %d, want %d", order[i], order[j], got, want)
			}
		}
	}
	if v, _ := ParseVersion("2.0.0-rc.6"); v.Stable() {
		t.Error("a release candidate is not stable")
	}
}

func TestSourcesAreTheFourEnginesKeyguardRuns(t *testing.T) {
	want := map[string]string{"betterleaks": "betterleaks/betterleaks", "gitleaks": "gitleaks/gitleaks", "trufflehog": "trufflesecurity/trufflehog", "titus": "praetorian-inc/titus"}
	if len(Sources) != 4 {
		t.Fatalf("%d sources", len(Sources))
	}
	for _, s := range Sources {
		if want[s.Name] != s.Repo || s.Binary != s.Name {
			t.Errorf("%+v", s)
		}
	}
}

// Scores wobble from run to run. The pinned engine is judged on its best run and the candidate on
// its worst, so that noise can only ever keep an engine where it is.
func TestCheckComparesThePinnedEnginesBestWithTheCandidatesWorst(t *testing.T) {
	g := newFakeGitHub(t)
	g.publish(rel{tag: "v1.1.0", label: "new"})
	pin, _ := pinnedEngine(t, "old")
	decide := func(oldRecalls, newRecalls []float64) Decision {
		t.Helper()
		next := map[string]int{}
		sc := ScorerFunc(func(_ context.Context, _, bin string) (Row, error) {
			data, err := os.ReadFile(bin)
			if err != nil {
				return Row{}, err
			}
			label := "old"
			ver := "1.0.0"
			recalls := oldRecalls
			if strings.Contains(string(data), "engine new") {
				label, ver, recalls = "new", "1.1.0", newRecalls
			}
			i := next[label]
			next[label]++
			return Row{Version: ver, Recall: recalls[i], RecallAll: 0.8, Precision: 0.97, Seconds: 1}, nil
		})
		o := &Options{API: g.srv.URL, Dir: t.TempDir(), Scorer: sc, Runs: 3}
		d, err := o.Check(context.Background(), src, pin)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	// the candidate's best run beats the pinned engine's, its worst does not: refused
	d := decide([]float64{0.94, 0.96, 0.95}, []float64{0.97, 0.95, 0.97})
	if d.Switch || d.PinnedRow.Recall != 0.96 || d.Candidate.Row.Recall != 0.95 {
		t.Errorf("pinned best %.2f against candidate worst %.2f: %v", d.PinnedRow.Recall, d.Candidate.Row.Recall, d.Reasons)
	}
	// its worst run ties the pinned engine's best: accepted
	if d := decide([]float64{0.94, 0.96, 0.95}, []float64{0.97, 0.96, 0.97}); !d.Switch {
		t.Errorf("a candidate that never falls under the pinned engine's best was refused: %v", d.Reasons)
	}
}
