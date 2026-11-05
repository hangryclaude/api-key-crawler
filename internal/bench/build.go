package bench

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/rand/v2"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"keyguard/internal/fp"
)

// Options controls corpus generation.
type Options struct {
	Seed  uint64 // every random choice derives from it; the same seed yields the same repo
	Scale int    // filler multiplier: 1 is about 650 commits and 9 MB; 0 means 1
}

// Corpus is a generated repo plus its truth. The raw fake values exist only in this struct's
// memory (Secrets); nothing on disk but the repo itself carries them.
type Corpus struct {
	Dir   string
	Repo  string // the git working copy, <Dir>/repo
	Truth *Truth
	Key   *fp.Keyring // engines under test must fingerprint with this to be scored

	secrets []Secret
	recs    []*plantRec
}

// Secret is the raw material of one positive plant, for building a known matcher in tests.
// It is never serialized.
type Secret struct {
	PlantID string
	Name    string // variable name it was assigned to, e.g. OPENAI_API_KEY
	Raw     string
	FP      string
}

// Secrets returns the raw value of every positive plant. Treat it like a secret: keep it in
// memory, never log or write it. Only Generate fills it; a corpus opened with Load holds none,
// so regenerate from the seed to rebuild a known matcher.
func (c *Corpus) Secrets() []Secret { return c.secrets }

// KeyringFor derives the bench keyring for a seed. It protects nothing (the corpus is fake)
// but keeps truth.json fingerprints repeatable.
func KeyringFor(seed uint64) *fp.Keyring {
	h := sha256.Sum256([]byte("keyguard-bench-salt/" + strconv.FormatUint(seed, 10)))
	h2 := sha256.Sum256(h[:])
	return fp.FromSalt(append(h[:], h2[:8]...))
}

// Load opens a corpus generated earlier.
func Load(dir string) (*Corpus, error) {
	t, err := LoadTruth(dir)
	if err != nil {
		return nil, err
	}
	return &Corpus{Dir: dir, Repo: filepath.Join(dir, t.Repo), Truth: t, Key: KeyringFor(t.Seed)}, nil
}

type plantRec struct {
	id       string
	typ      string
	variant  string
	positive bool
	prov     *Provider
	fake     Fake
	neg      *negItem
	kind     string
	file     *fileRec
	note     string

	line, endLine int
	forms         []string
	detectableBy  []string
	known         bool

	format string   // the provider id: the unit of the frozen split
	twin   string   // "valid" or "invalid" for a plant that is half of a near-miss pair
	twinOf string   // an invalid twin names the valid plant it imitates
	tags   []string // facts about how the value was made, such as floor-rejected
	where  string   // message, tag or ref when the value is in git metadata and not in a file
	refAs  string   // for a branch name: the ref as truth.json may show it, with the value shortened
}

type fileRec struct {
	path    string
	variant string
	ref     string
	mark    int
	removed int
	rend    rendered
	plants  []*plantRec
	engPath string // where the engine reads it: zip entries are "<zip>!.env"
}

type build struct {
	o  Options
	kr *fp.Keyring
	r  *rand.Rand
	fl *filler // history filler
	rf *filler // renders plant files
	h  *history

	main     *branch
	mutable  []string // filler-created paths that later commits may edit
	files    []*fileRec
	plants   []*plantRec
	events   []func()
	later    map[int][]func()
	step     int
	tempRefs []string
	pulls    map[int]int
	ids      map[string]int
	err      error
}

// Generate builds the corpus into dir, which must not exist or be empty, and must not sit
// inside a git work tree: the fakes are made to look real and must never be committed by
// accident.
func Generate(dir string, o Options) (*Corpus, error) {
	start := time.Now()
	if o.Scale <= 0 {
		o.Scale = 1
	}
	if ents, err := os.ReadDir(dir); err == nil && len(ents) > 0 {
		return nil, fmt.Errorf("bench: %s is not empty", dir)
	}
	if insideWorkTree(dir) {
		return nil, fmt.Errorf("bench: %s is inside a git work tree; the corpus belongs in a temp dir", dir)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	b := &build{
		o: o, kr: KeyringFor(o.Seed),
		r:     newRand(o.Seed, "history"),
		fl:    &filler{r: newRand(o.Seed, "filler")},
		rf:    &filler{r: newRand(o.Seed, "render")},
		later: map[int][]func(){}, pulls: map[int]int{}, ids: map[string]int{},
	}
	b.h = newHistory(newRand(o.Seed, "clock"))
	b.main = b.h.newBranch("refs/heads/main", nil)
	b.plan()
	if b.err != nil {
		return nil, b.err
	}
	b.run()
	repo := filepath.Join(dir, "repo")
	marks, err := b.materialize(repo)
	if err != nil {
		return nil, err
	}
	t, err := b.truth(repo, marks)
	if err != nil {
		return nil, err
	}
	t.Stats.GenerateSeconds = time.Since(start).Seconds()
	if err := t.save(dir); err != nil {
		return nil, err
	}
	c := &Corpus{Dir: dir, Repo: repo, Truth: t, Key: b.kr, recs: b.plants}
	for _, p := range b.plants {
		if p.positive {
			name := p.fake.Name
			if name == "" {
				name = p.prov.Env
			}
			c.secrets = append(c.secrets, Secret{PlantID: p.id, Name: name, Raw: p.fake.Raw, FP: b.kr.FP(p.fake.Raw)})
		}
	}
	return c, nil
}

// variantWhy names the blind spot a variant exposes when a ruled format is not detected in it.
var variantWhy = map[string]string{
	vTS:       "a type annotation before '=' breaks keyword-anchored rules",
	vGo:       "camelCase names (FalKey) do not contain the keyword (fal_key)",
	vURLEnc:   "percent-encoding changes the value or the text around it",
	vIpynb:    "escaped quotes and JSON string nesting",
	vYAML:     "block-scalar indentation inside the value",
	vJSON:     "the value is JSON-escaped",
	vEnv:      "the value is escaped to fit one line",
	vShell:    "the value is wrapped for a heredoc",
	vMinified: "no variable name beside the value",
}

// insideWorkTree reports whether dir, or the nearest ancestor that exists, is in a git work tree.
func insideWorkTree(dir string) bool {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return true
	}
	for {
		if st, err := os.Stat(dir); err == nil && st.IsDir() {
			_, err := git(dir, nil, "rev-parse", "--show-toplevel")
			return err == nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return true
		}
		dir = parent
	}
}

// uniqueID turns "pos-aws-env" into "pos-aws-env", "pos-aws-env.2"... so ids never collide.
func (b *build) uniqueID(id string) string {
	b.ids[id]++
	if n := b.ids[id]; n > 1 {
		return id + "." + strconv.Itoa(n)
	}
	return id
}

func (b *build) positive(p *Provider, variant string) *plantRec {
	id := b.uniqueID("pos-" + p.ID + "-" + variant)
	f := p.Gen(&Gen{r: newRand(b.o.Seed, "fake/"+id)})
	rec := &plantRec{id: id, typ: p.Type, variant: variant, positive: true, prov: p, fake: f, note: p.Doc, format: p.ID}
	b.plants = append(b.plants, rec)
	return rec
}

// plan decides what is planted where, renders every plant file and queues the events that
// commit them. The structure is independent of the seed (the seed only changes values and
// filler), so scores from different seeds compare.
func (b *build) plan() {
	rotating := []string{vPy, vJS, vTS, vGo, vJSON, vYAML, vTOML, vIpynb, vMinified, vDockerfile, vShell}
	multiRotating := []string{vPy, vGo, vJS, vTS, vJSON, vYAML, vTOML, vShell}
	urlencIDs := map[string]bool{"aws": true, "slack-webhook": true, "discord-webhook": true, "rsa-key": true,
		"generic-api-key": true, "openssh-key": true}
	keyFiles := map[string]string{
		"rsa-key": "id_rsa", "ec-key": "signing.key", "openssh-key": "id_ed25519",
		"gcp-service-account": "service-account.json", "firebase-admin": "firebase-adminsdk.json",
	}

	type placement struct {
		variant string
		plant   *plantRec
	}
	grouped := map[string][]*plantRec{}
	var singles []placement
	for i := range Providers {
		p := &Providers[i]
		grouped[vEnv] = append(grouped[vEnv], b.positive(p, vEnv))
		pool := rotating
		if p.Multi {
			pool = multiRotating
		}
		first := (i * 3) % len(pool)
		second := (first + len(pool)/2 + 1) % len(pool)
		if second == first {
			second = (second + 1) % len(pool)
		}
		for _, k := range []int{first, second} {
			grouped[pool[k]] = append(grouped[pool[k]], b.positive(p, pool[k]))
		}
		add := func(v string) { singles = append(singles, placement{v, b.positive(p, v)}) }
		if _, ok := keyFiles[p.ID]; ok {
			add(vKeyFile)
		}
		if i%9 == 0 {
			add(vB64)
		}
		if i%9 == 1 {
			add(vDeleted)
		}
		if i%9 == 6 {
			add(vZip)
		}
		if urlencIDs[p.ID] {
			add(vURLEnc)
		}
		if !p.Multi {
			switch i % 9 {
			case 2:
				add(vBranch)
			case 3:
				add(vTag)
			case 4:
				add(vPull)
			case 5:
				if i%2 == 1 {
					add(vBigfile)
				}
			}
		}

		// the agent-era placements (STEAL 4.3): three of the pool for a single-line format, the
		// JSON ones for a format whose value spans lines
		pool, picks := agentPool, 3
		if p.Multi {
			pool, picks = jsonPool, len(jsonPool)
		}
		for k := 0; k < picks; k++ {
			v := pool[(i+k*(len(pool)/picks))%len(pool)]
			grouped[v] = append(grouped[v], b.positive(p, v))
		}
		// and one of the ways a scanner can be blind: git metadata, an encoding, a container
		sp := specialPool[i%len(specialPool)]
		if p.Multi && (sp == vCommitMsg || sp == vTagMsg || sp == vBranchName || sp == vCastTyped) {
			sp = vTGZ
		}
		if sp == vBranchName && !refSafeFormat(p) {
			sp = vCommitMsg
		}
		add(sp)
	}

	// rotating and .env plants share files, one to three keys each, as real config files do
	vnames := make([]string, 0, len(grouped))
	for v := range grouped {
		vnames = append(vnames, v)
	}
	sort.Strings(vnames)
	n := 0
	for _, v := range vnames {
		ps := grouped[v]
		for len(ps) > 0 {
			take := min(len(ps), 1+b.rf.r.IntN(3))
			n++
			f := b.newFile(v, b.pathFor(v, n, ""), ps[:take])
			ps = ps[take:]
			b.events = append(b.events, b.addToMain(f))
		}
	}
	// single-plant placements
	for _, s := range singles {
		n++
		switch s.variant {
		case vCommitMsg:
			b.events = append(b.events, b.onCommitMessage(b.newMeta(s.variant, s.plant)))
			continue
		case vTagMsg:
			f := b.newMeta(s.variant, s.plant)
			b.events = append(b.events, b.onTagMessage(f, fmt.Sprintf("v1.%d.%d-notes", n, 1+n%7)))
			continue
		case vBranchName:
			b.events = append(b.events, b.onBranchName(b.newMeta(s.variant, s.plant)))
			continue
		}
		f := b.newFile(s.variant, b.pathFor(s.variant, n, keyFiles[s.plant.prov.ID]), []*plantRec{s.plant})
		switch s.variant {
		case vRename:
			b.events = append(b.events, b.onRename(f))
		case vDeleted:
			b.events = append(b.events, b.addThenRemove(f, n))
		case vBranch:
			b.events = append(b.events, b.onBranch(f, fmt.Sprintf("feature/%s-%d", b.rf.word(), n)))
		case vTag:
			b.events = append(b.events, b.onTag(f, fmt.Sprintf("v0.%d.0-rc%d", n, 1+n%3), n%2 == 1))
		case vPull:
			b.events = append(b.events, b.onPull(f))
		default:
			b.events = append(b.events, b.addToMain(f))
		}
	}
	// valid and invalid twins, one file per format
	for i := range Providers {
		n++
		if f := b.planTwin(&Providers[i], i, n); f != nil {
			b.events = append(b.events, b.addToMain(f))
		}
	}
	// negatives
	for _, nf := range negativeFiles(b.o.Seed) {
		b.events = append(b.events, b.addNegative(nf))
	}
	// realism: filler-only branches merged into main
	for i := 0; i < 3; i++ {
		b.events = append(b.events, b.mergedBranch(i))
	}
}

func (b *build) pathFor(variant string, n int, keyName string) string {
	w := b.rf.word()
	dir := fmt.Sprintf("%s-%d", w, n)
	switch variant {
	case vEnv:
		return path.Join("services", dir, []string{".env", ".env.local", ".env.production"}[n%3])
	case vShell:
		return path.Join("scripts", b.rf.verb()+"_"+dir+".sh")
	case vDockerfile:
		return path.Join("docker", dir, "Dockerfile")
	case vPy:
		return path.Join("services", dir, "settings.py")
	case vJS:
		return path.Join("web", dir, "config.js")
	case vTS:
		return path.Join("web", dir, "env.ts")
	case vGo:
		return path.Join("internal", w+strconv.Itoa(n), "config", "config.go")
	case vJSON:
		return path.Join("config", dir, "secrets.json")
	case vYAML:
		return path.Join("deploy", dir, "values.yaml")
	case vTOML:
		return path.Join("config", dir, "app.toml")
	case vIpynb:
		return path.Join("notebooks", dir+".ipynb")
	case vMinified:
		return path.Join("dist", dir, "app.min.js")
	case vKeyFile:
		if strings.HasSuffix(keyName, ".json") {
			return path.Join("credentials", dir, keyName)
		}
		return path.Join("deploy", "keys", dir, keyName)
	case vB64:
		return path.Join("k8s", dir, "secret.yaml")
	case vURLEnc:
		return path.Join("scripts", "notify_"+dir+".sh")
	case vDeleted:
		return path.Join("legacy", dir, ".env")
	case vBranch:
		return path.Join("experiments", dir, ".env")
	case vTag:
		return path.Join("release", dir, ".env")
	case vPull:
		return path.Join("contrib", dir, ".env")
	case vBigfile:
		return path.Join("logs", dir, "app.log")
	case vZip:
		return path.Join("backups", dir, "config.zip")
	}
	if p, ok := agentPath(variant, n, w); ok {
		return p
	}
	panic("bench: no path for variant " + variant)
}

func slotOf(p *plantRec) slot {
	name := p.fake.Name
	if name == "" && p.prov != nil {
		name = p.prov.Env
	}
	multi := false
	if p.prov != nil {
		multi = p.prov.Multi
	}
	return slot{name: name, value: p.fake.Value, multi: multi, pairs: p.fake.Pairs}
}

// newFile renders a file for the plants and resolves each plant's line, forms and flags.
func (b *build) newFile(variant, p string, ps []*plantRec) *fileRec {
	slots := make([]slot, len(ps))
	for i, pr := range ps {
		slots[i] = slotOf(pr)
	}
	f := &fileRec{path: p, variant: variant, plants: ps, engPath: p}
	f.rend = renderFile(variant, slots, b.rf.r, b.rf)
	if variant == vZip {
		f.engPath = p + "!.env"
	}
	for _, pr := range ps {
		pr.file = f
		b.resolve(pr, f)
	}
	b.files = append(b.files, f)
	return f
}

func stdB64(s string) string    { return base64.StdEncoding.EncodeToString([]byte(s)) }
func rawURLB64(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

func (b *build) fail(format string, a ...any) {
	if b.err == nil {
		b.err = fmt.Errorf(format, a...)
	}
}

// resolve computes where a plant sits in its rendered file and how scanners can see it.
func (b *build) resolve(pr *plantRec, f *fileRec) {
	text := f.rend.content
	if f.rend.inner != "" {
		text = f.rend.inner
	}
	esc := f.rend.esc
	if f.rend.locate != nil {
		pr.line, pr.endLine = f.rend.locate(pr.fake.Value)
		if pr.line == 0 {
			b.fail("bench: plant %s not found in %s", pr.id, f.path)
			return
		}
	} else {
		idx := strings.Index(text, esc(pr.fake.Value))
		if idx < 0 {
			b.fail("bench: plant %s not found in %s", pr.id, f.path)
			return
		}
		pr.line = 1 + strings.Count(text[:idx], "\n")
		pr.endLine = pr.line + strings.Count(esc(pr.fake.Value), "\n")
	}
	views := viewsOf(f, text)
	if f.rend.opaque != "" {
		views = nil // the engines cannot read this file; nothing it holds reaches a rule
	}

	// every spelling of the credential an engine can come to report: as written, as the
	// file escapes it, and as the engines' decoders read it
	var accept []string
	seen := map[string]bool{}
	addAccept := func(s string) {
		if s != "" && !seen[s] {
			seen[s] = true
			accept = append(accept, s)
		}
	}
	for _, c := range append([]string{pr.fake.Raw, pr.fake.Value}, pr.fake.Alt...) {
		for _, t := range []string{c, esc(c)} {
			addAccept(t)
			addAccept(percentDecode(t))
		}
	}
	for _, t := range accept {
		if t != pr.fake.Raw {
			pr.forms = append(pr.forms, t)
		}
	}
	// some engines report the whole assignment line (a k8s Secret entry, for one)
	needles := []string{esc(pr.fake.Value), pr.fake.Value, percentDecode(esc(pr.fake.Value))}
	for _, p := range pr.fake.Pairs {
		needles = append(needles, esc(p.Value), p.Value, percentDecode(esc(p.Value)))
	}
	for _, v := range views {
		for _, n := range needles {
			if strings.Contains(n, "\n") {
				continue // the first line of a PEM or JSON file names no credential
			}
			if line := lineAround(v, n); line != "" && !seen[line] {
				seen[line] = true
				pr.forms = append(pr.forms, line)
			}
		}
	}

	if pr.prov != nil && pr.positive && len(pr.prov.Rules) > 0 && f.rend.opaque == "" {
		by, err := coveredBy(pr.prov.Rules, f.engPath, views, accept)
		if err != nil {
			b.fail("%v", err)
			return
		}
		pr.detectableBy = by
	}
	if pr.positive && len(pr.detectableBy) == 0 {
		why := "no rule reports it as planted (" + pr.variant + ")"
		if hint := variantWhy[pr.variant]; hint != "" {
			why = "no rule reports it as planted: " + hint
		}
		if strings.HasSuffix(pr.prov.ID, "-lone") {
			why = "a composite rule drops it without its companion value in the file"
		}
		if pr.prov.Undetected != "" {
			why = pr.prov.Undetected
		}
		if f.rend.opaque != "" {
			why = f.rend.opaque
		}
		pr.note += " | undetected by design: " + why
	}
	// a matcher holding the value sees the bytes the full scan feeds it: the file as stored, or
	// what an archive holds once it has been opened
	hay := f.rend.content
	if f.rend.archive {
		hay = f.rend.inner
	}
	if pr.positive {
		for _, k := range knownForms(pr.fake.Raw) {
			if k != "" && strings.Contains(hay, k) {
				pr.known = true
				break
			}
		}
	}
}

func slotsOf(f *fileRec) []slot {
	out := make([]slot, len(f.plants))
	for i, p := range f.plants {
		out[i] = slotOf(p)
	}
	return out
}

// ---- events: what a commit does ----

func (b *build) mainMsg() string { return b.fl.message() }

func (b *build) addToMain(f *fileRec) func() {
	return func() {
		ch := []change{{path: f.path, content: f.rend.content}}
		b.commitMain(b.mainMsg(), ch)
		f.mark = b.main.tip
		f.ref = "refs/heads/main"
	}
}

func (b *build) commitMain(msg string, ch []change) {
	b.h.commit(b.main, msg, ch, 0, 0)
}

func (b *build) addThenRemove(f *fileRec, n int) func() {
	return func() {
		b.commitMain(b.mainMsg(), []change{{path: f.path, content: f.rend.content}})
		f.mark = b.main.tip
		f.ref = "refs/heads/main"
		b.after(4+b.r.IntN(12), func() {
			if n%2 == 0 { // delete the file
				b.commitMain("chore: remove legacy config", []change{{path: f.path, del: true}})
			} else { // move the values to the environment, keep the file
				c := f.rend.content
				for _, s := range slotsOf(f) {
					c = strings.ReplaceAll(c, f.rend.esc(s.value), "${"+s.name+"}")
				}
				b.commitMain("refactor: read config from the environment", []change{{path: f.path, content: c}})
			}
			f.removed = b.main.tip
		})
	}
}

func (b *build) onBranch(f *fileRec, name string) func() {
	return func() {
		br := b.h.newBranch("refs/heads/"+name, b.main)
		fillPath := b.fl.path("py")
		b.h.commit(br, b.mainMsg(), []change{{path: "wip/" + fillPath, content: b.fl.file("py", 20)}}, b.main.tip, 0)
		f.mark = b.h.commit(br, b.mainMsg(), []change{{path: f.path, content: f.rend.content}}, 0, 0)
		f.ref = "refs/heads/" + name
	}
}

func (b *build) onTag(f *fileRec, name string, annotated bool) func() {
	return func() {
		if annotated {
			// the commit hangs off a throwaway branch that is deleted after import
			tmp := "refs/heads/_tag_" + name
			br := b.h.newBranch(tmp, b.main)
			f.mark = b.h.commit(br, b.mainMsg(), []change{{path: f.path, content: f.rend.content}}, b.main.tip, 0)
			b.h.tag(name, f.mark, "release candidate "+name)
			b.tempRefs = append(b.tempRefs, tmp)
		} else {
			br := b.h.newBranch("refs/tags/"+name, b.main)
			f.mark = b.h.commit(br, b.mainMsg(), []change{{path: f.path, content: f.rend.content}}, b.main.tip, 0)
		}
		f.ref = "refs/tags/" + name
	}
}

func (b *build) onPull(f *fileRec) func() {
	return func() {
		n := len(b.pulls) + 1
		tmp := fmt.Sprintf("refs/heads/_pr_%d", n)
		br := b.h.newBranch(tmp, b.main)
		f.mark = b.h.commit(br, b.mainMsg(), []change{{path: f.path, content: f.rend.content}}, b.main.tip, 0)
		b.pulls[n] = f.mark
		b.tempRefs = append(b.tempRefs, tmp)
		f.ref = fmt.Sprintf("refs/pull/%d/head", n)
	}
}

// mergedBranch is realism: a feature branch of filler commits merged with a merge commit,
// so history is not a straight line and `git log -p` meets merges.
func (b *build) mergedBranch(i int) func() {
	return func() {
		br := b.h.newBranch(fmt.Sprintf("refs/heads/feature/merged-%d", i), b.main)
		var ch []change
		for j := 0; j < 2; j++ {
			ext := b.fl.randomExt()
			p := b.fl.path(ext)
			c := change{path: p, content: b.fl.file(ext, 20+b.fl.r.IntN(30))}
			b.h.commit(br, b.mainMsg(), []change{c}, b.main.tip, 0)
			ch = append(ch, c)
		}
		b.h.commit(b.main, fmt.Sprintf("Merge branch 'feature/merged-%d'", i), ch, 0, br.tip)
	}
}

func (b *build) addNegative(nf negFile) func() {
	rec := make([]*plantRec, 0, len(nf.items))
	fr := &fileRec{path: nf.path, variant: "negative", engPath: nf.path, rend: rendered{content: nf.content, esc: identity}}
	b.files = append(b.files, fr)
	for i := range nf.items {
		it := &nf.items[i]
		id := b.uniqueID("neg-" + it.kind)
		pr := &plantRec{id: id, typ: it.typ, variant: "negative", kind: it.kind, neg: it, file: fr, note: it.note,
			fake: Fake{Value: it.value, Raw: it.value, Alt: it.alt}}
		if it.value != "" {
			idx := strings.Index(nf.content, it.value)
			if idx < 0 {
				b.fail("bench: negative %s not found in %s", id, nf.path)
				continue
			}
			pr.line = 1 + strings.Count(nf.content[:idx], "\n")
			pr.endLine = pr.line + strings.Count(it.value, "\n")
			seen := map[string]bool{it.value: true}
			for _, a := range it.alt {
				if !seen[a] && strings.Contains(nf.content, a) {
					seen[a] = true
					pr.forms = append(pr.forms, a)
				}
			}
		} else {
			pr.line = 1
		}
		rec = append(rec, pr)
		b.plants = append(b.plants, pr)
	}
	fr.plants = rec
	return func() {
		b.commitMain(b.mainMsg(), []change{{path: nf.path, content: nf.content}})
		fr.mark = b.main.tip
		fr.ref = "refs/heads/main"
	}
}

func (b *build) after(steps int, fn func()) {
	b.later[b.step+steps] = append(b.later[b.step+steps], fn)
}

// run executes the timeline: filler commits with the planted events spread through them.
func (b *build) run() {
	// root commit: the skeleton every repo starts with
	skeleton := []change{
		{path: ".gitignore", content: "node_modules/\n.venv/\n"},
		{path: "package.json", content: "{\n  \"name\": \"bench-app\",\n  \"version\": \"1.0.0\",\n  \"private\": true\n}\n"},
		{path: "go.mod", content: "module example.invalid/bench\n\ngo 1.22\n"},
		{path: "Makefile", content: "build:\n\tgo build ./...\n\ntest:\n\tgo test ./...\n"},
		{path: "docs/architecture.md", content: b.fl.file("md", 40)},
	}
	b.h.commit(b.main, "chore: initial commit", skeleton, 0, 0)

	b.r.Shuffle(len(b.events), func(i, j int) { b.events[i], b.events[j] = b.events[j], b.events[i] })
	total := 400*b.o.Scale + len(b.events)
	slots := make(map[int]int, len(b.events))
	for i := range b.events {
		slots[8+i*(total-16)/len(b.events)] = i
	}
	for b.step = 0; b.step < total || len(b.laterPending()) > 0; b.step++ {
		ran := false
		if fns := b.later[b.step]; len(fns) > 0 {
			delete(b.later, b.step)
			for _, fn := range fns {
				fn()
			}
			ran = true
		}
		if i, ok := slots[b.step]; ok {
			b.events[i]()
			ran = true
		}
		if !ran {
			b.fillerCommit()
		}
	}
}

func (b *build) laterPending() []int {
	var ks []int
	for k := range b.later {
		if k >= b.step {
			ks = append(ks, k)
		}
	}
	return ks
}

func (b *build) fillerCommit() {
	var ch []change
	touched := map[string]bool{}
	for i, n := 0, 1+b.r.IntN(4); i < n; i++ {
		if len(b.mutable) == 0 || b.r.IntN(100) < 45 {
			ext := b.fl.randomExt()
			p := b.fl.path(ext)
			if _, exists := b.main.files[p]; exists || touched[p] {
				continue
			}
			touched[p] = true
			ch = append(ch, change{path: p, content: b.fl.file(ext, 14+b.fl.r.IntN(70))})
			b.mutable = append(b.mutable, p)
			continue
		}
		p := b.mutable[b.r.IntN(len(b.mutable))]
		if touched[p] {
			continue
		}
		touched[p] = true
		ch = append(ch, change{path: p, content: b.fl.mutate(b.main.files[p], strings.TrimPrefix(path.Ext(p), "."))})
	}
	if len(ch) == 0 {
		ch = append(ch, change{path: fmt.Sprintf("notes/%d.md", b.step), content: b.fl.file("md", 8)})
	}
	b.commitMain(b.mainMsg(), ch)
}

// ---- git ----

// gitEnv is a hermetic environment: no global or system git config (a developer's hooks and
// aliases must not run inside the corpus), no inherited GIT_* state.
func gitEnv() []string {
	var env []string
	for _, e := range os.Environ() {
		if !strings.HasPrefix(e, "GIT_") {
			env = append(env, e)
		}
	}
	return append(env, "GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_CONFIG_SYSTEM="+os.DevNull, "GIT_CONFIG_NOSYSTEM=1",
		"GIT_TERMINAL_PROMPT=0", "GIT_OPTIONAL_LOCKS=0")
}

func git(dir string, stdin []byte, args ...string) (string, error) {
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = gitEnv()
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		// git quotes the offending input line (fast-import does); keep any planted value out of
		// the error: first line only, random-looking tokens masked
		first, _, _ := strings.Cut(errb.String(), "\n")
		return "", fmt.Errorf("bench: git %s: %w: %.160s", args[0], err, fp.Scrub(first))
	}
	return out.String(), nil
}

// materialize turns the stream into a repo and returns mark -> commit sha.
func (b *build) materialize(repo string) (map[int]string, error) {
	if err := os.MkdirAll(repo, 0o755); err != nil {
		return nil, err
	}
	if _, err := git(repo, nil, "init", "-q", "-b", "main"); err != nil {
		return nil, err
	}
	if d := os.Getenv("BENCH_DUMP"); d != "" {
		os.WriteFile(d, b.h.buf.Bytes(), 0o644)
	}
	marksFile := filepath.Join(repo, ".git", "bench-marks")
	if _, err := git(repo, b.h.buf.Bytes(), "fast-import", "--quiet", "--date-format=raw", "--export-marks="+marksFile); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(marksFile)
	if err != nil {
		return nil, err
	}
	marks := map[int]string{}
	for _, l := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		m, sha, ok := strings.Cut(l, " ")
		if !ok {
			continue
		}
		n, err := strconv.Atoi(strings.TrimPrefix(m, ":"))
		if err != nil {
			return nil, err
		}
		marks[n] = sha
	}
	// pull refs are made the way a hosting service makes them: update-ref on a commit that
	// no branch holds
	for n, mark := range b.pulls {
		if _, err := git(repo, nil, "update-ref", fmt.Sprintf("refs/pull/%d/head", n), marks[mark]); err != nil {
			return nil, err
		}
	}
	for _, ref := range b.tempRefs {
		if _, err := git(repo, nil, "update-ref", "-d", ref); err != nil {
			return nil, err
		}
	}
	if _, err := git(repo, nil, "checkout", "-q", "-f", "main"); err != nil {
		return nil, err
	}
	return marks, nil
}

// truth assembles truth.json and measures the repo.
func (b *build) truth(repo string, marks map[int]string) (*Truth, error) {
	t := &Truth{Schema: truthSchema, Seed: b.o.Seed, Scale: b.o.Scale, Repo: "repo"}
	seenFP := map[string]string{}
	for _, pr := range b.plants {
		f := pr.file
		p := Plant{
			ID: pr.id, Type: pr.typ, Variant: pr.variant, Positive: pr.positive,
			DetectableBy: pr.detectableBy, Detectable: len(pr.detectableBy) > 0, Known: pr.known, Kind: pr.kind, Note: pr.note,
			Location: Location{Ref: f.ref, Commit: marks[f.mark], Path: f.path, Line: pr.line},
		}
		if pr.endLine > pr.line {
			p.Location.EndLine = pr.endLine
		}
		p.Format, p.Twin, p.TwinOf, p.Tags = pr.format, pr.twin, pr.twinOf, pr.tags
		p.Location.Where = pr.where
		if pr.refAs != "" {
			p.Location.Ref = pr.refAs // the real ref carries the value; truth.json must not
		}
		if pr.fake.Raw != "" {
			p.Len = len(pr.fake.Raw)
		}
		p.Half = HalfOf(p)
		if f.removed != 0 {
			p.RemovedIn = marks[f.removed]
		}
		if pr.prov != nil {
			p.Rules = pr.prov.Rules
		}
		if pr.fake.Raw != "" {
			p.FP = b.kr.FP(pr.fake.Raw)
			if pr.positive {
				if other, dup := seenFP[p.FP]; dup {
					return nil, fmt.Errorf("bench: plants %s and %s share a value", pr.id, other)
				}
				seenFP[p.FP] = pr.id
			}
		}
		for _, form := range pr.forms {
			if a := b.kr.FP(form); a != p.FP {
				p.AltFPs = append(p.AltFPs, a)
			}
		}
		// The engines fingerprint the canonical form of what they report (STEAL P0-08): the password
		// of a connection URI, a private key unwrapped to one line. A plant of those kinds is found
		// under that fingerprint, so it is expected under it too.
		if pr.fake.Raw != "" {
			if a := b.kr.FP(fp.Canonical(pr.fake.Raw)); a != p.FP && !slices.Contains(p.AltFPs, a) {
				p.AltFPs = append(p.AltFPs, a)
			}
		}
		if p.Location.Commit == "" {
			return nil, fmt.Errorf("bench: plant %s has no commit (mark %d)", pr.id, f.mark)
		}
		t.Plants = append(t.Plants, p)
	}

	out, err := git(repo, nil, "rev-list", "--all", "--count")
	if err != nil {
		return nil, err
	}
	t.Stats.Commits, _ = strconv.Atoi(strings.TrimSpace(out))
	out, err = git(repo, nil, "ls-tree", "-r", "--name-only", "main")
	if err != nil {
		return nil, err
	}
	t.Stats.Files = len(strings.Split(strings.TrimSpace(out), "\n"))
	out, err = git(repo, nil, "for-each-ref", "--format=%(refname)")
	if err != nil {
		return nil, err
	}
	t.Stats.Refs = len(strings.Split(strings.TrimSpace(out), "\n"))
	out, err = git(repo, nil, "cat-file", "--batch-all-objects", "--batch-check")
	if err != nil {
		return nil, err
	}
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		fs := strings.Fields(l)
		if len(fs) != 3 {
			continue
		}
		sz, _ := strconv.ParseInt(fs[2], 10, 64)
		t.Stats.Bytes += sz
		if fs[1] == "blob" {
			t.Stats.Blobs++
		}
	}
	vs := map[string]bool{}
	for _, p := range t.Plants {
		if p.Positive {
			t.Stats.Positives++
			vs[p.Variant] = true
			if p.Detectable {
				t.Stats.Detectable++
			}
			if p.Half == HalfHeldOut {
				t.Stats.HeldOut++
			} else {
				t.Stats.Tunable++
			}
		} else {
			t.Stats.Negatives++
			if p.Twin == "invalid" {
				t.Stats.Twins++
			}
		}
	}
	t.Stats.PositiveVariants = len(vs)
	t.Stats.Placings = len(vs)
	t.Stats.ProviderFormats = len(Providers)
	if t.Stats.Lines, err = countLines(repo); err != nil {
		return nil, err
	}
	return t, nil
}
