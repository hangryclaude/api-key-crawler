package bench

import (
	"fmt"
	"path"
	"strings"
	"sync"

	"keyguard/internal/fp"
)

// refSafe reports whether a value can be part of a branch name. git forbids spaces, control
// characters and ~ ^ : ? * [ \, and a name may not start with - or end in ., so only values made
// of the characters tokens usually are can be planted that way.
func refSafe(v string) bool {
	if v == "" || v[0] == '-' || v[0] == '.' {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

var (
	refSafeMu    sync.Mutex
	refSafeCache = map[string]bool{}
)

// refSafeFormat says whether every value of a format can name a branch. It decides from eight
// draws on fixed streams, not from the run's seed, so the plan of the corpus does not depend on
// the seed.
func refSafeFormat(p *Provider) bool {
	refSafeMu.Lock()
	defer refSafeMu.Unlock()
	if v, ok := refSafeCache[p.ID]; ok {
		return v
	}
	ok := !p.Multi
	for k := 0; ok && k < 8; k++ {
		ok = refSafe(p.Gen(&Gen{r: newRand(0, fmt.Sprintf("refsafe/%s/%d", p.ID, k))}).Raw)
	}
	refSafeCache[p.ID] = ok
	return ok
}

// newMeta records a plant whose value lives in git metadata: the text of a commit message or
// tag annotation, or a branch name. There is no file; the "content" is the text git keeps.
func (b *build) newMeta(variant string, pr *plantRec) *fileRec {
	s := slotOf(pr)
	var text, why string
	switch variant {
	case vCommitMsg:
		pr.where = "message"
		text = b.rf.message() + "\n\nPassing it inline until the secrets manager is set up.\n\n" + s.name + "=" + s.value + "\n"
		why = "betterleaks and gitleaks scan the patch of a commit, not its message"
	case vTagMsg:
		pr.where = "tag"
		text = "release notes\n\nrotate " + s.name + "=" + s.value + " once this ships\n"
		why = "betterleaks and gitleaks scan patches, and a tag annotation is not one"
	case vBranchName:
		pr.where = "ref"
		text = s.value
		why = "no engine reads ref names"
		pr.refAs = "refs/heads/feature/" + fp.Shape(pr.fake.Raw)
	}
	f := &fileRec{variant: variant, plants: []*plantRec{pr}, rend: rendered{content: text, esc: identity, opaque: why}}
	pr.file = f
	b.resolve(pr, f)
	b.files = append(b.files, f)
	return f
}

func (b *build) onCommitMessage(f *fileRec) func() {
	return func() {
		p := fmt.Sprintf("notes/%d.md", b.step)
		b.commitMain(f.rend.content, []change{{path: p, content: b.fl.file("md", 8)}})
		f.mark = b.main.tip
		f.ref = "refs/heads/main"
	}
}

func (b *build) onTagMessage(f *fileRec, name string) func() {
	return func() {
		tmp := "refs/heads/_tagmsg_" + name
		br := b.h.newBranch(tmp, b.main)
		f.mark = b.h.commit(br, b.mainMsg(), []change{{path: "notes/" + name + ".md", content: b.fl.file("md", 8)}}, b.main.tip, 0)
		b.h.tag(name, f.mark, f.rend.content)
		b.tempRefs = append(b.tempRefs, tmp)
		f.ref = "refs/tags/" + name
	}
}

func (b *build) onBranchName(f *fileRec) func() {
	return func() {
		ref := "refs/heads/feature/" + f.rend.content
		br := b.h.newBranch(ref, b.main)
		f.mark = b.h.commit(br, b.mainMsg(), []change{{path: "wip/" + b.fl.path("md"), content: b.fl.file("md", 8)}}, b.main.tip, 0)
		f.ref = ref
	}
}

// onRename adds the file under a draft name without its secrets, then renames it and adds them
// in one commit. git reports that commit as a rename (R097), which a scan that looks only at
// added files skips: trufflehog's full scan applies --diff-filter=AM (docs/STEAL.md P1-03).
func (b *build) onRename(f *fileRec) func() {
	return func() {
		old := path.Join(path.Dir(f.path), "draft.env")
		var keep []string
	lines:
		for _, l := range strings.Split(f.rend.content, "\n") {
			for _, s := range slotsOf(f) {
				for _, v := range append([]string{f.rend.esc(s.value), s.value}, pairValues(s)...) {
					if v != "" && strings.Contains(l, v) {
						continue lines
					}
				}
			}
			keep = append(keep, l)
		}
		b.commitMain(b.mainMsg(), []change{{path: old, content: strings.Join(keep, "\n")}})
		b.after(3+b.r.IntN(10), func() {
			b.commitMain("refactor: rename the draft config", []change{{path: f.path, from: old, content: f.rend.content}})
			f.mark = b.main.tip
			f.ref = "refs/heads/main"
		})
	}
}

func pairValues(s slot) []string {
	out := make([]string, len(s.pairs))
	for i, p := range s.pairs {
		out[i] = p.Value
	}
	return out
}

var (
	twinKindsMu    sync.Mutex
	twinKindsCache = map[string]map[string]bool{}
)

// twinKinds are the kinds of invalid twin a format has: those its own rules refuse on every one
// of eight draws from fixed streams, and the checksum twin, which a pattern cannot refuse by
// nature and is a negative by label. A shortened Slack token is still a Slack token to a rule that
// takes any length, so a format like that has no shape twin. The draws are fixed, not the run's,
// so the plan of the corpus does not depend on the seed.
func twinKinds(p *Provider) map[string]bool {
	twinKindsMu.Lock()
	defer twinKindsMu.Unlock()
	if k, ok := twinKindsCache[p.ID]; ok {
		return k
	}
	const draws = 8
	seen, refused := map[string]int{}, map[string]int{}
	for k := 0; k < draws; k++ {
		for _, tw := range p.Twins(&Gen{r: newRand(0, fmt.Sprintf("twincheck/%s/%d", p.ID, k))}) {
			seen[tw.Kind]++
			if tw.Kind == "checksum" {
				refused[tw.Kind]++
				continue
			}
			content := "NAME=" + tw.Fake.Value + "\n"
			by, err := coveredBy(p.Rules, ".env", []string{content}, []string{tw.Fake.Value})
			if err == nil && len(by) == 0 {
				refused[tw.Kind]++
			}
		}
	}
	kinds := map[string]bool{}
	for kind, n := range seen {
		if n == draws && refused[kind] == draws {
			kinds[kind] = true
		}
	}
	twinKindsCache[p.ID] = kinds
	return kinds
}

// planTwin plants a valid value of a format beside its invalid twins in one file, and returns
// that file, or nil for a format with no near-miss to make.
func (b *build) planTwin(p *Provider, i, n int) *fileRec {
	if p.Multi || p.Twins == nil {
		return nil
	}
	var tws []Twin
	kinds := twinKinds(p)
	for _, tw := range p.Twins(&Gen{r: newRand(b.o.Seed, "twin/"+p.ID)}) {
		if kinds[tw.Kind] {
			tws = append(tws, tw)
		}
	}
	if len(tws) == 0 {
		return nil
	}
	valid := b.positive(p, vTwin)
	valid.twin = "valid"
	ps := []*plantRec{valid}
	neutral := 0
	for _, tw := range tws {
		fk := tw.Fake
		switch {
		case tw.Neutral:
			fk.Name = neutralNames[(i+neutral)%len(neutralNames)]
			neutral++
		case tw.Kind == "floor":
			fk.Name = p.Env + "_OLD"
		default:
			fk.Name = p.Env + "_PREV"
		}
		rec := &plantRec{
			id: b.uniqueID("neg-twin-" + p.ID + "-" + tw.Kind), typ: p.Type, variant: vTwin, kind: "twin-" + tw.Kind,
			prov: p, fake: fk, format: p.ID, twin: "invalid", twinOf: valid.id, tags: tw.Tags,
			note: "invalid twin of " + valid.id + ": " + tw.Why,
		}
		b.plants = append(b.plants, rec)
		ps = append(ps, rec)
	}
	return b.newFile(vTwin, b.pathFor(vTwin, n, ""), ps)
}
