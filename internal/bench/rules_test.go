package bench

import (
	"flag"
	"fmt"
	"go/format"
	"os"
	"os/exec"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite rules_betterleaks_gen.go from the live betterleaks config")

// parseBetterleaksConfig reads the part of `betterleaks config show` the bench embeds: each
// rule's regex, keywords, entropy gate, secret group and required components, and the global
// path prefilter. The dump is TOML with ”'-quoted multi-line strings; this is not a TOML
// parser, only enough of one for that shape.
func parseBetterleaksConfig(text string) (map[string]ruleDef, []string, error) {
	type rawRule struct {
		id, regex, filter string
		keywords          []string
		group             int
		comps             []component
	}
	entropyRE := regexp.MustCompile(`entropy\(finding\["secret"\]\)\s*(?:<=|<)\s*([0-9.]+)`)
	var (
		rules     = map[string]ruleDef{}
		prefilter []string
		cur       *rawRule
		lines     = strings.Split(text, "\n")
	)
	flush := func() {
		if cur == nil || cur.id == "" {
			return
		}
		def := ruleDef{Regex: cur.regex, Keywords: cur.keywords, Group: cur.group, Components: cur.comps}
		for _, m := range entropyRE.FindAllStringSubmatch(cur.filter, -1) {
			if v, err := strconv.ParseFloat(m[1], 64); err == nil && v > def.Entropy {
				def.Entropy = v
			}
		}
		rules[cur.id] = def
	}
	// multi reads a '''-quoted value that starts on line i after the opening quotes in rest
	// and returns its text and the index of the line holding the closing quotes.
	multi := func(i int, rest string) (string, int) {
		if j := strings.Index(rest, "'''"); j >= 0 { // opens and closes on one line
			return rest[:j], i
		}
		var body []string
		if rest != "" {
			body = append(body, rest)
		}
		for i++; i < len(lines); i++ {
			if j := strings.Index(lines[i], "'''"); j >= 0 {
				return strings.Join(append(body, lines[i][:j]), "\n"), i
			}
			body = append(body, lines[i])
		}
		return strings.Join(body, "\n"), i
	}
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		if line == "[[rules]]" {
			flush()
			cur = &rawRule{}
			continue
		}
		key, val, ok := strings.Cut(line, " = ")
		if !ok || line[0] == ' ' || line[0] == '\t' {
			continue
		}
		var str string
		switch {
		case strings.HasPrefix(val, "'''"):
			str, i = multi(i, strings.TrimPrefix(val, "'''"))
		case strings.HasPrefix(val, "'") && strings.HasSuffix(val, "'") && len(val) >= 2:
			str = val[1 : len(val)-1]
		case val == "[":
			var body []string
			for i++; i < len(lines) && lines[i] != "]"; i++ {
				body = append(body, lines[i])
			}
			if cur != nil && key == "components" {
				for _, l := range body {
					id := regexp.MustCompile(`id = '([^']+)'`).FindStringSubmatch(l)
					if id == nil || strings.Contains(l, "optional = true") {
						continue // an optional component never gates the finding
					}
					within := 0
					if m := regexp.MustCompile(`within = '(\d+)L`).FindStringSubmatch(l); m != nil {
						within, _ = strconv.Atoi(m[1])
					}
					cur.comps = append(cur.comps, component{ID: id[1], Within: within})
				}
			}
			continue
		case strings.HasPrefix(val, "["):
			if cur != nil && key == "keywords" {
				for _, m := range regexp.MustCompile(`'([^']*)'`).FindAllStringSubmatch(val, -1) {
					cur.keywords = append(cur.keywords, strings.ToLower(m[1]))
				}
			}
			continue
		default:
			if cur != nil && key == "secretGroup" {
				cur.group, _ = strconv.Atoi(val)
			}
			continue
		}
		switch {
		case cur == nil && key == "prefilter":
			for _, m := range regexp.MustCompile("(?m)^\\s*`(.*)`,?$").FindAllStringSubmatch(str, -1) {
				prefilter = append(prefilter, m[1])
			}
		case cur != nil && key == "id":
			cur.id = str
		case cur != nil && key == "regex":
			cur.regex = str
		case cur != nil && key == "filter":
			cur.filter = str
		}
	}
	flush()
	if len(rules) == 0 {
		return nil, nil, fmt.Errorf("no rules parsed")
	}
	return rules, prefilter, nil
}

// neededRules is every betterleaks rule the provider table references, plus the components
// those rules require, transitively.
func neededRules(live map[string]ruleDef) ([]string, error) {
	seen := map[string]bool{}
	var queue []string
	for _, p := range Providers {
		for _, ref := range p.Rules {
			if id, ok := strings.CutPrefix(ref, "betterleaks/"); ok {
				queue = append(queue, id)
			}
		}
	}
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		if seen[id] {
			continue
		}
		seen[id] = true
		def, ok := live[id]
		if !ok {
			return nil, fmt.Errorf("provider table references betterleaks rule %q, which the live config does not have", id)
		}
		for _, c := range def.Components {
			queue = append(queue, c.ID)
		}
	}
	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids, nil
}

func goString(s string) string {
	if !strings.Contains(s, "`") {
		return "`" + s + "`"
	}
	return strconv.Quote(s)
}

func renderRulesFile(version string, live map[string]ruleDef, prefilter []string, ids []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "// Code generated by `go test ./internal/bench -run TestEmbeddedRulesMatchLiveBetterleaks -update` from\n")
	fmt.Fprintf(&b, "// `betterleaks config show` (betterleaks %s); DO NOT EDIT. The test compares every entry with the\n// live binary, so a rule that changes upstream fails loudly instead of silently skewing the bench.\n\n", version)
	b.WriteString("package bench\n\n// betterleaksRules holds the default rules that cover the corpus formats, and the component rules a\n// composite rule needs before it reports.\nvar betterleaksRules = map[string]ruleDef{\n")
	for _, id := range ids {
		d := live[id]
		fmt.Fprintf(&b, "\t%q: {Regex: %s", id, goString(d.Regex))
		if len(d.Keywords) > 0 {
			ks := make([]string, len(d.Keywords))
			for i, k := range d.Keywords {
				ks[i] = strconv.Quote(k)
			}
			fmt.Fprintf(&b, ", Keywords: []string{%s}", strings.Join(ks, ", "))
		}
		if d.Entropy > 0 {
			fmt.Fprintf(&b, ", Entropy: %s", strconv.FormatFloat(d.Entropy, 'f', -1, 64))
		}
		if d.Group > 0 {
			fmt.Fprintf(&b, ", Group: %d", d.Group)
		}
		if len(d.Components) > 0 {
			cs := make([]string, len(d.Components))
			for i, c := range d.Components {
				cs[i] = fmt.Sprintf("{%q, %d}", c.ID, c.Within)
			}
			fmt.Fprintf(&b, ", Components: []component{%s}", strings.Join(cs, ", "))
		}
		b.WriteString("},\n")
	}
	b.WriteString("}\n\n// betterleaksPrefilter lists the path patterns betterleaks never scans (lockfiles, vendored code, images).\nvar betterleaksPrefilter = []string{\n")
	for _, p := range prefilter {
		fmt.Fprintf(&b, "\t%s,\n", goString(p))
	}
	b.WriteString("}\n")
	return b.String()
}

// TestEmbeddedRulesMatchLiveBetterleaks keeps rules_betterleaks_gen.go honest: the bench decides
// what is "detectable by design" from this copy, so it must be what the installed binary runs.
func TestEmbeddedRulesMatchLiveBetterleaks(t *testing.T) {
	bin := engineBin(t, "betterleaks")
	cmd := exec.Command(bin, "config", "show")
	cmd.Dir = t.TempDir() // no ./.betterleaks.toml to pick up
	cmd.Env = withoutEnv(os.Environ(), "BETTERLEAKS_CONFIG", "GITLEAKS_CONFIG", "BETTERLEAKS_CONFIG_TOML", "GITLEAKS_CONFIG_TOML")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("betterleaks config show: %v", err)
	}
	live, prefilter, err := parseBetterleaksConfig(string(out))
	if err != nil {
		t.Fatal(err)
	}
	ids, err := neededRules(live)
	if err != nil {
		t.Fatal(err)
	}
	if *update {
		ver, _ := exec.Command(bin, "version").Output()
		src, err := format.Source([]byte(renderRulesFile(strings.TrimSpace(string(ver)), live, prefilter, ids)))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile("rules_betterleaks_gen.go", src, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("rewrote rules_betterleaks_gen.go: %d rules, %d prefilter patterns", len(ids), len(prefilter))
		return
	}
	for _, id := range ids {
		got, ok := betterleaksRules[id]
		if !ok {
			t.Errorf("rule %s is needed by the provider table but not embedded; run with -update", id)
			continue
		}
		if !reflect.DeepEqual(got, live[id]) {
			t.Errorf("rule %s differs from the live binary; run with -update\n embedded: %+v\n live:     %+v", id, got, live[id])
		}
	}
	for id := range betterleaksRules {
		if !contains(ids, id) {
			t.Errorf("embedded rule %s is not needed by any provider", id)
		}
	}
	if !reflect.DeepEqual(prefilter, betterleaksPrefilter) {
		t.Errorf("path prefilter differs from the live binary; run with -update")
	}
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

func withoutEnv(env []string, names ...string) []string {
	var out []string
outer:
	for _, e := range env {
		for _, n := range names {
			if strings.HasPrefix(e, n+"=") {
				continue outer
			}
		}
		out = append(out, e)
	}
	return out
}
