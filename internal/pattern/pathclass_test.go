package pattern

import (
	"slices"
	"testing"
)

func TestClassOf(t *testing.T) {
	for _, c := range []struct {
		path string
		want []string
	}{
		{"app/.env", []string{"env"}},
		{"app/.env.production", []string{"env"}},
		{"deploy/prod.env", []string{"env"}},
		{".claude.json", []string{"mcp"}},
		{".cursor/mcp.json", []string{"mcp"}},
		{"net/capture.har", []string{"har"}},
		{"export/cookies.txt", []string{"cookies"}},
		{"api/My.postman_collection.json", []string{"postman"}},
		{"infra/terraform.tfstate", []string{"tfstate"}},
		{"site/wp-config.php", []string{"wp-config"}},
		{"lab/run.ipynb", []string{"notebook"}},
		{"web/package-lock.json", []string{"lockfile"}},
		{"web/dist/app.min.js", []string{"minified"}},
		{"pkg/auth_test.go", []string{"test"}},
		{"pkg/testdata/x.txt", []string{"test"}},
		{"web/node_modules/dep/index.js", []string{"vendor"}},
		{"web/node_modules/dep/test/a.js", []string{"test", "vendor"}},
		{"src/main.go", nil},
		{"README.md", nil},
	} {
		got := ClassOf(c.path).Names()
		if !slices.Equal(got, c.want) {
			t.Errorf("ClassOf(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

// The gate is decided once per path, from the policy: what no rule looks at, and what the generic rules do not.
func TestFileGate(t *testing.T) {
	s := Default()
	s.ensure()
	up := New(s.table, s.globalSpec, Options{Paths: PathsUpstream})
	up.ensure()
	generic, other := ruleByID(t, "generic-api-key"), ruleByID(t, "github-pat")
	for _, c := range []struct {
		path                        string
		nativeAll, nativeGen, upAll bool
	}{
		{"src/main.go", false, false, false},
		{"web/node_modules/dep/index.js", false, true, true},
		{"yarn.lock", false, true, true},
		{"img/logo.png", true, true, true},
		{"x/.git/config", true, true, true},
	} {
		n, u := s.gate.of(c.path), up.gate.of(c.path)
		if n.all != c.nativeAll || n.skips(generic) != c.nativeGen || n.skips(other) != c.nativeAll {
			t.Errorf("native policy, %q: all %v, generic skipped %v", c.path, n.all, n.skips(generic))
		}
		if u.all != c.upAll || u.skips(other) != c.upAll {
			t.Errorf("upstream policy, %q: all %v", c.path, u.all)
		}
	}
}
