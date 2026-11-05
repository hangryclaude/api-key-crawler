package pattern

import (
	"regexp"

	"keyguard/internal/pattern/rules"
)

// PathPolicy decides what a path can silence.
//
// The reference engine skips a list of paths for every rule: dependency trees, lock files, vendored
// and minified libraries, images and documents. That list is also where its blind spot is: a real key
// pasted into a file under node_modules is never looked at. keyguard keeps the list for the rules
// that need it and drops it for the rest.
type PathPolicy uint8

const (
	// PathsNative applies the upstream list to the generic rules only, the ones that fire on any
	// word that looks like an assignment and are noise in a dependency tree. A rule with a
	// distinctive shape (a vendor prefix, a fixed length) is never skipped by where it is.
	// Only the contents of .git and files that are binary by extension are skipped for all.
	PathsNative PathPolicy = iota
	// PathsUpstream applies the whole upstream list to every rule. It is for holding the scanner to
	// the reference in a differential test.
	PathsUpstream
)

// hardPath is the paths no rule looks at: git's own directory, and images, fonts, documents and
// compiled objects by extension. Their content is binary anyway; this saves opening them.
var hardPath = regexp.MustCompile(`(?i)(?:^|/)\.git(?:/|$)|\.(?:bmp|gif|jpe?g|png|tiff?|ico|webp|eot|[ot]tf|woff2?|docx?|xlsx?|pptx?|pdf|dll|pdb|exe|so|dylib|class)$`)

// pathGate is the compiled path lists of one scanner.
type pathGate struct {
	policy PathPolicy
	global *filter
}

// skipsDir says whether the walk should not enter a directory. Under the native policy only .git is
// refused outright; the rest of the upstream list is judged per rule, file by file.
func (g *pathGate) skipsDir(rel string) bool {
	if g.policy == PathsUpstream {
		return g.global.dropsPath(rel)
	}
	return hardPath.MatchString(rel)
}

// fileGate is what is decided about one path, once, before any rule looks at it.
type fileGate struct {
	all     bool // no rule looks at this path
	generic bool // the generic rules do not (the upstream list matched)
}

func (g *pathGate) of(rel string) fileGate {
	if hardPath.MatchString(rel) {
		return fileGate{all: true}
	}
	if rel == "" || !g.global.dropsPath(rel) {
		return fileGate{}
	}
	if g.policy == PathsUpstream {
		return fileGate{all: true}
	}
	return fileGate{generic: true}
}

// skips says whether rule r is not to look at a file with this gate.
func (f fileGate) skips(r *rules.Rule) bool {
	return f.all || (f.generic && isGeneric(r))
}

// isGeneric marks the rules that fire on an assignment-shaped line, whatever the service.
func isGeneric(r *rules.Rule) bool { return r.Provider == "generic" }

// PathClass names what a path says about its content. It tunes how much a generic finding is worth
// and never switches a distinctive rule off.
type PathClass uint16

const (
	ClassEnv      PathClass = 1 << iota // .env and friends
	ClassMCP                            // agent and tool configuration (mcp.json, settings.json)
	ClassHAR                            // recorded HTTP traffic
	ClassCookies                        // cookie jars
	ClassPostman                        // API client collections and environments
	ClassTFState                        // infrastructure state files
	ClassWPConfig                       // wp-config.php
	ClassNotebook                       // Jupyter notebooks
	ClassLockfile                       // dependency lock files
	ClassMinified                       // minified or bundled code
	ClassTest                           // tests, fixtures, examples
	ClassVendor                         // dependency and vendor trees
)

var classPatterns = []struct {
	class PathClass
	re    *regexp.Regexp
}{
	{ClassEnv, regexp.MustCompile(`(?i)(?:^|/)(?:\.env(?:\.[\w.-]+)?|[\w.-]+\.env|env\.[\w.-]+)$`)},
	{ClassMCP, regexp.MustCompile(`(?i)(?:^|/)(?:\.?mcp(?:[._-][\w.-]*)?\.json|claude_desktop_config\.json|\.claude\.json|settings(?:\.local)?\.json|\.cursor/mcp\.json)$`)},
	{ClassHAR, regexp.MustCompile(`(?i)\.har$`)},
	{ClassCookies, regexp.MustCompile(`(?i)(?:^|/)(?:cookies?(?:\.txt|\.json|\.sqlite)?|[\w.-]*cookies\.txt)$`)},
	{ClassPostman, regexp.MustCompile(`(?i)\.postman_(?:collection|environment|globals)(?:\.json)?$|(?:^|/)postman[\w.-]*\.json$`)},
	{ClassTFState, regexp.MustCompile(`(?i)(?:^|/)(?:terraform\.tfstate(?:\.backup)?|[\w.-]+\.tfstate|\.terraform/.*)$`)},
	{ClassWPConfig, regexp.MustCompile(`(?i)(?:^|/)wp-config(?:-sample)?\.php$`)},
	{ClassNotebook, regexp.MustCompile(`(?i)\.ipynb$`)},
	{ClassLockfile, regexp.MustCompile(`(?i)(?:^|/)(?:package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|deno\.lock|Cargo\.lock|go\.sum|Gemfile\.lock|poetry\.lock|Pipfile\.lock|composer\.lock|gradle\.lockfile|packages\.lock\.json)$`)},
	{ClassMinified, regexp.MustCompile(`(?i)(?:\.min\.(?:js|css|mjs)|[.-]bundle\.js|\.chunk\.js|\.map)$`)},
	{ClassTest, regexp.MustCompile(`(?i)(?:^|/)(?:tests?|__tests__|spec|fixtures?|testdata|examples?|samples?|mocks?)/|(?:_test\.\w+|\.test\.\w+|\.spec\.\w+|_spec\.\w+)$`)},
	{ClassVendor, regexp.MustCompile(`(?:^|/)(?:node_modules|vendor|bower_components|third_party|site-packages|\.venv|venv)/`)},
}

// ClassOf classifies a slash-separated path relative to the scan root.
func ClassOf(path string) PathClass {
	var c PathClass
	for _, p := range classPatterns {
		if p.re.MatchString(path) {
			c |= p.class
		}
	}
	return c
}

// Names lists the classes in the set, for notes and tests.
func (c PathClass) Names() []string {
	names := map[PathClass]string{
		ClassEnv: "env", ClassMCP: "mcp", ClassHAR: "har", ClassCookies: "cookies", ClassPostman: "postman",
		ClassTFState: "tfstate", ClassWPConfig: "wp-config", ClassNotebook: "notebook", ClassLockfile: "lockfile",
		ClassMinified: "minified", ClassTest: "test", ClassVendor: "vendor",
	}
	var out []string
	for bit := PathClass(1); bit != 0 && bit <= ClassVendor; bit <<= 1 {
		if c&bit != 0 {
			out = append(out, names[bit])
		}
	}
	return out
}
