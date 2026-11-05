package selftest

import (
	"bytes"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
)

// checkHooksQuiet is invariant 5 watched from outside. A hook fails open on its own errors
// and says so on stderr; across a whole run of ordinary git, an ordinary machine should never
// need to. A single warning means some check above passed because a hook gave up, not
// because it looked.
func checkHooksQuiet(s *suite) (string, error) {
	var bad []string
	for _, cp := range s.captured {
		if !cp.tolerate && strings.Contains(cp.text, "keyguard: warning:") {
			bad = append(bad, cp.cmd)
		}
	}
	if len(bad) > 0 {
		return "", fmt.Errorf("%d commands got a hook warning, which means a hook fell back to fail-open: %s", len(bad), strings.Join(firstN(bad, 4), "; "))
	}
	return fmt.Sprintf("%d commands run, none of them got a fail-open warning", len(s.captured)), nil
}

func firstN(in []string, n int) []string {
	if len(in) > n {
		return append(in[:n:n], fmt.Sprintf("and %d more", len(in)-n))
	}
	return in
}

// checkNoLeaks is invariant 1 on this run: no fake, in any of the spellings a store matches,
// is in anything keyguard printed or wrote. The repos are left out because they hold the
// fakes by construction, and so is the cache, which is a git object store of those repos.
func checkNoLeaks(s *suite) (string, error) {
	var forbidden [][]byte
	for _, v := range s.fakes {
		for _, f := range forms(v) {
			forbidden = append(forbidden, []byte(f))
		}
	}
	has := func(b []byte) bool {
		for _, f := range forbidden {
			if bytes.Contains(b, f) {
				return true
			}
		}
		return false
	}
	for i, cp := range s.captured {
		if has([]byte(cp.text)) {
			return "", fmt.Errorf("the output of `%s` (command %d of %d) holds a planted secret", cp.cmd, i+1, len(s.captured))
		}
	}

	files := 0
	roots := append([]string{s.home}, s.roots...)
	for _, root := range roots {
		cache := filepath.Join(root, "cache")
		if root == s.home {
			cache = filepath.Join(s.root, "cache")
		}
		var found error
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			switch {
			case err != nil:
				return nil // not there is not leaking
			case d.IsDir() && p == cache:
				return fs.SkipDir
			case d.IsDir():
				return nil
			}
			b, rerr := readSmall(p)
			if rerr != nil {
				return nil
			}
			files++
			if has(b) {
				found = fmt.Errorf("%s holds a planted secret", s.line(strings.TrimPrefix(p, s.dir+string(filepath.Separator))))
				return fs.SkipAll
			}
			return nil
		})
		if found != nil {
			return "", found
		}
		if err != nil {
			return "", err
		}
	}
	if b, err := readSmall(s.gitconfig); err == nil && has(b) {
		return "", fmt.Errorf("the global git config holds a planted secret")
	}
	return fmt.Sprintf("%d fakes in 5 spellings searched for in %d command outputs and %d files under the data roots: none found", len(s.fakes), len(s.captured), files), nil
}
