package main

import (
	"os"
	"path/filepath"
	"strings"
	"sync"

	"keyguard/internal/core"
	"keyguard/internal/inventory"
	"keyguard/internal/known"
)

func knownLoad() (*known.Matcher, error) { return known.LoadMatcher(core.KnownRoots()) }

// visibilityFrom answers hooks.Deps.Visibility from the saved inventory: who can read the
// remote a push is going to. A path or file:// URL is Local (nothing leaves this Mac); a
// GitHub URL is looked up; anything else, or a GitHub repo keyguard has not listed yet (a
// repo made a minute ago), is Unknown, which the push gate treats as public.
//
// The snapshot is read on the first remote that needs it, so a push to a local path never
// pays for it.
func visibilityFrom(snapshot string) func(remote, url string) core.Visibility {
	var (
		once sync.Once
		byID map[string]core.Visibility
	)
	return func(remote, url string) core.Visibility {
		id, local := remoteID(url)
		if local {
			return core.Local
		}
		if id == "" {
			return core.Unknown
		}
		once.Do(func() {
			byID = map[string]core.Visibility{}
			srcs, _ := inventory.LoadSnapshot(snapshot)
			for _, s := range srcs {
				byID[strings.ToLower(s.ID)] = s.Visibility
			}
		})
		if v, ok := byID[id]; ok && v != "" {
			return v
		}
		// A gist's URL has no owner in it; its source id does.
		if strings.HasPrefix(id, "gist.github.com/") {
			gist := id[strings.LastIndex(id, "/"):]
			for sid, v := range byID {
				if strings.HasPrefix(sid, "gist.github.com/") && strings.HasSuffix(sid, gist) {
					return v
				}
			}
		}
		return core.Unknown
	}
}

// remoteID turns a git remote URL into a lower-case source id ("github.com/owner/name",
// "github.com/owner/name.wiki", "gist.github.com/<owner>/<id>"). local is true for a
// filesystem remote. An empty id with local false is a host keyguard does not watch.
func remoteID(url string) (id string, local bool) {
	url = strings.TrimSpace(url)
	switch {
	case url == "":
		return "", false
	case strings.HasPrefix(url, "file://"), filepath.IsAbs(url), strings.HasPrefix(url, "./"), strings.HasPrefix(url, "../"), url == ".", url == "..":
		return "", true
	}
	var host, path string
	if i := strings.Index(url, "://"); i >= 0 {
		rest := url[i+3:]
		if at := strings.IndexByte(rest, '@'); at >= 0 && at < strings.IndexByte(rest+"/", '/') {
			rest = rest[at+1:] // user:token@host
		}
		host, path, _ = strings.Cut(rest, "/")
		if c := strings.IndexByte(host, ':'); c >= 0 {
			host = host[:c] // the port
		}
	} else if c := strings.IndexByte(url, ':'); c > 0 && !strings.Contains(url[:c], "/") {
		host, path = url[:c], url[c+1:] // scp-like: git@github.com:owner/name.git
		if at := strings.IndexByte(host, '@'); at >= 0 {
			host = host[at+1:]
		}
	} else if fi, err := os.Stat(url); err == nil && fi.IsDir() {
		return "", true // a relative directory
	} else {
		return "", false
	}
	host = strings.ToLower(strings.TrimPrefix(strings.ToLower(host), "www."))
	path = strings.TrimSuffix(strings.Trim(strings.ToLower(path), "/"), ".git")
	path = strings.TrimSuffix(path, "/")
	switch host {
	case "github.com", "gist.github.com":
		if path == "" {
			return "", false
		}
		return host + "/" + path, false
	}
	return "", false
}
