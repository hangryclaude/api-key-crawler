package engines

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"keyguard/internal/core"
)

// The tests below ask "what did the engine process get": its argv, its environment, its
// working directory. A real engine cannot say, so these stand in for the binary and nothing
// else; git, the parsing and the process handling around it stay real.

// call is one start of a recording engine.
type call struct {
	args []string
	env  map[string]string
	cwd  string
}

// recordedEnv are the variables a recording engine writes down.
var recordedEnv = []string{
	"GOMAXPROCS", "TMPDIR", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_CONFIG_NOSYSTEM", "GIT_NO_REPLACE_OBJECTS",
	"GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_ATTR_SOURCE", "GITHUB_TOKEN", "GH_TOKEN", "TITUS_CACHE_DIR",
	"BETTERLEAKS_CONFIG", "BETTERLEAKS_CONFIG_TOML", "GITLEAKS_CONFIG", "GITLEAKS_CONFIG_TOML",
}

// recordingEngine builds an engine binary into the test's own temp dir that appends every start
// to a log and then prints stdout, prints stderr and exits with code. It returns the engine
// and a func that reads the calls so far.
func recordingEngine(t *testing.T, name string, kr core.Fingerprinter, stdout, stderr string, exit int, opts ...Option) (core.Engine, func() []call) {
	t.Helper()
	dir := t.TempDir()
	logf := filepath.Join(dir, "calls.log")
	outf, errf := filepath.Join(dir, "stdout"), filepath.Join(dir, "stderr")
	for p, s := range map[string]string{outf: stdout, errf: stderr} {
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var sb strings.Builder
	sb.WriteString("#!/bin/sh\n{\necho INVOKE\nfor a in \"$@\"; do printf 'ARG %s\\n' \"$a\"; done\n")
	for _, k := range recordedEnv {
		fmt.Fprintf(&sb, "if [ -n \"${%s+x}\" ]; then printf 'ENV %s=%%s\\n' \"$%s\"; fi\n", k, k, k)
	}
	sb.WriteString("printf 'CWD %s\\n' \"$(pwd -P)\"\n")
	fmt.Fprintf(&sb, "} >> '%s'\ncat '%s'\ncat '%s' >&2\nexit %d\n", logf, outf, errf, exit)
	bin := filepath.Join(dir, name)
	if err := os.WriteFile(bin, []byte(sb.String()), 0o755); err != nil {
		t.Fatal(err)
	}
	e, err := New(name, bin, kr, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return e, func() []call { return readCalls(t, logf) }
}

func readCalls(t *testing.T, logf string) []call {
	t.Helper()
	f, err := os.Open(logf)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var calls []call
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "INVOKE":
			calls = append(calls, call{env: map[string]string{}})
		case len(calls) == 0:
		case strings.HasPrefix(line, "ARG "):
			c := &calls[len(calls)-1]
			c.args = append(c.args, line[4:])
		case strings.HasPrefix(line, "ENV "):
			k, v, _ := strings.Cut(line[4:], "=")
			calls[len(calls)-1].env[k] = v
		case strings.HasPrefix(line, "CWD "):
			calls[len(calls)-1].cwd = line[4:]
		}
	}
	return calls
}

// hasArgs reports whether want appears in args as consecutive elements.
func hasArgs(args []string, want ...string) bool {
	for i := range args {
		if i+len(want) <= len(args) && strings.Join(args[i:i+len(want)], "\x00") == strings.Join(want, "\x00") {
			return true
		}
	}
	return false
}

// argWithPrefix returns the first argument that starts with p.
func argWithPrefix(args []string, p string) (string, bool) {
	for _, a := range args {
		if strings.HasPrefix(a, p) {
			return a, true
		}
	}
	return "", false
}

// shimEngine wraps a real engine binary in a script in the test's temp dir. pre and post are
// shell lines run before and after it, with the engine's exit status preserved. The real
// binary is only ever executed, never written to.
func shimEngine(t *testing.T, name, real, pre, post string, kr core.Fingerprinter, opts ...Option) core.Engine {
	t.Helper()
	bin := filepath.Join(t.TempDir(), name)
	script := fmt.Sprintf("#!/bin/sh\n%s\n'%s' \"$@\"\nrc=$?\n%s\nexit $rc\n", pre, real, post)
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	e, err := New(name, bin, kr, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// listener counts the connections made to a loopback port. An engine that dials it did so
// because a host name in the scanned text told it to.
type listener struct {
	addr string
	n    atomic.Int64
	ln   net.Listener
}

func newListener(t *testing.T) *listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := &listener{addr: ln.Addr().String(), ln: ln}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			l.n.Add(1)
			c.Close()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return l
}

// uriOf joins a credential URI from its parts, so no source line of this repo is one.
func uriOf(scheme, user, pw, rest string) string {
	return scheme + "://" + user + ":" + pw + "@" + rest
}

func (l *listener) port() string { return l.addr[strings.LastIndex(l.addr, ":")+1:] }

func (l *listener) count() int { return int(l.n.Load()) }
