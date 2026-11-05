package guard

import (
	"bytes"
	"context"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"keyguard/internal/core"
	"keyguard/internal/known"
)

const (
	helperEnv   = "KG_GUARD_HELPER"
	guardBudget = 20 * time.Millisecond // p50 on a 100 KB Write (STEAL P0-14 brief)
	perfRuns    = 21
)

// When the test binary is started with KG_GUARD_HELPER=1 it is `keyguard guard claude`: the
// event on stdin, the decision on stdout, the default loader reading the stores of the data
// roots. That is what Claude Code starts for every tool call, so it is what is timed.
func init() {
	if os.Getenv(helperEnv) == "1" {
		os.Exit(Hook(context.Background(), os.Stdin, os.Stdout, os.Stderr, Options{}))
	}
}

func p50(ds []time.Duration) time.Duration {
	s := append([]time.Duration(nil), ds...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	return s[int(math.Ceil(0.5*float64(len(s))))-1]
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

func loadAverage() (float64, bool) {
	out, err := exec.Command("sysctl", "-n", "vm.loadavg").Output()
	if err != nil {
		return 0, false
	}
	f := strings.Fields(strings.Trim(string(out), "{} \n"))
	if len(f) == 0 {
		return 0, false
	}
	v, err := strconv.ParseFloat(f[0], 64)
	return v, err == nil
}

// A 100 KB Write is searched for the learned keys of a store of realistic size inside the
// budget, in process and as the process Claude Code starts.
func TestGuardDecisionBudget(t *testing.T) {
	r := rng()
	home := t.TempDir()
	root := filepath.Join(t.TempDir(), "kg")
	var env strings.Builder
	var keys []string
	for i := range 300 {
		keys = append(keys, key(r, "sk-"))
		fmt.Fprintf(&env, "SERVICE_%03d_API_KEY=%s\n", i, keys[i])
	}
	if err := os.WriteFile(filepath.Join(home, ".env"), []byte(env.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := known.Learn(known.Options{Home: home, Root: root, GHUsers: []string{}}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KEYGUARD_HOME", root)

	// 100 KB of code-shaped text with no key in it, and the same with one at the end.
	var body strings.Builder
	for body.Len() < 100<<10 {
		fmt.Fprintf(&body, "func handler%d(w http.ResponseWriter, r *http.Request) { log.Printf(\"%%s\", r.URL.Path) }\n", body.Len())
	}
	clean := body.String()
	m, err := known.LoadMatcher([]string{root})
	if err != nil || m.Len() == 0 {
		t.Fatalf("store: %d forms, %v", m.Len(), err)
	}
	st, err := known.ReadStore(root)
	if err != nil || st == nil || len(st.Secrets()) != 300 {
		t.Fatalf("store holds %v secrets, %v", len(st.Secrets()), err)
	}

	payload := func(content string) []byte {
		var b bytes.Buffer
		b.ReadFrom(event(t, "Write", map[string]any{"file_path": "/p/big.go", "content": content}))
		return b.Bytes()
	}
	cleanEvent := payload(clean)

	// In process, with the matcher already loaded: the decision itself.
	inProc := func() time.Duration {
		start := time.Now()
		var out, errw bytes.Buffer
		code := Hook(context.Background(), bytes.NewReader(cleanEvent), &out, &errw, Options{Known: func() (core.KnownMatcher, error) { return m, nil }})
		if code != ExitAllow {
			t.Fatalf("a clean 100 KB write was refused: %d %s", code, out.String())
		}
		return time.Since(start)
	}
	for range 3 {
		inProc()
	}
	var inDur []time.Duration
	for range perfRuns {
		inDur = append(inDur, inProc())
	}

	// As a process: the test binary re-executed as the guard, loading the store from disk.
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	asProcess := func(ev []byte) (time.Duration, outcome) {
		cmd := exec.Command(self)
		cmd.Env = append(os.Environ(), helperEnv+"=1", "KEYGUARD_HOME="+root)
		cmd.Stdin = bytes.NewReader(ev)
		var out, errw bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errw
		start := time.Now()
		err := cmd.Run()
		d := time.Since(start)
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatal(err)
		}
		return d, outcome{code, out.String(), errw.String()}
	}
	for range 3 {
		asProcess(cleanEvent)
	}
	var procDur []time.Duration
	for range perfRuns {
		d, o := asProcess(cleanEvent)
		if o.code != ExitAllow || o.out != "" {
			t.Fatalf("the helper process refused a clean write: %+v", o)
		}
		procDur = append(procDur, d)
	}
	// The same event with one of the keys at the end is refused, by the process too.
	var denyDur []time.Duration
	leaky := payload(clean + "\n// token " + keys[299] + "\n")
	for range perfRuns {
		d, o := asProcess(leaky)
		if o.code != ExitBlock || !strings.Contains(o.out, `"permissionDecision":"deny"`) {
			t.Fatalf("the helper process let a learned key through: %+v", o)
		}
		denyDur = append(denyDur, d)
	}

	load, ok := loadAverage()
	t.Logf("guard decision on a 100 KB Write, %d learned secrets (%d forms): in process p50 %.2f ms; as a process (store loaded from disk) p50 %.2f ms, refusing a key p50 %.2f ms; load average %.1f on %d cores",
		len(st.Secrets()), m.Len(), ms(p50(inDur)), ms(p50(procDur)), ms(p50(denyDur)), load, runtime.NumCPU())
	if ok && load > float64(runtime.NumCPU()) {
		t.Logf("load average %.1f on %d cores: timings are not enforced against the %v budget", load, runtime.NumCPU(), guardBudget)
		return
	}
	if p50(inDur) > guardBudget || p50(procDur) > guardBudget {
		t.Errorf("guard decision p50 in process %v, as a process %v; budget %v", p50(inDur), p50(procDur), guardBudget)
	}
}
