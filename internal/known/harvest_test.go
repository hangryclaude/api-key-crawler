package known

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"keyguard/internal/core"
)

// lock makes a directory unreadable for the test and puts it right before TempDir's own
// cleanup runs.
func lock(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o755) })
}

// The walk must not so much as open the directories it is told to skip: that is the
// difference between 3 seconds and 3 minutes over a tree of node_modules.
func TestWalkSkipsDependencyTreesWithoutEnteringThem(t *testing.T) {
	f := newFixture(t)
	keep := f.secret("sk-proj-", 40, "KEEP_API_KEY")
	f.write("dev/app/.env", "KEEP_API_KEY="+keep+"\n")
	for _, d := range []string{"dev/app/node_modules", "dev/app/.git", "dev/app/.venv", "dev/app/sub/node_modules", "dev/app/.next", "sec/tools", "sec/targets", "sec/practice", "sec/ctf"} {
		lock(t, filepath.Join(f.home, d))
	}
	f.write("sec/proj/.env", "PROJ_API_KEY="+f.secret("sk-proj-", 40, "PROJ_API_KEY")+"\n")
	rep, _ := f.learn(Options{})
	if len(rep.Skipped) != 0 {
		t.Errorf("the walk entered a directory it should have skipped: %v", rep.Skipped)
	}
	f.check()
	// A directory that is not on the skip list and cannot be read is reported, by path.
	lock(t, filepath.Join(f.home, "dev/other"))
	rep, _ = f.learn(Options{})
	if len(rep.Skipped) != 1 || !containsSub(rep.Skipped, "dev/other: unreadable") {
		t.Errorf("skipped: %v", rep.Skipped)
	}
}

func TestSymlinksAndSpecialFiles(t *testing.T) {
	f := newFixture(t)
	real := f.secret("sk-proj-", 40, "SHARED_API_KEY")
	shared := f.write("shared/secrets.txt", "SHARED_API_KEY="+real+"\n")
	if err := os.MkdirAll(filepath.Join(f.home, "dev/a"), 0o755); err != nil {
		t.Fatal(err)
	}
	// A symlinked .env is read through; a dangling one and a symlinked directory are not an error.
	os.Symlink(shared, filepath.Join(f.home, "dev/a/.env"))
	os.Symlink(filepath.Join(f.home, "nonexistent"), filepath.Join(f.home, "dev/a/.env.dangling"))
	hidden := f.reject("sk-proj-", 40, "behind a symlinked directory")
	f.write("elsewhere/.env", "HIDDEN_API_KEY="+hidden+"\n")
	os.Symlink(filepath.Join(f.home, "elsewhere"), filepath.Join(f.home, "dev/linkeddir"))
	// A named pipe called .env would block a reader forever.
	if err := syscall.Mkfifo(filepath.Join(f.home, "dev/a/.env.fifo"), 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan *Report, 1)
	go func() { rep, _ := f.learn(Options{}); done <- rep }()
	select {
	case rep := <-done:
		if len(rep.Skipped) != 0 {
			t.Errorf("skipped: %v", rep.Skipped)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("Learn hung, probably opening a named pipe")
	}
	f.check()
}

func TestPruneRefusedWhenASourceCannotBeRead(t *testing.T) {
	f := newFixture(t)
	a := f.secret("sk-proj-", 40, "A_API_KEY")
	pa := f.write("dev/a/.env", "A_API_KEY="+a+"\n")
	f.learn(Options{})
	// The source is still there but unreadable now: that proves nothing about the secret.
	if err := os.Chmod(pa, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(pa, 0o600) })
	rep, _ := f.learn(Options{Prune: true})
	if rep.Pruned != 0 || rep.Retained != 1 || !containsSub(rep.Notes, "prune skipped") {
		t.Fatalf("pruned %d retained %d notes %v", rep.Pruned, rep.Retained, rep.Notes)
	}
	f.check()
}

// A JWT with the given role in its payload, assembled at runtime.
func jwtWithRole(r *rand.Rand, role string) string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"HS256","typ":"JWT"}`)) + "." + enc([]byte(`{"iss":"supabase","role":"`+role+`"}`)) + "." + randFrom(r, urlchars, 43)
}

func TestPublicByDesignValuesAreNotLearned(t *testing.T) {
	f := newFixture(t)
	secret := f.secret("sk-proj-", 40, "NEXT_PUBLIC_OPENAI_API_KEY") // a real secret under a public-looking name stays learned
	service := jwtWithRole(f.r, "service_role")
	f.values = append(f.values, service)
	f.want[service] = "SUPABASE_SERVICE_ROLE_KEY"
	public := map[string]string{
		"STRIPE_PUBLISHABLE_KEY":   "pk_live_" + randFrom(f.r, alnum, 40),
		"CLERK_PUBLISHABLE_KEY":    "pk_test_" + randFrom(f.r, alnum, 40),
		"NEXT_PUBLIC_POSTHOG_KEY":  "phc_" + randFrom(f.r, alnum, 43),
		"MAPBOX_TOKEN":             "pk.eyJ" + randFrom(f.r, urlchars, 60),
		"SUPABASE_ANON_KEY":        jwtWithRole(f.r, "anon"),
		"SUPABASE_PUBLISHABLE_KEY": "sb_publishable_" + randFrom(f.r, alnum, 30),
	}
	var env strings.Builder
	env.WriteString("NEXT_PUBLIC_OPENAI_API_KEY=" + secret + "\nSUPABASE_SERVICE_ROLE_KEY=" + service + "\n")
	for name, v := range public {
		f.values = append(f.values, v)
		f.not[v] = "public by design"
		env.WriteString(name + "=" + v + "\n")
	}
	f.write("dev/web/.env.local", env.String())
	rep, _ := f.learn(Options{})
	f.check()
	if rep.Rejected[rejPublic] != len(public) {
		t.Errorf("%d values rejected as public, want %d", rep.Rejected[rejPublic], len(public))
	}
	// The override learns them.
	f2 := newFixture(t)
	f2.home = f.home
	f2.learn(Options{KeepPublic: true})
	st, kr := f2.store()
	have := map[string]bool{}
	for _, e := range st.Entries {
		have[e.FP] = true
	}
	for name, v := range public {
		if !have[kr.FP(v)] {
			t.Errorf("%s was not learned with KeepPublic", name)
		}
	}
}

func TestLearnToolCredentialFilesAndEnvironment(t *testing.T) {
	f := newFixture(t)
	w := func(rel, content, wantName string, n int, prefix string) {
		t.Helper()
		v := f.secret(prefix, n, wantName)
		f.write(rel, strings.ReplaceAll(content, "@@", v))
	}
	w(".config/git/credentials", "https://someone:@@@github.com\n", "credentials (url password)", 36, "")
	w(".pgpass", "# comment\nlocalhost:5432:*:app:@@\n", "pgpass app@localhost", 30, "")
	esc := f.secret("", 12, "pgpass u@h")
	pg := mustRead(t, filepath.Join(f.home, ".pgpass"))
	f.write(".pgpass", pg+`h:5432:db:u:`+esc[:6]+`\:`+esc[6:]+"\n")
	delete(f.want, esc)
	f.want[esc[:6]+":"+esc[6:]] = "pgpass u@h"
	w(".my.cnf", "[client]\nuser=root\npassword=@@\n", "password", 24, "")
	w(".vault-token", "@@", "vault-token", 28, "hvs.")
	w(".gem/credentials", "---\n:rubygems_api_key: @@\n", "rubygems_api_key", 40, "rubygems_")
	w(".cargo/credentials.toml", "[registry]\ntoken = \"@@\"\n", "token", 40, "cio")
	w(".terraform.d/credentials.tfrc.json", `{"credentials":{"app.terraform.io":{"token":"@@"}}}`, "token", 50, "")
	w(".yarnrc.yml", "npmRegistryServer: \"https://registry.example.org\"\nnpmAuthToken: @@\n", "npmAuthToken", 36, "")
	w(".s3cfg", "[default]\naccess_key = abc\nsecret_key = @@\n", "secret_key", 40, "")
	w(".config/rclone/rclone.conf", "[r]\ntype = s3\nsecret_access_key = @@\n", "secret_access_key", 40, "")
	w(".claude/settings.json", `{"env":{"ANTHROPIC_API_KEY":"@@"},"model":"x"}`, "ANTHROPIC_API_KEY", 50, "sk-ant-")
	w(".codex/config.toml", "[mcp_servers.fal.env]\nFAL_KEY = \"@@\"\n", "FAL_KEY", 40, "")
	// ~/.claude.json is megabytes of history around a small config block.
	v := f.secret("", 40, "SERVICE_API_KEY")
	history := strings.Repeat(`{"display":"hello there, a line of chat history","pastedContents":{}},`, 20000)
	f.write(".claude.json", `{"history":[`+history+`{}],"mcpServers":{"svc":{"env":{"SERVICE_API_KEY":"`+v+`"}}}}`)
	if st, _ := os.Stat(filepath.Join(f.home, ".claude.json")); st.Size() < 1<<20 {
		t.Fatalf("the test file is only %d bytes", st.Size())
	}
	// The process environment is learned only when the caller hands it over.
	envKey := f.reject("", 40, "in the environment, which this run was not given")
	f.learn(Options{})
	f.check()
	delete(f.not, envKey)
	f.want[envKey] = "MY_SERVICE_TOKEN"
	rep, _ := f.learn(Options{Env: []string{"MY_SERVICE_TOKEN=" + envKey, "PATH=/usr/bin:/bin", "EMPTY=", "no-equals-sign"}})
	f.check()
	found := false
	for _, s := range rep.Learned {
		if s.Source == "environment" && s.Name == "MY_SERVICE_TOKEN" {
			found = true
		}
	}
	if !found {
		t.Error("the environment variable was not learned")
	}
}

// Two runs at once (the weekly deep job and a manual learn) must not lose each other's
// additions: each reads the store, merges, writes.
func TestConcurrentLearnsLoseNothing(t *testing.T) {
	root := testEnv(t)
	r := newRNG(t)
	const runs = 12
	vals := make([]string, runs)
	homes := make([]string, runs)
	for i := range vals {
		vals[i] = "sk-proj-" + randFrom(r, alnum, 40)
		homes[i] = t.TempDir()
		p := filepath.Join(homes[i], "dev", "x", ".env")
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte(fmt.Sprintf("SERVICE_%d_API_KEY=%s\n", i, vals[i])), 0o600)
	}
	start := make(chan struct{})
	errs := make(chan error, runs)
	for i := 0; i < runs; i++ {
		go func(i int) {
			<-start
			_, err := Learn(Options{Home: homes[i], Root: root, GHUsers: []string{}})
			errs <- err
		}(i)
	}
	close(start)
	for i := 0; i < runs; i++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	st, kr := (&fixture{t: t, root: root}).store()
	have := map[string]bool{}
	for _, e := range st.Entries {
		have[e.FP] = true
	}
	for i, v := range vals {
		if !have[kr.FP(v)] {
			t.Errorf("concurrent run %d: its secret is not in the store", i)
		}
	}
}

func TestBasicAuthHeaderValue(t *testing.T) {
	f := newFixture(t)
	pw := f.secret("", 28, "AUTH_HEADER (basic auth password)")
	f.write("dev/a/.env", "AUTH_HEADER=Basic "+b64("svc:"+pw)+"\n")
	f.learn(Options{})
	f.check()
}

func TestCancelledLearnWritesNothing(t *testing.T) {
	f := newFixture(t)
	f.write("dev/a/.env", "A_API_KEY="+f.secret("sk-proj-", 40, "")+"\n")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Learn(Options{Ctx: ctx, Home: f.home, Root: f.root, GHUsers: []string{}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(core.PathsAt(f.root).Known, storeFile)); statErr == nil {
		t.Error("a cancelled run wrote a store")
	}
}
