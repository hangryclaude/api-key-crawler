package db

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func lockPath(t *testing.T) string { return filepath.Join(t.TempDir(), "state", "lock") }

func writeLock(t *testing.T, path string, pid int, token string, age time.Duration) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf("pid=%d\ntoken=%s\nstarted=%s\n", pid, token, time.Now().Add(-age).UTC().Format(time.RFC3339))
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-age)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
}

func TestLockIsExclusiveAndNamesTheHolder(t *testing.T) {
	path := lockPath(t)
	a, err := AcquireLock(path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = AcquireLock(path)
	if !errors.Is(err, ErrLocked) {
		t.Fatalf("second acquire: %v", err)
	}
	var le *LockedError
	if !errors.As(err, &le) || le.PID != os.Getpid() || le.Path != path {
		t.Fatalf("LockedError = %+v", le)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("lock mode %v", fi.Mode().Perm())
	}
	if !a.Held() {
		t.Fatal("Held() false on a held lock")
	}
	if err := a.Release(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("Release left the file: %v", err)
	}
	b, err := AcquireLock(path)
	if err != nil {
		t.Fatalf("acquire after release: %v", err)
	}
	b.Release()
	if err := b.Release(); err != nil {
		t.Fatalf("Release twice: %v", err)
	}
}

func TestLockStaleByAgeIsTakenOverEvenWithLivePid(t *testing.T) {
	path := lockPath(t)
	writeLock(t, path, os.Getpid(), "old", StaleAfter+time.Minute)
	l, err := AcquireLock(path)
	if err != nil {
		t.Fatalf("a lock untouched for over two hours must be taken over: %v", err)
	}
	l.Release()
}

func TestLockFreshWithLivePidIsHeld(t *testing.T) {
	path := lockPath(t)
	writeLock(t, path, os.Getpid(), "other", time.Minute)
	if _, err := AcquireLock(path); !errors.Is(err, ErrLocked) {
		t.Fatalf("fresh lock of a live pid: %v", err)
	}
}

func TestLockStaleByDeadPid(t *testing.T) {
	cmd := exec.Command("true")
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	dead := cmd.Process.Pid
	path := lockPath(t)
	writeLock(t, path, dead, "crashed", time.Second)
	l, err := AcquireLock(path)
	if err != nil {
		t.Fatalf("a crashed run's lock should not block for two hours: %v", err)
	}
	l.Release()
}

func TestLockEmptyFile(t *testing.T) {
	path := lockPath(t)
	writeLock(t, path, 0, "", time.Second)
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := AcquireLock(path); !errors.Is(err, ErrLocked) {
		t.Fatalf("a just-created empty lock is a writer mid-flight: %v", err)
	}
	old := time.Now().Add(-5 * time.Minute)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	l, err := AcquireLock(path)
	if err != nil {
		t.Fatalf("an empty lock older than a minute belongs to a dead writer: %v", err)
	}
	l.Release()
}

// Many takers all see the same stale lock; exactly one may end up holding the new one.
func TestLockStaleRaceHasOneWinner(t *testing.T) {
	path := lockPath(t)
	writeLock(t, path, os.Getpid(), "ancient", StaleAfter+time.Hour)
	const n = 24
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		winners []*Lock
		losers  int
		start   = make(chan struct{})
	)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			l, err := AcquireLock(path)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				winners = append(winners, l)
			case errors.Is(err, ErrLocked):
				losers++
			default:
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()
	if len(winners) != 1 || losers != n-1 {
		t.Fatalf("%d winners and %d losers among %d takers", len(winners), losers, n)
	}
	winners[0].Release()
}

func TestLockCleanupDoesNotRemoveATakeover(t *testing.T) {
	path := lockPath(t)
	a, err := AcquireLock(path)
	if err != nil {
		t.Fatal(err)
	}
	writeLock(t, path, os.Getpid(), "the-new-holder", 0) // another run took it over
	if a.Held() {
		t.Fatal("Held() true after a takeover")
	}
	if err := a.Release(); err != nil {
		t.Fatal(err)
	}
	info, err := readLock(path)
	if err != nil || info.token != "the-new-holder" {
		t.Fatalf("the old holder's cleanup removed the new holder's lock: %v %+v", err, info)
	}
}

func TestLockHeartbeatKeepsALongRunFresh(t *testing.T) {
	old := heartbeat
	heartbeat = 20 * time.Millisecond
	defer func() { heartbeat = old }()
	path := lockPath(t)
	l, err := AcquireLock(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Release()
	past := time.Now().Add(-3 * time.Hour)
	if err := os.Chtimes(path, past, past); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		fi, _ := os.Stat(path)
		if time.Since(fi.ModTime()) < time.Minute {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the heartbeat never refreshed the lock")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := AcquireLock(path); !errors.Is(err, ErrLocked) {
		t.Fatalf("a heartbeating lock was taken over: %v", err)
	}
}

func TestLockLostIsSignalled(t *testing.T) {
	old := heartbeat
	heartbeat = 20 * time.Millisecond
	defer func() { heartbeat = old }()
	path := lockPath(t)
	l, err := AcquireLock(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Release()
	writeLock(t, path, os.Getpid(), "thief", 0)
	select {
	case <-l.Lost():
	case <-time.After(5 * time.Second):
		t.Fatal("a takeover was never noticed")
	}
}

func TestLockedErrorSaysWhoHoldsIt(t *testing.T) {
	e := &LockedError{Path: "/x/lock", PID: 42, Started: "2026-11-03T10:00:00Z"}
	if got := e.Error(); got != "db: pid 42 (started 2026-11-03T10:00:00Z) holds /x/lock" {
		t.Fatalf("%q", got)
	}
	if got := (&LockedError{Path: "/x/lock"}).Error(); got != "db: another run holds /x/lock" {
		t.Fatalf("%q", got)
	}
}
