package db

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// StaleAfter is how long a lock file may go untouched before another run may take it. A
// live holder refreshes the file every heartbeat, so only a run that hung or was killed
// ever gets this old.
const StaleAfter = 2 * time.Hour

// ErrLocked is what AcquireLock wraps when another run holds the lock.
var ErrLocked = errors.New("another keyguard run holds the lock")

// LockedError says who holds the lock, so the message can tell the user whether to wait.
type LockedError struct {
	Path    string
	PID     int
	Started string
}

func (e *LockedError) Error() string {
	who := "another run"
	if e.PID > 0 {
		who = "pid " + strconv.Itoa(e.PID)
	}
	if e.Started != "" {
		who += " (started " + e.Started + ")"
	}
	return fmt.Sprintf("db: %s holds %s", who, e.Path)
}

func (e *LockedError) Unwrap() error { return ErrLocked }

// heartbeat is a variable so tests can run it in milliseconds. AcquireLock reads it once,
// so a test changing it never races with a lock that is already running.
var heartbeat = 30 * time.Second

// Lock is a held run lock: a file made with O_EXCL that names its owner. Hold it from the
// moment a run opens the findings until the last Save, so two runs never write the same
// files. A stale lock (dead pid, or untouched for StaleAfter) is taken over.
type Lock struct {
	path  string
	token string
	stop  chan struct{}
	lost  chan struct{}
	wg    sync.WaitGroup
	once  sync.Once
}

// AcquireLock takes the lock at path or says who has it.
func AcquireLock(path string) (*Lock, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	token := newToken()
	// Taking over a stale lock can lose a race to another taker; the loser then finds a
	// fresh lock and reports ErrLocked. While another taker is mid-break the loop backs off
	// for a moment instead of spinning, and the deadline only guards against a pathology.
	deadline := time.Now().Add(5 * time.Second)
	for wait := time.Millisecond; ; wait = min(2*wait, 20*time.Millisecond) {
		err := createLockFile(path, token)
		if err == nil {
			l := &Lock{path: path, token: token, stop: make(chan struct{}), lost: make(chan struct{})}
			l.wg.Add(1)
			go l.beat(heartbeat)
			return l, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return nil, err
		}
		info, err := readLock(path)
		if errors.Is(err, fs.ErrNotExist) {
			continue // released between our create and our read
		}
		if err != nil {
			return nil, err
		}
		if !info.stale(time.Now()) {
			return nil, &LockedError{Path: path, PID: info.pid, Started: info.started}
		}
		broke, err := breakStale(path, info)
		if err != nil {
			return nil, err
		}
		if !broke {
			if time.Now().After(deadline) {
				return nil, fmt.Errorf("db: could not take %s: a stale lock kept changing hands for 5s", path)
			}
			time.Sleep(wait)
		}
	}
}

func newToken() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func createLockFile(path, token string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(f, "pid=%d\ntoken=%s\nstarted=%s\n", os.Getpid(), token, time.Now().UTC().Format(time.RFC3339))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(path) // never leave a lock nobody can identify
	}
	return err
}

type lockInfo struct {
	pid     int
	token   string
	started string
	mtime   time.Time
}

func readLock(path string) (lockInfo, error) {
	var info lockInfo
	st, err := os.Stat(path)
	if err != nil {
		return info, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return info, err
	}
	info.mtime = st.ModTime()
	for _, ln := range strings.Split(string(b), "\n") {
		k, v, _ := strings.Cut(ln, "=")
		switch k {
		case "pid":
			info.pid, _ = strconv.Atoi(v)
		case "token":
			info.token = v
		case "started":
			info.started = v
		}
	}
	return info, nil
}

// stale reports whether the lock's owner is gone. Age comes first because it also covers a
// hung owner; a dead pid is the fast path after a crash, so the next poll does
// not wait two hours behind a run that no longer exists.
func (i lockInfo) stale(now time.Time) bool {
	age := now.Sub(i.mtime)
	switch {
	case age > StaleAfter:
		return true
	case i.pid <= 0:
		// Created but never filled in: its writer died in between. A fresh one is a writer
		// still working, so give it a minute.
		return age > time.Minute
	}
	return !pidAlive(i.pid)
}

func pidAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM) // EPERM: exists, owned by someone else
}

// breakStale removes the stale lock seen, unless somebody else got there first. Two takers
// that both judged the old lock stale must not both delete: the second would remove the
// first one's fresh lock. A guard file serializes them and the lock is read again under it.
func breakStale(path string, seen lockInfo) (broke bool, err error) {
	guard := path + ".break"
	g, err := os.OpenFile(guard, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if errors.Is(err, fs.ErrExist) {
		// Another taker is mid-break, which takes microseconds; a guard older than a minute
		// belongs to a taker that died, and removing it unblocks the next attempt.
		if st, serr := os.Stat(guard); serr == nil && time.Since(st.ModTime()) > time.Minute {
			os.Remove(guard)
		}
		return false, nil
	}
	if err != nil {
		return false, err
	}
	g.Close()
	defer os.Remove(guard)
	cur, err := readLock(path)
	if errors.Is(err, fs.ErrNotExist) {
		return true, nil // already gone: go and create
	}
	if err != nil {
		return false, err
	}
	if cur.token != seen.token || !cur.stale(time.Now()) {
		return false, nil // replaced or revived since we looked: not ours to remove
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return false, err
	}
	return true, nil
}

// beat keeps the lock's mtime fresh and notices when the lock has been taken over, which
// happens if the machine slept past StaleAfter with a run in flight.
func (l *Lock) beat(every time.Duration) {
	defer l.wg.Done()
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-l.stop:
			return
		case <-t.C:
			if !l.Held() {
				close(l.lost)
				return
			}
			now := time.Now()
			os.Chtimes(l.path, now, now)
		}
	}
}

// Held reports whether the lock file still names this lock. A writer calls it before it
// saves: if another run took the lock over, writing now would clobber that run's state.
func (l *Lock) Held() bool {
	info, err := readLock(l.path)
	return err == nil && info.token == l.token
}

// Lost is closed if the lock is found taken over while it is held.
func (l *Lock) Lost() <-chan struct{} { return l.lost }

// Release gives the lock up. It removes the file only if the file is still this lock's: a
// takeover by another run must survive the old holder's cleanup.
func (l *Lock) Release() error {
	l.once.Do(func() { close(l.stop) })
	l.wg.Wait()
	info, err := readLock(l.path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.token != l.token {
		return nil
	}
	if err := os.Remove(l.path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}
