package sweep

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The blob ledger remembers which blobs a scanner has already read, so a rescan reads only
// what no current scanner version has seen (STEAL P1-08, P1-09). It holds object ids and
// nothing else: a blob's id is a hash of its content, never the content, and no context,
// path or value is ever written here (PLAN invariant 1).
//
// One file per scanner version, state/ledger/<scanner>.<key>.bin, where <key> is a hash of
// the scanner's name, its version and, for the engines that read the rules file, the rules
// themselves. A new engine version or new rules is a new file, and the files of the scanner's
// older versions are moved to superseded/ (nothing is deleted), so a bump invalidates exactly
// that scanner's entries and no other's.
//
// Entries are (source, blob), not just blobs. A key copied into a second repository is a
// second place the user must clean, and a ledger that forgot which repo a blob was read in
// would skip it there and leave that place out of the report. Cross-repo dedup would save 2%
// of the bytes (STEAL P1-09), which is not worth a location.
//
// Appending is the only write: header line once, then 28-byte records (8 bytes of the source
// id's hash, 20 bytes of the blob id). A torn last record is ignored on load, and a lost or
// damaged file costs a rescan, never a missed secret, because blobs enter the ledger only
// after the hits found in them are saved (see seenView.Commit and scanRepo).
const (
	ledgerMagic  = "kgledger 1"
	ledgerRecLen = 8 + 20
)

type (
	oid    [20]byte // a SHA-1 blob id; GitHub serves no other object format
	srcTag [8]byte  // the first 8 bytes of sha256(source id)
	record struct {
		src srcTag
		id  oid
	}
)

// parseOID reads a 40-digit lowercase hex object id without allocating. Anything else
// (a SHA-256 id, junk) is not ledgered and is simply read every time.
func parseOID(s string) (id oid, ok bool) {
	if len(s) != 40 {
		return id, false
	}
	for i := range id {
		hi, lo := unhex(s[2*i]), unhex(s[2*i+1])
		if hi < 0 || lo < 0 {
			return id, false
		}
		id[i] = byte(hi<<4 | lo)
	}
	return id, true
}

func unhex(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	}
	return -1
}

func tagOf(source string) srcTag {
	sum := sha256.Sum256([]byte(source))
	return srcTag(sum[:8])
}

// ledger is the set of ledger files under one directory, loaded on first use.
type ledger struct {
	dir  string
	note func(string)

	mu   sync.Mutex
	sets map[string]*oidSet
}

func newLedger(dir string, note func(string)) *ledger {
	return &ledger{dir: dir, note: note, sets: map[string]*oidSet{}}
}

// unitFile names the file of one scanner version.
func unitFile(unit, version string) (name, key string) {
	sum := sha256.Sum256([]byte(unit + "\x00" + version))
	key = hex.EncodeToString(sum[:8])
	return unit + "." + key + ".bin", key
}

// set returns the ledger of one scanner at one version. The first call loads its file and
// moves the same scanner's other versions aside.
func (l *ledger) set(unit, version string) *oidSet {
	name, key := unitFile(unit, version)
	l.mu.Lock()
	defer l.mu.Unlock()
	if s := l.sets[name]; s != nil {
		return s
	}
	s := &oidSet{l: l, path: filepath.Join(l.dir, name), header: fmt.Sprintf("%s %s %s\n", ledgerMagic, unit, key), m: map[record]struct{}{}, bySrc: map[srcTag]int{}}
	s.load()
	l.supersede(unit, name)
	l.sets[name] = s
	return s
}

// supersede moves every other version of unit out of the ledger directory. The files hold
// nothing but ids, but the move-only rule applies to state as much as to the user's files.
func (l *ledger) supersede(unit, keep string) {
	ents, err := os.ReadDir(l.dir)
	if err != nil {
		return
	}
	moved := 0
	for _, e := range ents {
		n := e.Name()
		if n == keep || e.IsDir() || !strings.HasPrefix(n, unit+".") || !strings.HasSuffix(n, ".bin") || strings.Count(n, ".") != 2 {
			continue
		}
		if err := l.moveAside(n, ""); err != nil {
			l.note(fmt.Sprintf("blob ledger: cannot move %s aside: %v", n, err))
			continue
		}
		moved++
	}
	if moved > 0 {
		l.note(fmt.Sprintf("blob ledger: %s changed version, so %d older ledger file(s) of it were moved to superseded/ and it reads every blob again", unit, moved))
	}
}

func (l *ledger) moveAside(name, why string) error {
	dest := filepath.Join(l.dir, "superseded")
	if err := os.MkdirAll(dest, 0o700); err != nil {
		return err
	}
	to := filepath.Join(dest, name+why)
	if _, err := os.Lstat(to); err == nil {
		to += "." + strconv.FormatInt(time.Now().UnixNano(), 10)
	}
	return os.Rename(filepath.Join(l.dir, name), to)
}

// storeSizeFile holds how many secrets the findings had when the ledger last agreed with them.
const storeSizeFile = ".secrets"

// checkStore doubts the ledger when the findings it was built beside have shrunk. The ledger
// says a blob was read and its hits saved; if findings.json has since been lost, restored from
// an older copy or edited down, the hits are no longer where the ledger thinks they are, and
// trusting it would leave them missing for good. Secrets are never removed from the store, so
// fewer than before means exactly that. Every ledger file is moved aside and every blob is read
// again, which also rebuilds the findings.
func (l *ledger) checkStore(n int) {
	b, err := os.ReadFile(filepath.Join(l.dir, storeSizeFile))
	if err != nil {
		return
	}
	was, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || n >= was {
		return
	}
	ents, err := os.ReadDir(l.dir)
	if err != nil {
		return
	}
	moved := 0
	for _, e := range ents {
		if n := e.Name(); !e.IsDir() && strings.HasSuffix(n, ".bin") {
			if err := l.moveAside(n, ".stale"); err != nil {
				l.note(fmt.Sprintf("blob ledger: cannot move %s aside: %v", n, err))
				continue
			}
			moved++
		}
	}
	l.note(fmt.Sprintf("blob ledger: the findings hold %d secret(s) where they once held %d, so the ledger was not trusted: %d file(s) were moved to superseded/ and every blob is read again", n, was, moved))
}

// recordStore remembers the findings' size once a run has saved them.
func (l *ledger) recordStore(n int) {
	if err := os.MkdirAll(l.dir, 0o700); err != nil {
		l.note("blob ledger: " + err.Error())
		return
	}
	if err := os.WriteFile(filepath.Join(l.dir, storeSizeFile), []byte(strconv.Itoa(n)+"\n"), 0o600); err != nil {
		l.note("blob ledger: " + err.Error())
	}
}

// close releases the open files. Appends are not buffered, so nothing is lost by not calling it.
func (l *ledger) close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, s := range l.sets {
		s.close()
	}
}

// oidSet is one ledger file in memory. A map costs about 60 bytes a blob, which for the 13
// public repos is nothing; it is the part to revisit if the sweep ever covers all 469.
type oidSet struct {
	l      *ledger
	path   string
	header string

	mu     sync.RWMutex
	m      map[record]struct{}
	bySrc  map[srcTag]int // how many blobs each source has in the set
	f      *os.File
	broken bool // a write failed: the set still answers, but nothing more is appended
}

func (s *oidSet) has(src srcTag, id oid) bool {
	s.mu.RLock()
	_, ok := s.m[record{src, id}]
	s.mu.RUnlock()
	return ok
}

// known reports how many blobs the set holds for src, which is how a caller tells a first scan
// of a source (nothing to look up) from a rescan.
func (s *oidSet) known(src srcTag) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.bySrc[src]
}

func (s *oidSet) size() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.m)
}

// load reads the file. A file that is not this version's, or whose header is damaged, is moved
// aside and the set starts empty: the cost is one rescan.
func (s *oidSet) load() {
	f, err := os.Open(s.path)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			s.l.note("blob ledger: " + filepath.Base(s.path) + " is unreadable (" + err.Error() + "); reading every blob again")
		}
		return
	}
	defer f.Close()
	br := bufio.NewReaderSize(f, 1<<20)
	head, err := br.ReadString('\n')
	if err != nil || head != s.header {
		f.Close()
		if err := s.l.moveAside(filepath.Base(s.path), ".damaged"); err != nil {
			s.l.note("blob ledger: " + filepath.Base(s.path) + " has a damaged header and could not be moved aside: " + err.Error())
		} else {
			s.l.note("blob ledger: " + filepath.Base(s.path) + " had a damaged header; it was moved to superseded/ and every blob is read again")
		}
		return
	}
	var rec [ledgerRecLen]byte
	for {
		if _, err := io.ReadFull(br, rec[:]); err != nil {
			return // EOF, or a torn last record
		}
		r := record{src: srcTag(rec[:8]), id: oid(rec[8:])}
		if _, dup := s.m[r]; !dup {
			s.m[r] = struct{}{}
			s.bySrc[r.src]++
		}
	}
}

// add appends the ids src has had read and remembers them. It reports the first write
// failure; the ids are remembered in memory either way, so one failing disk does not make a
// run read everything twice.
func (s *oidSet) add(src srcTag, ids []oid) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var buf []byte
	for _, id := range ids {
		r := record{src, id}
		if _, dup := s.m[r]; dup {
			continue
		}
		s.m[r] = struct{}{}
		s.bySrc[src]++
		buf = append(buf, src[:]...)
		buf = append(buf, id[:]...)
	}
	if len(buf) == 0 || s.broken {
		return nil
	}
	if err := s.append(buf); err != nil {
		s.broken = true
		return err
	}
	return nil
}

func (s *oidSet) append(buf []byte) error {
	if s.f == nil {
		if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
			return err
		}
		f, err := os.OpenFile(s.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		fi, err := f.Stat()
		if err != nil {
			f.Close()
			return err
		}
		hl := int64(len(s.header))
		switch {
		case fi.Size() == 0:
			buf = append([]byte(s.header), buf...)
		case (fi.Size()-hl)%ledgerRecLen != 0:
			// A torn record from a crash. load ignored it; cut it off, or every record
			// appended after it would be read shifted by its length.
			if err := f.Truncate(hl + (fi.Size()-hl)/ledgerRecLen*ledgerRecLen); err != nil {
				f.Close()
				return err
			}
		}
		s.f = f
	}
	_, err := s.f.Write(buf)
	return err
}

func (s *oidSet) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f != nil {
		s.f.Close()
		s.f = nil
	}
}

// seenView is one scan's window onto a ledger set: the set's answers for one source, plus the
// blobs this scan has read and will add once their hits are safe. It implements BlobSeen.
type seenView struct {
	set    *oidSet
	src    srcTag
	bypass bool // read everything, but still record it (an explicit full rescan of one source)

	mu      sync.Mutex
	pending []oid
	skipped int
}

func newSeenView(set *oidSet, source string, bypass bool) *seenView {
	return &seenView{set: set, src: tagOf(source), bypass: bypass}
}

// Seen reports whether this scanner has already read the blob in this source.
func (v *seenView) Seen(sha string) bool {
	if v.bypass {
		return false
	}
	id, ok := parseOID(sha)
	if !ok {
		return false
	}
	if v.set.has(v.src, id) {
		v.mu.Lock()
		v.skipped++
		v.mu.Unlock()
		return true
	}
	return false
}

// Note records that the scan read a blob. It enters the ledger at Commit, not now.
func (v *seenView) Note(sha string) {
	if id, ok := parseOID(sha); ok {
		v.noteID(id)
	}
}

func (v *seenView) noteID(id oid) {
	v.mu.Lock()
	v.pending = append(v.pending, id)
	v.mu.Unlock()
}

// warm reports whether the source has anything in the set, so a scan of it can be skipped
// outright when every blob turns out to be known. A first scan has nothing to look up, and
// the engine does not wait for a listing that cannot save it anything.
func (v *seenView) warm() bool { return !v.bypass && v.set.known(v.src) > 0 }

// allSeen reports whether every id is already in the set.
func (v *seenView) allSeen(ids []oid) bool {
	if v.bypass {
		return false
	}
	for _, id := range ids {
		if !v.set.has(v.src, id) {
			return false
		}
	}
	return true
}

// Commit adds what the scan read to the ledger. The caller does it after the findings are saved.
func (v *seenView) Commit() error {
	v.mu.Lock()
	ids := v.pending
	v.pending = nil
	v.mu.Unlock()
	return v.set.add(v.src, ids)
}

// Skipped is how many blobs Seen answered yes for.
func (v *seenView) Skipped() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.skipped
}
