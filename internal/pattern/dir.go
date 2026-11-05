package pattern

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sync"
)

const (
	// tileSize is the largest buffer scanned in one piece. A file over it is scanned in tiles that
	// share tileOverlap bytes with their neighbours, so a secret on a seam is in one tile whole and
	// is reported by the tile it starts in. The size is the plan's; the overlap is far more than a
	// match can cover (anchor.go caps a window at a few KiB past a keyword).
	tileSize    = 16 << 20
	tileOverlap = 64 << 10
	// sniffLen is how much of a file is looked at to call it binary.
	sniffLen = 8 << 10
)

// Stats counts what a scan did and did not look at. Every skip and cap is here, so that a caller can
// say so (no silent caps): Notes turns them into lines.
type Stats struct {
	Files      int   // files opened
	Bytes      int64 // bytes scanned
	Binary     int   // skipped: a NUL byte in the first 8 KiB
	Skipped    int   // skipped by the path policy
	Empty      int
	Unreadable int
	Tiled      int // files over 16 MiB, scanned in tiles
	Cuts       int // windows cut at the token cap
	Fallbacks  int // windows the linear matcher gave up on, which regexp then searched
	Findings   int
}

func (a *Stats) add(b Stats) {
	a.Files += b.Files
	a.Bytes += b.Bytes
	a.Binary += b.Binary
	a.Skipped += b.Skipped
	a.Empty += b.Empty
	a.Unreadable += b.Unreadable
	a.Tiled += b.Tiled
	a.Cuts += b.Cuts
	a.Fallbacks += b.Fallbacks
	a.Findings += b.Findings
}

// Notes are lines for the places that report what was dropped, capped or skipped. They name counts
// and kinds, never values or paths.
func (a Stats) Notes() []string {
	var n []string
	if a.Binary > 0 {
		n = append(n, fmt.Sprintf("native: %d binary files skipped (a NUL byte in the first 8 KiB)", a.Binary))
	}
	if a.Tiled > 0 {
		n = append(n, fmt.Sprintf("native: %d files over 16 MiB scanned in tiles", a.Tiled))
	}
	if a.Cuts > 0 {
		n = append(n, fmt.Sprintf("native: %d windows cut at the %d-byte token cap", a.Cuts, unboundedCap))
	}
	if a.Unreadable > 0 {
		n = append(n, fmt.Sprintf("native: %d files could not be read", a.Unreadable))
	}
	return n
}

// Scan reports the secrets in data, the content of the file at path. The path is slash-separated and
// relative to the root of whatever is being scanned, as the rules' path patterns expect; it may be empty. emit is called
// from this goroutine, and data is not retained. Offsets in the findings index data.
func (s *Scanner) Scan(path string, data []byte, emit func(Finding)) {
	w := s.getWork()
	defer s.putWork(w)
	for _, f := range w.pathFindings(path) {
		emit(f)
	}
	if len(data) <= tileSize+tileOverlap {
		for _, f := range w.scanBuf(path, data, 0, 0, len(data)) {
			emit(f)
		}
		return
	}
	lines, prev := 0, 0
	for k := 0; k*tileSize < len(data); k++ {
		own0, own1 := k*tileSize, min((k+1)*tileSize, len(data))
		lo, hi := max(0, own0-tileOverlap), min(len(data), own1+tileOverlap)
		lines += bytes.Count(data[prev:lo], []byte{'\n'})
		prev = lo
		for _, f := range w.scanBuf(path, data[lo:hi], lines, own0-lo, own1-lo) {
			f.MatchStart, f.MatchEnd, f.Start, f.End = f.MatchStart+lo, f.MatchEnd+lo, f.Start+lo, f.End+lo
			emit(f)
		}
	}
}

// ScanBytes is Scan that returns what it found.
func (s *Scanner) ScanBytes(path string, data []byte) []Finding {
	var out []Finding
	s.Scan(path, data, func(f Finding) { out = append(out, f) })
	return out
}

// ScanBytes scans one buffer with the default scanner.
func ScanBytes(path string, data []byte) []Finding { return Default().ScanBytes(path, data) }

// ScanDir scans a directory tree, or a single file, with the default scanner.
func ScanDir(ctx context.Context, dir string, emit func(Finding, []byte)) (Stats, error) {
	return Default().ScanDir(ctx, dir, emit)
}

// ScanDir reads every regular file under root (root itself, if it is a file) and reports what it
// finds. Symbolic links are not followed. emit is called once at a time, with the findings of a
// file in order, and the bytes the offsets index, which are valid only for the call. A file that
// cannot be read is counted and skipped; a failure of the scan itself, or of the context, is the
// error, and what was emitted before it is valid.
func (s *Scanner) ScanDir(ctx context.Context, root string, emit func(Finding, []byte)) (Stats, error) {
	s.ensure()
	info, err := os.Lstat(root)
	if err != nil {
		return Stats{}, err
	}
	threads := s.opt.Threads
	if threads <= 0 {
		threads = 2
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type job struct {
		abs, rel string
		size     int64
	}
	jobs := make(chan job, 128)
	var (
		mu       sync.Mutex // serialises emit, the totals and the first error
		total    Stats
		firstErr error
		wg       sync.WaitGroup
	)
	fail := func(err error) {
		mu.Lock()
		if firstErr == nil {
			firstErr = err
		}
		mu.Unlock()
		cancel()
	}
	locked := func(f Finding, data []byte) {
		mu.Lock()
		total.Findings++
		emit(f, data)
		mu.Unlock()
	}

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := s.getWork()
			defer s.putWork(w)
			var st Stats
			var buf []byte
			for j := range jobs {
				if ctx.Err() != nil {
					continue
				}
				func() {
					// A panic in a worker would take the process down; it becomes the scan's error. The
					// message names the failure and the file, never anything read from it.
					defer func() {
						if r := recover(); r != nil {
							msg := "panic"
							if re, ok := r.(runtime.Error); ok {
								msg = re.Error()
							}
							fail(fmt.Errorf("pattern: internal error scanning %s: %s", j.rel, msg))
						}
					}()
					buf = s.scanFile(w, j.abs, j.rel, j.size, buf, &st, locked)
				}()
			}
			mu.Lock()
			total.add(st)
			mu.Unlock()
		}()
	}

	var walked Stats
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			walked.Unreadable++
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		rel := "."
		if !info.IsDir() {
			rel = filepath.Base(root)
		} else if path != root {
			r, rerr := filepath.Rel(root, path)
			if rerr != nil {
				walked.Unreadable++
				return nil
			}
			rel = filepath.ToSlash(r)
		}
		if d.IsDir() {
			if rel != "." && s.gate.skipsDir(rel) {
				walked.Skipped++
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			walked.Skipped++ // a symbolic link, a socket, a device
			return nil
		}
		fi, ierr := d.Info()
		if ierr != nil {
			walked.Unreadable++
			return nil
		}
		if fi.Size() == 0 {
			walked.Empty++
			return nil
		}
		if s.gate.of(rel).all {
			walked.Skipped++
			return nil
		}
		select {
		case jobs <- job{path, rel, fi.Size()}:
		case <-ctx.Done():
			return ctx.Err()
		}
		return nil
	})
	close(jobs)
	wg.Wait()
	total.add(walked)

	mu.Lock()
	defer mu.Unlock()
	switch {
	case firstErr != nil:
		return total, firstErr
	case walkErr != nil && !errors.Is(walkErr, context.Canceled):
		return total, walkErr
	}
	return total, ctx.Err()
}

// scanFile reads one file into buf (grown as needed) and scans it, in tiles if it is big.
func (s *Scanner) scanFile(w *work, abs, rel string, size int64, buf []byte, st *Stats, emit func(Finding, []byte)) []byte {
	f, err := os.Open(abs)
	if err != nil {
		st.Unreadable++
		return buf
	}
	defer f.Close()
	st.Files++

	for _, pf := range w.pathFindings(rel) {
		emit(pf, nil)
	}

	first := int(min(size, tileSize+tileOverlap))
	if cap(buf) < first {
		buf = make([]byte, first, first+first/8)
	}
	n, err := io.ReadFull(f, buf[:first])
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		st.Unreadable++
		return buf
	}
	if bytes.IndexByte(buf[:min(n, sniffLen)], 0) >= 0 {
		st.Binary++
		return buf
	}
	st.Bytes += int64(n)
	if size <= tileSize+tileOverlap || n < first {
		for _, fd := range w.scanBuf(rel, buf[:n], 0, 0, n) {
			emit(fd, buf[:n])
		}
		st.Cuts += w.cuts
		st.Fallbacks += w.fallbacks
		return buf
	}

	// A file over a tile: the first read is the first tile's buffer; later ones are read in place.
	st.Tiled++
	lines, prev := 0, int64(0)
	for k := int64(0); k*tileSize < size; k++ {
		own0, own1 := k*tileSize, min((k+1)*tileSize, size)
		lo, hi := max(0, own0-tileOverlap), min(size, own1+tileOverlap)
		need := int(hi - lo)
		if cap(buf) < need {
			buf = make([]byte, need)
		}
		if k > 0 {
			rn, err := f.ReadAt(buf[:need], lo)
			if err != nil && !errors.Is(err, io.EOF) {
				st.Unreadable++
				return buf
			}
			need = rn
			st.Bytes += int64(rn)
		} else {
			need = n
		}
		// Count the newlines between the previous tile's start and this one's, from the bytes this
		// tile has: the overlap is the only place they can come from, because tiles are far
		// bigger than it. For a gap the buffer lacks, read it.
		lines += newlinesBetween(f, prev, lo)
		prev = lo
		for _, fd := range w.scanBuf(rel, buf[:need], lines, int(own0-lo), int(own1-lo)) {
			fd.Base = int(lo)
			emit(fd, buf[:need])
		}
		st.Cuts += w.cuts
		st.Fallbacks += w.fallbacks
	}
	return buf
}

// newlinesBetween counts the newlines in the file from offset a to offset b.
func newlinesBetween(f *os.File, a, b int64) int {
	if b <= a {
		return 0
	}
	var chunk [1 << 16]byte
	n := 0
	for off := a; off < b; {
		m := int(min(int64(len(chunk)), b-off))
		rn, err := f.ReadAt(chunk[:m], off)
		n += bytes.Count(chunk[:rn], []byte{'\n'})
		off += int64(rn)
		if err != nil || rn == 0 {
			break
		}
	}
	return n
}
