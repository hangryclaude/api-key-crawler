package known

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"

	"keyguard/internal/core"
)

// MaxBlobSize is the largest object MatchBlobs reads into memory (PLAN.md blob mode).
// Bigger ones are skipped, counted and reported in BlobStats rather than silently dropped.
const MaxBlobSize = 50 << 20

// BlobHit is one git object that holds learned secrets.
type BlobHit struct {
	SHA     string
	Type    string // blob, commit or tag
	Size    int64
	Matches []core.KnownMatch // offsets are into the object's content
	// Inside are the matches found in archives and compressed streams the object holds
	// (zip, tar, gzip, bzip2, zlib, nested up to three deep): a secret in a committed
	// .zip or .tar.gz is not in the bytes git stores.
	Inside []MemberHit
	// Truncated reports that the object had more matches than MatchLimit returns.
	Truncated bool
}

// BlobStats accounts for every object in the stream, so a caller can put the numbers in
// its run record: nothing is skipped without being counted.
type BlobStats struct {
	Objects      int   // objects in the stream
	Scanned      int   // objects searched
	Bytes        int64 // content bytes searched
	Hits         int   // objects with at least one match
	Skipped      int   // over the size cap
	SkippedBytes int64
	Trees        int // not searched: a tree is binary directory data and holds no secret
	Missing      int // objects git could not find

	Archives            int   // containers and compressed streams opened
	ArchiveBytes        int64 // decompressed bytes searched
	ArchiveSkips        int   // members or containers not read: too big, too deep, too many, corrupt
	ArchivesUnsupported int   // xz, zstd, 7z, rar: recognised but not openable with the standard library
}

// MatchBlobs reads the output of `git cat-file --batch` (or --batch-all-objects --batch)
// and calls fn for each object that holds a learned secret. Commits and tags are searched
// along with blobs, since a commit message is as good a place to paste a key as a file.
// Objects over MaxBlobSize are read past and counted, never held in memory. Archives and
// compressed streams are opened and their members searched too, within fixed bounds that
// are counted in BlobStats when they bite.
func (m *Matcher) MatchBlobs(r io.Reader, fn func(BlobHit)) (BlobStats, error) {
	return m.MatchBlobsMax(r, MaxBlobSize, fn)
}

// MatchBlobsMax is MatchBlobs with an explicit size cap.
func (m *Matcher) MatchBlobsMax(r io.Reader, maxSize int64, fn func(BlobHit)) (BlobStats, error) {
	var st BlobStats
	br := bufio.NewReaderSize(r, 1<<20)
	var buf []byte
	for {
		header, err := br.ReadSlice('\n')
		if errors.Is(err, io.EOF) && len(header) == 0 {
			return st, nil
		}
		if err != nil {
			return st, fmt.Errorf("known: reading object header: %w", err)
		}
		st.Objects++
		idb, typb, size, missing, ok := parseObjectHeader(header)
		if !ok {
			return st, errors.New("known: malformed object header in cat-file stream")
		}
		if missing {
			st.Missing++
			continue
		}
		var typ string
		switch string(typb) {
		case "blob":
			typ = "blob"
		case "commit":
			typ = "commit"
		case "tag":
			typ = "tag"
		case "tree":
			typ = "tree"
		default:
			return st, errors.New("known: unknown object type in cat-file stream")
		}
		// The header lives in the reader's buffer, which the content read overwrites; keep
		// the id in a fixed array and make a string only for objects that hit.
		var id [64]byte
		idLen := copy(id[:], idb)
		if typ == "tree" {
			st.Trees++
			if err := discard(br, size+1); err != nil {
				return st, err
			}
			continue
		}
		if size > maxSize {
			st.Skipped++
			st.SkippedBytes += size
			if err := discard(br, size+1); err != nil {
				return st, err
			}
			continue
		}
		if int64(cap(buf)) < size {
			buf = make([]byte, size+size/4)
		}
		buf = buf[:size]
		if _, err := io.ReadFull(br, buf); err != nil {
			return st, errors.New("known: object content is shorter than its header says")
		}
		if c, err := br.ReadByte(); err != nil || c != '\n' {
			return st, errors.New("known: object content is not followed by a newline")
		}
		st.Scanned++
		st.Bytes += size
		ms, truncated := m.MatchLimit(buf, 0)
		inside := m.scanInside(buf, &st)
		if len(ms) == 0 && len(inside) == 0 {
			continue
		}
		st.Hits++
		fn(BlobHit{SHA: string(id[:idLen]), Type: typ, Size: size, Matches: ms, Inside: inside, Truncated: truncated})
	}
}

// parseObjectHeader reads "<id> <type> <size>" or "<id> missing" without allocating: it
// runs once per object, and a full scan has millions.
func parseObjectHeader(h []byte) (id, typ []byte, size int64, missing, ok bool) {
	h = bytes.TrimRight(h, "\r\n")
	sp := bytes.IndexByte(h, ' ')
	if sp <= 0 {
		return nil, nil, 0, false, false
	}
	id, rest := h[:sp], h[sp+1:]
	if string(rest) == "missing" || string(rest) == "ambiguous" {
		return id, nil, 0, true, true
	}
	sp = bytes.IndexByte(rest, ' ')
	if sp <= 0 || sp == len(rest)-1 {
		return nil, nil, 0, false, false
	}
	typ, num := rest[:sp], rest[sp+1:]
	for _, c := range num {
		if c < '0' || c > '9' || size > 1<<55 {
			return nil, nil, 0, false, false
		}
		size = size*10 + int64(c-'0')
	}
	return id, typ, size, false, true
}

func discard(br *bufio.Reader, n int64) error {
	if _, err := io.CopyN(io.Discard, br, n); err != nil {
		return errors.New("known: cat-file stream ended inside an object")
	}
	return nil
}
