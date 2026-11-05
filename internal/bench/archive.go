package bench

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"io"
)

// The full scan opens the containers a key hides in, to the depth and size docs/STEAL.md P1-16
// sets (Kingfisher's caps): zip, gzip and tar, which makes .jar, .tgz and a bare .gz readable.
const (
	maxArchiveDepth = 3
	maxArchiveBytes = 64 << 20  // one archive, compressed
	maxArchiveTotal = 256 << 20 // everything one blob unpacks to
)

// expandArchive calls visit with the name and content of every file inside data, descending
// into archives within archives. Members are named "<name>!<member>", the way betterleaks
// writes them. left is the budget of unpacked bytes shared by the whole walk; a member that
// would overrun it ends the walk, and the caller counts that as a skipped blob.
func expandArchive(data []byte, name string, depth int, left *int64, visit func(name string, content []byte)) {
	if depth >= maxArchiveDepth || len(data) > maxArchiveBytes {
		return
	}
	read := func(r io.Reader) ([]byte, bool) {
		b, err := io.ReadAll(io.LimitReader(r, *left+1))
		if err != nil || int64(len(b)) > *left {
			return nil, false
		}
		*left -= int64(len(b))
		return b, true
	}
	member := func(n string, b []byte) {
		visit(n, b)
		expandArchive(b, n, depth+1, left, visit)
	}
	switch {
	case bytes.HasPrefix(data, []byte("PK\x03\x04")):
		zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			return
		}
		for _, f := range zr.File {
			if f.FileInfo().IsDir() {
				continue
			}
			rc, err := f.Open()
			if err != nil {
				continue
			}
			b, ok := read(rc)
			rc.Close()
			if !ok {
				return
			}
			member(name+"!"+f.Name, b)
		}
	case bytes.HasPrefix(data, []byte{0x1f, 0x8b}):
		gz, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return
		}
		b, ok := read(gz)
		if !ok {
			return
		}
		if isTar(b) {
			expandArchive(b, name, depth+1, left, visit)
		} else {
			member(name+"!", b)
		}
	case isTar(data):
		tr := tar.NewReader(bytes.NewReader(data))
		for {
			h, err := tr.Next()
			if err != nil {
				return
			}
			if h.Typeflag != tar.TypeReg {
				continue
			}
			b, ok := read(tr)
			if !ok {
				return
			}
			member(name+"!"+h.Name, b)
		}
	}
}

// isTar recognizes the ustar magic at offset 257 of the first header.
func isTar(b []byte) bool {
	return len(b) >= 262 && string(b[257:262]) == "ustar"
}
