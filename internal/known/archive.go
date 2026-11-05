package known

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"compress/zlib"
	"io"
	"strings"

	"keyguard/internal/core"
	"keyguard/internal/fp"
)

// Bounds on what a blob may expand to while it is searched. A repository is untrusted
// input and a few hundred bytes of deflate can stand for gigabytes; anything past a bound
// is counted in BlobStats, never silently dropped.
const (
	maxArchiveDepth = 3
	maxMemberSize   = 64 << 20  // one decompressed member or stream
	maxArchiveTotal = 256 << 20 // everything one top-level blob expands to
	maxMembers      = 20_000
)

// MemberHit is a learned secret found inside an archive or compressed stream that a git
// object holds. Offsets are into the decompressed member.
type MemberHit struct {
	Member  string // "dir/file.txt", "a.zip!/b.tar.gz!/c/d.env", "blob.gz!gz" for a bare stream
	Matches []core.KnownMatch
}

type archiveKind int

const (
	notArchive archiveKind = iota
	kindZip
	kindGzip
	kindBzip2
	kindZlib
	kindTar
	kindUnsupported // xz, zstd, 7z, rar: recognised, not openable with the standard library
)

// archiveKindOf recognises a container by its first bytes. It is the only cost a plain
// blob pays.
func archiveKindOf(b []byte) archiveKind {
	switch {
	case len(b) >= 4 && b[0] == 'P' && b[1] == 'K' && (b[2] == 3 && b[3] == 4 || b[2] == 5 && b[3] == 6):
		return kindZip
	case len(b) >= 3 && b[0] == 0x1f && b[1] == 0x8b && b[2] == 8:
		return kindGzip
	case len(b) >= 4 && b[0] == 'B' && b[1] == 'Z' && b[2] == 'h' && b[3] >= '1' && b[3] <= '9':
		return kindBzip2
	case len(b) >= 2 && b[0] == 0x78 && (uint(b[0])<<8|uint(b[1]))%31 == 0:
		return kindZlib
	case len(b) >= 262 && string(b[257:262]) == "ustar":
		return kindTar
	case bytes.HasPrefix(b, []byte{0xfd, '7', 'z', 'X', 'Z', 0}), bytes.HasPrefix(b, []byte{0x28, 0xb5, 0x2f, 0xfd}),
		bytes.HasPrefix(b, []byte("7z\xbc\xaf\x27\x1c")), bytes.HasPrefix(b, []byte("Rar!")):
		return kindUnsupported
	}
	return notArchive
}

type archiveScan struct {
	m       *Matcher
	st      *BlobStats
	budget  int64
	members int
}

// scanInside opens data if it is an archive or compressed stream and searches every
// member, recursing into nested containers up to maxArchiveDepth.
func (m *Matcher) scanInside(data []byte, st *BlobStats) []MemberHit {
	if archiveKindOf(data) == notArchive {
		return nil
	}
	a := &archiveScan{m: m, st: st, budget: maxArchiveTotal}
	hits, _ := a.open(data, "", 0)
	return hits
}

// open searches the members of a container or stream. opened is false when data is not
// one, or could not be read as one, so the caller falls back to searching its bytes.
func (a *archiveScan) open(data []byte, label string, depth int) (hits []MemberHit, opened bool) {
	kind := archiveKindOf(data)
	if kind == notArchive {
		return nil, false
	}
	if kind == kindUnsupported {
		a.st.ArchivesUnsupported++
		return nil, false
	}
	if depth >= maxArchiveDepth {
		a.st.ArchiveSkips++
		return nil, false
	}
	switch kind {
	case kindZip:
		zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			a.st.ArchiveSkips++
			return nil, false
		}
		a.st.Archives++
		var out []MemberHit
		for _, f := range zr.File {
			if f.FileInfo().IsDir() {
				continue
			}
			if a.members++; a.members > maxMembers {
				a.st.ArchiveSkips++
				break
			}
			if f.UncompressedSize64 > maxMemberSize {
				a.st.ArchiveSkips++
				continue
			}
			rc, err := f.Open()
			if err != nil {
				a.st.ArchiveSkips++
				continue
			}
			body, ok := a.read(rc)
			rc.Close()
			if !ok {
				continue
			}
			out = append(out, a.member(body, joinMember(label, f.Name), depth)...)
		}
		return out, true
	case kindTar:
		a.st.Archives++
		tr := tar.NewReader(bytes.NewReader(data))
		var out []MemberHit
		for {
			h, err := tr.Next()
			if err != nil {
				if err != io.EOF {
					a.st.ArchiveSkips++
				}
				return out, true
			}
			if h.Typeflag != tar.TypeReg {
				continue
			}
			if h.Size > maxMemberSize {
				a.st.ArchiveSkips++
				continue
			}
			if a.members++; a.members > maxMembers {
				a.st.ArchiveSkips++
				return out, true
			}
			body, ok := a.read(tr)
			if !ok {
				continue
			}
			out = append(out, a.member(body, joinMember(label, h.Name), depth)...)
		}
	}
	// A bare compressed stream: one member, named after the stream.
	var r io.Reader
	var suffix string
	switch kind {
	case kindGzip:
		gr, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			a.st.ArchiveSkips++
			return nil, false
		}
		defer gr.Close()
		r, suffix = gr, "gz"
	case kindBzip2:
		r, suffix = bzip2.NewReader(bytes.NewReader(data)), "bz2"
	case kindZlib:
		zr, err := zlib.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, false // 0x78 plus a valid check word is also how plenty of binary data starts
		}
		defer zr.Close()
		r, suffix = zr, "zlib"
	}
	a.st.Archives++
	body, ok := a.read(r)
	if !ok {
		return nil, false
	}
	return a.member(body, label+"!"+suffix, depth), true
}

// read takes one member's bytes under the per-member and per-blob bounds.
func (a *archiveScan) read(r io.Reader) ([]byte, bool) {
	body, err := io.ReadAll(io.LimitReader(r, maxMemberSize+1))
	if len(body) > maxMemberSize || a.budget-int64(len(body)) < 0 {
		a.st.ArchiveSkips++
		return nil, false
	}
	if err != nil && len(body) == 0 {
		a.st.ArchiveSkips++
		return nil, false
	}
	a.budget -= int64(len(body))
	return body, true
}

// member searches one decompressed member. If the member is itself a container its
// members are searched instead of its bytes (a tar's bytes hold the same text its members
// do, and a zip's hold nothing readable); if it cannot be opened its bytes are searched.
func (a *archiveScan) member(body []byte, name string, depth int) []MemberHit {
	a.st.ArchiveBytes += int64(len(body))
	inner, opened := a.open(body, name, depth+1)
	if opened {
		return inner
	}
	if ms, _ := a.m.MatchLimit(body, 0); len(ms) > 0 {
		return []MemberHit{{Member: name, Matches: ms}}
	}
	return nil
}

// joinMember builds "outer!/inner" labels. Names come from an untrusted archive and are
// shown in reports, so control characters are dropped, the length is capped, and any token
// that looks like a secret is masked, as for every other string keyguard prints.
func joinMember(outer, name string) string {
	name = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, name)
	if len(name) > 200 {
		name = name[:200] + "…"
	}
	name = fp.Scrub(name)
	if outer == "" {
		return name
	}
	return outer + "!/" + name
}
