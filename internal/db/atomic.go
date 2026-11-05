package db

import (
	"os"
	"path/filepath"
)

// WriteFileAtomic replaces path with data so a reader (a hook, the report, a poll that
// overlaps a deep scan) sees the old file or the new one, never half of one. The temp file
// lives beside the target so the rename stays on one filesystem, gets its final mode before
// any content lands, and is synced before the rename so a power cut cannot leave an empty
// file under the real name. Use it for what cannot be rebuilt: the findings, the ignore list.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	return writeAtomic(path, data, perm, true)
}

// WriteFileAtomicLazy is WriteFileAtomic without the disk flush, for files the next run can
// rebuild: a source's scan state, the inventory snapshot, a run record. On macOS a flush
// costs about 6 ms, which across 469 sources dominates a poll that has nothing to scan. A
// lost or empty file is read as "never scanned" and costs a rescan, never a missed secret,
// provided the findings it vouches for were written durably first.
func WriteFileAtomicLazy(path string, data []byte, perm os.FileMode) error {
	return writeAtomic(path, data, perm, false)
}

func writeAtomic(path string, data []byte, perm os.FileMode, durable bool) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // a no-op once the rename succeeded
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if durable {
		if err := tmp.Sync(); err != nil {
			tmp.Close()
			return err
		}
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	if durable {
		if d, err := os.Open(dir); err == nil { // best effort: makes the rename itself durable
			d.Sync()
			d.Close()
		}
	}
	return nil
}
