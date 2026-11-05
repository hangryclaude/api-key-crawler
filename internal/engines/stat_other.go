//go:build !darwin

package engines

import "io/fs"

// statExtra has nothing to add off macOS, where the engines are not run in production: size
// and mtime key the hash, and CI's Linux job only has to build.
func statExtra(fs.FileInfo) (ctime int64, dev, ino uint64) { return 0, 0, 0 }
