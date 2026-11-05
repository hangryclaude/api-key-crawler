package engines

import (
	"io/fs"
	"syscall"
)

// statExtra is the change time, device and inode of a file. A write of any kind moves the
// ctime, and nothing a user process can do sets it back.
func statExtra(fi fs.FileInfo) (ctime int64, dev, ino uint64) {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return st.Ctimespec.Nano(), uint64(st.Dev), st.Ino
	}
	return 0, 0, 0
}
