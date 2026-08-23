//go:build aix || android || darwin || dragonfly || freebsd || illumos || ios || linux || netbsd || openbsd || solaris

package enforcement

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// openRegularFileNoFollow binds validation and reading to one descriptor. The
// non-blocking flag also prevents a hostile FIFO from stalling the verifier
// before fstat can reject it.
func openRegularFileNoFollow(path string) (*os.File, error) {
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("open regular file without following links")
	}
	file := os.NewFile(uintptr(descriptor), path)
	if file == nil {
		_ = unix.Close(descriptor)
		return nil, errors.New("bind regular file descriptor")
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, errors.New("opened path is not a regular file")
	}
	return file, nil
}
