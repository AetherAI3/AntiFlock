//go:build !windows

package runtime

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func lockQueueFile(file *os.File) error {
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return errors.New("agent queue is already active in another process")
	}
	return nil
}

func unlockQueueFile(file *os.File) error {
	if err := unix.Flock(int(file.Fd()), unix.LOCK_UN); err != nil {
		return errors.New("release agent queue writer lock")
	}
	return nil
}
