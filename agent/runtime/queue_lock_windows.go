//go:build windows

package runtime

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

func lockQueueFile(file *os.File) error {
	var overlapped windows.Overlapped
	if err := windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &overlapped); err != nil {
		return errors.New("agent queue is already active in another process")
	}
	return nil
}

func unlockQueueFile(file *os.File) error {
	var overlapped windows.Overlapped
	if err := windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, &overlapped); err != nil {
		return errors.New("release agent queue writer lock")
	}
	return nil
}
