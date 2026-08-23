//go:build !(aix || android || darwin || dragonfly || freebsd || illumos || ios || linux || netbsd || openbsd || solaris || windows)

package driver

import (
	"errors"
	"os"
)

// The file journal requires a platform with no-follow opens and file locks.
// Other platforms must use MemoryJournal or a platform-specific Journal.
func openJournalFileNoFollow(string) (*os.File, error) {
	return nil, errors.New("file journal is unsupported on this platform")
}

func openJournalLockFile(string) (*os.File, error) {
	return nil, errors.New("file journal is unsupported on this platform")
}

func tryLockJournalFile(*os.File) (bool, error) {
	return false, errors.New("file journal is unsupported on this platform")
}

func unlockJournalFile(*os.File) error { return nil }

func syncJournalDirectory(string) error { return nil }

func checkPrivateDirectoryMode(os.FileInfo) error {
	return errors.New("file journal is unsupported on this platform")
}
