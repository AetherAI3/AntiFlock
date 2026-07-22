//go:build !windows

package identity

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func protectIdentityDirectory(path string) error {
	return os.Chmod(path, 0o700)
}

func protectIdentityFile(path string, mode os.FileMode) error {
	return os.Chmod(path, mode.Perm())
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func installNoReplace(source, target string) error {
	// A same-directory hard link gives us an atomic no-replace commit without
	// relying on rename behavior that overwrites an unexpected destination.
	if err := os.Link(source, target); err != nil {
		return err
	}
	if err := syncDirectory(filepath.Dir(target)); err != nil {
		return fmt.Errorf("sync installed identity link: %w", err)
	}
	if err := os.Remove(source); err != nil {
		return fmt.Errorf("remove temporary identity link: %w", err)
	}
	if err := syncDirectory(filepath.Dir(target)); err != nil {
		return fmt.Errorf("sync temporary identity link removal: %w", err)
	}
	return nil
}

func tryLockIdentityFile(file *os.File) (bool, error) {
	err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
		return false, nil
	}
	return false, err
}

func unlockIdentityFile(file *os.File) error {
	return syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
}
