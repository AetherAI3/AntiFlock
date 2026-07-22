//go:build !windows

package storage

import "os"

func protectStorageDirectory(path string) error {
	return os.Chmod(path, 0o700)
}

func protectStorageFile(path string) error {
	return os.Chmod(path, 0o600)
}
