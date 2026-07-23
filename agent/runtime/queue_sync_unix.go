//go:build !windows

package runtime

import (
	"errors"
	"os"
)

// syncQueueDirectory persists the post-rename directory entry on Unix. The
// queue binary only collects on Linux, where this protects rename durability
// across a power loss after a successful staged-file sync.
func syncQueueDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil { return errors.New("open agent queue directory for sync") }
	defer directory.Close()
	if err := directory.Sync(); err != nil { return errors.New("sync agent queue directory") }
	return nil
}
