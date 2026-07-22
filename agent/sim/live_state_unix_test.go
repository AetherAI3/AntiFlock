//go:build !windows

package sim

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLiveStateRejectsSymlinkedIdentityFilesAndDirectories(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "state")
	if err := ensurePrivateDirectory(directory); err != nil {
		t.Fatal(err)
	}
	if _, _, err := createLiveIdentity(directory, "sim-agent-node", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(directory, "state.json")
	target := filepath.Join(root, "other-state.json")
	content, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(statePath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, statePath); err != nil {
		t.Fatal(err)
	}
	if _, err := loadLiveState(directory, "sim-agent-node"); err == nil {
		t.Fatal("symlinked simulator identity state was accepted")
	}

	linkedDirectory := filepath.Join(root, "linked-state")
	if err := os.Symlink(directory, linkedDirectory); err != nil {
		t.Fatal(err)
	}
	if err := ensurePrivateDirectory(linkedDirectory); err == nil {
		t.Fatal("symlinked simulator state directory was accepted")
	}
}
