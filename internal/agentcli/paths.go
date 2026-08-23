package agentcli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// ErrNotContained is returned when a path escapes its permitted root.
var ErrNotContained = errors.New("path is not contained in its permitted root")

// protectedRoots are directories the agent must never treat as its own,
// whatever the config says. Matching is on the cleaned absolute path.
var protectedRoots = []string{"/", "/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib64", "/opt", "/proc", "/root", "/run", "/sbin", "/srv", "/sys", "/tmp", "/usr", "/var", "/var/lib", "/var/log", "/var/run", "/var/tmp"}

// IsProtectedRoot reports whether path is one of the well-known system roots.
func IsProtectedRoot(path string) bool {
	cleaned := filepath.ToSlash(filepath.Clean(path))
	for _, root := range protectedRoots {
		if cleaned == root {
			return true
		}
	}
	return false
}

// Contained checks that candidate lives at or below root without using any
// ".." component and without the root or any component of candidate being a
// symbolic link. Both paths must be absolute and canonical. The check is
// lexical first (so ".." is rejected before touching the filesystem) and
// then physical (Lstat of every component below root).
func Contained(root, candidate string) error {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || IsProtectedRoot(root) {
		return ErrNotContained
	}
	if !filepath.IsAbs(candidate) || filepath.Clean(candidate) != candidate {
		return ErrNotContained
	}
	relative, err := filepath.Rel(root, candidate)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return ErrNotContained
	}
	if info, err := os.Lstat(root); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrNotContained
	}
	if relative == "." {
		return nil
	}
	current := root
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		if component == "" || component == "." || component == ".." {
			return ErrNotContained
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil {
			return ErrNotContained
		}
		// The final component may itself be a symlink: it is removed as a link,
		// never followed. Intermediate components must be real directories.
		if current != candidate && (!info.IsDir() || info.Mode()&os.ModeSymlink != 0) {
			return ErrNotContained
		}
	}
	return nil
}

// RealDirectory reports whether path is an existing directory that is not a
// symbolic link.
func RealDirectory(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0
}
