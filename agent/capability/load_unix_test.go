//go:build unix

package capability

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestLoadManifestFileRejectsFIFOWithoutBlocking(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "manifest.fifo")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("mkfifo unsupported here: %v", err)
	}
	// No writer is ever attached: a blocking open would hang this test.
	_, err := LoadManifestFile(path, defaultLoadOptions())
	if code := loadCode(t, err); code != ReasonFileType {
		t.Fatalf("FIFO accepted or wrong code: %v", err)
	}
}

func TestLoadManifestFileRejectsDeviceNode(t *testing.T) {
	t.Parallel()
	if _, err := os.Stat("/dev/null"); err != nil {
		t.Skip("no /dev/null")
	}
	_, err := LoadManifestFile("/dev/null", defaultLoadOptions())
	if code := loadCode(t, err); code != ReasonFileType {
		t.Fatalf("device node accepted or wrong code: %v", err)
	}
}

func TestLoadManifestFileRequireOwnerRejectsLooseModes(t *testing.T) {
	t.Parallel()
	data := manifestJSON(t, signedManifest(t))
	for _, mode := range []os.FileMode{0o602, 0o620, 0o666} {
		path := filepath.Join(t.TempDir(), "manifest.json")
		if err := os.WriteFile(path, data, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm()&0o022 == 0 {
			t.Skipf("file system does not preserve mode %o", mode)
		}
		opts := defaultLoadOptions()
		opts.RequireOwner = true
		_, err = LoadManifestFile(path, opts)
		if code := loadCode(t, err); code != ReasonFilePermissions {
			t.Fatalf("mode %o accepted under RequireOwner: %v", mode, err)
		}
		opts.RequireOwner = false
		if _, err := LoadManifestFile(path, opts); err != nil {
			t.Fatalf("mode %o rejected without RequireOwner: %v", mode, err)
		}
	}
}

func TestLoadManifestFileRequireOwnerAcceptsOwnedPrivateFile(t *testing.T) {
	t.Parallel()
	path := writeFixture(t, manifestJSON(t, signedManifest(t)))
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	opts := defaultLoadOptions()
	opts.RequireOwner = true
	if _, err := LoadManifestFile(path, opts); err != nil {
		t.Fatalf("owned 0600 file rejected: %v", err)
	}
}

func TestLoadManifestFileSymlinkReportsFileType(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	target := filepath.Join(dir, "real.json")
	if err := os.WriteFile(target, manifestJSON(t, signedManifest(t)), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unsupported here: %v", err)
	}
	_, err := LoadManifestFile(link, defaultLoadOptions())
	if code := loadCode(t, err); code != ReasonFileType {
		t.Fatalf("symlink code %s, want %s", code, ReasonFileType)
	}
}
