//go:build !windows

package identity_test

import (
	"os"
	"testing"
)

func assertPrivatePathProtection(t *testing.T, path string, directory bool) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	want := os.FileMode(0o600)
	if directory {
		want = 0o700
	}
	if info.Mode().Perm() != want {
		t.Fatalf("%s permissions = %o, want %o", path, info.Mode().Perm(), want)
	}
}
