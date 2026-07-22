//go:build windows

package identity_test

import (
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func assertPrivatePathProtection(t *testing.T, path string, _ bool) {
	t.Helper()
	const fileAllAccess windows.ACCESS_MASK = 0x001f01ff
	information := windows.SECURITY_INFORMATION(
		windows.OWNER_SECURITY_INFORMATION |
			windows.DACL_SECURITY_INFORMATION,
	)
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, information)
	if err != nil {
		t.Fatalf("read Windows security descriptor for %s: %v", path, err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		t.Fatalf("read Windows owner for %s: %v", path, err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatalf("read current Windows user for %s: %v", path, err)
	}
	if !owner.Equals(user.User.Sid) {
		t.Fatalf("Windows owner for %s is not the current user", path)
	}
	control, _, err := descriptor.Control()
	if err != nil {
		t.Fatalf("read Windows DACL control for %s: %v", path, err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatalf("Windows DACL for %s still inherits permissions", path)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatalf("read Windows DACL for %s: %v", path, err)
	}
	if dacl == nil {
		t.Fatalf("Windows DACL for %s is absent", path)
	}
	if dacl.AceCount != 1 {
		t.Fatalf("Windows DACL for %s has %d entries, want exactly one", path, dacl.AceCount)
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(dacl, 0, &ace); err != nil {
		t.Fatalf("read Windows ACE for %s: %v", path, err)
	}
	if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Mask&fileAllAccess != fileAllAccess {
		t.Fatalf("Windows ACE for %s does not grant current-user full control", path)
	}
	aceSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
	if !aceSID.Equals(user.User.Sid) {
		t.Fatalf("Windows DACL for %s grants access to a principal other than the current user", path)
	}
}
