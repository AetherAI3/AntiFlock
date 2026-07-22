//go:build windows

package storage

import (
	"fmt"

	"golang.org/x/sys/windows"
)

func protectStorageDirectory(path string) error {
	return applyStorageACL(path, true)
}

func protectStorageFile(path string) error {
	return applyStorageACL(path, false)
}

func applyStorageACL(path string, directory bool) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return fmt.Errorf("read current Windows user token: %w", err)
	}
	sid, err := user.User.Sid.Copy()
	if err != nil {
		return fmt.Errorf("copy current Windows user SID: %w", err)
	}
	inheritance := ""
	if directory {
		inheritance = "OICI"
	}
	sddl := fmt.Sprintf("O:%sG:%sD:P(A;%s;FA;;;%s)", sid.String(), sid.String(), inheritance, sid.String())
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("build current-user-only Windows storage descriptor: %w", err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return fmt.Errorf("read current-user-only Windows storage DACL: %w", err)
	}
	securityInformation := windows.SECURITY_INFORMATION(windows.OWNER_SECURITY_INFORMATION |
		windows.GROUP_SECURITY_INFORMATION |
		windows.DACL_SECURITY_INFORMATION |
		windows.PROTECTED_DACL_SECURITY_INFORMATION)
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, securityInformation, sid, sid, dacl, nil); err != nil {
		return fmt.Errorf("apply current-user-only Windows storage DACL: %w", err)
	}
	return nil
}
