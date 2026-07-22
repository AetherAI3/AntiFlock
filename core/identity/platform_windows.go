//go:build windows

package identity

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

func protectIdentityDirectory(path string) error {
	return applyCurrentUserOnlyACL(path, true)
}

func protectIdentityFile(path string, _ os.FileMode) error {
	return applyCurrentUserOnlyACL(path, false)
}

func applyCurrentUserOnlyACL(path string, directory bool) error {
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
	// The protected DACL disables inheritance and grants full control only to
	// the current user. This is applied through Win32 security APIs directly;
	// no path or SID is passed through a command shell.
	sddl := fmt.Sprintf("O:%sG:%sD:P(A;%s;FA;;;%s)", sid.String(), sid.String(), inheritance, sid.String())
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("build current-user-only Windows security descriptor: %w", err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return fmt.Errorf("read current-user-only Windows DACL: %w", err)
	}
	securityInformation := windows.SECURITY_INFORMATION(windows.OWNER_SECURITY_INFORMATION |
		windows.GROUP_SECURITY_INFORMATION |
		windows.DACL_SECURITY_INFORMATION |
		windows.PROTECTED_DACL_SECURITY_INFORMATION)
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, securityInformation, sid, sid, dacl, nil); err != nil {
		return fmt.Errorf("apply current-user-only Windows DACL: %w", err)
	}
	return nil
}

func syncDirectory(string) error {
	// Identity files are committed with MOVEFILE_WRITE_THROUGH below. Windows
	// does not expose POSIX directory fsync semantics; the write-through move is
	// the supported durability primitive for each parent-directory mutation.
	return nil
}

func installNoReplace(source, target string) error {
	from, err := windows.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return err
	}
	// MOVEFILE_REPLACE_EXISTING is deliberately absent: an unexpected target
	// fails closed instead of overwriting identity material.
	return windows.MoveFileEx(from, to, windows.MOVEFILE_WRITE_THROUGH)
}

func tryLockIdentityFile(file *os.File) (bool, error) {
	var overlapped windows.Overlapped
	err := windows.LockFileEx(
		windows.Handle(file.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0,
		1,
		0,
		&overlapped,
	)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) || errors.Is(err, windows.ERROR_IO_PENDING) {
		return false, nil
	}
	return false, err
}

func unlockIdentityFile(file *os.File) error {
	var overlapped windows.Overlapped
	return windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, &overlapped)
}
