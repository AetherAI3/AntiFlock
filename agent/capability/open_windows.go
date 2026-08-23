//go:build windows

package capability

import (
	"errors"
	"os"
	"syscall"
	"time"
)

// openNoFollow opens path with FILE_FLAG_OPEN_REPARSE_POINT so a symlink or
// junction at the final component is opened as itself, then rejects it by its
// attributes. Identity (volume serial, file index, size, last-write time) is
// taken from the open handle.
//
// RequireOwner fails closed on Windows: there is no portable, safe owner
// comparison available through the standard library alone.
func openNoFollow(path string, requireOwner bool) (*os.File, fileIdentity, error) {
	if requireOwner {
		return nil, fileIdentity{}, loadError(ReasonPlatformUnsupported, errors.New("owner verification is not supported on this platform"))
	}
	pointer, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, fileIdentity{}, loadError(ReasonFileOpen, errors.New("manifest path is not a valid string"))
	}
	handle, err := syscall.CreateFile(pointer, syscall.GENERIC_READ,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE, nil,
		syscall.OPEN_EXISTING, syscall.FILE_ATTRIBUTE_NORMAL|syscall.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, fileIdentity{}, loadError(ReasonFileOpen, errors.New("manifest could not be opened"))
	}
	file := os.NewFile(uintptr(handle), path)
	identity, err := platformStat(file)
	if err != nil {
		file.Close()
		return nil, fileIdentity{}, loadError(ReasonFileOpen, errors.New("manifest could not be stat'ed"))
	}
	if !identity.Regular {
		file.Close()
		return nil, fileIdentity{}, loadError(ReasonFileType, errors.New("manifest path is a reparse point, directory, or non-disk file"))
	}
	return file, identity, nil
}

func platformStat(file *os.File) (fileIdentity, error) {
	handle := syscall.Handle(file.Fd())
	fileType, err := syscall.GetFileType(handle)
	if err != nil {
		return fileIdentity{}, err
	}
	var info syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(handle, &info); err != nil {
		return fileIdentity{}, err
	}
	regular := fileType == syscall.FILE_TYPE_DISK &&
		info.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT == 0 &&
		info.FileAttributes&syscall.FILE_ATTRIBUTE_DIRECTORY == 0
	return fileIdentity{
		Size:    int64(info.FileSizeHigh)<<32 | int64(info.FileSizeLow),
		ModTime: time.Unix(0, info.LastWriteTime.Nanoseconds()),
		Inode:   uint64(info.FileIndexHigh)<<32 | uint64(info.FileIndexLow),
		Device:  uint64(info.VolumeSerialNumber),
		Regular: regular,
	}, nil
}
