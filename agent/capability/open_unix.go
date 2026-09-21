//go:build unix

package capability

import (
	"errors"
	"os"
	"syscall"
)

// openNoFollow opens path read-only with O_NOFOLLOW so a symlink at the final
// component is rejected by the kernel, O_NONBLOCK so opening a FIFO never
// blocks, and O_CLOEXEC so the descriptor is never inherited. The identity is
// taken from the open descriptor, never from the path.
func openNoFollow(path string, requireOwner bool) (*os.File, fileIdentity, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, fileIdentity{}, loadError(ReasonFileType, errors.New("manifest path is a symlink"))
		}
		return nil, fileIdentity{}, loadError(ReasonFileOpen, errors.New("manifest could not be opened"))
	}
	file := os.NewFile(uintptr(fd), path)
	identity, err := platformStat(file)
	if err != nil {
		file.Close()
		return nil, fileIdentity{}, loadError(ReasonFileOpen, errors.New("manifest could not be stat'ed"))
	}
	if !identity.Regular {
		file.Close()
		return nil, fileIdentity{}, loadError(ReasonFileType, errors.New("manifest path is not a regular file"))
	}
	if requireOwner {
		if identity.Owner != uint32(os.Geteuid()) {
			file.Close()
			return nil, fileIdentity{}, loadError(ReasonFilePermissions, errors.New("manifest is not owned by the effective user"))
		}
		if identity.GroupOrWorldWritable {
			file.Close()
			return nil, fileIdentity{}, loadError(ReasonFilePermissions, errors.New("manifest is group- or world-writable"))
		}
	}
	// The file is regular, so blocking reads are safe and cheaper.
	_ = syscall.SetNonblock(fd, false)
	return file, identity, nil
}

func platformStat(file *os.File) (fileIdentity, error) {
	info, err := file.Stat()
	if err != nil {
		return fileIdentity{}, err
	}
	identity := fileIdentity{
		Size:                 info.Size(),
		ModTime:              info.ModTime(),
		Regular:              info.Mode().IsRegular(),
		GroupOrWorldWritable: info.Mode().Perm()&0o022 != 0,
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		identity.Inode = uint64(stat.Ino)
		identity.Device = uint64(stat.Dev)
		identity.Owner = stat.Uid
	} else {
		return fileIdentity{}, errors.New("stat did not return a Stat_t")
	}
	return identity, nil
}
