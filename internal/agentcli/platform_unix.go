//go:build linux || darwin || freebsd || netbsd || openbsd

package agentcli

import (
	"errors"
	"os"
	"runtime"
	"syscall"
)

func osGOOS() string { return runtime.GOOS }

func diskFree(path string) (uint64, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0, errors.New("statfs failed")
	}
	return uint64(stat.Bavail) * uint64(stat.Bsize), nil
}

func ownedByRoot(info os.FileInfo) (bool, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		return false, errors.New("ownership is unavailable")
	}
	return stat.Uid == 0, nil
}
