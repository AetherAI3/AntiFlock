//go:build linux

package enforcement

import (
	"os"
	"syscall"
)

func nftFileOwnedByRoot(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == 0
}
