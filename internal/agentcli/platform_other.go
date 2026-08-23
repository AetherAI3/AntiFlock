//go:build !(linux || darwin || freebsd || netbsd || openbsd)

package agentcli

import (
	"errors"
	"os"
	"runtime"
)

func osGOOS() string { return runtime.GOOS }

func diskFree(string) (uint64, error) { return 0, errors.New("free-space query is unsupported") }

func ownedByRoot(os.FileInfo) (bool, error) { return false, errors.New("ownership is unavailable") }
