//go:build !unix && !windows

package capability

import (
	"errors"
	"os"
)

// openNoFollow has no hardened implementation on this platform and fails
// closed rather than falling back to a symlink-following open.
func openNoFollow(string, bool) (*os.File, fileIdentity, error) {
	return nil, fileIdentity{}, loadError(ReasonPlatformUnsupported, errors.New("hardened manifest loading is not implemented on this platform"))
}

func platformStat(*os.File) (fileIdentity, error) {
	return fileIdentity{}, errors.New("hardened manifest loading is not implemented on this platform")
}
