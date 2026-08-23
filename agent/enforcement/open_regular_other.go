//go:build plan9 || js || wasip1

package enforcement

import (
	"errors"
	"os"
)

func openRegularFileNoFollow(string) (*os.File, error) {
	return nil, errors.New("no-follow regular-file loading is unavailable on this platform")
}
