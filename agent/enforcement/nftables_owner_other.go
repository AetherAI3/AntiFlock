//go:build !linux

package enforcement

import "os"

// nftables mutation is supported only on Unix hosts where root ownership can
// be established. Other platforms retain dry-run rendering and library use.
func nftFileOwnedByRoot(_ os.FileInfo) bool {
	return false
}
