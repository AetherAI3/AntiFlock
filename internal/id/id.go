package id

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// New returns a URL- and log-safe random identifier with a human-readable
// prefix. It deliberately does not encode time, machine identity, or location.
func New(prefix string) string {
	var entropy [16]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		panic(fmt.Errorf("generate random identifier: %w", err))
	}
	return prefix + "_" + hex.EncodeToString(entropy[:])
}
