package integration

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"
)

const (
	// MaxIdentifierLength bounds every identifier string crossing a seam.
	MaxIdentifierLength = 256
	// digestLength is the hex length of a SHA-256 digest.
	digestLength = sha256.Size * 2
)

// Digest hashes content with SHA-256 and returns lowercase hex. It is the only
// digest form accepted across any seam.
func Digest(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

// DigestString hashes an identifier so adapters receive a stable, one-way
// reference instead of the raw value. Raw deployment, node, and subject
// identifiers never cross a seam.
func DigestString(value string) string {
	return Digest([]byte(value))
}

// ValidDigest reports whether value is a lowercase hex SHA-256 digest.
func ValidDigest(value string) bool {
	if len(value) != digestLength {
		return false
	}
	for _, r := range value {
		if !(r >= '0' && r <= '9') && !(r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

// ValidIdentifier reports whether value is a non-empty, bounded, canonical
// identifier: printable ASCII without whitespace or control characters.
func ValidIdentifier(value string) bool {
	return ValidIdentifierLen(value, MaxIdentifierLength)
}

// ValidIdentifierLen is ValidIdentifier with a caller-chosen maximum length.
func ValidIdentifierLen(value string, maximum int) bool {
	if value == "" || len(value) > maximum {
		return false
	}
	for _, r := range value {
		if r > unicode.MaxASCII || unicode.IsSpace(r) || unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// KeyID derives the canonical identifier of an Ed25519 public key: the
// prefix, a colon, and the SHA-256 of the PKIX encoding. Every signed record
// crossing a seam names its key this way so a verifier can detect key
// substitution before checking the signature.
func KeyID(prefix string, publicKey ed25519.PublicKey) (string, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return "", fmt.Errorf("%w: public key must be Ed25519", ErrInvalidInput)
	}
	encoded, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("%w: marshal public key: %v", ErrInvalidInput, err)
	}
	return prefix + ":" + Digest(encoded), nil
}

// canonicalTime renders a timestamp in the single form used inside digests.
func canonicalTime(value time.Time) string {
	return value.UTC().Format(time.RFC3339Nano)
}

// canonicalJSON encodes a fixed-order struct payload for hashing.
func canonicalJSON(payload any) ([]byte, error) {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: encode canonical payload: %v", ErrInvalidInput, err)
	}
	return encoded, nil
}

// sortedUnique returns a sorted copy of values without duplicates.
func sortedUnique(values []string) []string {
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

// validStringList reports whether values is bounded, sorted, unique, and every
// element is a valid identifier.
func validStringList(values []string, maximum int) bool {
	if len(values) > maximum {
		return false
	}
	for index, value := range values {
		if !ValidIdentifier(value) {
			return false
		}
		if index > 0 && strings.Compare(values[index-1], value) >= 0 {
			return false
		}
	}
	return true
}
