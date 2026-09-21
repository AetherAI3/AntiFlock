package capability

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
	"unicode"
)

// Loader bounds.
const (
	// MaxManifestBytes is the largest manifest file the loader will read.
	MaxManifestBytes = 256 * 1024
	// MaxJSONDepth is the deepest nesting the loader accepts. A canonical
	// manifest nests four levels (object, array, object, array).
	MaxJSONDepth = 8
)

// LoadOptions configures LoadManifestFile. ExpectedNodeID and NodePublicKey
// are required: a manifest is never loaded without a node binding and a
// signature check.
type LoadOptions struct {
	ExpectedNodeID string
	NodePublicKey  ed25519.PublicKey
	// Now is the time expiry is evaluated against; zero means time.Now.
	Now time.Time
	// RequireOwner additionally rejects files not owned by the effective user
	// or writable by group or world. Unsupported platforms fail closed.
	RequireOwner bool

	// Test seams. afterOpen runs after the first stat and before the read;
	// betweenReads runs after the read and before the re-stat.
	afterOpen    func()
	betweenReads func()
}

// LoadError carries the stable reason code for a loader failure. Err never
// contains file content.
type LoadError struct {
	Code string
	Err  error
}

func (err *LoadError) Error() string {
	if err.Err == nil {
		return err.Code
	}
	return err.Code + ": " + err.Err.Error()
}

func (err *LoadError) Unwrap() error { return err.Err }

func loadError(code string, err error) error { return &LoadError{Code: code, Err: err} }

// fileIdentity is the platform-independent view of an open file used to
// detect modification between open, read, and re-stat.
type fileIdentity struct {
	Size    int64
	ModTime time.Time
	Inode   uint64
	Device  uint64
	Owner   uint32
	Regular bool
	// GroupOrWorldWritable is only meaningful on platforms with POSIX modes.
	GroupOrWorldWritable bool
}

func (identity fileIdentity) same(other fileIdentity) bool {
	return identity.Size == other.Size && identity.ModTime.Equal(other.ModTime) &&
		identity.Inode == other.Inode && identity.Device == other.Device
}

// LoadManifestFile reads, authenticates, and validates a Manifest from path.
// Checks run in this order, and the first failure is final:
//
//  1. open without following symlinks; reject non-regular files; owner and
//     mode checks when RequireOwner;
//  2. bounded read; the byte count must equal the stat size; the post-read
//     stat must match the pre-read stat (size, mtime, inode, device);
//  3. strict JSON: depth, duplicate keys, hostile strings, unknown fields,
//     trailing content;
//  4. Manifest.Validate;
//  5. node binding (ExpectedNodeID);
//  6. signature (NodePublicKey);
//  7. validity window at Now.
//
// The node binding is checked before the signature on purpose: a manifest
// for another node is reported as a node mismatch even when it carries a
// valid signature from that other node, and the loader never consults any key
// but the expected node's.
func LoadManifestFile(path string, opts LoadOptions) (*Manifest, error) {
	if !validIdentifier(opts.ExpectedNodeID, MaxNodeIDLength) || len(opts.NodePublicKey) != ed25519.PublicKeySize {
		return nil, loadError(ReasonOptionsInvalid, errors.New("expected node id and Ed25519 node public key are required"))
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	data, err := readBounded(path, opts)
	if err != nil {
		return nil, err
	}
	return loadManifestBytes(data, opts.ExpectedNodeID, opts.NodePublicKey, now)
}

func readBounded(path string, opts LoadOptions) ([]byte, error) {
	file, before, err := openNoFollow(path, opts.RequireOwner)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if !before.Regular {
		return nil, loadError(ReasonFileType, errors.New("manifest path is not a regular file"))
	}
	if before.Size > MaxManifestBytes {
		return nil, loadError(ReasonFileOversize, fmt.Errorf("manifest exceeds %d bytes", MaxManifestBytes))
	}
	if opts.afterOpen != nil {
		opts.afterOpen()
	}
	data, err := io.ReadAll(io.LimitReader(file, MaxManifestBytes+1))
	if err != nil {
		return nil, loadError(ReasonFileChanged, errors.New("manifest read failed"))
	}
	if len(data) > MaxManifestBytes {
		return nil, loadError(ReasonFileOversize, fmt.Errorf("manifest exceeds %d bytes", MaxManifestBytes))
	}
	if int64(len(data)) != before.Size {
		return nil, loadError(ReasonFileChanged, errors.New("manifest size changed during read"))
	}
	if opts.betweenReads != nil {
		opts.betweenReads()
	}
	after, err := statOpen(file)
	if err != nil {
		return nil, err
	}
	if !before.same(after) {
		return nil, loadError(ReasonFileChanged, errors.New("manifest changed after read"))
	}
	return data, nil
}

// loadManifestBytes is the file-independent half of LoadManifestFile. It is
// the fuzz target.
func loadManifestBytes(data []byte, expectedNodeID string, nodePublicKey ed25519.PublicKey, now time.Time) (*Manifest, error) {
	if len(data) > MaxManifestBytes {
		return nil, loadError(ReasonFileOversize, fmt.Errorf("manifest exceeds %d bytes", MaxManifestBytes))
	}
	if err := prescanJSON(data); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil {
		if isUnknownField(err) {
			return nil, loadError(ReasonJSONUnknownField, errors.New("manifest contains an unknown field"))
		}
		return nil, loadError(ReasonJSONSyntax, errors.New("manifest is not valid JSON for the schema"))
	}
	if decoder.More() {
		return nil, loadError(ReasonJSONTrailing, errors.New("content follows the manifest object"))
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, loadError(ReasonJSONTrailing, errors.New("content follows the manifest object"))
	}
	if err := manifest.Validate(); err != nil {
		return nil, loadError(ReasonSchema, err)
	}
	if manifest.NodeID != expectedNodeID {
		return nil, loadError(ReasonNodeMismatch, errors.New("manifest belongs to another node"))
	}
	if err := manifest.Verify(nodePublicKey); err != nil {
		return nil, loadError(ReasonSignatureInvalid, err)
	}
	if !now.Before(manifest.ExpiresAt) {
		return nil, loadError(ReasonExpired, errors.New("manifest has expired"))
	}
	if manifest.IssuedAt.After(now.Add(maxClockSkew)) {
		return nil, loadError(ReasonNotYetValid, errors.New("manifest is issued in the future"))
	}
	return &manifest, nil
}

func isUnknownField(err error) bool {
	// encoding/json reports this as a plain error string; there is no typed
	// sentinel.
	return err != nil && bytes.Contains([]byte(err.Error()), []byte("unknown field"))
}

type jsonFrame struct {
	object    bool
	expectKey bool
	seen      map[string]struct{}
}

// prescanJSON walks the token stream once before decoding to enforce depth,
// duplicate member names, hostile strings, a single top-level object, and no
// trailing tokens. It operates on tokens only and allocates per object.
func prescanJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	var stack []jsonFrame
	sawTopLevel := false
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if sawTopLevel && len(stack) == 0 {
			return loadError(ReasonJSONTrailing, errors.New("content follows the manifest object"))
		}
		if err != nil {
			return loadError(ReasonJSONSyntax, errors.New("manifest is not well-formed JSON"))
		}
		if delim, ok := token.(json.Delim); ok {
			switch delim {
			case '{', '[':
				if len(stack) == 0 {
					if delim != '{' {
						return loadError(ReasonJSONSyntax, errors.New("manifest must be a JSON object"))
					}
					sawTopLevel = true
				} else {
					markValue(&stack[len(stack)-1])
				}
				if len(stack)+1 > MaxJSONDepth {
					return loadError(ReasonJSONNesting, fmt.Errorf("nesting exceeds %d", MaxJSONDepth))
				}
				frame := jsonFrame{object: delim == '{', expectKey: delim == '{'}
				if frame.object {
					frame.seen = make(map[string]struct{})
				}
				stack = append(stack, frame)
			case '}', ']':
				stack = stack[:len(stack)-1]
			}
			continue
		}
		if len(stack) == 0 {
			return loadError(ReasonJSONSyntax, errors.New("manifest must be a JSON object"))
		}
		frame := &stack[len(stack)-1]
		if text, ok := token.(string); ok {
			if !cleanString(text) {
				return loadError(ReasonJSONString, errors.New("manifest contains a non-printable or format character"))
			}
			if frame.object && frame.expectKey {
				// encoding/json matches struct fields case-insensitively, so two
				// member names that differ only by case would both bind to one
				// field with last-wins. Fold before comparing.
				folded := strings.ToLower(text)
				if _, duplicate := frame.seen[folded]; duplicate {
					return loadError(ReasonJSONDuplicateKey, errors.New("manifest repeats a member name"))
				}
				frame.seen[folded] = struct{}{}
				frame.expectKey = false
				continue
			}
		}
		markValue(frame)
	}
	if !sawTopLevel || len(stack) != 0 {
		return loadError(ReasonJSONSyntax, errors.New("manifest is not a complete JSON object"))
	}
	return nil
}

func markValue(frame *jsonFrame) {
	if frame.object {
		frame.expectKey = true
	}
}

// cleanString rejects control characters (C0 and DEL), C1 controls, every
// Unicode format character (which includes bidi overrides and zero-width
// joiners), and anything Go does not consider printable. Space is allowed.
func cleanString(value string) bool {
	for _, r := range value {
		if r == unicode.ReplacementChar {
			return false
		}
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			return false
		}
		if unicode.Is(unicode.Cf, r) || unicode.IsControl(r) {
			return false
		}
		if !unicode.IsPrint(r) && r != ' ' {
			return false
		}
	}
	return true
}

// statOpen re-stats an open file for the post-read comparison.
func statOpen(file *os.File) (fileIdentity, error) {
	identity, err := platformStat(file)
	if err != nil {
		return fileIdentity{}, loadError(ReasonFileChanged, errors.New("manifest could not be re-stat'ed"))
	}
	return identity, nil
}
