package sim

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const liveStateSchema = "antiflock.sim-state/v1"

type liveState struct {
	SchemaVersion      string `json:"schemaVersion"`
	NodeID             string `json:"nodeId"`
	EnrollmentID       string `json:"enrollmentId,omitempty"`
	BootID             string `json:"bootId"`
	PublicKeyDigest    string `json:"publicKeyDigest"`
	EnrollmentIssuedAt string `json:"enrollmentIssuedAt"`
	LastSequence       uint64 `json:"lastSequence"`
}

func ensurePrivateDirectory(path string) error {
	if path == "" {
		return errors.New("simulator state directory is required")
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return errors.New("create simulator state directory")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return errors.New("resolve simulator state directory")
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil || filepath.Clean(resolved) != filepath.Clean(absolute) {
		return errors.New("simulator state directory must not traverse symlinks")
	}
	info, err := os.Lstat(absolute)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("simulator state path is not a private directory")
	}
	if err := os.Chmod(path, 0o700); err != nil {
		return errors.New("restrict simulator state directory")
	}
	return nil
}

func loadLiveState(directory, expectedNodeID string) (*liveState, error) {
	path := filepath.Join(directory, "state.json")
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 {
		return nil, errors.New("simulator state is not a private regular file")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("read simulator state")
	}
	if len(content) == 0 || len(content) > 32*1024 {
		return nil, errors.New("simulator state is empty or oversized")
	}
	var state liveState
	decoder := json.NewDecoder(strings.NewReader(string(content)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return nil, errors.New("simulator state is invalid")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("simulator state contains trailing data")
	}
	if state.SchemaVersion != liveStateSchema || state.NodeID != expectedNodeID || state.BootID == "" ||
		len(state.PublicKeyDigest) != sha256.Size*2 || state.EnrollmentIssuedAt == "" {
		return nil, errors.New("simulator state identity is invalid")
	}
	if _, err := time.Parse(time.RFC3339Nano, state.EnrollmentIssuedAt); err != nil {
		return nil, errors.New("simulator enrollment time is invalid")
	}
	return &state, nil
}

func loadLivePrivateKey(directory string) (ed25519.PrivateKey, bool, error) {
	path := filepath.Join(directory, "node.seed")
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 {
		return nil, false, errors.New("simulator node key is not a private regular file")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, false, errors.New("read simulator node key")
	}
	if len(content) != ed25519.SeedSize {
		return nil, false, errors.New("simulator node key has an invalid size")
	}
	return ed25519.NewKeyFromSeed(content), true, nil
}

func createLiveIdentity(directory, nodeID string, now time.Time) (*liveState, ed25519.PrivateKey, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, errors.New("generate simulator node identity")
	}
	seed := privateKey.Seed()
	keyPath := filepath.Join(directory, "node.seed")
	file, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, nil, errors.New("create simulator node key")
	}
	writeErr := error(nil)
	if _, err := file.Write(seed); err != nil {
		writeErr = errors.New("write simulator node key")
	} else if err := file.Sync(); err != nil {
		writeErr = errors.New("sync simulator node key")
	}
	if closeErr := file.Close(); writeErr == nil && closeErr != nil {
		writeErr = errors.New("close simulator node key")
	}
	if writeErr != nil {
		return nil, nil, writeErr
	}
	bootID, err := randomIdentifier("sim-boot")
	if err != nil {
		return nil, nil, err
	}
	digest := sha256.Sum256(publicKey)
	state := &liveState{
		SchemaVersion: liveStateSchema, NodeID: nodeID, BootID: bootID,
		PublicKeyDigest: hex.EncodeToString(digest[:]), EnrollmentIssuedAt: now.UTC().Truncate(time.Second).Format(time.RFC3339Nano),
	}
	if err := saveLiveState(directory, state); err != nil {
		_ = os.Remove(keyPath)
		return nil, nil, err
	}
	return state, privateKey, nil
}

func validateLiveIdentity(state *liveState, privateKey ed25519.PrivateKey) error {
	if state == nil || len(privateKey) != ed25519.PrivateKeySize {
		return errors.New("simulator node identity is incomplete")
	}
	digest := sha256.Sum256(privateKey.Public().(ed25519.PublicKey))
	if state.PublicKeyDigest != hex.EncodeToString(digest[:]) {
		return errors.New("simulator node key does not match persistent state")
	}
	return nil
}

func saveLiveState(directory string, state *liveState) error {
	if state == nil {
		return errors.New("simulator state is required")
	}
	content, err := json.Marshal(state)
	if err != nil {
		return errors.New("encode simulator state")
	}
	temporary, err := os.CreateTemp(directory, ".state-*.tmp")
	if err != nil {
		return errors.New("create simulator state stage")
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return errors.New("restrict simulator state stage")
	}
	if _, err := temporary.Write(content); err != nil {
		temporary.Close()
		return errors.New("write simulator state stage")
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return errors.New("sync simulator state stage")
	}
	if err := temporary.Close(); err != nil {
		return errors.New("close simulator state stage")
	}
	destination := filepath.Join(directory, "state.json")
	if err := os.Rename(temporaryPath, destination); err != nil {
		return errors.New("install simulator state")
	}
	if err := syncLiveStateDirectory(directory); err != nil {
		return err
	}
	return nil
}

func randomIdentifier(prefix string) (string, error) {
	raw := make([]byte, 12)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate %s identifier", prefix)
	}
	return prefix + "-" + hex.EncodeToString(raw), nil
}
