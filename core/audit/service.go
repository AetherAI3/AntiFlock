package audit

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/DBarr3/AntiFlock/core/storage"
	"github.com/DBarr3/AntiFlock/internal/id"
	"github.com/DBarr3/AntiFlock/internal/model"
)

const (
	auditVerificationPageSize = 100
	anchorVersion             = "antiflock.audit-anchor/v1"
	anchorLockTimeout         = 45 * time.Second
)

type Service struct {
	database   *storage.DB
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
	keyID      string
	keyring    map[string]ed25519.PublicKey
	anchorPath string
	clock      func() time.Time
	mu         sync.Mutex
}

type AppendRequest struct {
	ActorType    string
	ActorID      string
	Action       string
	ResourceType string
	ResourceID   string
	Outcome      string
	Details      any
}

type anchor struct {
	Version   string    `json:"version"`
	KeyID     string    `json:"keyId"`
	Count     uint64    `json:"count"`
	Sequence  uint64    `json:"sequence"`
	HeadHash  string    `json:"headHash"`
	UpdatedAt time.Time `json:"updatedAt"`
	Signature string    `json:"signature"`
}

func New(database *storage.DB, privateKey ed25519.PrivateKey, anchorPath string) (*Service, error) {
	return NewWithKeyring(database, privateKey, nil, anchorPath)
}

// NewWithKeyring keeps historical audit records verifiable across signing-key
// rotation. Historical keys are verification-only; all new entries and anchors
// use the current private key.
func NewWithKeyring(database *storage.DB, privateKey ed25519.PrivateKey, historical []ed25519.PublicKey, anchorPath string) (*Service, error) {
	if database == nil {
		return nil, errors.New("audit database is required")
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("audit private key must be Ed25519")
	}
	if anchorPath == "" {
		return nil, errors.New("audit anchor path is required")
	}
	service := &Service{
		database: database, privateKey: append(ed25519.PrivateKey(nil), privateKey...),
		publicKey: append(ed25519.PublicKey(nil), privateKey.Public().(ed25519.PublicKey)...), anchorPath: anchorPath,
		clock: func() time.Time { return time.Now().UTC() }, keyring: make(map[string]ed25519.PublicKey),
	}
	encodedPublicKey, err := x509.MarshalPKIXPublicKey(service.publicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal audit public key: %w", err)
	}
	fingerprint := sha256.Sum256(encodedPublicKey)
	service.keyID = "audit:" + hex.EncodeToString(fingerprint[:])
	service.keyring[service.keyID] = service.publicKey
	for _, publicKey := range historical {
		if len(publicKey) != ed25519.PublicKeySize {
			return nil, errors.New("historical audit public key must be Ed25519")
		}
		keyID, keyErr := auditKeyID(publicKey)
		if keyErr != nil {
			return nil, keyErr
		}
		service.keyring[keyID] = append(ed25519.PublicKey(nil), publicKey...)
	}
	if err := service.initialize(context.Background()); err != nil {
		return nil, err
	}
	return service, nil
}

func (service *Service) initialize(ctx context.Context) error {
	service.mu.Lock()
	defer service.mu.Unlock()
	release, err := service.acquireAnchorLock(ctx)
	if err != nil {
		return err
	}
	defer release()
	return service.initializeLocked(ctx)
}

func (service *Service) initializeLocked(ctx context.Context) error {
	if _, err := os.Stat(service.anchorPath); errors.Is(err, os.ErrNotExist) {
		head, headErr := service.database.GetAuditHead(ctx)
		if headErr != nil {
			return headErr
		}
		if head.Count != 0 {
			return errors.New("audit entries exist without a trusted external anchor")
		}
		return service.writeAnchor(anchor{Version: anchorVersion, KeyID: service.keyID})
	} else if err != nil {
		return fmt.Errorf("inspect audit anchor: %w", err)
	}
	return service.verifyLocked(ctx)
}

func (service *Service) Append(ctx context.Context, request AppendRequest) (model.AuditEntry, error) {
	return service.AppendWithMutation(ctx, request, service.database.AuditEntryMutation())
}

// AppendWithMutation serializes the chain and executes a storage-issued closed
// mutation capability. Only reviewed storage transitions can implement that
// capability, and each commits the entry in the same SQLite transaction as its
// domain mutation. The external anchor advances only after that commit.
func (service *Service) AppendWithMutation(
	ctx context.Context,
	request AppendRequest,
	mutation storage.AuditedMutation,
) (model.AuditEntry, error) {
	service.mu.Lock()
	defer service.mu.Unlock()
	release, err := service.acquireAnchorLock(ctx)
	if err != nil {
		return model.AuditEntry{}, err
	}
	defer release()
	if mutation == nil {
		return model.AuditEntry{}, errors.New("audit mutation is required")
	}
	for field, value := range map[string]string{
		"actor type": request.ActorType, "actor id": request.ActorID, "action": request.Action,
		"resource type": request.ResourceType, "resource id": request.ResourceID, "outcome": request.Outcome,
	} {
		if !validAuditIdentifier(value, 256) {
			return model.AuditEntry{}, fmt.Errorf("audit %s is required and must be canonical", field)
		}
	}
	currentAnchor, err := service.loadAnchor()
	if err != nil {
		return model.AuditEntry{}, err
	}
	head, err := service.database.GetAuditHead(ctx)
	if err != nil {
		return model.AuditEntry{}, err
	}
	if !anchorMatchesHead(currentAnchor, head) {
		return model.AuditEntry{}, errors.New("audit anchor does not match database head; verification and recovery are required")
	}
	details, err := json.Marshal(request.Details)
	if err != nil {
		return model.AuditEntry{}, fmt.Errorf("encode audit details: %w", err)
	}
	if len(details) > 64*1024 {
		return model.AuditEntry{}, errors.New("audit details exceed 64 KiB")
	}
	entry := model.AuditEntry{
		ID: id.New("audit"), KeyID: service.keyID, OccurredAt: service.clock(), ActorType: request.ActorType,
		ActorID: request.ActorID, Action: request.Action, ResourceType: request.ResourceType,
		ResourceID: request.ResourceID, Outcome: request.Outcome, Details: details,
		PreviousHash: currentAnchor.HeadHash,
	}
	digest, err := hashEntry(entry)
	if err != nil {
		return model.AuditEntry{}, err
	}
	entry.EntryHash = hex.EncodeToString(digest)
	entry.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(service.privateKey, digest))
	if err := storage.CommitAuditedMutation(ctx, mutation, entry); err != nil {
		return model.AuditEntry{}, err
	}
	newHead, err := service.database.GetAuditHead(ctx)
	if err != nil {
		return entry, fmt.Errorf("domain mutation committed but audit head could not be read: %w", err)
	}
	if newHead.Count != head.Count+1 || newHead.Sequence <= head.Sequence || newHead.Hash != entry.EntryHash {
		return entry, errors.New("domain mutation committed but audit head advanced unexpectedly")
	}
	entry.Sequence = newHead.Sequence
	if err := service.writeAnchor(anchor{
		Version: anchorVersion, Count: newHead.Count, Sequence: newHead.Sequence, HeadHash: newHead.Hash,
		KeyID: service.keyID,
	}); err != nil {
		return entry, fmt.Errorf("domain mutation committed but external audit anchor update failed: %w", err)
	}
	return entry, nil
}

func validAuditIdentifier(value string, maximum int) bool {
	if value == "" || len(value) > maximum || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func (service *Service) Verify(ctx context.Context) error {
	service.mu.Lock()
	defer service.mu.Unlock()
	release, err := service.acquireAnchorLock(ctx)
	if err != nil {
		return err
	}
	defer release()
	return service.verifyLocked(ctx)
}

func (service *Service) verifyLocked(ctx context.Context) error {
	trusted, err := service.loadAnchor()
	if err != nil {
		return err
	}
	previous := ""
	var afterSequence, count uint64
	var recoveryAnchors []storage.AuditHead
	prefixMatched := trusted.Count == 0 && trusted.Sequence == 0 && trusted.HeadHash == ""
	for {
		entries, err := service.database.ListAuditEntriesAfter(ctx, afterSequence, auditVerificationPageSize)
		if err != nil {
			return err
		}
		if len(entries) == 0 {
			break
		}
		for _, entry := range entries {
			if entry.Sequence <= afterSequence {
				return fmt.Errorf("audit sequence is not monotonic at %d", entry.Sequence)
			}
			if entry.PreviousHash != previous {
				return fmt.Errorf("audit chain break at sequence %d", entry.Sequence)
			}
			verificationKey, knownKey := service.keyring[entry.KeyID]
			if !knownKey {
				return fmt.Errorf("audit entry %d uses unknown signing key %q", entry.Sequence, entry.KeyID)
			}
			digest, err := hashEntry(entry)
			if err != nil {
				return err
			}
			if hex.EncodeToString(digest) != entry.EntryHash {
				return fmt.Errorf("audit hash mismatch at sequence %d", entry.Sequence)
			}
			signature, err := base64.RawURLEncoding.DecodeString(entry.Signature)
			if err != nil || !ed25519.Verify(verificationKey, digest, signature) {
				return fmt.Errorf("audit signature mismatch at sequence %d", entry.Sequence)
			}
			previous = entry.EntryHash
			afterSequence = entry.Sequence
			count++
			if count == trusted.Count {
				prefixMatched = entry.Sequence == trusted.Sequence && entry.EntryHash == trusted.HeadHash
			}
			if count > trusted.Count {
				recoveryAnchors = append(recoveryAnchors, storage.AuditHead{Count: count, Sequence: entry.Sequence, Hash: entry.EntryHash})
			}
		}
	}
	actual := storage.AuditHead{Count: count, Sequence: afterSequence, Hash: previous}
	state, err := service.database.GetAuditHead(ctx)
	if err != nil {
		return err
	}
	if state != actual {
		return fmt.Errorf("audit state does not match verified chain: state=%+v chain=%+v", state, actual)
	}
	if anchorMatchesHead(trusted, actual) {
		return nil
	}
	if count > trusted.Count && prefixMatched {
		for _, recovered := range recoveryAnchors {
			if err := service.writeAnchor(anchor{
				Version: anchorVersion, KeyID: service.keyID, Count: recovered.Count, Sequence: recovered.Sequence, HeadHash: recovered.Hash,
			}); err != nil {
				return err
			}
		}
		return nil
	}
	return fmt.Errorf(
		"audit truncation or anchor divergence detected: anchor count=%d sequence=%d, database count=%d sequence=%d",
		trusted.Count, trusted.Sequence, actual.Count, actual.Sequence,
	)
}

func (service *Service) acquireAnchorLock(ctx context.Context) (func(), error) {
	lockPath := service.anchorPath + ".lock"
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o700); err != nil {
		return nil, fmt.Errorf("create audit lock directory: %w", err)
	}
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open cross-process audit anchor lock: %w", err)
	}
	if err := lock.Chmod(0o600); err != nil {
		lock.Close()
		return nil, fmt.Errorf("protect cross-process audit anchor lock: %w", err)
	}
	deadline := time.Now().Add(anchorLockTimeout)
	for {
		acquired, lockErr := tryLockAnchorFile(lock)
		if lockErr != nil {
			lock.Close()
			return nil, fmt.Errorf("acquire cross-process audit anchor lock: %w", lockErr)
		}
		if acquired {
			return func() {
				_ = unlockAnchorFile(lock)
				_ = lock.Close()
			}, nil
		}
		if time.Now().After(deadline) {
			lock.Close()
			return nil, errors.New("timed out waiting for the cross-process audit anchor lock")
		}
		timer := time.NewTimer(20 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			lock.Close()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

func anchorMatchesHead(value anchor, head storage.AuditHead) bool {
	return value.Count == head.Count && value.Sequence == head.Sequence && value.HeadHash == head.Hash
}

func (service *Service) loadAnchor() (anchor, error) {
	content, err := os.ReadFile(service.anchorPath)
	if err != nil {
		return anchor{}, fmt.Errorf("read audit anchor: %w", err)
	}
	if len(content) == 0 {
		return anchor{}, errors.New("audit anchor journal is empty")
	}
	if content[len(content)-1] != '\n' {
		lastComplete := bytes.LastIndexByte(content, '\n')
		if lastComplete < 0 {
			return anchor{}, errors.New("audit anchor journal has no complete record")
		}
		file, openErr := os.OpenFile(service.anchorPath, os.O_WRONLY, 0o600)
		if openErr != nil {
			return anchor{}, fmt.Errorf("open torn audit anchor for repair: %w", openErr)
		}
		if truncateErr := file.Truncate(int64(lastComplete + 1)); truncateErr != nil {
			file.Close()
			return anchor{}, fmt.Errorf("truncate torn audit anchor tail: %w", truncateErr)
		}
		if syncErr := file.Sync(); syncErr != nil {
			file.Close()
			return anchor{}, fmt.Errorf("sync repaired audit anchor: %w", syncErr)
		}
		if closeErr := file.Close(); closeErr != nil {
			return anchor{}, fmt.Errorf("close repaired audit anchor: %w", closeErr)
		}
		content = content[:lastComplete+1]
	}
	var current anchor
	lines := bytes.Split(bytes.TrimSuffix(content, []byte{'\n'}), []byte{'\n'})
	for index, lineBytes := range lines {
		line := index + 1
		var value anchor
		if err := json.Unmarshal(lineBytes, &value); err != nil {
			return anchor{}, fmt.Errorf("decode audit anchor journal line %d: %w", line, err)
		}
		if err := service.verifyAnchor(value); err != nil {
			return anchor{}, fmt.Errorf("verify audit anchor journal line %d: %w", line, err)
		}
		if line == 1 {
			if value.Count != 0 || value.Sequence != 0 || value.HeadHash != "" {
				return anchor{}, errors.New("audit anchor journal is missing its genesis record")
			}
		} else if value.Count != current.Count+1 || value.Sequence <= current.Sequence || value.HeadHash == "" {
			return anchor{}, fmt.Errorf("audit anchor journal is not monotonic at line %d", line)
		}
		current = value
	}
	return current, nil
}

func (service *Service) writeAnchor(value anchor) error {
	value.Version = anchorVersion
	value.KeyID = service.keyID
	value.UpdatedAt = service.clock()
	digest, err := anchorDigest(value)
	if err != nil {
		return err
	}
	value.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(service.privateKey, digest))
	content, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode audit anchor: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(service.anchorPath), 0o700); err != nil {
		return fmt.Errorf("create audit anchor directory: %w", err)
	}
	file, err := os.OpenFile(service.anchorPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open audit anchor journal: %w", err)
	}
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return fmt.Errorf("protect audit anchor: %w", err)
	}
	if _, err := file.Write(append(content, '\n')); err != nil {
		file.Close()
		return fmt.Errorf("write audit anchor: %w", err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return fmt.Errorf("sync audit anchor: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close audit anchor: %w", err)
	}
	return nil
}

func (service *Service) verifyAnchor(value anchor) error {
	if value.Version != anchorVersion {
		return fmt.Errorf("unsupported audit anchor version %q", value.Version)
	}
	verificationKey, knownKey := service.keyring[value.KeyID]
	if !knownKey {
		return fmt.Errorf("unknown audit anchor signing key %q", value.KeyID)
	}
	signature, err := base64.RawURLEncoding.DecodeString(value.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("audit anchor signature encoding is invalid")
	}
	digest, err := anchorDigest(value)
	if err != nil {
		return err
	}
	if !ed25519.Verify(verificationKey, digest, signature) {
		return errors.New("audit anchor signature verification failed")
	}
	return nil
}

func auditKeyID(publicKey ed25519.PublicKey) (string, error) {
	encoded, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("marshal audit public key: %w", err)
	}
	fingerprint := sha256.Sum256(encoded)
	return "audit:" + hex.EncodeToString(fingerprint[:]), nil
}

func anchorDigest(value anchor) ([]byte, error) {
	payload := struct {
		Version   string `json:"version"`
		KeyID     string `json:"keyId"`
		Count     uint64 `json:"count"`
		Sequence  uint64 `json:"sequence"`
		HeadHash  string `json:"headHash"`
		UpdatedAt string `json:"updatedAt"`
	}{value.Version, value.KeyID, value.Count, value.Sequence, value.HeadHash, value.UpdatedAt.UTC().Format(time.RFC3339Nano)}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("encode audit anchor digest: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return digest[:], nil
}

func hashEntry(entry model.AuditEntry) ([]byte, error) {
	payload := struct {
		ID           string          `json:"id"`
		KeyID        string          `json:"keyId"`
		OccurredAt   string          `json:"occurredAt"`
		ActorType    string          `json:"actorType"`
		ActorID      string          `json:"actorId"`
		Action       string          `json:"action"`
		ResourceType string          `json:"resourceType"`
		ResourceID   string          `json:"resourceId"`
		Outcome      string          `json:"outcome"`
		Details      json.RawMessage `json:"details"`
		PreviousHash string          `json:"previousHash"`
	}{
		entry.ID, entry.KeyID, entry.OccurredAt.UTC().Format(time.RFC3339Nano), entry.ActorType,
		entry.ActorID, entry.Action, entry.ResourceType, entry.ResourceID, entry.Outcome,
		entry.Details, entry.PreviousHash,
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("encode audit hash payload: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return digest[:], nil
}
