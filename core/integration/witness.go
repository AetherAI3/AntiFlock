package integration

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"
)

// WitnessKeyPrefix prefixes every witness KeyID (see KeyID).
const WitnessKeyPrefix = "witness"

// NodeCountBucket is a coarse, privacy-preserving size class for a deployment.
// Exact node counts never cross the witness seam.
type NodeCountBucket string

// Node-count buckets accepted in a Checkpoint. The empty bucket means "not
// disclosed" and is always permitted.
const (
	NodeCountUndisclosed NodeCountBucket = ""
	NodeCountNone        NodeCountBucket = "0"
	NodeCountSmall       NodeCountBucket = "1-9"
	NodeCountMedium      NodeCountBucket = "10-99"
	NodeCountLarge       NodeCountBucket = "100-999"
	NodeCountVeryLarge   NodeCountBucket = "1000+"
)

// BucketNodeCount maps an exact count to its NodeCountBucket.
func BucketNodeCount(count int) NodeCountBucket {
	switch {
	case count <= 0:
		return NodeCountNone
	case count < 10:
		return NodeCountSmall
	case count < 100:
		return NodeCountMedium
	case count < 1000:
		return NodeCountLarge
	default:
		return NodeCountVeryLarge
	}
}

func validNodeCountBucket(bucket NodeCountBucket) bool {
	switch bucket {
	case NodeCountUndisclosed, NodeCountNone, NodeCountSmall, NodeCountMedium, NodeCountLarge, NodeCountVeryLarge:
		return true
	}
	return false
}

// Checkpoint is the ONLY value an ExternalWitness receives. It is a
// privacy-minimal projection of the local audit anchor (core/audit): enough
// for an out-of-band party to later prove that a given audit head existed at a
// given sequence, and nothing else.
//
// Privacy rule: no raw deployment id, no node ids, no labels, no user content,
// no telemetry. The field set is pinned by TestCheckpointFieldAllowlist; adding
// a field is a privacy decision that must update that test.
//
// InterfaceVersion = 1.
type Checkpoint struct {
	// DeploymentDigest is DigestString(deploymentID): a stable one-way
	// reference, never the identifier itself.
	DeploymentDigest string `json:"deploymentDigest"`
	// AuditHeadDigest is the hex audit head hash (model.AuditEntry.EntryHash of
	// the latest committed entry).
	AuditHeadDigest string `json:"auditHeadDigest"`
	// Sequence is the audit head sequence the digest belongs to. It must be
	// positive: the genesis anchor has no head and is never witnessed.
	Sequence uint64 `json:"sequence"`
	// IssuedAt is when core produced the checkpoint.
	IssuedAt time.Time `json:"issuedAt"`
	// NodeCountBucket is the coarse deployment size class, or empty.
	NodeCountBucket NodeCountBucket `json:"nodeCountBucket,omitempty"`
}

// Validate reports whether the checkpoint satisfies the seam contract.
func (checkpoint Checkpoint) Validate() error {
	switch {
	case !ValidDigest(checkpoint.DeploymentDigest):
		return fmt.Errorf("%w: checkpoint deployment digest must be a hex SHA-256", ErrInvalidInput)
	case !ValidDigest(checkpoint.AuditHeadDigest):
		return fmt.Errorf("%w: checkpoint audit head digest must be a hex SHA-256", ErrInvalidInput)
	case checkpoint.Sequence == 0:
		return fmt.Errorf("%w: checkpoint sequence must be positive", ErrInvalidInput)
	case checkpoint.IssuedAt.IsZero():
		return fmt.Errorf("%w: checkpoint issued time is required", ErrInvalidInput)
	case !validNodeCountBucket(checkpoint.NodeCountBucket):
		return fmt.Errorf("%w: checkpoint node count bucket is not recognised", ErrInvalidInput)
	}
	return nil
}

// CheckpointDigest returns the canonical digest a witness signs over. Both
// sides compute it independently; a receipt is bound to exactly this value.
func CheckpointDigest(checkpoint Checkpoint) (string, error) {
	if err := checkpoint.Validate(); err != nil {
		return "", err
	}
	encoded, err := canonicalJSON(struct {
		Version          int    `json:"version"`
		DeploymentDigest string `json:"deploymentDigest"`
		AuditHeadDigest  string `json:"auditHeadDigest"`
		Sequence         uint64 `json:"sequence"`
		IssuedAt         string `json:"issuedAt"`
		NodeCountBucket  string `json:"nodeCountBucket"`
	}{
		InterfaceVersion, checkpoint.DeploymentDigest, checkpoint.AuditHeadDigest,
		checkpoint.Sequence, canonicalTime(checkpoint.IssuedAt), string(checkpoint.NodeCountBucket),
	})
	if err != nil {
		return "", err
	}
	return Digest(encoded), nil
}

// WitnessReceipt is the witness's signed acknowledgement of one Checkpoint.
//
// InterfaceVersion = 1.
type WitnessReceipt struct {
	// WitnessID is the witness's self-chosen identifier (a canonical
	// identifier, not a hostname or address).
	WitnessID string `json:"witnessId"`
	// CheckpointDigest is CheckpointDigest(checkpoint) as computed by the
	// witness. Core compares it with its own computation.
	CheckpointDigest string `json:"checkpointDigest"`
	// WitnessedAt is the witness's own clock reading. It is evidence of what
	// the witness claims, not a trusted timestamp.
	WitnessedAt time.Time `json:"witnessedAt"`
	// Signature is the Ed25519 signature over ReceiptSigningPayload.
	Signature []byte `json:"signature"`
	// KeyID is KeyID(WitnessKeyPrefix, witnessPublicKey).
	KeyID string `json:"keyId"`
}

// ReceiptSigningPayload returns the bytes a witness signs for a receipt. The
// signature field itself is excluded.
func ReceiptSigningPayload(receipt WitnessReceipt) ([]byte, error) {
	if !ValidIdentifier(receipt.WitnessID) {
		return nil, fmt.Errorf("%w: receipt witness id must be a canonical identifier", ErrInvalidReceipt)
	}
	if !ValidDigest(receipt.CheckpointDigest) {
		return nil, fmt.Errorf("%w: receipt checkpoint digest must be a hex SHA-256", ErrInvalidReceipt)
	}
	if receipt.WitnessedAt.IsZero() {
		return nil, fmt.Errorf("%w: receipt witnessed time is required", ErrInvalidReceipt)
	}
	if !ValidIdentifier(receipt.KeyID) {
		return nil, fmt.Errorf("%w: receipt key id must be a canonical identifier", ErrInvalidReceipt)
	}
	encoded, err := canonicalJSON(struct {
		Version          int    `json:"version"`
		WitnessID        string `json:"witnessId"`
		CheckpointDigest string `json:"checkpointDigest"`
		WitnessedAt      string `json:"witnessedAt"`
		KeyID            string `json:"keyId"`
	}{InterfaceVersion, receipt.WitnessID, receipt.CheckpointDigest, canonicalTime(receipt.WitnessedAt), receipt.KeyID})
	if err != nil {
		return nil, err
	}
	digest := Digest(encoded)
	return []byte(digest), nil
}

// SignReceipt fills Signature and KeyID for a receipt using the witness's
// private key. Reference adapters use it; a remote witness performs the same
// computation on its own side.
func SignReceipt(receipt WitnessReceipt, privateKey ed25519.PrivateKey) (WitnessReceipt, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return WitnessReceipt{}, fmt.Errorf("%w: witness private key must be Ed25519", ErrInvalidInput)
	}
	keyID, err := KeyID(WitnessKeyPrefix, privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		return WitnessReceipt{}, err
	}
	receipt.KeyID = keyID
	receipt.WitnessedAt = receipt.WitnessedAt.UTC()
	payload, err := ReceiptSigningPayload(receipt)
	if err != nil {
		return WitnessReceipt{}, err
	}
	receipt.Signature = ed25519.Sign(privateKey, payload)
	return receipt, nil
}

// VerifyReceipt checks that receipt was signed by witnessPublicKey and that
// its KeyID names that key. It does not check the receipt against any
// checkpoint; callers compare receipt.CheckpointDigest with their own
// CheckpointDigest computation.
func VerifyReceipt(receipt WitnessReceipt, witnessPublicKey ed25519.PublicKey) error {
	if len(witnessPublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: witness public key must be Ed25519", ErrInvalidInput)
	}
	expectedKeyID, err := KeyID(WitnessKeyPrefix, witnessPublicKey)
	if err != nil {
		return err
	}
	if receipt.KeyID != expectedKeyID {
		return fmt.Errorf("%w: receipt key id does not name the witness key", ErrInvalidReceipt)
	}
	if len(receipt.Signature) != ed25519.SignatureSize {
		return fmt.Errorf("%w: receipt signature has the wrong size", ErrInvalidReceipt)
	}
	payload, err := ReceiptSigningPayload(receipt)
	if err != nil {
		return err
	}
	if !ed25519.Verify(witnessPublicKey, payload, receipt.Signature) {
		return fmt.Errorf("%w: receipt signature does not verify", ErrInvalidReceipt)
	}
	return nil
}

// VerifyReceiptFor is VerifyReceipt plus the digest binding to checkpoint.
func VerifyReceiptFor(receipt WitnessReceipt, checkpoint Checkpoint, witnessPublicKey ed25519.PublicKey) error {
	expected, err := CheckpointDigest(checkpoint)
	if err != nil {
		return err
	}
	if receipt.CheckpointDigest != expected {
		return fmt.Errorf("%w: receipt is bound to a different checkpoint", ErrInvalidReceipt)
	}
	return VerifyReceipt(receipt, witnessPublicKey)
}

// ExternalWitness is an out-of-band party that records audit-head
// checkpoints so that a coordinated rollback of the local database and anchor
// journal (docs/threat-model.md, residual truth for audit tampering) becomes
// detectable.
//
// Guarantees: Submit is called only with a Checkpoint that passes Validate.
// A witness MAY reject a checkpoint whose Sequence does not exceed the last
// one it recorded for the same DeploymentDigest; it MUST NOT alter a
// checkpoint. A returned receipt MUST verify under the witness's public key
// and MUST be bound to CheckpointDigest(checkpoint).
//
// Failure semantics: a wrapped ErrInvalidInput means the checkpoint was
// refused and nothing was recorded; a wrapped ErrUnavailable means the
// outcome is unknown and the caller may retry with the same checkpoint; any
// other error is permanent for that checkpoint. Core treats witness failure
// as a degraded-evidence condition, never as a reason to block local
// operation.
//
// Privacy rule: the witness learns a deployment digest, an audit head digest,
// a sequence, a timestamp, and optionally a node-count bucket. Nothing else.
//
// InterfaceVersion = 1.
type ExternalWitness interface {
	Submit(ctx context.Context, checkpoint Checkpoint) (WitnessReceipt, error)
}

// ErrSequenceRegression is returned by witnesses that refuse a checkpoint
// whose sequence does not advance past the last witnessed one for the same
// deployment. It wraps ErrInvalidInput.
var ErrSequenceRegression = fmt.Errorf("%w: checkpoint sequence does not advance", ErrInvalidInput)

// IsRetryable reports whether an adapter error allows retry with the same
// input.
func IsRetryable(err error) bool {
	return errors.Is(err, ErrUnavailable)
}
