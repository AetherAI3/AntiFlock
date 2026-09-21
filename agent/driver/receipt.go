package driver

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"
)

// ReceiptKind classifies a Receipt.
type ReceiptKind uint8

const (
	// ReceiptKindUnknown is the zero value and is rejected.
	ReceiptKindUnknown ReceiptKind = iota
	// ReceiptKindApply records a completed mutation.
	ReceiptKindApply
	// ReceiptKindVerify records a post-apply verification.
	ReceiptKindVerify
	// ReceiptKindRollback records a revert.
	ReceiptKindRollback
	// ReceiptKindRecover records a crash-recovery action.
	ReceiptKindRecover
	// ReceiptKindCommit records lifecycle commit.
	ReceiptKindCommit
)

// String returns the stable spelling of the kind.
func (kind ReceiptKind) String() string {
	switch kind {
	case ReceiptKindApply:
		return "APPLY"
	case ReceiptKindVerify:
		return "VERIFY"
	case ReceiptKindRollback:
		return "ROLLBACK"
	case ReceiptKindRecover:
		return "RECOVER"
	case ReceiptKindCommit:
		return "COMMIT"
	default:
		return "UNKNOWN"
	}
}

// Receipt is the signable, append-only record of one driver action. Digest
// is deterministic over every field so a signer can bind it without
// re-encoding.
type Receipt struct {
	SchemaVersion  uint32
	Kind           ReceiptKind
	PlanID         string
	PlanRevision   uint64
	OperationID    string
	Target         string
	OwnershipToken string
	Digest         string
	ReasonCode     string
	At             time.Time
}

// Validate enforces the Receipt invariants.
func (receipt Receipt) Validate() error {
	if receipt.SchemaVersion != ContractVersion {
		return fmt.Errorf("%w: receipt schema version %d is not %d", ErrInvalidRequest, receipt.SchemaVersion, ContractVersion)
	}
	if receipt.Kind == ReceiptKindUnknown || receipt.Kind > ReceiptKindCommit {
		return fmt.Errorf("%w: receipt kind is unknown", ErrInvalidRequest)
	}
	if !validIdentifier(receipt.PlanID) || receipt.PlanRevision == 0 || !validIdentifier(receipt.OperationID) {
		return fmt.Errorf("%w: receipt plan id, revision and operation id are required", ErrInvalidRequest)
	}
	if receipt.Target != "" {
		if err := ValidateTarget(receipt.Target); err != nil {
			return err
		}
	}
	if !validIdentifier(receipt.OwnershipToken) {
		return fmt.Errorf("%w: receipt ownership token is not a bounded identifier", ErrInvalidRequest)
	}
	if !validDigest(receipt.Digest) {
		return fmt.Errorf("%w: receipt digest must be hex SHA-256", ErrInvalidRequest)
	}
	if !validReasonCode(receipt.ReasonCode) {
		return fmt.Errorf("%w: receipt reason code is not a bounded AF- identifier", ErrInvalidRequest)
	}
	if receipt.At.IsZero() {
		return fmt.Errorf("%w: receipt at is required", ErrInvalidRequest)
	}
	return nil
}

// ContentDigest returns the deterministic SHA-256 identity of the receipt.
// It is the value a node key signs.
func (receipt Receipt) ContentDigest() (string, error) {
	if err := receipt.Validate(); err != nil {
		return "", err
	}
	hasher := newDigest("AntiFlock-DriverReceipt-v1")
	hasher.uint(uint64(receipt.SchemaVersion))
	hasher.uint(uint64(receipt.Kind))
	hasher.str(receipt.PlanID)
	hasher.uint(receipt.PlanRevision)
	hasher.str(receipt.OperationID)
	hasher.str(receipt.Target)
	hasher.str(receipt.OwnershipToken)
	hasher.str(receipt.Digest)
	hasher.str(receipt.ReasonCode)
	hasher.time(receipt.At)
	return hasher.hex(), nil
}

// ErrReceiptDuplicate reports an Append of a receipt whose content digest is
// already stored. Receipts are append-only; a duplicate is a replay.
var ErrReceiptDuplicate = errors.New("driver receipt already recorded")

// ReceiptStore is the durable, append-only receipt log. Guarantee: Append
// validates and rejects duplicates; List returns receipts for one plan in
// append order and never mutates the store.
type ReceiptStore interface {
	Append(ctx context.Context, receipt Receipt) error
	List(ctx context.Context, planID string) ([]Receipt, error)
}

// MemoryReceiptStore is the in-process ReceiptStore for tests and the
// reference driver. It is safe for concurrent use.
type MemoryReceiptStore struct {
	mu       sync.Mutex
	receipts []Receipt
	digests  map[string]struct{}
}

// NewMemoryReceiptStore returns an empty store.
func NewMemoryReceiptStore() *MemoryReceiptStore {
	return &MemoryReceiptStore{digests: make(map[string]struct{})}
}

// Append implements ReceiptStore.
func (store *MemoryReceiptStore) Append(ctx context.Context, receipt Receipt) error {
	if store == nil {
		return errors.New("receipt store is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	digest, err := receipt.ContentDigest()
	if err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, duplicate := store.digests[digest]; duplicate {
		return ErrReceiptDuplicate
	}
	store.digests[digest] = struct{}{}
	store.receipts = append(store.receipts, receipt)
	return nil
}

// List implements ReceiptStore.
func (store *MemoryReceiptStore) List(ctx context.Context, planID string) ([]Receipt, error) {
	if store == nil {
		return nil, errors.New("receipt store is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !validIdentifier(planID) {
		return nil, fmt.Errorf("%w: receipt plan id is not a bounded identifier", ErrInvalidRequest)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	var matches []Receipt
	for _, receipt := range store.receipts {
		if receipt.PlanID == planID {
			matches = append(matches, receipt)
		}
	}
	return slices.Clone(matches), nil
}
