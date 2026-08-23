package driver

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"
)

// MaxReservationResultBytes bounds the opaque terminal result a store keeps
// for a released reservation. It equals the enforcer's plan size ceiling.
const MaxReservationResultBytes = 512 * 1024

// Reservation sentinel errors. They mirror enforcement.ErrPlanReplay and
// enforcement.ErrPlanInProgress closely enough that an adapter can map one
// onto the other without losing the distinction the enforcer reports.
var (
	// ErrAlreadyReserved reports a Reserve of a plan id that is already
	// reserved under a different key (replay), or of the identical key while
	// the plan is still in progress.
	ErrAlreadyReserved = errors.New("plan is already reserved")
	// ErrStaleRevision reports a policy revision below the durable policy
	// floor or a plan revision at or below the durable plan floor.
	ErrStaleRevision = errors.New("plan revision is stale")
	// ErrReservationNotTerminal reports a Release whose step is not
	// terminal; reservations are released only by commit or rollback.
	ErrReservationNotTerminal = errors.New("reservation can only be released by a terminal step")
	// ErrReservationUnknown reports a Release for a token the store never
	// issued.
	ErrReservationUnknown = errors.New("reservation is unknown")
	// ErrReservationConflict reports a second Release with a different
	// terminal step or result than the one already stored.
	ErrReservationConflict = errors.New("reservation was already released with a different result")
)

// Reservation is the outcome of Reserve. A fresh reservation has
// Replayed=false. An identical key redelivered after release has
// Replayed=true and carries the stored terminal step and result, matching
// the enforcer's idempotent redelivery of a persisted signed result.
type Reservation struct {
	Token    ReservationToken
	Replayed bool
	Terminal Step
	Result   []byte
}

// RevisionFloor is the pair of durable monotonic floors a store enforces.
type RevisionFloor struct {
	PolicyRevision uint64
	PlanRevision   uint64
}

// ReservationStore is the durable replay boundary. Guarantee: Reserve
// persists before it returns; the identical key redelivered after release
// returns the stored terminal result; the identical key while in progress,
// or the same plan id under a different key, is ErrAlreadyReserved; a policy
// revision below the policy floor or a plan revision at or below the plan
// floor is ErrStaleRevision; Release accepts only terminal steps, stores an
// opaque bounded result, and never forgets the key; Floor reports both
// durable floors.
type ReservationStore interface {
	Reserve(ctx context.Context, key ReservationKey) (Reservation, error)
	Release(ctx context.Context, token ReservationToken, terminal Step, result []byte) error
	Floor(ctx context.Context) (RevisionFloor, error)
}

type reservationRecord struct {
	token    ReservationToken
	released bool
	terminal Step
	result   []byte
}

// MemoryReservationStore is the in-process ReservationStore for tests and
// simulation. Its semantics match enforcement.MemoryStateStore: both floors
// are monotonic and a plan id is reserved at most once.
type MemoryReservationStore struct {
	mu      sync.Mutex
	floor   RevisionFloor
	clock   func() time.Time
	records map[string]reservationRecord
}

// NewMemoryReservationStore returns a store whose floors start at the given
// revisions. The clock stamps IssuedAt; a nil clock uses time.Now.
func NewMemoryReservationStore(lastPolicyRevision, lastPlanRevision uint64, clock func() time.Time) *MemoryReservationStore {
	if clock == nil {
		clock = time.Now
	}
	return &MemoryReservationStore{
		floor: RevisionFloor{PolicyRevision: lastPolicyRevision, PlanRevision: lastPlanRevision},
		clock: clock, records: make(map[string]reservationRecord),
	}
}

// Reserve implements ReservationStore.
func (store *MemoryReservationStore) Reserve(ctx context.Context, key ReservationKey) (Reservation, error) {
	if store == nil {
		return Reservation{}, errors.New("reservation store is required")
	}
	if err := ctx.Err(); err != nil {
		return Reservation{}, err
	}
	digest, err := key.Digest()
	if err != nil {
		return Reservation{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if existing, exists := store.records[key.PlanID]; exists {
		if existing.token.Key != key {
			return Reservation{}, ErrAlreadyReserved
		}
		if !existing.released {
			return Reservation{}, ErrAlreadyReserved
		}
		return Reservation{Token: existing.token, Replayed: true, Terminal: existing.terminal, Result: slices.Clone(existing.result)}, nil
	}
	if key.PolicyRevision < store.floor.PolicyRevision || key.PlanRevision <= store.floor.PlanRevision {
		return Reservation{}, ErrStaleRevision
	}
	token := ReservationToken{Key: key, Token: digest, IssuedAt: store.clock().UTC()}
	if token.IssuedAt.IsZero() {
		return Reservation{}, errors.New("reservation clock returned a zero time")
	}
	store.floor = RevisionFloor{PolicyRevision: key.PolicyRevision, PlanRevision: key.PlanRevision}
	store.records[key.PlanID] = reservationRecord{token: token}
	return Reservation{Token: token}, nil
}

// Release implements ReservationStore.
func (store *MemoryReservationStore) Release(ctx context.Context, token ReservationToken, terminal Step, result []byte) error {
	if store == nil {
		return errors.New("reservation store is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := token.Validate(); err != nil {
		return err
	}
	if !terminal.Terminal() {
		return ErrReservationNotTerminal
	}
	if len(result) > MaxReservationResultBytes {
		return fmt.Errorf("%w: terminal result exceeds %d bytes", ErrInvalidRequest, MaxReservationResultBytes)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	record, exists := store.records[token.Key.PlanID]
	if !exists || record.token.Token != token.Token {
		return ErrReservationUnknown
	}
	if record.released {
		if record.terminal == terminal && slices.Equal(record.result, result) {
			return nil
		}
		return ErrReservationConflict
	}
	record.released = true
	record.terminal = terminal
	record.result = slices.Clone(result)
	store.records[token.Key.PlanID] = record
	return nil
}

// Floor implements ReservationStore.
func (store *MemoryReservationStore) Floor(ctx context.Context) (RevisionFloor, error) {
	if store == nil {
		return RevisionFloor{}, errors.New("reservation store is required")
	}
	if err := ctx.Err(); err != nil {
		return RevisionFloor{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.floor, nil
}
