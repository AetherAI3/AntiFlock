package driver

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Reservation sentinel errors. They mirror enforcement.ErrPlanReplay and
// enforcement.ErrPlanInProgress closely enough that an adapter can map one
// onto the other without losing the distinction the enforcer reports.
var (
	// ErrAlreadyReserved reports a second Reserve of a key, or of a plan id,
	// that is already reserved; it covers both in-progress and replayed
	// plans because the durable record outlives the run.
	ErrAlreadyReserved = errors.New("plan is already reserved")
	// ErrStaleRevision reports a plan revision at or below the durable
	// monotonic floor.
	ErrStaleRevision = errors.New("plan revision is stale")
	// ErrReservationNotTerminal reports a Release whose step is not
	// terminal; reservations are released only by commit or rollback.
	ErrReservationNotTerminal = errors.New("reservation can only be released by a terminal step")
	// ErrReservationUnknown reports a Release for a token the store never
	// issued.
	ErrReservationUnknown = errors.New("reservation is unknown")
)

// ReservationStore is the durable replay boundary. Guarantee: Reserve
// persists before it returns; a second Reserve of the same key, or of the
// same plan id with a different key, is ErrAlreadyReserved; a revision at or
// below the floor is ErrStaleRevision; Release accepts only terminal steps
// and never forgets the key, so a released plan can never be replayed; Floor
// reports the durable revision below which every plan is stale.
type ReservationStore interface {
	Reserve(ctx context.Context, key ReservationKey) (ReservationToken, error)
	Release(ctx context.Context, token ReservationToken, terminal Step) error
	Floor(ctx context.Context) (uint64, error)
}

type reservationRecord struct {
	token    ReservationToken
	released bool
	terminal Step
}

// MemoryReservationStore is the in-process ReservationStore for tests and
// simulation. Its semantics match enforcement.MemoryStateStore: the plan
// revision floor is monotonic and a plan id is reserved at most once.
type MemoryReservationStore struct {
	mu      sync.Mutex
	floor   uint64
	clock   func() time.Time
	records map[string]reservationRecord
}

// NewMemoryReservationStore returns a store whose floor starts at
// lastPlanRevision. The clock stamps IssuedAt; a nil clock uses time.Now.
func NewMemoryReservationStore(lastPlanRevision uint64, clock func() time.Time) *MemoryReservationStore {
	if clock == nil {
		clock = time.Now
	}
	return &MemoryReservationStore{floor: lastPlanRevision, clock: clock, records: make(map[string]reservationRecord)}
}

// Reserve implements ReservationStore.
func (store *MemoryReservationStore) Reserve(ctx context.Context, key ReservationKey) (ReservationToken, error) {
	if store == nil {
		return ReservationToken{}, errors.New("reservation store is required")
	}
	if err := ctx.Err(); err != nil {
		return ReservationToken{}, err
	}
	digest, err := key.Digest()
	if err != nil {
		return ReservationToken{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, exists := store.records[key.PlanID]; exists {
		return ReservationToken{}, ErrAlreadyReserved
	}
	if key.PlanRevision <= store.floor {
		return ReservationToken{}, ErrStaleRevision
	}
	token := ReservationToken{Key: key, Token: digest, IssuedAt: store.clock().UTC()}
	if token.IssuedAt.IsZero() {
		return ReservationToken{}, errors.New("reservation clock returned a zero time")
	}
	store.floor = key.PlanRevision
	store.records[key.PlanID] = reservationRecord{token: token}
	return token, nil
}

// Release implements ReservationStore.
func (store *MemoryReservationStore) Release(ctx context.Context, token ReservationToken, terminal Step) error {
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
	store.mu.Lock()
	defer store.mu.Unlock()
	record, exists := store.records[token.Key.PlanID]
	if !exists || record.token.Token != token.Token {
		return ErrReservationUnknown
	}
	if record.released {
		if record.terminal == terminal {
			return nil
		}
		return fmt.Errorf("%w: already released by %s", ErrReservationUnknown, record.terminal)
	}
	record.released = true
	record.terminal = terminal
	store.records[token.Key.PlanID] = record
	return nil
}

// Floor implements ReservationStore.
func (store *MemoryReservationStore) Floor(ctx context.Context) (uint64, error) {
	if store == nil {
		return 0, errors.New("reservation store is required")
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.floor, nil
}
