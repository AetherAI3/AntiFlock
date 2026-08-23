package driver

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"
)

// Step is one stage of the required driver lifecycle. The order of the
// constants is the required order of execution.
type Step uint8

const (
	// StepNone is the zero value and is rejected in records.
	StepNone Step = iota
	// StepCapture reads host state.
	StepCapture
	// StepSimulate predicts the change without touching the host.
	StepSimulate
	// StepApprove binds an external Approval to the exact plan.
	StepApprove
	// StepReserve takes the durable replay reservation.
	StepReserve
	// StepApply mutates the host.
	StepApply
	// StepVerify re-reads the host and compares with the receipt.
	StepVerify
	// StepRecord appends the signable receipts.
	StepRecord
	// StepCommit is the successful terminal step.
	StepCommit
	// StepRollback is the reverting terminal step.
	StepRollback
)

// String returns the stable spelling of the step.
func (step Step) String() string {
	switch step {
	case StepCapture:
		return "CAPTURE"
	case StepSimulate:
		return "SIMULATE"
	case StepApprove:
		return "APPROVE"
	case StepReserve:
		return "RESERVE"
	case StepApply:
		return "APPLY"
	case StepVerify:
		return "VERIFY"
	case StepRecord:
		return "RECORD"
	case StepCommit:
		return "COMMIT"
	case StepRollback:
		return "ROLLBACK"
	default:
		return "NONE"
	}
}

// Valid reports whether the step is a named lifecycle step.
func (step Step) Valid() bool { return step >= StepCapture && step <= StepRollback }

// Terminal reports whether the step ends a lifecycle.
func (step Step) Terminal() bool { return step == StepCommit || step == StepRollback }

// JournalKind classifies a JournalRecord.
type JournalKind uint8

const (
	// JournalKindUnknown is the zero value and is rejected.
	JournalKindUnknown JournalKind = iota
	// JournalKindBegin opens an in-flight entry.
	JournalKindBegin
	// JournalKindAdvance moves an open entry to a later step.
	JournalKindAdvance
	// JournalKindFinish closes an entry at a terminal step.
	JournalKindFinish
)

// String returns the stable spelling of the kind.
func (kind JournalKind) String() string {
	switch kind {
	case JournalKindBegin:
		return "BEGIN"
	case JournalKindAdvance:
		return "ADVANCE"
	case JournalKindFinish:
		return "FINISH"
	default:
		return "UNKNOWN"
	}
}

// JournalRecord is one append-only line of the crash-safe journal. Every
// record is written before the action it describes takes effect on the host,
// so an interrupted process leaves an open entry recovery can act on.
// OwnershipToken, Digest, Target and Reservation are empty until the step that
// produces them; together they let a Lifecycle that crashed at any step
// re-derive the ownership token, verify or roll back, and release the
// reservation without any other state.
type JournalRecord struct {
	SchemaVersion  uint32
	Kind           JournalKind
	PlanID         string
	PlanRevision   uint64
	OperationID    string
	Step           Step
	OwnershipToken string
	Digest         string
	Target         string
	Reservation    ReservationKey
	At             time.Time
}

// Validate enforces the JournalRecord invariants.
func (record JournalRecord) Validate() error {
	if record.SchemaVersion != ContractVersion {
		return fmt.Errorf("%w: journal record schema version %d is not %d", ErrInvalidRequest, record.SchemaVersion, ContractVersion)
	}
	if record.Kind == JournalKindUnknown || record.Kind > JournalKindFinish {
		return fmt.Errorf("%w: journal record kind is unknown", ErrInvalidRequest)
	}
	if !validIdentifier(record.PlanID) || record.PlanRevision == 0 || !validIdentifier(record.OperationID) {
		return fmt.Errorf("%w: journal record plan id, revision and operation id are required", ErrInvalidRequest)
	}
	if !record.Step.Valid() {
		return fmt.Errorf("%w: journal record step is unknown", ErrInvalidRequest)
	}
	if record.Kind == JournalKindFinish && !record.Step.Terminal() {
		return fmt.Errorf("%w: journal finish must name a terminal step", ErrInvalidRequest)
	}
	if record.Kind != JournalKindFinish && record.Step.Terminal() {
		return fmt.Errorf("%w: only journal finish may name a terminal step", ErrInvalidRequest)
	}
	if record.OwnershipToken != "" && !validIdentifier(record.OwnershipToken) {
		return fmt.Errorf("%w: journal record ownership token is not a bounded identifier", ErrInvalidRequest)
	}
	if record.Digest != "" && !validDigest(record.Digest) {
		return fmt.Errorf("%w: journal record digest must be hex SHA-256", ErrInvalidRequest)
	}
	if record.Target != "" {
		if err := ValidateTarget(record.Target); err != nil {
			return err
		}
	}
	if record.Reservation != (ReservationKey{}) {
		if err := record.Reservation.Validate(); err != nil {
			return err
		}
	}
	if record.At.IsZero() {
		return fmt.Errorf("%w: journal record at is required", ErrInvalidRequest)
	}
	return nil
}

// Identity returns the (plan id, revision, operation id) key of the record.
func (record JournalRecord) Identity() JournalIdentity {
	return JournalIdentity{PlanID: record.PlanID, PlanRevision: record.PlanRevision, OperationID: record.OperationID}
}

// JournalIdentity keys one operation of one plan revision.
type JournalIdentity struct {
	PlanID       string
	PlanRevision uint64
	OperationID  string
}

// Journal sentinel errors.
var (
	// ErrJournalCorrupt reports a journal that cannot be trusted. A driver
	// must report HealthUnavailable with ReasonProbeJournalCorrupt and
	// refuse to mutate until an operator intervenes.
	ErrJournalCorrupt = errors.New("driver journal is corrupt")
	// ErrJournalActive reports a Begin for an identity that already has an
	// open entry.
	ErrJournalActive = errors.New("driver journal entry is already open")
	// ErrJournalInactive reports an Advance or Finish for an identity with
	// no open entry.
	ErrJournalInactive = errors.New("driver journal entry is not open")
	// ErrJournalOrder reports an Advance to a step that is not later than
	// the open entry's current step.
	ErrJournalOrder = errors.New("driver journal step must advance")
	// ErrJournalFull reports a journal at its size bound.
	ErrJournalFull = errors.New("driver journal is full")
)

// MaxJournalRecords bounds every Journal implementation. Finished entries are
// compacted away once the journal exceeds JournalCompactionThreshold, so the
// bound only limits simultaneously open work plus recent history.
const (
	MaxJournalRecords          = 4096
	JournalCompactionThreshold = 1024
)

// Journal is the crash-safe state journal. Guarantee: every write is durable
// before it returns; records are append-only; at most one open entry exists
// per JournalIdentity; InFlight reports the latest record of each open
// entry; a journal that fails to load yields ErrJournalCorrupt from every
// method.
type Journal interface {
	Begin(ctx context.Context, record JournalRecord) error
	Advance(ctx context.Context, record JournalRecord) error
	Finish(ctx context.Context, record JournalRecord) error
	InFlight(ctx context.Context) ([]JournalRecord, error)
	Records(ctx context.Context) ([]JournalRecord, error)
}

// journalState is the pure, storage-independent journal discipline shared by
// MemoryJournal and FileJournal.
type journalState struct {
	records []JournalRecord
}

func (state *journalState) open() map[JournalIdentity]JournalRecord {
	open := make(map[JournalIdentity]JournalRecord)
	for _, record := range state.records {
		identity := record.Identity()
		switch record.Kind {
		case JournalKindBegin, JournalKindAdvance:
			open[identity] = record
		case JournalKindFinish:
			delete(open, identity)
		}
	}
	return open
}

// check validates the whole record sequence; it is what load uses to decide
// ErrJournalCorrupt.
func (state *journalState) check() error {
	if len(state.records) > MaxJournalRecords {
		return fmt.Errorf("%w: more than %d records", ErrJournalCorrupt, MaxJournalRecords)
	}
	open := make(map[JournalIdentity]JournalRecord)
	for _, record := range state.records {
		if err := record.Validate(); err != nil {
			return fmt.Errorf("%w: %v", ErrJournalCorrupt, err)
		}
		identity := record.Identity()
		current, isOpen := open[identity]
		switch record.Kind {
		case JournalKindBegin:
			if isOpen {
				return fmt.Errorf("%w: duplicate begin", ErrJournalCorrupt)
			}
			open[identity] = record
		case JournalKindAdvance:
			if !isOpen || record.Step <= current.Step {
				return fmt.Errorf("%w: advance without open entry or out of order", ErrJournalCorrupt)
			}
			open[identity] = record
		case JournalKindFinish:
			if !isOpen {
				return fmt.Errorf("%w: finish without open entry", ErrJournalCorrupt)
			}
			delete(open, identity)
		}
	}
	return nil
}

func (state *journalState) append(record JournalRecord) error {
	if err := record.Validate(); err != nil {
		return err
	}
	if len(state.records) >= MaxJournalRecords {
		return ErrJournalFull
	}
	open := state.open()
	current, isOpen := open[record.Identity()]
	switch record.Kind {
	case JournalKindBegin:
		if isOpen {
			return ErrJournalActive
		}
	case JournalKindAdvance:
		if !isOpen {
			return ErrJournalInactive
		}
		if record.Step <= current.Step {
			return ErrJournalOrder
		}
	case JournalKindFinish:
		if !isOpen {
			return ErrJournalInactive
		}
	}
	state.records = append(state.records, record)
	if record.Kind == JournalKindFinish {
		state.compact()
	}
	return nil
}

// compact drops the oldest finished entries once the journal exceeds
// JournalCompactionThreshold, keeping every record of every open entry and
// shrinking to half the threshold so compaction is not re-run on every write.
func (state *journalState) compact() {
	if len(state.records) <= JournalCompactionThreshold {
		return
	}
	open := state.open()
	counts := make(map[JournalIdentity]int)
	for _, record := range state.records {
		counts[record.Identity()]++
	}
	remaining := len(state.records)
	dropped := make(map[JournalIdentity]struct{})
	for _, record := range state.records {
		if remaining <= JournalCompactionThreshold/2 {
			break
		}
		identity := record.Identity()
		if _, isOpen := open[identity]; isOpen {
			continue
		}
		if _, done := dropped[identity]; done {
			continue
		}
		dropped[identity] = struct{}{}
		remaining -= counts[identity]
	}
	if len(dropped) == 0 {
		return
	}
	kept := make([]JournalRecord, 0, remaining)
	for _, record := range state.records {
		if _, drop := dropped[record.Identity()]; !drop {
			kept = append(kept, record)
		}
	}
	state.records = kept
}

func (state *journalState) inFlight() []JournalRecord {
	open := state.open()
	result := make([]JournalRecord, 0, len(open))
	for _, record := range open {
		result = append(result, record)
	}
	slices.SortFunc(result, func(a, b JournalRecord) int {
		if a.PlanID != b.PlanID {
			return compareStrings(a.PlanID, b.PlanID)
		}
		if a.PlanRevision != b.PlanRevision {
			if a.PlanRevision < b.PlanRevision {
				return -1
			}
			return 1
		}
		return compareStrings(a.OperationID, b.OperationID)
	})
	return result
}

func compareStrings(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

// MemoryJournal is the in-process Journal for tests and the reference
// driver. It is safe for concurrent use and survives Reopen of a driver that
// shares the same pointer, which is how the conformance suite models a
// restart.
type MemoryJournal struct {
	mu    sync.Mutex
	state journalState
	// corrupt, when set, makes every method return ErrJournalCorrupt so
	// tests can model an unreadable journal.
	corrupt bool
}

// NewMemoryJournal returns an empty journal.
func NewMemoryJournal() *MemoryJournal { return &MemoryJournal{} }

// Corrupt marks the journal unreadable; every later call returns
// ErrJournalCorrupt.
func (journal *MemoryJournal) Corrupt() {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	journal.corrupt = true
}

func (journal *MemoryJournal) write(ctx context.Context, record JournalRecord) error {
	if journal == nil {
		return errors.New("journal is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if journal.corrupt {
		return ErrJournalCorrupt
	}
	return journal.state.append(record)
}

// Begin implements Journal.
func (journal *MemoryJournal) Begin(ctx context.Context, record JournalRecord) error {
	record.Kind = JournalKindBegin
	return journal.write(ctx, record)
}

// Advance implements Journal.
func (journal *MemoryJournal) Advance(ctx context.Context, record JournalRecord) error {
	record.Kind = JournalKindAdvance
	return journal.write(ctx, record)
}

// Finish implements Journal.
func (journal *MemoryJournal) Finish(ctx context.Context, record JournalRecord) error {
	record.Kind = JournalKindFinish
	return journal.write(ctx, record)
}

// InFlight implements Journal.
func (journal *MemoryJournal) InFlight(ctx context.Context) ([]JournalRecord, error) {
	if journal == nil {
		return nil, errors.New("journal is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if journal.corrupt {
		return nil, ErrJournalCorrupt
	}
	return journal.state.inFlight(), nil
}

// Records implements Journal.
func (journal *MemoryJournal) Records(ctx context.Context) ([]JournalRecord, error) {
	if journal == nil {
		return nil, errors.New("journal is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if journal.corrupt {
		return nil, ErrJournalCorrupt
	}
	return slices.Clone(journal.state.records), nil
}
