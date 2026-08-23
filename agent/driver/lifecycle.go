package driver

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
)

// Lifecycle sentinel errors.
var (
	// ErrLifecycleOrder reports a step invoked out of the required order.
	ErrLifecycleOrder = errors.New("driver lifecycle step is out of order")
	// ErrPlanActive reports a Begin while another plan is active.
	ErrPlanActive = errors.New("another plan is active in this lifecycle")
	// ErrNoActivePlan reports a step invoked with no plan begun.
	ErrNoActivePlan = errors.New("no plan is active in this lifecycle")
	// ErrApprovalMismatch reports an Approval that does not bind to the
	// exact plan id, revision, operation and target of the active run.
	ErrApprovalMismatch = errors.New("approval does not bind to the active plan")
	// ErrSimulationRejected reports a simulation that predicted failure.
	ErrSimulationRejected = errors.New("simulation predicted the operation would fail")
	// ErrVerificationFailed reports a post-apply verification mismatch.
	ErrVerificationFailed = errors.New("post-apply verification failed")
)

// MaxStepTimeout is the ceiling for every lifecycle step. It matches the
// enforcer's maximum step timeout so a plan cannot hold the node longer than
// the plan contract already allows.
const MaxStepTimeout = 2 * time.Minute

// StepTimeouts bounds each lifecycle step. Every value must lie in
// (0, MaxStepTimeout].
type StepTimeouts struct {
	Capture  time.Duration
	Simulate time.Duration
	Reserve  time.Duration
	Apply    time.Duration
	Verify   time.Duration
	Record   time.Duration
	Rollback time.Duration
}

// DefaultStepTimeouts returns conservative defaults.
func DefaultStepTimeouts() StepTimeouts {
	return StepTimeouts{
		Capture: 10 * time.Second, Simulate: 5 * time.Second, Reserve: 5 * time.Second,
		Apply: 30 * time.Second, Verify: 10 * time.Second, Record: 5 * time.Second, Rollback: 30 * time.Second,
	}
}

// Validate enforces the StepTimeouts invariants.
func (timeouts StepTimeouts) Validate() error {
	for name, value := range map[string]time.Duration{
		"capture": timeouts.Capture, "simulate": timeouts.Simulate, "reserve": timeouts.Reserve,
		"apply": timeouts.Apply, "verify": timeouts.Verify, "record": timeouts.Record, "rollback": timeouts.Rollback,
	} {
		if value <= 0 || value > MaxStepTimeout {
			return fmt.Errorf("%w: %s timeout must be within (0, %s]", ErrInvalidRequest, name, MaxStepTimeout)
		}
	}
	return nil
}

// Approval is the opaque, externally produced authorisation for one
// operation. The driver and lifecycle never mint one; they only check that
// the supplied value binds to the exact plan id, revision, operation and
// target. ApproverKind names the kind of authority (for example "operator"
// or "policy-core"); this package does not decide who may approve.
type Approval struct {
	PlanID       string
	PlanRevision uint64
	OperationID  string
	Target       string
	ApproverKind string
	Digest       string
}

// ApprovalDigest computes the binding digest of an approval.
func ApprovalDigest(planID string, planRevision uint64, operationID, target, approverKind string) (string, error) {
	if !validIdentifier(planID) || planRevision == 0 || !validIdentifier(operationID) || !validIdentifier(approverKind) {
		return "", fmt.Errorf("%w: approval plan id, revision, operation id and approver kind are required", ErrInvalidRequest)
	}
	if err := ValidateTarget(target); err != nil {
		return "", err
	}
	hasher := newDigest("AntiFlock-DriverApproval-v1")
	hasher.str(planID)
	hasher.uint(planRevision)
	hasher.str(operationID)
	hasher.str(target)
	hasher.str(approverKind)
	return hasher.hex(), nil
}

// Validate enforces the Approval invariants, including that Digest matches
// the bound fields.
func (approval Approval) Validate() error {
	digest, err := ApprovalDigest(approval.PlanID, approval.PlanRevision, approval.OperationID, approval.Target, approval.ApproverKind)
	if err != nil {
		return err
	}
	if approval.Digest != digest {
		return fmt.Errorf("%w: approval digest does not match its fields", ErrApprovalMismatch)
	}
	return nil
}

// LifecycleState is the explicit state of a Lifecycle.
type LifecycleState uint8

const (
	// StateIdle has no active plan.
	StateIdle LifecycleState = iota
	// StateBegun has a plan but no capture yet.
	StateBegun
	// StateCaptured holds a host snapshot.
	StateCaptured
	// StateSimulated holds a successful simulation.
	StateSimulated
	// StateApproved holds a bound approval.
	StateApproved
	// StateReserved holds a durable reservation.
	StateReserved
	// StateApplied holds an apply receipt.
	StateApplied
	// StateVerified holds a passing verification.
	StateVerified
	// StateRecorded has appended its receipts.
	StateRecorded
	// StateCommitted is the successful terminal state.
	StateCommitted
	// StateRolledBack is the reverting terminal state.
	StateRolledBack
	// StateFailed means a step failed; only Rollback is permitted.
	StateFailed
)

// String returns the stable spelling of the state.
func (state LifecycleState) String() string {
	names := [...]string{"IDLE", "BEGUN", "CAPTURED", "SIMULATED", "APPROVED", "RESERVED", "APPLIED", "VERIFIED", "RECORDED", "COMMITTED", "ROLLED_BACK", "FAILED"}
	if int(state) < len(names) {
		return names[state]
	}
	return "UNKNOWN"
}

// Terminal reports whether the state ends a run.
func (state LifecycleState) Terminal() bool {
	return state == StateIdle || state == StateCommitted || state == StateRolledBack
}

// PlanRef identifies the operation a Lifecycle run is executing.
type PlanRef struct {
	PlanID       string
	PlanRevision uint64
	OperationID  string
}

// Validate enforces the PlanRef invariants.
func (ref PlanRef) Validate() error {
	if !validIdentifier(ref.PlanID) || ref.PlanRevision == 0 || !validIdentifier(ref.OperationID) {
		return fmt.Errorf("%w: plan id, revision and operation id are required", ErrInvalidRequest)
	}
	return nil
}

// LifecycleConfig wires a Lifecycle. Every field except Timeouts is
// required; a zero Timeouts uses DefaultStepTimeouts.
type LifecycleConfig struct {
	Driver       Driver
	Journal      Journal
	Reservations ReservationStore
	Receipts     ReceiptStore
	Clock        func() time.Time
	Timeouts     StepTimeouts
}

type lifecycleRun struct {
	ref          PlanRef
	scope        Scope
	snapshot     Snapshot
	digest       string
	simulation   SimulationResult
	operation    *antiflockv1.PlanOperation
	approval     Approval
	reservation  ReservationToken
	reserved     bool
	receipt      ApplyReceipt
	applied      bool
	verification VerificationResult
}

// Lifecycle enforces the required order capture -> simulate -> approve ->
// reserve -> apply -> verify -> record -> commit | rollback for exactly one
// plan operation at a time. Every step is bounded by StepTimeouts, journalled
// before it acts, and refused with ErrLifecycleOrder when invoked early.
// Rollback is the universal abort and is permitted from any active state.
type Lifecycle struct {
	config LifecycleConfig
	mu     sync.Mutex
	state  LifecycleState
	run    *lifecycleRun
}

// NewLifecycle validates the configuration and returns an idle Lifecycle.
func NewLifecycle(config LifecycleConfig) (*Lifecycle, error) {
	if config.Driver == nil || config.Journal == nil || config.Reservations == nil || config.Receipts == nil || config.Clock == nil {
		return nil, errors.New("lifecycle driver, journal, reservation store, receipt store and clock are required")
	}
	if config.Timeouts == (StepTimeouts{}) {
		config.Timeouts = DefaultStepTimeouts()
	}
	if err := config.Timeouts.Validate(); err != nil {
		return nil, err
	}
	if !validIdentifier(config.Driver.Name()) || !validIdentifier(config.Driver.Version()) {
		return nil, errors.New("lifecycle driver name and version must be bounded identifiers")
	}
	if err := config.Driver.PrivilegeBoundary().Validate(); err != nil {
		return nil, err
	}
	return &Lifecycle{config: config, state: StateIdle}, nil
}

// State returns the current lifecycle state.
func (lifecycle *Lifecycle) State() LifecycleState {
	lifecycle.mu.Lock()
	defer lifecycle.mu.Unlock()
	return lifecycle.state
}

func (lifecycle *Lifecycle) require(expected LifecycleState) error {
	if lifecycle.run == nil {
		return ErrNoActivePlan
	}
	if lifecycle.state != expected {
		return fmt.Errorf("%w: state is %s, expected %s", ErrLifecycleOrder, lifecycle.state, expected)
	}
	return nil
}

func (lifecycle *Lifecycle) record(kind JournalKind, step Step, ownership, digest string) JournalRecord {
	return JournalRecord{
		SchemaVersion: ContractVersion, Kind: kind,
		PlanID: lifecycle.run.ref.PlanID, PlanRevision: lifecycle.run.ref.PlanRevision, OperationID: lifecycle.run.ref.OperationID,
		Step: step, OwnershipToken: ownership, Digest: digest, At: lifecycle.config.Clock().UTC(),
	}
}

func bounded(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, timeout)
}

// Begin opens a run for ref. It fails with ErrPlanActive while a previous
// run has not reached a terminal state.
func (lifecycle *Lifecycle) Begin(ctx context.Context, ref PlanRef) error {
	if err := ref.Validate(); err != nil {
		return err
	}
	lifecycle.mu.Lock()
	defer lifecycle.mu.Unlock()
	if lifecycle.run != nil && !lifecycle.state.Terminal() {
		return ErrPlanActive
	}
	lifecycle.run = &lifecycleRun{ref: ref}
	lifecycle.state = StateBegun
	ctx, cancel := bounded(ctx, lifecycle.config.Timeouts.Record)
	defer cancel()
	if err := lifecycle.config.Journal.Begin(ctx, lifecycle.record(JournalKindBegin, StepCapture, "", "")); err != nil {
		lifecycle.run = nil
		lifecycle.state = StateIdle
		return err
	}
	return nil
}

// Capture performs the read-only host capture.
func (lifecycle *Lifecycle) Capture(ctx context.Context, scope Scope) (Snapshot, error) {
	lifecycle.mu.Lock()
	defer lifecycle.mu.Unlock()
	if err := lifecycle.require(StateBegun); err != nil {
		return Snapshot{}, err
	}
	if err := scope.Validate(); err != nil {
		return Snapshot{}, err
	}
	ctx, cancel := bounded(ctx, lifecycle.config.Timeouts.Capture)
	defer cancel()
	snapshot, err := lifecycle.config.Driver.Capture(ctx, scope)
	if err != nil {
		lifecycle.state = StateFailed
		return Snapshot{}, err
	}
	digest, err := snapshot.Digest()
	if err != nil {
		lifecycle.state = StateFailed
		return Snapshot{}, err
	}
	lifecycle.run.scope = scope
	lifecycle.run.snapshot = snapshot
	lifecycle.run.digest = digest
	lifecycle.state = StateCaptured
	return snapshot, nil
}

// Simulate runs the pure simulation against the captured snapshot. A
// simulation that predicts failure moves the run to StateFailed and returns
// ErrSimulationRejected together with the result.
func (lifecycle *Lifecycle) Simulate(ctx context.Context, operation *antiflockv1.PlanOperation) (SimulationResult, error) {
	lifecycle.mu.Lock()
	defer lifecycle.mu.Unlock()
	if err := lifecycle.require(StateCaptured); err != nil {
		return SimulationResult{}, err
	}
	if operation == nil || operation.GetId() != lifecycle.run.ref.OperationID {
		return SimulationResult{}, fmt.Errorf("%w: operation id does not match the active plan", ErrInvalidRequest)
	}
	if err := ValidateTarget(operation.GetTarget()); err != nil {
		return SimulationResult{}, err
	}
	ctx, cancel := bounded(ctx, lifecycle.config.Timeouts.Simulate)
	defer cancel()
	if err := lifecycle.config.Journal.Advance(ctx, lifecycle.record(JournalKindAdvance, StepSimulate, "", lifecycle.run.digest)); err != nil {
		return SimulationResult{}, err
	}
	result, err := lifecycle.config.Driver.Simulate(ctx, lifecycle.run.snapshot, operation)
	if err != nil {
		lifecycle.state = StateFailed
		return SimulationResult{}, err
	}
	if err := result.Validate(); err != nil {
		lifecycle.state = StateFailed
		return SimulationResult{}, err
	}
	if result.SnapshotDigest != lifecycle.run.digest || result.Target != operation.GetTarget() || result.OperationID != operation.GetId() {
		lifecycle.state = StateFailed
		return SimulationResult{}, fmt.Errorf("%w: simulation is not bound to the captured snapshot and operation", ErrInvalidRequest)
	}
	lifecycle.run.simulation = result
	lifecycle.run.operation = operation
	if !result.WouldSucceed {
		lifecycle.state = StateFailed
		return result, ErrSimulationRejected
	}
	lifecycle.state = StateSimulated
	return result, nil
}

// Approve binds an external approval to the simulated operation. The
// lifecycle never constructs approvals.
func (lifecycle *Lifecycle) Approve(ctx context.Context, approval Approval) error {
	lifecycle.mu.Lock()
	defer lifecycle.mu.Unlock()
	if err := lifecycle.require(StateSimulated); err != nil {
		return err
	}
	if err := approval.Validate(); err != nil {
		return err
	}
	run := lifecycle.run
	if approval.PlanID != run.ref.PlanID || approval.PlanRevision != run.ref.PlanRevision ||
		approval.OperationID != run.ref.OperationID || approval.Target != run.operation.GetTarget() {
		return ErrApprovalMismatch
	}
	ctx, cancel := bounded(ctx, lifecycle.config.Timeouts.Record)
	defer cancel()
	if err := lifecycle.config.Journal.Advance(ctx, lifecycle.record(JournalKindAdvance, StepApprove, "", approval.Digest)); err != nil {
		return err
	}
	run.approval = approval
	lifecycle.state = StateApproved
	return nil
}

// Reserve takes the durable replay reservation for the approved plan.
func (lifecycle *Lifecycle) Reserve(ctx context.Context, key ReservationKey) (ReservationToken, error) {
	lifecycle.mu.Lock()
	defer lifecycle.mu.Unlock()
	if err := lifecycle.require(StateApproved); err != nil {
		return ReservationToken{}, err
	}
	if err := key.Validate(); err != nil {
		return ReservationToken{}, err
	}
	if key.PlanID != lifecycle.run.ref.PlanID || key.PlanRevision != lifecycle.run.ref.PlanRevision {
		return ReservationToken{}, fmt.Errorf("%w: reservation key does not name the active plan", ErrReservationInvalid)
	}
	ctx, cancel := bounded(ctx, lifecycle.config.Timeouts.Reserve)
	defer cancel()
	token, err := lifecycle.config.Reservations.Reserve(ctx, key)
	if err != nil {
		lifecycle.state = StateFailed
		return ReservationToken{}, err
	}
	if err := lifecycle.config.Journal.Advance(ctx, lifecycle.record(JournalKindAdvance, StepReserve, "", token.Token)); err != nil {
		lifecycle.state = StateFailed
		return ReservationToken{}, err
	}
	lifecycle.run.reservation = token
	lifecycle.run.reserved = true
	lifecycle.state = StateReserved
	return token, nil
}

// Apply re-captures the host, refuses on drift, journals, then crosses the
// driver boundary with a request bound to the exact approved target.
func (lifecycle *Lifecycle) Apply(ctx context.Context) (ApplyReceipt, error) {
	lifecycle.mu.Lock()
	defer lifecycle.mu.Unlock()
	if err := lifecycle.require(StateReserved); err != nil {
		return ApplyReceipt{}, err
	}
	run := lifecycle.run
	ctx, cancel := bounded(ctx, lifecycle.config.Timeouts.Apply)
	defer cancel()
	current, err := lifecycle.config.Driver.Capture(ctx, run.scope)
	if err != nil {
		lifecycle.state = StateFailed
		return ApplyReceipt{}, err
	}
	currentDigest, err := current.Digest()
	if err != nil || currentDigest != run.digest {
		lifecycle.state = StateFailed
		return ApplyReceipt{}, ErrHostDrift
	}
	if err := lifecycle.config.Journal.Advance(ctx, lifecycle.record(JournalKindAdvance, StepApply, "", run.digest)); err != nil {
		lifecycle.state = StateFailed
		return ApplyReceipt{}, err
	}
	request := ApplyRequest{
		PlanID: run.ref.PlanID, PlanRevision: run.ref.PlanRevision, OperationID: run.ref.OperationID,
		Target: run.approval.Target, Operation: run.operation, Reservation: run.reservation,
		Timeout: lifecycle.config.Timeouts.Apply,
	}
	receipt, err := lifecycle.config.Driver.Apply(ctx, request)
	if err != nil {
		lifecycle.state = StateFailed
		return ApplyReceipt{}, err
	}
	if err := receipt.Validate(); err != nil {
		lifecycle.state = StateFailed
		return ApplyReceipt{}, err
	}
	if receipt.PlanID != run.ref.PlanID || receipt.PlanRevision != run.ref.PlanRevision || receipt.OperationID != run.ref.OperationID || receipt.Target != request.Target {
		lifecycle.state = StateFailed
		return ApplyReceipt{}, fmt.Errorf("%w: apply receipt is not bound to the request", ErrInvalidRequest)
	}
	run.receipt = receipt
	run.applied = true
	lifecycle.state = StateApplied
	return receipt, nil
}

// Verify re-reads the host and compares it with the apply receipt. A
// mismatch moves the run to StateFailed and returns ErrVerificationFailed.
func (lifecycle *Lifecycle) Verify(ctx context.Context) (VerificationResult, error) {
	lifecycle.mu.Lock()
	defer lifecycle.mu.Unlock()
	if err := lifecycle.require(StateApplied); err != nil {
		return VerificationResult{}, err
	}
	run := lifecycle.run
	ctx, cancel := bounded(ctx, lifecycle.config.Timeouts.Verify)
	defer cancel()
	if err := lifecycle.config.Journal.Advance(ctx, lifecycle.record(JournalKindAdvance, StepVerify, run.receipt.OwnershipToken, run.receipt.AppliedDigest)); err != nil {
		lifecycle.state = StateFailed
		return VerificationResult{}, err
	}
	result, err := lifecycle.config.Driver.Verify(ctx, run.receipt)
	if err != nil {
		lifecycle.state = StateFailed
		return VerificationResult{}, err
	}
	if err := result.Validate(); err != nil {
		lifecycle.state = StateFailed
		return VerificationResult{}, err
	}
	run.verification = result
	if !result.Verified || result.ExpectedDigest != run.receipt.AppliedDigest {
		lifecycle.state = StateFailed
		return result, ErrVerificationFailed
	}
	lifecycle.state = StateVerified
	return result, nil
}

// Record appends the apply and verify receipts to the receipt store.
func (lifecycle *Lifecycle) Record(ctx context.Context) error {
	lifecycle.mu.Lock()
	defer lifecycle.mu.Unlock()
	if err := lifecycle.require(StateVerified); err != nil {
		return err
	}
	run := lifecycle.run
	ctx, cancel := bounded(ctx, lifecycle.config.Timeouts.Record)
	defer cancel()
	if err := lifecycle.config.Journal.Advance(ctx, lifecycle.record(JournalKindAdvance, StepRecord, run.receipt.OwnershipToken, run.receipt.AppliedDigest)); err != nil {
		lifecycle.state = StateFailed
		return err
	}
	verify := Receipt{
		SchemaVersion: ContractVersion, Kind: ReceiptKindVerify,
		PlanID: run.ref.PlanID, PlanRevision: run.ref.PlanRevision, OperationID: run.ref.OperationID,
		Target: run.receipt.Target, OwnershipToken: run.receipt.OwnershipToken, Digest: run.verification.ObservedDigest,
		ReasonCode: ReasonVerified, At: run.verification.At,
	}
	for _, receipt := range []Receipt{run.receipt.Receipt(), verify} {
		if err := lifecycle.config.Receipts.Append(ctx, receipt); err != nil {
			lifecycle.state = StateFailed
			return err
		}
	}
	lifecycle.state = StateRecorded
	return nil
}

// Commit releases the reservation as committed and closes the journal.
func (lifecycle *Lifecycle) Commit(ctx context.Context) error {
	lifecycle.mu.Lock()
	defer lifecycle.mu.Unlock()
	if err := lifecycle.require(StateRecorded); err != nil {
		return err
	}
	run := lifecycle.run
	ctx, cancel := bounded(ctx, lifecycle.config.Timeouts.Record)
	defer cancel()
	if err := lifecycle.config.Reservations.Release(ctx, run.reservation, StepCommit); err != nil {
		lifecycle.state = StateFailed
		return err
	}
	commit := Receipt{
		SchemaVersion: ContractVersion, Kind: ReceiptKindCommit,
		PlanID: run.ref.PlanID, PlanRevision: run.ref.PlanRevision, OperationID: run.ref.OperationID,
		Target: run.receipt.Target, OwnershipToken: run.receipt.OwnershipToken, Digest: run.receipt.AppliedDigest,
		ReasonCode: ReasonApplied, At: lifecycle.config.Clock().UTC(),
	}
	if err := lifecycle.config.Receipts.Append(ctx, commit); err != nil {
		lifecycle.state = StateFailed
		return err
	}
	if err := lifecycle.config.Journal.Finish(ctx, lifecycle.record(JournalKindFinish, StepCommit, run.receipt.OwnershipToken, run.receipt.AppliedDigest)); err != nil {
		lifecycle.state = StateFailed
		return err
	}
	lifecycle.state = StateCommitted
	return nil
}

// Rollback is the universal abort. From any active state it reverts an
// applied mutation through the driver (idempotently), records the rollback
// receipt, releases the reservation as rolled back, and closes the journal.
// With nothing applied it only releases and closes.
func (lifecycle *Lifecycle) Rollback(ctx context.Context) (RollbackReceipt, error) {
	lifecycle.mu.Lock()
	defer lifecycle.mu.Unlock()
	if lifecycle.run == nil {
		return RollbackReceipt{}, ErrNoActivePlan
	}
	if lifecycle.state.Terminal() {
		return RollbackReceipt{}, fmt.Errorf("%w: state is %s", ErrLifecycleOrder, lifecycle.state)
	}
	run := lifecycle.run
	ctx, cancel := bounded(ctx, lifecycle.config.Timeouts.Rollback)
	defer cancel()
	var receipt RollbackReceipt
	if run.applied {
		request := RollbackRequest{
			PlanID: run.ref.PlanID, PlanRevision: run.ref.PlanRevision, OperationID: run.ref.OperationID,
			OwnershipToken: run.receipt.OwnershipToken, Timeout: lifecycle.config.Timeouts.Rollback,
		}
		var err error
		receipt, err = lifecycle.config.Driver.Rollback(ctx, request)
		if err != nil {
			lifecycle.state = StateFailed
			return RollbackReceipt{}, err
		}
		if err := receipt.Validate(); err != nil {
			lifecycle.state = StateFailed
			return RollbackReceipt{}, err
		}
		if err := lifecycle.config.Receipts.Append(ctx, receipt.Receipt()); err != nil && !errors.Is(err, ErrReceiptDuplicate) {
			lifecycle.state = StateFailed
			return RollbackReceipt{}, err
		}
	}
	if run.reserved {
		if err := lifecycle.config.Reservations.Release(ctx, run.reservation, StepRollback); err != nil {
			lifecycle.state = StateFailed
			return RollbackReceipt{}, err
		}
	}
	if err := lifecycle.config.Journal.Finish(ctx, lifecycle.record(JournalKindFinish, StepRollback, run.receipt.OwnershipToken, receipt.RestoredDigest)); err != nil {
		lifecycle.state = StateFailed
		return RollbackReceipt{}, err
	}
	lifecycle.state = StateRolledBack
	return receipt, nil
}
