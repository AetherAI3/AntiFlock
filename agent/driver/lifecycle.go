package driver

import (
	"context"
	"errors"
	"fmt"
	"slices"
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
//
// The journal is also read: Begin refuses with ErrRecoveryPending while the
// journal holds in-flight entries, Health surfaces them, and Recover finishes
// or reverts each one deterministically from the journal alone.
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

func (lifecycle *Lifecycle) record(run *lifecycleRun, kind JournalKind, step Step, ownership, digest string) JournalRecord {
	record := JournalRecord{
		SchemaVersion: ContractVersion, Kind: kind,
		PlanID: run.ref.PlanID, PlanRevision: run.ref.PlanRevision, OperationID: run.ref.OperationID,
		Step: step, OwnershipToken: ownership, Digest: digest, At: lifecycle.config.Clock().UTC(),
	}
	if run.operation != nil {
		record.Target = run.operation.GetTarget()
	}
	if run.reserved {
		record.Reservation = run.reservation.Key
	}
	return record
}

func bounded(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, timeout)
}

// Begin opens a run for ref. It fails with ErrPlanActive while a previous
// run has not reached a terminal state and with ErrRecoveryPending while the
// journal holds in-flight entries from an earlier process.
func (lifecycle *Lifecycle) Begin(ctx context.Context, ref PlanRef) error {
	if err := ref.Validate(); err != nil {
		return err
	}
	lifecycle.mu.Lock()
	defer lifecycle.mu.Unlock()
	if lifecycle.run != nil && !lifecycle.state.Terminal() {
		return ErrPlanActive
	}
	ctx, cancel := bounded(ctx, lifecycle.config.Timeouts.Record)
	defer cancel()
	inFlight, err := lifecycle.config.Journal.InFlight(ctx)
	if err != nil {
		return err
	}
	if len(inFlight) > 0 {
		return fmt.Errorf("%w: %d in-flight journal entries", ErrRecoveryPending, len(inFlight))
	}
	run := &lifecycleRun{ref: ref}
	if err := lifecycle.config.Journal.Begin(ctx, lifecycle.record(run, JournalKindBegin, StepCapture, "", "")); err != nil {
		return err
	}
	lifecycle.run = run
	lifecycle.state = StateBegun
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
// ErrSimulationRejected together with the result. The predicted after-digest
// is journalled so recovery can verify an apply whose receipt was lost.
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
	if err := lifecycle.config.Journal.Advance(ctx, lifecycle.record(lifecycle.run, JournalKindAdvance, StepSimulate, "", result.Diff.AfterDigest)); err != nil {
		lifecycle.state = StateFailed
		return SimulationResult{}, err
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
	if err := lifecycle.config.Journal.Advance(ctx, lifecycle.record(run, JournalKindAdvance, StepApprove, "", approval.Digest)); err != nil {
		return err
	}
	run.approval = approval
	lifecycle.state = StateApproved
	return nil
}

// Reserve takes the durable replay reservation for the approved plan. A
// redelivered reservation that already carries a terminal result is refused
// with ErrAlreadyReserved at this level: the lifecycle never re-executes a
// finished plan; the caller reads Reservation.Result from the store instead.
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
	reservation, err := lifecycle.config.Reservations.Reserve(ctx, key)
	if err != nil {
		lifecycle.state = StateFailed
		return ReservationToken{}, err
	}
	if reservation.Replayed {
		lifecycle.state = StateFailed
		return ReservationToken{}, fmt.Errorf("%w: plan already has a terminal result", ErrAlreadyReserved)
	}
	lifecycle.run.reservation = reservation.Token
	lifecycle.run.reserved = true
	if err := lifecycle.config.Journal.Advance(ctx, lifecycle.record(lifecycle.run, JournalKindAdvance, StepReserve, "", reservation.Token.Token)); err != nil {
		lifecycle.state = StateFailed
		return ReservationToken{}, err
	}
	lifecycle.state = StateReserved
	return reservation.Token, nil
}

// Apply re-captures the host, refuses on drift, journals, then crosses the
// driver boundary with a request bound to the exact approved target. The
// receipt is journalled (ADVANCE VERIFY with the ownership token and applied
// digest) before Apply returns so a crash afterwards is recoverable.
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
	if err != nil {
		lifecycle.state = StateFailed
		return ApplyReceipt{}, err
	}
	if currentDigest != run.digest {
		lifecycle.state = StateFailed
		return ApplyReceipt{}, ErrHostDrift
	}
	if err := lifecycle.config.Journal.Advance(ctx, lifecycle.record(run, JournalKindAdvance, StepApply, "", run.digest)); err != nil {
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
	expectedToken := OwnershipTokenFor(run.ref.PlanID, run.ref.PlanRevision, run.ref.OperationID, request.Target, run.reservation.Token)
	if receipt.PlanID != run.ref.PlanID || receipt.PlanRevision != run.ref.PlanRevision || receipt.OperationID != run.ref.OperationID ||
		receipt.Target != request.Target || receipt.OwnershipToken != expectedToken {
		lifecycle.state = StateFailed
		return ApplyReceipt{}, fmt.Errorf("%w: apply receipt is not bound to the request", ErrInvalidRequest)
	}
	run.receipt = receipt
	run.applied = true
	if err := lifecycle.config.Journal.Advance(ctx, lifecycle.record(run, JournalKindAdvance, StepVerify, receipt.OwnershipToken, receipt.AppliedDigest)); err != nil {
		lifecycle.state = StateFailed
		return receipt, err
	}
	lifecycle.state = StateApplied
	return receipt, nil
}

// Verify re-reads the host and compares it with the apply receipt. A
// mismatch moves the run to StateFailed and returns ErrVerificationFailed.
// Verify is read-only and writes nothing to the journal.
func (lifecycle *Lifecycle) Verify(ctx context.Context) (VerificationResult, error) {
	lifecycle.mu.Lock()
	defer lifecycle.mu.Unlock()
	if err := lifecycle.require(StateApplied); err != nil {
		return VerificationResult{}, err
	}
	run := lifecycle.run
	ctx, cancel := bounded(ctx, lifecycle.config.Timeouts.Verify)
	defer cancel()
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

func verifyReceipt(run *lifecycleRun, verification VerificationResult) Receipt {
	return Receipt{
		SchemaVersion: ContractVersion, Kind: ReceiptKindVerify,
		PlanID: run.ref.PlanID, PlanRevision: run.ref.PlanRevision, OperationID: run.ref.OperationID,
		Target: run.receipt.Target, OwnershipToken: run.receipt.OwnershipToken, Digest: verification.ObservedDigest,
		ReasonCode: ReasonVerified, At: verification.At,
	}
}

func commitReceipt(run *lifecycleRun, reason string, at time.Time) Receipt {
	return Receipt{
		SchemaVersion: ContractVersion, Kind: ReceiptKindCommit,
		PlanID: run.ref.PlanID, PlanRevision: run.ref.PlanRevision, OperationID: run.ref.OperationID,
		Target: run.receipt.Target, OwnershipToken: run.receipt.OwnershipToken, Digest: run.receipt.AppliedDigest,
		ReasonCode: reason, At: at,
	}
}

// appendReceipt tolerates a duplicate so recovery can re-run an interrupted
// Record step.
func (lifecycle *Lifecycle) appendReceipt(ctx context.Context, receipt Receipt) error {
	if err := lifecycle.config.Receipts.Append(ctx, receipt); err != nil && !errors.Is(err, ErrReceiptDuplicate) {
		return err
	}
	return nil
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
	if err := lifecycle.config.Journal.Advance(ctx, lifecycle.record(run, JournalKindAdvance, StepRecord, run.receipt.OwnershipToken, run.receipt.AppliedDigest)); err != nil {
		lifecycle.state = StateFailed
		return err
	}
	for _, receipt := range []Receipt{run.receipt.Receipt(), verifyReceipt(run, run.verification)} {
		if err := lifecycle.appendReceipt(ctx, receipt); err != nil {
			lifecycle.state = StateFailed
			return err
		}
	}
	lifecycle.state = StateRecorded
	return nil
}

// Commit appends the commit receipt, releases the reservation as committed
// with that receipt's content digest as the stored terminal result, and
// closes the journal.
func (lifecycle *Lifecycle) Commit(ctx context.Context) error {
	lifecycle.mu.Lock()
	defer lifecycle.mu.Unlock()
	if err := lifecycle.require(StateRecorded); err != nil {
		return err
	}
	ctx, cancel := bounded(ctx, lifecycle.config.Timeouts.Record)
	defer cancel()
	if err := lifecycle.commit(ctx, lifecycle.run, ReasonApplied); err != nil {
		lifecycle.state = StateFailed
		return err
	}
	lifecycle.state = StateCommitted
	return nil
}

func (lifecycle *Lifecycle) commit(ctx context.Context, run *lifecycleRun, reason string) error {
	receipt := commitReceipt(run, reason, lifecycle.config.Clock().UTC())
	digest, err := receipt.ContentDigest()
	if err != nil {
		return err
	}
	if err := lifecycle.appendReceipt(ctx, receipt); err != nil {
		return err
	}
	if err := lifecycle.config.Reservations.Release(ctx, run.reservation, StepCommit, []byte(digest)); err != nil {
		return err
	}
	return lifecycle.config.Journal.Finish(ctx, lifecycle.record(run, JournalKindFinish, StepCommit, run.receipt.OwnershipToken, run.receipt.AppliedDigest))
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
	ctx, cancel := bounded(ctx, lifecycle.config.Timeouts.Rollback)
	defer cancel()
	receipt, err := lifecycle.rollback(ctx, lifecycle.run, ReasonRolledBack)
	if err != nil {
		lifecycle.state = StateFailed
		return RollbackReceipt{}, err
	}
	lifecycle.state = StateRolledBack
	return receipt, nil
}

// rollback reverts whatever run recorded. An ownership token the driver
// does not know (nothing was ever applied) is tolerated.
func (lifecycle *Lifecycle) rollback(ctx context.Context, run *lifecycleRun, reason string) (RollbackReceipt, error) {
	var receipt RollbackReceipt
	var result []byte
	if run.applied {
		request := RollbackRequest{
			PlanID: run.ref.PlanID, PlanRevision: run.ref.PlanRevision, OperationID: run.ref.OperationID,
			OwnershipToken: run.receipt.OwnershipToken, Timeout: lifecycle.config.Timeouts.Rollback,
		}
		var err error
		receipt, err = lifecycle.config.Driver.Rollback(ctx, request)
		switch {
		case errors.Is(err, ErrUnknownOwnership):
			receipt = RollbackReceipt{}
		case err != nil:
			return RollbackReceipt{}, err
		default:
			if err := receipt.Validate(); err != nil {
				return RollbackReceipt{}, err
			}
			record := receipt.Receipt()
			record.ReasonCode = reason
			digest, err := record.ContentDigest()
			if err != nil {
				return RollbackReceipt{}, err
			}
			result = []byte(digest)
			if err := lifecycle.appendReceipt(ctx, record); err != nil {
				return RollbackReceipt{}, err
			}
		}
	}
	if run.reserved {
		if err := lifecycle.config.Reservations.Release(ctx, run.reservation, StepRollback, result); err != nil {
			return RollbackReceipt{}, err
		}
	}
	if err := lifecycle.config.Journal.Finish(ctx, lifecycle.record(run, JournalKindFinish, StepRollback, run.receipt.OwnershipToken, receipt.RestoredDigest)); err != nil {
		return RollbackReceipt{}, err
	}
	return receipt, nil
}

// Health reports the lifecycle's view: a corrupt journal is UNAVAILABLE with
// ReasonProbeJournalCorrupt, in-flight entries are DEGRADED with
// ReasonRecoveryPending, otherwise the driver's own health.
func (lifecycle *Lifecycle) Health(ctx context.Context) (HealthReport, error) {
	if err := ctx.Err(); err != nil {
		return HealthReport{}, err
	}
	inFlight, err := lifecycle.config.Journal.InFlight(ctx)
	at := lifecycle.config.Clock().UTC()
	if err != nil {
		return HealthReport{Status: HealthUnavailable, ReasonCodes: []string{ReasonProbeJournalCorrupt}, At: at}, nil
	}
	if len(inFlight) > 0 {
		return HealthReport{Status: HealthDegraded, ReasonCodes: []string{ReasonRecoveryPending}, At: at}, nil
	}
	return lifecycle.config.Driver.Health(ctx)
}

// Recover reads the journal and, for every in-flight entry, either finishes
// it or reverts it, deterministically and idempotently:
//
//   - CAPTURE, SIMULATE, APPROVE: nothing reserved or applied; the entry is
//     closed as ROLLBACK (ReasonRecoveryAborted).
//   - RESERVE: the reservation is released as ROLLBACK and the entry closed.
//   - APPLY, VERIFY, RECORD: the driver's own Recover runs first, then the
//     ownership token is re-derived (OwnershipTokenFor) and the host is
//     verified against the journalled applied digest (VERIFY/RECORD) or the
//     simulated after-digest (APPLY). A verified host is completed: receipts
//     appended, reservation released as COMMIT, entry closed
//     (ReasonRecoveryCommit). Anything else is rolled back through the
//     driver, released as ROLLBACK, and closed (ReasonRecoveryRollback).
//
// Recover never consults the host to decide what it owns; it reads the
// host only through Verify, which is read-only. It refuses to run while this
// Lifecycle has an active plan.
func (lifecycle *Lifecycle) Recover(ctx context.Context) (RecoveryReport, error) {
	lifecycle.mu.Lock()
	defer lifecycle.mu.Unlock()
	if lifecycle.run != nil && !lifecycle.state.Terminal() {
		return RecoveryReport{}, ErrPlanActive
	}
	ctx, cancel := bounded(ctx, lifecycle.config.Timeouts.Rollback)
	defer cancel()
	report := RecoveryReport{At: lifecycle.config.Clock().UTC()}
	inFlight, err := lifecycle.config.Journal.InFlight(ctx)
	if err != nil {
		return RecoveryReport{}, err
	}
	if len(inFlight) == 0 {
		report.ReasonCodes = []string{ReasonRecoveryClean}
		return report, nil
	}
	records, err := lifecycle.config.Journal.Records(ctx)
	if err != nil {
		return RecoveryReport{}, err
	}
	if _, err := lifecycle.config.Driver.Recover(ctx); err != nil {
		return RecoveryReport{}, err
	}
	reasons := map[string]struct{}{}
	for _, entry := range inFlight {
		operation, reason, err := lifecycle.recoverEntry(ctx, entry, records)
		if err != nil {
			return RecoveryReport{}, err
		}
		reasons[reason] = struct{}{}
		report.Operations = append(report.Operations, operation)
	}
	for reason := range reasons {
		report.ReasonCodes = append(report.ReasonCodes, reason)
	}
	slices.Sort(report.ReasonCodes)
	if err := report.Validate(); err != nil {
		return RecoveryReport{}, err
	}
	return report, nil
}

func (lifecycle *Lifecycle) recoverEntry(ctx context.Context, entry JournalRecord, records []JournalRecord) (RecoveredOperation, string, error) {
	run := &lifecycleRun{ref: PlanRef{PlanID: entry.PlanID, PlanRevision: entry.PlanRevision, OperationID: entry.OperationID}}
	operation := RecoveredOperation{
		PlanID: entry.PlanID, PlanRevision: entry.PlanRevision, OperationID: entry.OperationID, Step: entry.Step, OwnershipToken: "none",
	}
	if entry.Reservation != (ReservationKey{}) {
		digest, err := entry.Reservation.Digest()
		if err != nil {
			return RecoveredOperation{}, "", err
		}
		run.reservation = ReservationToken{Key: entry.Reservation, Token: digest, IssuedAt: entry.At}
		run.reserved = true
	}
	if entry.Target != "" {
		run.operation = &antiflockv1.PlanOperation{Id: entry.OperationID, Target: entry.Target}
	}
	switch entry.Step {
	case StepCapture, StepSimulate, StepApprove, StepReserve:
		if _, err := lifecycle.rollback(ctx, run, ReasonRecoveryRollback); err != nil {
			return RecoveredOperation{}, "", err
		}
		operation.Finished = true
		return operation, ReasonRecoveryAborted, nil
	}
	// APPLY, VERIFY or RECORD: an apply may have happened.
	if !run.reserved || entry.Target == "" {
		return RecoveredOperation{}, "", fmt.Errorf("%w: apply entry lacks reservation or target", ErrJournalCorrupt)
	}
	token := OwnershipTokenFor(entry.PlanID, entry.PlanRevision, entry.OperationID, entry.Target, run.reservation.Token)
	expected := entry.Digest
	before := entry.Digest
	for _, record := range records {
		if record.Identity() != entry.Identity() {
			continue
		}
		if entry.Step == StepApply && record.Step == StepSimulate {
			expected = record.Digest
		}
		if entry.Step != StepApply && record.Step == StepApply {
			before = record.Digest
		}
	}
	operation.OwnershipToken = token
	run.receipt = ApplyReceipt{
		PlanID: entry.PlanID, PlanRevision: entry.PlanRevision, OperationID: entry.OperationID, Target: entry.Target,
		OwnershipToken: token, BeforeDigest: before, AppliedDigest: expected, ReasonCode: ReasonApplied,
		StartedAt: entry.At, CompletedAt: entry.At,
	}
	run.applied = true
	verified := false
	if run.receipt.Validate() == nil {
		verification, err := lifecycle.config.Driver.Verify(ctx, run.receipt)
		switch {
		case err == nil && verification.Validate() == nil && verification.Verified && verification.ExpectedDigest == expected:
			run.verification = verification
			verified = true
		case err != nil && !errors.Is(err, ErrUnknownOwnership):
			return RecoveredOperation{}, "", err
		}
	}
	if verified {
		for _, receipt := range []Receipt{run.receipt.Receipt(), verifyReceipt(run, run.verification)} {
			if err := lifecycle.appendReceipt(ctx, receipt); err != nil {
				return RecoveredOperation{}, "", err
			}
		}
		if err := lifecycle.commit(ctx, run, ReasonRecoveryCommit); err != nil {
			return RecoveredOperation{}, "", err
		}
		operation.Finished = true
		return operation, ReasonRecoveryCommit, nil
	}
	receipt, err := lifecycle.rollback(ctx, run, ReasonRecoveryRollback)
	if err != nil {
		return RecoveredOperation{}, "", err
	}
	operation.Reverted = receipt.ReasonCode == ReasonRolledBack || receipt.AlreadyRolledBack
	operation.Finished = true
	return operation, ReasonRecoveryRollback, nil
}
