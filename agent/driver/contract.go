// This file defines the versioned driver contract: the generic interfaces a
// host-mutation driver must implement, the value types that cross them, and
// the invariants every implementation is held to by the conformance suite in
// agent/driver/conformance. ProbeResult and Prober live in probe.go (frozen).
//
// Contract guarantees (ContractVersion 1):
//
//   - Capture, Simulate, Check, Verify, Health, RecoveryPaths and CommandPlan
//     never mutate host state. Simulate is a pure function of its inputs.
//   - Apply mutates only the exact Target named in the request, only under a
//     valid reservation, and only within the request timeout.
//   - Rollback and Recover are idempotent. Recovery never depends on the host
//     being in the post-apply state; a driver reads its journal, not the
//     network, to find what it owns.
//   - Every string a driver emits is printable ASCII with no control or
//     format characters. Raw command output, secrets and unescaped untrusted
//     text never enter a Snapshot, Diff, receipt or reason code.
//   - A driver never approves its own work: Approval values are produced by
//     the caller and bound to an exact plan id, revision, operation and target.
//   - No driver ever spawns a shell. PrivilegeBoundary describes the one
//     binary and argument pattern it may execute, and targets that contain
//     shell metacharacters are rejected before any boundary is crossed.
package driver

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
)

// ContractVersion is the version of the driver contract described by this
// package. Drivers report the version they implement through Driver.Version
// metadata; the lifecycle and conformance suite are written against this one.
const ContractVersion uint32 = 1

// Bounds applied by the value-type Validate methods. They are small on
// purpose: a driver describes one operation against one host, not an
// inventory.
const (
	MaxIdentifierLength    = 128
	MaxTargetLength        = 256
	MaxSnapshotEntries     = 4096
	MaxSnapshotValueLength = 1024
	MaxDiffLines           = 4096
	MaxDiffLineLength      = 512
	MaxReasonCodes         = 32
	MaxRecoveryPaths       = 64
	MaxSafeMessageLength   = 512
	MaxOperationTimeout    = 2 * time.Minute
	MaxCommandArguments    = 64
	MaxCommandInputBytes   = 64 * 1024
)

// Sentinel errors shared by every driver. Implementations wrap these so the
// lifecycle and conformance suite can fail closed on a single comparison.
var (
	// ErrInvalidRequest reports a request that failed structural validation.
	ErrInvalidRequest = errors.New("driver request is invalid")
	// ErrUnsafeTarget reports a target containing whitespace, control
	// characters, or shell metacharacters.
	ErrUnsafeTarget = errors.New("driver target is unsafe")
	// ErrTargetMismatch reports an Apply whose Target differs from the target
	// the operation and reservation were bound to.
	ErrTargetMismatch = errors.New("driver apply target does not match the bound target")
	// ErrReservationInvalid reports a missing, malformed, or foreign
	// reservation token.
	ErrReservationInvalid = errors.New("driver reservation is invalid")
	// ErrUnknownOwnership reports a rollback or verification for an
	// ownership token the driver never issued.
	ErrUnknownOwnership = errors.New("driver ownership token is unknown")
	// ErrHostDrift reports that the host changed between capture and apply.
	ErrHostDrift = errors.New("host state drifted since capture")
	// ErrCrashInjected is returned by a driver whose CrashSimulator hook was
	// armed; it stands in for process death between mutation and journal
	// completion.
	ErrCrashInjected = errors.New("driver crash injected")
	// ErrNotImplemented reports an interface the driver deliberately does not
	// provide.
	ErrNotImplemented = errors.New("driver operation is not implemented")
)

// Reason codes emitted by the contract layer. Drivers extend these with the
// AF-DRIVER-<NAME>- prefix documented in probe.go.
const (
	ReasonApplied          = "AF-DRIVER-APPLIED"
	ReasonVerified         = "AF-DRIVER-VERIFIED"
	ReasonVerifyMismatch   = "AF-DRIVER-VERIFY-MISMATCH"
	ReasonRolledBack       = "AF-DRIVER-ROLLED-BACK"
	ReasonAlreadyRolled    = "AF-DRIVER-ALREADY-ROLLED-BACK"
	ReasonRecovered        = "AF-DRIVER-RECOVERED"
	ReasonRecoveryClean    = "AF-DRIVER-RECOVERY-CLEAN"
	ReasonSimulationOK     = "AF-DRIVER-SIMULATION-OK"
	ReasonSimulationNoop   = "AF-DRIVER-SIMULATION-NOOP"
	ReasonSimulationReject = "AF-DRIVER-SIMULATION-REJECTED"
	ReasonCheckPassed      = "AF-DRIVER-CHECK-PASSED"
	ReasonCheckFailed      = "AF-DRIVER-CHECK-FAILED"
	ReasonCheckUnsupported = "AF-DRIVER-CHECK-UNSUPPORTED"
	ReasonTargetUnsafe     = "AF-DRIVER-TARGET-UNSAFE"
)

// Scope bounds a host-state capture to one operation type and, optionally,
// to named targets. An empty Targets list captures every entry of that type
// the driver owns or observes, never the whole host.
type Scope struct {
	OperationType antiflockv1.PlanOperationType
	Targets       []string
}

// Validate enforces the Scope invariants.
func (scope Scope) Validate() error {
	if scope.OperationType == antiflockv1.PlanOperationType_PLAN_OPERATION_TYPE_UNSPECIFIED ||
		antiflockv1.PlanOperationType_name[int32(scope.OperationType)] == "" {
		return fmt.Errorf("%w: scope operation type is unspecified or unknown", ErrInvalidRequest)
	}
	if len(scope.Targets) > MaxSnapshotEntries {
		return fmt.Errorf("%w: scope names more than %d targets", ErrInvalidRequest, MaxSnapshotEntries)
	}
	for _, target := range scope.Targets {
		if err := ValidateTarget(target); err != nil {
			return err
		}
	}
	return nil
}

// SnapshotEntry is one observed key/value of host state. Both halves are
// printable ASCII and bounded; values are driver-rendered summaries, never
// raw command output.
type SnapshotEntry struct {
	Key   string
	Value string
}

// Snapshot is a read-only, driver-scoped capture of host state. Digest covers
// the driver name, scope, and entries but deliberately excludes CapturedAt so
// two captures of an unchanged host produce the same digest.
type Snapshot struct {
	SchemaVersion uint32
	DriverName    string
	Scope         Scope
	Entries       []SnapshotEntry
	CapturedAt    time.Time
}

// Validate enforces the Snapshot invariants: bounded, sorted, unique,
// printable entries.
func (snapshot Snapshot) Validate() error {
	if snapshot.SchemaVersion != ContractVersion {
		return fmt.Errorf("%w: snapshot schema version %d is not %d", ErrInvalidRequest, snapshot.SchemaVersion, ContractVersion)
	}
	if !validIdentifier(snapshot.DriverName) {
		return fmt.Errorf("%w: snapshot driver name is not a bounded identifier", ErrInvalidRequest)
	}
	if err := snapshot.Scope.Validate(); err != nil {
		return err
	}
	if len(snapshot.Entries) > MaxSnapshotEntries {
		return fmt.Errorf("%w: snapshot exceeds %d entries", ErrInvalidRequest, MaxSnapshotEntries)
	}
	for index, entry := range snapshot.Entries {
		if err := ValidateTarget(entry.Key); err != nil {
			return fmt.Errorf("%w: snapshot entry key", err)
		}
		if len(entry.Value) > MaxSnapshotValueLength || !printableASCII(entry.Value) {
			return fmt.Errorf("%w: snapshot entry value is oversized or not printable ASCII", ErrInvalidRequest)
		}
		if index > 0 && snapshot.Entries[index-1].Key >= entry.Key {
			return fmt.Errorf("%w: snapshot entries must be sorted and unique by key", ErrInvalidRequest)
		}
	}
	if snapshot.CapturedAt.IsZero() {
		return fmt.Errorf("%w: snapshot captured-at is required", ErrInvalidRequest)
	}
	return nil
}

// Digest returns the deterministic SHA-256 identity of the captured state.
func (snapshot Snapshot) Digest() (string, error) {
	if err := snapshot.Validate(); err != nil {
		return "", err
	}
	hasher := newDigest("AntiFlock-DriverSnapshot-v1")
	hasher.uint(uint64(snapshot.SchemaVersion))
	hasher.str(snapshot.DriverName)
	hasher.uint(uint64(snapshot.Scope.OperationType))
	targets := slices.Clone(snapshot.Scope.Targets)
	slices.Sort(targets)
	hasher.strs(targets)
	hasher.uint(uint64(len(snapshot.Entries)))
	for _, entry := range snapshot.Entries {
		hasher.str(entry.Key)
		hasher.str(entry.Value)
	}
	return hasher.hex(), nil
}

// Diff is the human-safe rendering of a simulated change. Lines are data:
// printable ASCII, bounded, never interpreted.
type Diff struct {
	BeforeDigest string
	AfterDigest  string
	Lines        []string
}

// Validate enforces the Diff invariants.
func (diff Diff) Validate() error {
	if !validDigest(diff.BeforeDigest) || !validDigest(diff.AfterDigest) {
		return fmt.Errorf("%w: diff digests must be hex SHA-256", ErrInvalidRequest)
	}
	if len(diff.Lines) > MaxDiffLines {
		return fmt.Errorf("%w: diff exceeds %d lines", ErrInvalidRequest, MaxDiffLines)
	}
	for _, line := range diff.Lines {
		if line == "" || len(line) > MaxDiffLineLength || !printableASCII(line) {
			return fmt.Errorf("%w: diff line is empty, oversized, or not printable ASCII", ErrInvalidRequest)
		}
	}
	return nil
}

// SimulationResult is the outcome of a pure simulation. WouldSucceed is the
// driver's prediction; it is never a promise, and the lifecycle still
// verifies after apply.
type SimulationResult struct {
	OperationID   string
	Target        string
	SnapshotDigest string
	Diff          Diff
	WouldSucceed  bool
	ReasonCodes   []string
}

// Validate enforces the SimulationResult invariants.
func (result SimulationResult) Validate() error {
	if !validIdentifier(result.OperationID) {
		return fmt.Errorf("%w: simulation operation id is not a bounded identifier", ErrInvalidRequest)
	}
	if err := ValidateTarget(result.Target); err != nil {
		return err
	}
	if !validDigest(result.SnapshotDigest) || result.SnapshotDigest != result.Diff.BeforeDigest {
		return fmt.Errorf("%w: simulation snapshot digest must equal the diff before-digest", ErrInvalidRequest)
	}
	if err := result.Diff.Validate(); err != nil {
		return err
	}
	return validateReasonCodes(result.ReasonCodes)
}

// CheckObservation mirrors enforcement.CheckObservation field for field so the
// enforcer can adapt a driver check without a new type. SafeMessage is
// operator-facing and must never carry raw host output.
type CheckObservation struct {
	Outcome     antiflockv1.CheckOutcome
	ReasonCode  string
	SafeMessage string
	Evidence    []*antiflockv1.EvidenceReference
}

// Validate enforces the CheckObservation invariants.
func (observation CheckObservation) Validate() error {
	if observation.Outcome == antiflockv1.CheckOutcome_CHECK_OUTCOME_UNSPECIFIED ||
		antiflockv1.CheckOutcome_name[int32(observation.Outcome)] == "" {
		return fmt.Errorf("%w: check outcome is unspecified or unknown", ErrInvalidRequest)
	}
	if !validReasonCode(observation.ReasonCode) {
		return fmt.Errorf("%w: check reason code is not a bounded AF- identifier", ErrInvalidRequest)
	}
	if len(observation.SafeMessage) > MaxSafeMessageLength || !printableASCII(observation.SafeMessage) {
		return fmt.Errorf("%w: check safe message is oversized or not printable ASCII", ErrInvalidRequest)
	}
	return nil
}

// ReservationKey is the replay identity of one plan revision on one node.
// Fingerprint is the caller's digest of the executable plan content; Nonce is
// the plan nonce as a printable string (hex or base64 as the caller chooses).
type ReservationKey struct {
	PlanID       string
	PlanRevision uint64
	Nonce        string
	Fingerprint  string
}

// Validate enforces the ReservationKey invariants.
func (key ReservationKey) Validate() error {
	if !validIdentifier(key.PlanID) {
		return fmt.Errorf("%w: reservation plan id is not a bounded identifier", ErrReservationInvalid)
	}
	if key.PlanRevision == 0 {
		return fmt.Errorf("%w: reservation plan revision is required", ErrReservationInvalid)
	}
	if !validIdentifier(key.Nonce) || !validIdentifier(key.Fingerprint) || len(key.Fingerprint) > 256 {
		return fmt.Errorf("%w: reservation nonce and fingerprint must be bounded identifiers", ErrReservationInvalid)
	}
	return nil
}

// Digest returns the deterministic identity of the key. ReservationToken
// values are derived from it so a driver can recognise a token it did not
// mint.
func (key ReservationKey) Digest() (string, error) {
	if err := key.Validate(); err != nil {
		return "", err
	}
	hasher := newDigest("AntiFlock-DriverReservation-v1")
	hasher.str(key.PlanID)
	hasher.uint(key.PlanRevision)
	hasher.str(key.Nonce)
	hasher.str(key.Fingerprint)
	return hasher.hex(), nil
}

// ReservationToken proves a durable reservation was taken for Key before any
// mutation. Token equals Key.Digest(); a token whose Token does not match its
// Key is rejected as foreign.
type ReservationToken struct {
	Key      ReservationKey
	Token    string
	IssuedAt time.Time
}

// Validate enforces the ReservationToken invariants, including that Token
// was derived from Key.
func (token ReservationToken) Validate() error {
	digest, err := token.Key.Digest()
	if err != nil {
		return err
	}
	if token.Token != digest {
		return fmt.Errorf("%w: reservation token was not derived from its key", ErrReservationInvalid)
	}
	if token.IssuedAt.IsZero() {
		return fmt.Errorf("%w: reservation issued-at is required", ErrReservationInvalid)
	}
	return nil
}

// ApplyRequest binds one mutation to an exact plan id, revision, operation,
// target and reservation. Target must equal Operation.GetTarget(); the
// duplication is deliberate so a caller cannot apply an operation against a
// target it did not reserve.
type ApplyRequest struct {
	PlanID       string
	PlanRevision uint64
	OperationID  string
	Target       string
	Operation    *antiflockv1.PlanOperation
	Reservation  ReservationToken
	Timeout      time.Duration
}

// Validate enforces the ApplyRequest invariants. It returns ErrTargetMismatch
// when Target and Operation.Target disagree and ErrReservationInvalid when the
// reservation does not name the same plan id and revision.
func (request ApplyRequest) Validate() error {
	if !validIdentifier(request.PlanID) || request.PlanRevision == 0 || !validIdentifier(request.OperationID) {
		return fmt.Errorf("%w: apply plan id, revision and operation id are required", ErrInvalidRequest)
	}
	if err := ValidateTarget(request.Target); err != nil {
		return err
	}
	if request.Operation == nil {
		return fmt.Errorf("%w: apply operation is required", ErrInvalidRequest)
	}
	if request.Operation.GetId() != request.OperationID {
		return fmt.Errorf("%w: apply operation id does not match the operation", ErrInvalidRequest)
	}
	if request.Operation.GetTarget() != request.Target {
		return ErrTargetMismatch
	}
	if request.Operation.GetType() == antiflockv1.PlanOperationType_PLAN_OPERATION_TYPE_UNSPECIFIED ||
		antiflockv1.PlanOperationType_name[int32(request.Operation.GetType())] == "" {
		return fmt.Errorf("%w: apply operation type is unspecified or unknown", ErrInvalidRequest)
	}
	if err := request.Reservation.Validate(); err != nil {
		return err
	}
	if request.Reservation.Key.PlanID != request.PlanID || request.Reservation.Key.PlanRevision != request.PlanRevision {
		return fmt.Errorf("%w: reservation names a different plan id or revision", ErrReservationInvalid)
	}
	if request.Timeout <= 0 || request.Timeout > MaxOperationTimeout {
		return fmt.Errorf("%w: apply timeout must be within (0, %s]", ErrInvalidRequest, MaxOperationTimeout)
	}
	return nil
}

// ApplyReceipt is the driver's durable account of one mutation. OwnershipToken
// is the handle Rollback and Recover use; AppliedDigest is the snapshot digest
// observed immediately after the mutation.
type ApplyReceipt struct {
	PlanID         string
	PlanRevision   uint64
	OperationID    string
	Target         string
	OwnershipToken string
	BeforeDigest   string
	AppliedDigest  string
	ReasonCode     string
	StartedAt      time.Time
	CompletedAt    time.Time
}

// Validate enforces the ApplyReceipt invariants.
func (receipt ApplyReceipt) Validate() error {
	if !validIdentifier(receipt.PlanID) || receipt.PlanRevision == 0 || !validIdentifier(receipt.OperationID) {
		return fmt.Errorf("%w: apply receipt plan id, revision and operation id are required", ErrInvalidRequest)
	}
	if err := ValidateTarget(receipt.Target); err != nil {
		return err
	}
	if !validIdentifier(receipt.OwnershipToken) {
		return fmt.Errorf("%w: apply receipt ownership token is not a bounded identifier", ErrInvalidRequest)
	}
	if !validDigest(receipt.BeforeDigest) || !validDigest(receipt.AppliedDigest) {
		return fmt.Errorf("%w: apply receipt digests must be hex SHA-256", ErrInvalidRequest)
	}
	if !validReasonCode(receipt.ReasonCode) {
		return fmt.Errorf("%w: apply receipt reason code is not a bounded AF- identifier", ErrInvalidRequest)
	}
	if receipt.StartedAt.IsZero() || receipt.CompletedAt.Before(receipt.StartedAt) {
		return fmt.Errorf("%w: apply receipt timestamps are missing or inverted", ErrInvalidRequest)
	}
	return nil
}

// Receipt converts the apply receipt to the generic signable Receipt.
func (receipt ApplyReceipt) Receipt() Receipt {
	return Receipt{
		SchemaVersion: ContractVersion, Kind: ReceiptKindApply,
		PlanID: receipt.PlanID, PlanRevision: receipt.PlanRevision, OperationID: receipt.OperationID,
		Target: receipt.Target, OwnershipToken: receipt.OwnershipToken, Digest: receipt.AppliedDigest,
		ReasonCode: receipt.ReasonCode, At: receipt.CompletedAt,
	}
}

// VerificationResult is the post-apply comparison between what the driver
// expected to own and what the host shows.
type VerificationResult struct {
	OwnershipToken string
	ExpectedDigest string
	ObservedDigest string
	Verified       bool
	ReasonCodes    []string
	At             time.Time
}

// Validate enforces the VerificationResult invariants, including that
// Verified is only true when the digests agree.
func (result VerificationResult) Validate() error {
	if !validIdentifier(result.OwnershipToken) {
		return fmt.Errorf("%w: verification ownership token is not a bounded identifier", ErrInvalidRequest)
	}
	if !validDigest(result.ExpectedDigest) || !validDigest(result.ObservedDigest) {
		return fmt.Errorf("%w: verification digests must be hex SHA-256", ErrInvalidRequest)
	}
	if result.Verified && result.ExpectedDigest != result.ObservedDigest {
		return fmt.Errorf("%w: verification cannot pass with differing digests", ErrInvalidRequest)
	}
	if result.At.IsZero() {
		return fmt.Errorf("%w: verification at is required", ErrInvalidRequest)
	}
	return validateReasonCodes(result.ReasonCodes)
}

// RollbackRequest names the ownership to revert. Rolling back an ownership
// token twice is a no-op success with AlreadyRolledBack set.
type RollbackRequest struct {
	PlanID         string
	PlanRevision   uint64
	OperationID    string
	OwnershipToken string
	Timeout        time.Duration
}

// Validate enforces the RollbackRequest invariants.
func (request RollbackRequest) Validate() error {
	if !validIdentifier(request.PlanID) || request.PlanRevision == 0 || !validIdentifier(request.OperationID) {
		return fmt.Errorf("%w: rollback plan id, revision and operation id are required", ErrInvalidRequest)
	}
	if !validIdentifier(request.OwnershipToken) {
		return fmt.Errorf("%w: rollback ownership token is not a bounded identifier", ErrInvalidRequest)
	}
	if request.Timeout <= 0 || request.Timeout > MaxOperationTimeout {
		return fmt.Errorf("%w: rollback timeout must be within (0, %s]", ErrInvalidRequest, MaxOperationTimeout)
	}
	return nil
}

// RollbackReceipt records the outcome of a rollback. RestoredDigest is the
// snapshot digest observed after the revert.
type RollbackReceipt struct {
	PlanID            string
	PlanRevision      uint64
	OperationID       string
	OwnershipToken    string
	RestoredDigest    string
	AlreadyRolledBack bool
	ReasonCode        string
	At                time.Time
}

// Validate enforces the RollbackReceipt invariants.
func (receipt RollbackReceipt) Validate() error {
	if !validIdentifier(receipt.PlanID) || receipt.PlanRevision == 0 || !validIdentifier(receipt.OperationID) {
		return fmt.Errorf("%w: rollback receipt plan id, revision and operation id are required", ErrInvalidRequest)
	}
	if !validIdentifier(receipt.OwnershipToken) || !validDigest(receipt.RestoredDigest) || !validReasonCode(receipt.ReasonCode) {
		return fmt.Errorf("%w: rollback receipt token, digest or reason code is invalid", ErrInvalidRequest)
	}
	if receipt.At.IsZero() {
		return fmt.Errorf("%w: rollback receipt at is required", ErrInvalidRequest)
	}
	return nil
}

// Receipt converts the rollback receipt to the generic signable Receipt.
func (receipt RollbackReceipt) Receipt() Receipt {
	return Receipt{
		SchemaVersion: ContractVersion, Kind: ReceiptKindRollback,
		PlanID: receipt.PlanID, PlanRevision: receipt.PlanRevision, OperationID: receipt.OperationID,
		OwnershipToken: receipt.OwnershipToken, Digest: receipt.RestoredDigest,
		ReasonCode: receipt.ReasonCode, At: receipt.At,
	}
}

// RecoveredOperation is one journal entry Recover acted on.
type RecoveredOperation struct {
	PlanID         string
	PlanRevision   uint64
	OperationID    string
	OwnershipToken string
	Step           Step
	Reverted       bool
	Finished       bool
}

// RecoveryReport summarises a Recover pass. A clean pass has no operations
// and ReasonRecoveryClean.
type RecoveryReport struct {
	Operations  []RecoveredOperation
	ReasonCodes []string
	At          time.Time
}

// Validate enforces the RecoveryReport invariants.
func (report RecoveryReport) Validate() error {
	if report.At.IsZero() {
		return fmt.Errorf("%w: recovery report at is required", ErrInvalidRequest)
	}
	for _, operation := range report.Operations {
		if !validIdentifier(operation.PlanID) || operation.PlanRevision == 0 || !validIdentifier(operation.OperationID) || !validIdentifier(operation.OwnershipToken) {
			return fmt.Errorf("%w: recovered operation identity is invalid", ErrInvalidRequest)
		}
		if !operation.Step.Valid() {
			return fmt.Errorf("%w: recovered operation step is unknown", ErrInvalidRequest)
		}
	}
	return validateReasonCodes(report.ReasonCodes)
}

// HealthReport is the driver's current self-assessment. A driver whose
// journal is corrupt must report HealthUnavailable with
// ReasonProbeJournalCorrupt.
type HealthReport struct {
	Status      HealthStatus
	ReasonCodes []string
	At          time.Time
}

// Validate enforces the HealthReport invariants.
func (report HealthReport) Validate() error {
	if report.Status > HealthUnavailable {
		return fmt.Errorf("%w: health status %d is unknown", ErrInvalidRequest, report.Status)
	}
	if report.At.IsZero() {
		return fmt.Errorf("%w: health report at is required", ErrInvalidRequest)
	}
	return validateReasonCodes(report.ReasonCodes)
}

// RecoveryPathKind classifies an out-of-band recovery path.
type RecoveryPathKind uint8

const (
	// RecoveryPathUnknown is the zero value and is rejected.
	RecoveryPathUnknown RecoveryPathKind = iota
	// RecoveryPathNetwork is a literal network (IP or CIDR) that stays
	// reachable regardless of the plan.
	RecoveryPathNetwork
	// RecoveryPathLocalConsole is a local, non-network path such as a
	// serial console or local socket.
	RecoveryPathLocalConsole
)

// String returns the stable spelling of the kind.
func (kind RecoveryPathKind) String() string {
	switch kind {
	case RecoveryPathNetwork:
		return "NETWORK"
	case RecoveryPathLocalConsole:
		return "LOCAL_CONSOLE"
	default:
		return "UNKNOWN"
	}
}

// RecoveryPath is one out-of-band path that must remain reachable
// independent of any plan the driver applies.
type RecoveryPath struct {
	Kind        RecoveryPathKind
	Address     string
	Description string
}

// Validate enforces the RecoveryPath invariants.
func (path RecoveryPath) Validate() error {
	if path.Kind == RecoveryPathUnknown || path.Kind > RecoveryPathLocalConsole {
		return fmt.Errorf("%w: recovery path kind is unknown", ErrInvalidRequest)
	}
	if err := ValidateTarget(path.Address); err != nil {
		return err
	}
	if len(path.Description) > MaxSafeMessageLength || !printableASCII(path.Description) {
		return fmt.Errorf("%w: recovery path description is oversized or not printable ASCII", ErrInvalidRequest)
	}
	return nil
}

// PrivilegeBoundary is the explicit statement of what a driver executes.
// Binary is an absolute path or a symbolic name for drivers that execute
// nothing; ArgumentPattern is the exact argument vector (wildcards are not
// permitted); Privilege names the credential required; ShellFree must be
// true for every conforming driver.
type PrivilegeBoundary struct {
	Binary          string
	ArgumentPattern []string
	Privilege       string
	ShellFree       bool
	Description     string
}

// Validate enforces the PrivilegeBoundary invariants.
func (boundary PrivilegeBoundary) Validate() error {
	if !validIdentifier(boundary.Binary) || len(boundary.Binary) > MaxTargetLength {
		return fmt.Errorf("%w: privilege boundary binary is not a bounded identifier", ErrInvalidRequest)
	}
	if len(boundary.ArgumentPattern) > MaxCommandArguments {
		return fmt.Errorf("%w: privilege boundary exceeds %d arguments", ErrInvalidRequest, MaxCommandArguments)
	}
	for _, argument := range boundary.ArgumentPattern {
		if argument == "" || len(argument) > MaxTargetLength || !printableASCII(argument) {
			return fmt.Errorf("%w: privilege boundary argument is empty, oversized, or not printable ASCII", ErrInvalidRequest)
		}
	}
	if !validIdentifier(boundary.Privilege) {
		return fmt.Errorf("%w: privilege boundary privilege is not a bounded identifier", ErrInvalidRequest)
	}
	if !boundary.ShellFree {
		return fmt.Errorf("%w: privilege boundary must be shell-free", ErrInvalidRequest)
	}
	if len(boundary.Description) > MaxSafeMessageLength || !printableASCII(boundary.Description) {
		return fmt.Errorf("%w: privilege boundary description is oversized or not printable ASCII", ErrInvalidRequest)
	}
	return nil
}

// CommandPlan is the reviewable, shell-free dry run of what Apply would
// execute: one executable, an explicit argument vector, and stdin input.
// Drivers that execute nothing return their own name and an empty vector.
type CommandPlan struct {
	Executable string
	Arguments  []string
	Input      string
}

// Validate enforces the CommandPlan invariants, including that no argument
// contains shell metacharacters.
func (plan CommandPlan) Validate() error {
	if !validIdentifier(plan.Executable) || len(plan.Executable) > MaxTargetLength {
		return fmt.Errorf("%w: command executable is not a bounded identifier", ErrInvalidRequest)
	}
	if len(plan.Arguments) > MaxCommandArguments {
		return fmt.Errorf("%w: command exceeds %d arguments", ErrInvalidRequest, MaxCommandArguments)
	}
	for _, argument := range plan.Arguments {
		if err := ValidateTarget(argument); err != nil {
			return fmt.Errorf("%w: command argument", err)
		}
	}
	if len(plan.Input) > MaxCommandInputBytes {
		return fmt.Errorf("%w: command input exceeds %d bytes", ErrInvalidRequest, MaxCommandInputBytes)
	}
	for _, r := range plan.Input {
		if r == '\n' || r == '\t' {
			continue
		}
		if r > 0x7e || r < 0x20 {
			return fmt.Errorf("%w: command input contains control or non-ASCII bytes", ErrInvalidRequest)
		}
	}
	return nil
}

// HostStateCapturer reads host state. Guarantee: Capture is read-only,
// honours ctx, returns a Snapshot whose Digest is stable for unchanged state,
// and never exceeds MaxSnapshotEntries.
type HostStateCapturer interface {
	Capture(ctx context.Context, scope Scope) (Snapshot, error)
}

// Simulator predicts the effect of an operation. Guarantee: Simulate is a
// pure function of snapshot and operation; it never reads or touches the
// host, and calling it leaves every Capture digest unchanged.
type Simulator interface {
	Simulate(ctx context.Context, snapshot Snapshot, operation *antiflockv1.PlanOperation) (SimulationResult, error)
}

// PreconditionChecker evaluates a plan check. Guarantee: read-only; an
// unsupported check type yields CHECK_OUTCOME_UNKNOWN with
// ReasonCheckUnsupported rather than an error, so the enforcer can fail
// closed on a required check.
type PreconditionChecker interface {
	Check(ctx context.Context, check *antiflockv1.PlanCheck) (CheckObservation, error)
}

// Applier performs the mutation. Guarantee: the request is validated before
// any boundary is crossed; only request.Target changes; the journal records
// ownership before the host changes; ctx expiry before mutation leaves the
// host untouched and returns the ctx error.
type Applier interface {
	Apply(ctx context.Context, request ApplyRequest) (ApplyReceipt, error)
}

// PostApplyVerifier re-reads the host and compares it with a receipt.
// Guarantee: read-only; Verified is true only when digests match.
type PostApplyVerifier interface {
	Verify(ctx context.Context, receipt ApplyReceipt) (VerificationResult, error)
}

// RollbackDriver reverts an owned mutation. Guarantee: idempotent; a second
// rollback of the same ownership token is a no-op success with
// AlreadyRolledBack=true; an unknown token is ErrUnknownOwnership.
type RollbackDriver interface {
	Rollback(ctx context.Context, request RollbackRequest) (RollbackReceipt, error)
}

// CrashRecoverer finishes or reverts in-flight work found in the journal.
// Guarantee: idempotent; reads the journal, not the network; never requires
// the host to be in the post-apply state; a corrupt journal yields
// ErrJournalCorrupt and no host access.
type CrashRecoverer interface {
	Recover(ctx context.Context) (RecoveryReport, error)
}

// HealthReporter reports the driver's current self-assessment. Guarantee:
// read-only; a corrupt journal reports HealthUnavailable with
// ReasonProbeJournalCorrupt.
type HealthReporter interface {
	Health(ctx context.Context) (HealthReport, error)
}

// RecoveryAccess enumerates out-of-band recovery paths. Guarantee: read-only;
// every path returned must remain reachable regardless of the plan; a driver
// with no independent path returns an empty list so the caller can refuse
// to proceed.
type RecoveryAccess interface {
	RecoveryPaths(ctx context.Context) ([]RecoveryPath, error)
}

// CommandPlanner exposes the exact command Apply would run for an operation.
// Guarantee: read-only; targets containing shell metacharacters are rejected
// with ErrUnsafeTarget before any plan is rendered.
type CommandPlanner interface {
	CommandPlan(ctx context.Context, operation *antiflockv1.PlanOperation) (CommandPlan, error)
}

// Driver is the complete host-mutation boundary. Name and Version are
// bounded identifiers; PrivilegeBoundary must validate.
type Driver interface {
	Prober
	HostStateCapturer
	Simulator
	PreconditionChecker
	Applier
	PostApplyVerifier
	RollbackDriver
	CrashRecoverer
	HealthReporter
	RecoveryAccess
	CommandPlanner
	Name() string
	Version() string
	PrivilegeBoundary() PrivilegeBoundary
}

// Reopener is implemented by drivers that can hand out a fresh instance over
// the same durable state (journal, reservation store, host). The conformance
// suite uses it to model a process restart; production callers do not need
// it.
type Reopener interface {
	Reopen() (Driver, error)
}

// CrashSimulator is implemented by drivers that can model process death.
// After InjectCrash, the next Apply journals Begin, mutates the host, and
// returns ErrCrashInjected without journalling Finish. The conformance suite
// requires it so crash recovery is tested against every driver.
type CrashSimulator interface {
	InjectCrash()
}

// ValidateTarget enforces the target rules shared by every driver: non-empty,
// bounded, printable ASCII, no whitespace, and none of the shell
// metacharacters ; | & $ ` < > ( ) { } [ ] * ? ! ~ ' " \ or #.
func ValidateTarget(target string) error {
	if target == "" || len(target) > MaxTargetLength {
		return fmt.Errorf("%w: target is empty or longer than %d bytes", ErrUnsafeTarget, MaxTargetLength)
	}
	if !printableASCII(target) {
		return fmt.Errorf("%w: target contains control or non-ASCII characters", ErrUnsafeTarget)
	}
	if strings.ContainsAny(target, " \t;|&$`<>(){}[]*?!~'\"\\#") {
		return fmt.Errorf("%w: target contains whitespace or shell metacharacters", ErrUnsafeTarget)
	}
	return nil
}

func validateReasonCodes(codes []string) error {
	if len(codes) == 0 || len(codes) > MaxReasonCodes {
		return fmt.Errorf("%w: between 1 and %d reason codes are required", ErrInvalidRequest, MaxReasonCodes)
	}
	for _, code := range codes {
		if !validReasonCode(code) {
			return fmt.Errorf("%w: reason code is not a bounded AF- identifier", ErrInvalidRequest)
		}
	}
	return nil
}

func validDigest(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

// digestWriter is the shared length-prefixed SHA-256 layout used by every
// Digest in this package; it matches the layout ProbeResult.Digest uses.
type digestWriter struct {
	hash interface {
		Write([]byte) (int, error)
		Sum([]byte) []byte
	}
}

func newDigest(domain string) digestWriter {
	writer := digestWriter{hash: sha256.New()}
	writer.str(domain)
	return writer
}

func (writer digestWriter) bytes(value []byte) {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	writer.hash.Write(length[:])
	writer.hash.Write(value)
}

func (writer digestWriter) str(value string) { writer.bytes([]byte(value)) }

func (writer digestWriter) uint(value uint64) {
	var buffer [8]byte
	binary.BigEndian.PutUint64(buffer[:], value)
	writer.bytes(buffer[:])
}

func (writer digestWriter) strs(values []string) {
	writer.uint(uint64(len(values)))
	for _, value := range values {
		writer.str(value)
	}
}

func (writer digestWriter) time(value time.Time) {
	writer.uint(uint64(value.UTC().Unix()))
	writer.uint(uint64(value.UTC().Nanosecond()))
}

func (writer digestWriter) hex() string { return hex.EncodeToString(writer.hash.Sum(nil)) }
