// Package memory is the reference driver.Driver over an in-memory fake host.
// It exists so the lifecycle, the conformance suite and simulations have a
// complete, host-free implementation of the contract. It never touches the
// real host; its "host" is a map of rules keyed by operation type and
// target, and its durable state (journal, ownership records) lives in a
// Backing that survives Reopen the way a file journal survives a restart.
package memory

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
	"github.com/DBarr3/AntiFlock/agent/driver"
	"google.golang.org/protobuf/proto"
)

// Reason codes specific to the memory driver.
const (
	ReasonRecoveryPending = "AF-DRIVER-MEMORY-RECOVERY-PENDING"
	ReasonTypeMismatch    = "AF-DRIVER-MEMORY-TYPE-MISMATCH"
)

// Defaults used when Config leaves the field empty.
const (
	DefaultName     = "memory"
	DefaultVersion  = "1.0.0"
	executableName  = "antiflock-memory-driver"
	probeKey        = "memory.reference.enforce"
	probeValidity   = 10 * time.Minute
	maxHostRules    = driver.MaxSnapshotEntries
	maxSavedRecords = driver.MaxJournalRecords
)

type ruleKey struct {
	Type   antiflockv1.PlanOperationType
	Target string
}

type savedState struct {
	key      ruleKey
	previous string
	existed  bool
}

// Backing is the durable state shared by every Driver instance opened over
// it: the fake host, the driver journal, ownership records, and the set of
// ownership tokens already rolled back. Process-local state (the crash hook)
// lives in the Driver and is lost on Reopen, which is exactly what a restart
// loses.
type Backing struct {
	journal driver.Journal
	mu      sync.Mutex
	rules   map[ruleKey]string
	saved   map[string]savedState
	rolled  map[string]ruleKey
}

// NewBacking returns empty durable state over the given driver journal. The
// journal must be dedicated to the driver; it must not be shared with a
// Lifecycle, which journals the same identities at the orchestration level.
func NewBacking(journal driver.Journal) (*Backing, error) {
	if journal == nil {
		return nil, errors.New("memory backing journal is required")
	}
	return &Backing{
		journal: journal, rules: make(map[ruleKey]string),
		saved: make(map[string]savedState), rolled: make(map[string]ruleKey),
	}, nil
}

// Rules returns a copy of the fake host's rules for assertions in tests.
func (backing *Backing) Rules() map[string]string {
	backing.mu.Lock()
	defer backing.mu.Unlock()
	out := make(map[string]string, len(backing.rules))
	for key, value := range backing.rules {
		out[key.Type.String()+"/"+key.Target] = value
	}
	return out
}

// Config wires a Driver.
type Config struct {
	Backing       *Backing
	Clock         func() time.Time
	Name          string
	Version       string
	RecoveryPaths []driver.RecoveryPath
}

// Driver is the reference implementation. It is safe for concurrent use.
type Driver struct {
	backing       *Backing
	clock         func() time.Time
	name          string
	version       string
	recoveryPaths []driver.RecoveryPath
	config        Config
	crash         atomic.Bool
}

// New validates the configuration and returns a Driver. A nil RecoveryPaths
// list gets one loopback console path so the reference driver reports
// recovery readiness; pass an empty non-nil slice to model a driver with no
// independent recovery access.
func New(config Config) (*Driver, error) {
	if config.Backing == nil || config.Clock == nil {
		return nil, errors.New("memory driver backing and clock are required")
	}
	if config.Name == "" {
		config.Name = DefaultName
	}
	if config.Version == "" {
		config.Version = DefaultVersion
	}
	if config.RecoveryPaths == nil {
		config.RecoveryPaths = []driver.RecoveryPath{{
			Kind: driver.RecoveryPathLocalConsole, Address: "memory://console", Description: "in-process console; never affected by any plan",
		}}
	}
	if len(config.RecoveryPaths) > driver.MaxRecoveryPaths {
		return nil, fmt.Errorf("%w: more than %d recovery paths", driver.ErrInvalidRequest, driver.MaxRecoveryPaths)
	}
	for _, path := range config.RecoveryPaths {
		if err := path.Validate(); err != nil {
			return nil, err
		}
	}
	instance := &Driver{
		backing: config.Backing, clock: config.Clock, name: config.Name, version: config.Version,
		recoveryPaths: slices.Clone(config.RecoveryPaths), config: config,
	}
	if err := instance.PrivilegeBoundary().Validate(); err != nil {
		return nil, err
	}
	return instance, nil
}

var _ driver.Driver = (*Driver)(nil)
var _ driver.Reopener = (*Driver)(nil)
var _ driver.CrashSimulator = (*Driver)(nil)

// Name implements driver.Driver.
func (instance *Driver) Name() string { return instance.name }

// Version implements driver.Driver.
func (instance *Driver) Version() string { return instance.version }

// PrivilegeBoundary implements driver.Driver. The memory driver executes
// nothing; it declares itself so the statement is explicit.
func (instance *Driver) PrivilegeBoundary() driver.PrivilegeBoundary {
	return driver.PrivilegeBoundary{
		Binary: executableName, ArgumentPattern: []string{"apply", "<operation-type>", "<target>"},
		Privilege: "none", ShellFree: true,
		Description: "in-process reference driver; no binary is executed and no host state is touched",
	}
}

// Reopen implements driver.Reopener: a fresh instance over the same Backing
// with process-local state cleared.
func (instance *Driver) Reopen() (driver.Driver, error) {
	return New(instance.config)
}

// InjectCrash implements driver.CrashSimulator. The next Apply mutates the
// fake host and returns driver.ErrCrashInjected without finishing its
// journal entry.
func (instance *Driver) InjectCrash() { instance.crash.Store(true) }

func (instance *Driver) now() time.Time { return instance.clock().UTC() }

// journalHealthy returns ErrJournalCorrupt when the journal cannot be read;
// it is the gate every mutation passes before touching the fake host.
func (instance *Driver) inFlight(ctx context.Context) ([]driver.JournalRecord, error) {
	records, err := instance.backing.journal.InFlight(ctx)
	if err != nil {
		if errors.Is(err, driver.ErrJournalCorrupt) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %v", driver.ErrJournalCorrupt, err)
	}
	return records, nil
}

// Probe implements driver.Prober.
func (instance *Driver) Probe(ctx context.Context) ([]driver.ProbeResult, error) {
	health, err := instance.Health(ctx)
	if err != nil {
		return nil, err
	}
	paths, err := instance.RecoveryPaths(ctx)
	if err != nil {
		return nil, err
	}
	now := instance.now()
	result := driver.ProbeResult{
		SchemaVersion: driver.ProbeSchemaVersion,
		Key:           probeKey,
		Domain:        antiflockv1.CapabilityDomain_CAPABILITY_DOMAIN_FIREWALL,
		Operations: []antiflockv1.CapabilityOperation{
			antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_OBSERVE,
			antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_ENFORCE,
			antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_VERIFY,
			antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_ROLLBACK,
		},
		SupportLevel:  antiflockv1.CapabilitySupportLevel_CAPABILITY_SUPPORT_LEVEL_EXPERIMENTAL,
		DriverName:    instance.name,
		DriverVersion: instance.version,
		Health:        health.Status,
		RecoveryReady: health.Status == driver.HealthHealthy && len(paths) > 0,
		ReasonCodes:   slices.Clone(health.ReasonCodes),
		Constraints:   []string{"simulation-only", "no-host-mutation"},
		ProbedAt:      now,
		ExpiresAt:     now.Add(probeValidity),
	}
	if err := result.Validate(); err != nil {
		return nil, err
	}
	return []driver.ProbeResult{result}, nil
}

// Health implements driver.HealthReporter.
func (instance *Driver) Health(ctx context.Context) (driver.HealthReport, error) {
	if err := ctx.Err(); err != nil {
		return driver.HealthReport{}, err
	}
	report := driver.HealthReport{At: instance.now()}
	records, err := instance.inFlight(ctx)
	switch {
	case err != nil:
		report.Status = driver.HealthUnavailable
		report.ReasonCodes = []string{driver.ReasonProbeJournalCorrupt}
	case len(records) > 0:
		report.Status = driver.HealthDegraded
		report.ReasonCodes = []string{ReasonRecoveryPending}
	default:
		report.Status = driver.HealthHealthy
		report.ReasonCodes = []string{driver.ReasonProbeOK}
	}
	return report, nil
}

// RecoveryPaths implements driver.RecoveryAccess.
func (instance *Driver) RecoveryPaths(ctx context.Context) ([]driver.RecoveryPath, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return slices.Clone(instance.recoveryPaths), nil
}

// Capture implements driver.HostStateCapturer.
func (instance *Driver) Capture(ctx context.Context, scope driver.Scope) (driver.Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return driver.Snapshot{}, err
	}
	if err := scope.Validate(); err != nil {
		return driver.Snapshot{}, err
	}
	instance.backing.mu.Lock()
	entries := instance.capture(scope)
	instance.backing.mu.Unlock()
	snapshot := driver.Snapshot{
		SchemaVersion: driver.ContractVersion, DriverName: instance.name, Scope: scope,
		Entries: entries, CapturedAt: instance.now(),
	}
	if err := snapshot.Validate(); err != nil {
		return driver.Snapshot{}, err
	}
	return snapshot, nil
}

// capture must be called with backing.mu held.
func (instance *Driver) capture(scope driver.Scope) []driver.SnapshotEntry {
	wanted := make(map[string]struct{}, len(scope.Targets))
	for _, target := range scope.Targets {
		wanted[target] = struct{}{}
	}
	entries := make([]driver.SnapshotEntry, 0)
	for key, value := range instance.backing.rules {
		if key.Type != scope.OperationType {
			continue
		}
		if len(wanted) > 0 {
			if _, ok := wanted[key.Target]; !ok {
				continue
			}
		}
		entries = append(entries, driver.SnapshotEntry{Key: key.Target, Value: value})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Key < entries[j].Key })
	return entries
}

// render is the deterministic value the fake host stores for an operation.
// It carries only the operation type and a digest of its parameters, never
// the parameters themselves.
func render(operation *antiflockv1.PlanOperation) (string, error) {
	parameters, err := proto.MarshalOptions{Deterministic: true}.Marshal(operation.GetParameters())
	if err != nil {
		return "", fmt.Errorf("%w: encode operation parameters", driver.ErrInvalidRequest)
	}
	digest := sha256.Sum256(parameters)
	return strings.ToLower(strings.TrimPrefix(operation.GetType().String(), "PLAN_OPERATION_TYPE_")) + ":" + hex.EncodeToString(digest[:8]), nil
}

func validOperation(operation *antiflockv1.PlanOperation) error {
	if operation == nil {
		return fmt.Errorf("%w: operation is required", driver.ErrInvalidRequest)
	}
	if operation.GetType() == antiflockv1.PlanOperationType_PLAN_OPERATION_TYPE_UNSPECIFIED ||
		antiflockv1.PlanOperationType_name[int32(operation.GetType())] == "" {
		return fmt.Errorf("%w: operation type is unspecified or unknown", driver.ErrInvalidRequest)
	}
	if strings.TrimSpace(operation.GetId()) == "" || len(operation.GetId()) > driver.MaxIdentifierLength {
		return fmt.Errorf("%w: operation id is required", driver.ErrInvalidRequest)
	}
	return driver.ValidateTarget(operation.GetTarget())
}

// Simulate implements driver.Simulator. It is a pure function of the
// snapshot and operation and never reads the fake host.
func (instance *Driver) Simulate(ctx context.Context, snapshot driver.Snapshot, operation *antiflockv1.PlanOperation) (driver.SimulationResult, error) {
	if err := ctx.Err(); err != nil {
		return driver.SimulationResult{}, err
	}
	if err := validOperation(operation); err != nil {
		return driver.SimulationResult{}, err
	}
	before, err := snapshot.Digest()
	if err != nil {
		return driver.SimulationResult{}, err
	}
	result := driver.SimulationResult{OperationID: operation.GetId(), Target: operation.GetTarget(), SnapshotDigest: before}
	if operation.GetType() != snapshot.Scope.OperationType {
		result.Diff = driver.Diff{BeforeDigest: before, AfterDigest: before, Lines: []string{"! operation type does not match the captured scope"}}
		result.ReasonCodes = []string{driver.ReasonSimulationReject, ReasonTypeMismatch}
		return result, nil
	}
	value, err := render(operation)
	if err != nil {
		return driver.SimulationResult{}, err
	}
	after := snapshot
	after.Entries = slices.Clone(snapshot.Entries)
	var lines []string
	index := slices.IndexFunc(after.Entries, func(entry driver.SnapshotEntry) bool { return entry.Key == operation.GetTarget() })
	switch {
	case index < 0:
		after.Entries = append(after.Entries, driver.SnapshotEntry{Key: operation.GetTarget(), Value: value})
		sort.Slice(after.Entries, func(i, j int) bool { return after.Entries[i].Key < after.Entries[j].Key })
		lines = []string{"+ " + operation.GetTarget() + " = " + value}
	case after.Entries[index].Value == value:
		lines = []string{"= " + operation.GetTarget() + " unchanged"}
	default:
		lines = []string{"~ " + operation.GetTarget() + ": " + after.Entries[index].Value + " -> " + value}
		after.Entries[index].Value = value
	}
	afterDigest, err := after.Digest()
	if err != nil {
		return driver.SimulationResult{}, err
	}
	result.Diff = driver.Diff{BeforeDigest: before, AfterDigest: afterDigest, Lines: lines}
	result.WouldSucceed = true
	if afterDigest == before {
		result.ReasonCodes = []string{driver.ReasonSimulationNoop}
	} else {
		result.ReasonCodes = []string{driver.ReasonSimulationOK}
	}
	if err := result.Validate(); err != nil {
		return driver.SimulationResult{}, err
	}
	return result, nil
}

// Check implements driver.PreconditionChecker. Only state.capture is
// supported; it passes when the journal is readable.
func (instance *Driver) Check(ctx context.Context, check *antiflockv1.PlanCheck) (driver.CheckObservation, error) {
	if err := ctx.Err(); err != nil {
		return driver.CheckObservation{}, err
	}
	if check == nil || strings.TrimSpace(check.GetId()) == "" {
		return driver.CheckObservation{}, fmt.Errorf("%w: check and check id are required", driver.ErrInvalidRequest)
	}
	if check.GetCheckType() != "state.capture" {
		return driver.CheckObservation{
			Outcome: antiflockv1.CheckOutcome_CHECK_OUTCOME_UNKNOWN, ReasonCode: driver.ReasonCheckUnsupported,
			SafeMessage: "The memory driver does not implement this check type.",
		}, nil
	}
	if _, err := instance.inFlight(ctx); err != nil {
		return driver.CheckObservation{
			Outcome: antiflockv1.CheckOutcome_CHECK_OUTCOME_FAILED, ReasonCode: driver.ReasonProbeJournalCorrupt,
			SafeMessage: "The driver journal is unreadable; state capture is refused.",
		}, nil
	}
	return driver.CheckObservation{
		Outcome: antiflockv1.CheckOutcome_CHECK_OUTCOME_PASSED, ReasonCode: driver.ReasonCheckPassed,
		SafeMessage: "Host state capture is available.",
	}, nil
}

// CommandPlan implements driver.CommandPlanner.
func (instance *Driver) CommandPlan(ctx context.Context, operation *antiflockv1.PlanOperation) (driver.CommandPlan, error) {
	if err := ctx.Err(); err != nil {
		return driver.CommandPlan{}, err
	}
	if err := validOperation(operation); err != nil {
		return driver.CommandPlan{}, err
	}
	plan := driver.CommandPlan{
		Executable: executableName,
		Arguments:  []string{"apply", strings.ToLower(strings.TrimPrefix(operation.GetType().String(), "PLAN_OPERATION_TYPE_")), operation.GetTarget()},
	}
	if err := plan.Validate(); err != nil {
		return driver.CommandPlan{}, err
	}
	return plan, nil
}

func ownershipToken(request driver.ApplyRequest, startedAt time.Time) string {
	hash := sha256.New()
	write := func(value string) {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(value)))
		hash.Write(length[:])
		hash.Write([]byte(value))
	}
	write("AntiFlock-MemoryDriverOwnership-v1")
	write(request.PlanID)
	write(fmt.Sprintf("%d", request.PlanRevision))
	write(request.OperationID)
	write(request.Target)
	write(request.Reservation.Token)
	write(startedAt.UTC().Format(time.RFC3339Nano))
	return hex.EncodeToString(hash.Sum(nil))
}

// Apply implements driver.Applier. Order: validate, check journal health,
// capture before-state, simulate, persist the ownership record, journal
// Begin, mutate, journal Finish. A crash injected after the mutation leaves
// the journal open for Recover.
func (instance *Driver) Apply(ctx context.Context, request driver.ApplyRequest) (driver.ApplyReceipt, error) {
	if err := request.Validate(); err != nil {
		return driver.ApplyReceipt{}, err
	}
	if err := ctx.Err(); err != nil {
		return driver.ApplyReceipt{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, request.Timeout)
	defer cancel()
	if _, err := instance.inFlight(ctx); err != nil {
		return driver.ApplyReceipt{}, err
	}
	scope := driver.Scope{OperationType: request.Operation.GetType(), Targets: []string{request.Target}}
	startedAt := instance.now()
	instance.backing.mu.Lock()
	defer instance.backing.mu.Unlock()
	before := driver.Snapshot{SchemaVersion: driver.ContractVersion, DriverName: instance.name, Scope: scope, Entries: instance.capture(scope), CapturedAt: startedAt}
	simulation, err := instance.Simulate(ctx, before, request.Operation)
	if err != nil {
		return driver.ApplyReceipt{}, err
	}
	if !simulation.WouldSucceed {
		return driver.ApplyReceipt{}, fmt.Errorf("%w: %s", driver.ErrInvalidRequest, strings.Join(simulation.ReasonCodes, ","))
	}
	if len(instance.backing.rules) >= maxHostRules || len(instance.backing.saved) >= maxSavedRecords {
		return driver.ApplyReceipt{}, fmt.Errorf("%w: fake host is full", driver.ErrInvalidRequest)
	}
	key := ruleKey{Type: request.Operation.GetType(), Target: request.Target}
	token := ownershipToken(request, startedAt)
	previous, existed := instance.backing.rules[key]
	instance.backing.saved[token] = savedState{key: key, previous: previous, existed: existed}
	record := driver.JournalRecord{
		SchemaVersion: driver.ContractVersion, PlanID: request.PlanID, PlanRevision: request.PlanRevision,
		OperationID: request.OperationID, Step: driver.StepApply, OwnershipToken: token, Digest: simulation.SnapshotDigest, At: startedAt,
	}
	if err := instance.backing.journal.Begin(ctx, record); err != nil {
		delete(instance.backing.saved, token)
		return driver.ApplyReceipt{}, err
	}
	if err := ctx.Err(); err != nil {
		delete(instance.backing.saved, token)
		record.Step = driver.StepRollback
		_ = instance.backing.journal.Finish(context.WithoutCancel(ctx), record)
		return driver.ApplyReceipt{}, err
	}
	value, _ := render(request.Operation)
	instance.backing.rules[key] = value
	if instance.crash.CompareAndSwap(true, false) {
		return driver.ApplyReceipt{}, driver.ErrCrashInjected
	}
	after := driver.Snapshot{SchemaVersion: driver.ContractVersion, DriverName: instance.name, Scope: scope, Entries: instance.capture(scope), CapturedAt: instance.now()}
	appliedDigest, err := after.Digest()
	if err != nil {
		return driver.ApplyReceipt{}, err
	}
	completedAt := instance.now()
	record.Step = driver.StepCommit
	record.Digest = appliedDigest
	record.At = completedAt
	if err := instance.backing.journal.Finish(ctx, record); err != nil {
		return driver.ApplyReceipt{}, err
	}
	receipt := driver.ApplyReceipt{
		PlanID: request.PlanID, PlanRevision: request.PlanRevision, OperationID: request.OperationID, Target: request.Target,
		OwnershipToken: token, BeforeDigest: simulation.SnapshotDigest, AppliedDigest: appliedDigest,
		ReasonCode: driver.ReasonApplied, StartedAt: startedAt, CompletedAt: completedAt,
	}
	if err := receipt.Validate(); err != nil {
		return driver.ApplyReceipt{}, err
	}
	return receipt, nil
}

// Verify implements driver.PostApplyVerifier.
func (instance *Driver) Verify(ctx context.Context, receipt driver.ApplyReceipt) (driver.VerificationResult, error) {
	if err := receipt.Validate(); err != nil {
		return driver.VerificationResult{}, err
	}
	if err := ctx.Err(); err != nil {
		return driver.VerificationResult{}, err
	}
	instance.backing.mu.Lock()
	defer instance.backing.mu.Unlock()
	key, known := instance.ownedKey(receipt.OwnershipToken)
	if !known {
		return driver.VerificationResult{}, driver.ErrUnknownOwnership
	}
	scope := driver.Scope{OperationType: key.Type, Targets: []string{key.Target}}
	now := instance.now()
	observed := driver.Snapshot{SchemaVersion: driver.ContractVersion, DriverName: instance.name, Scope: scope, Entries: instance.capture(scope), CapturedAt: now}
	digest, err := observed.Digest()
	if err != nil {
		return driver.VerificationResult{}, err
	}
	result := driver.VerificationResult{
		OwnershipToken: receipt.OwnershipToken, ExpectedDigest: receipt.AppliedDigest, ObservedDigest: digest,
		Verified: digest == receipt.AppliedDigest, At: now,
	}
	if result.Verified {
		result.ReasonCodes = []string{driver.ReasonVerified}
	} else {
		result.ReasonCodes = []string{driver.ReasonVerifyMismatch}
	}
	return result, nil
}

// ownedKey must be called with backing.mu held.
func (instance *Driver) ownedKey(token string) (ruleKey, bool) {
	if saved, ok := instance.backing.saved[token]; ok {
		return saved.key, true
	}
	if key, ok := instance.backing.rolled[token]; ok {
		return key, true
	}
	return ruleKey{}, false
}

// restore must be called with backing.mu held. It reverts the rule named by
// the ownership record and marks the token rolled back.
func (instance *Driver) restore(token string) (ruleKey, bool) {
	saved, ok := instance.backing.saved[token]
	if !ok {
		return ruleKey{}, false
	}
	if saved.existed {
		instance.backing.rules[saved.key] = saved.previous
	} else {
		delete(instance.backing.rules, saved.key)
	}
	delete(instance.backing.saved, token)
	instance.backing.rolled[token] = saved.key
	return saved.key, true
}

// Rollback implements driver.RollbackDriver. A second rollback of the same
// token is a no-op success with AlreadyRolledBack set.
func (instance *Driver) Rollback(ctx context.Context, request driver.RollbackRequest) (driver.RollbackReceipt, error) {
	if err := request.Validate(); err != nil {
		return driver.RollbackReceipt{}, err
	}
	if err := ctx.Err(); err != nil {
		return driver.RollbackReceipt{}, err
	}
	if _, err := instance.inFlight(ctx); err != nil {
		return driver.RollbackReceipt{}, err
	}
	instance.backing.mu.Lock()
	defer instance.backing.mu.Unlock()
	now := instance.now()
	receipt := driver.RollbackReceipt{
		PlanID: request.PlanID, PlanRevision: request.PlanRevision, OperationID: request.OperationID,
		OwnershipToken: request.OwnershipToken, At: now,
	}
	var key ruleKey
	if rolledKey, already := instance.backing.rolled[request.OwnershipToken]; already {
		key = rolledKey
		receipt.AlreadyRolledBack = true
		receipt.ReasonCode = driver.ReasonAlreadyRolled
	} else {
		restored, ok := instance.restore(request.OwnershipToken)
		if !ok {
			return driver.RollbackReceipt{}, driver.ErrUnknownOwnership
		}
		key = restored
		receipt.ReasonCode = driver.ReasonRolledBack
		if err := instance.closeOpenEntry(ctx, request.PlanID, request.PlanRevision, request.OperationID, request.OwnershipToken, now); err != nil {
			return driver.RollbackReceipt{}, err
		}
	}
	scope := driver.Scope{OperationType: key.Type, Targets: []string{key.Target}}
	restored := driver.Snapshot{SchemaVersion: driver.ContractVersion, DriverName: instance.name, Scope: scope, Entries: instance.capture(scope), CapturedAt: now}
	digest, err := restored.Digest()
	if err != nil {
		return driver.RollbackReceipt{}, err
	}
	receipt.RestoredDigest = digest
	if err := receipt.Validate(); err != nil {
		return driver.RollbackReceipt{}, err
	}
	return receipt, nil
}

// closeOpenEntry finishes a still-open journal entry for the identity (the
// crash case) with a rollback record; a closed entry is left alone.
func (instance *Driver) closeOpenEntry(ctx context.Context, planID string, revision uint64, operationID, token string, at time.Time) error {
	records, err := instance.inFlight(ctx)
	if err != nil {
		return err
	}
	for _, record := range records {
		if record.PlanID == planID && record.PlanRevision == revision && record.OperationID == operationID {
			return instance.backing.journal.Finish(ctx, driver.JournalRecord{
				SchemaVersion: driver.ContractVersion, PlanID: planID, PlanRevision: revision, OperationID: operationID,
				Step: driver.StepRollback, OwnershipToken: token, At: at,
			})
		}
	}
	return nil
}

// Recover implements driver.CrashRecoverer. It reads the journal, reverts
// every open apply through its ownership record, and closes the entry. It
// never inspects the fake host to decide what to do.
func (instance *Driver) Recover(ctx context.Context) (driver.RecoveryReport, error) {
	if err := ctx.Err(); err != nil {
		return driver.RecoveryReport{}, err
	}
	records, err := instance.inFlight(ctx)
	if err != nil {
		return driver.RecoveryReport{}, err
	}
	instance.backing.mu.Lock()
	defer instance.backing.mu.Unlock()
	now := instance.now()
	report := driver.RecoveryReport{At: now}
	for _, record := range records {
		operation := driver.RecoveredOperation{
			PlanID: record.PlanID, PlanRevision: record.PlanRevision, OperationID: record.OperationID,
			OwnershipToken: record.OwnershipToken, Step: record.Step,
		}
		if record.OwnershipToken != "" {
			if _, reverted := instance.restore(record.OwnershipToken); reverted {
				operation.Reverted = true
			}
		}
		finish := driver.JournalRecord{
			SchemaVersion: driver.ContractVersion, PlanID: record.PlanID, PlanRevision: record.PlanRevision, OperationID: record.OperationID,
			Step: driver.StepRollback, OwnershipToken: record.OwnershipToken, At: now,
		}
		if err := instance.backing.journal.Finish(ctx, finish); err != nil {
			return driver.RecoveryReport{}, err
		}
		operation.Finished = true
		if operation.OwnershipToken == "" {
			operation.OwnershipToken = "none"
		}
		report.Operations = append(report.Operations, operation)
	}
	if len(report.Operations) == 0 {
		report.ReasonCodes = []string{driver.ReasonRecoveryClean}
	} else {
		report.ReasonCodes = []string{driver.ReasonRecovered}
	}
	if err := report.Validate(); err != nil {
		return driver.RecoveryReport{}, err
	}
	return report, nil
}
