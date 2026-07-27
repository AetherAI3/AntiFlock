package nano

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/DBarr3/AntiFlock/core/audit"
	"github.com/DBarr3/AntiFlock/core/storage"
	"github.com/DBarr3/AntiFlock/internal/id"
)

// Registry admits immutable Nano source into the constrained watchdog profile.
// It has no provider, process, network, or action-execution capability.
type Registry struct {
	database *storage.DB
	audit    *audit.Service
	clock    func() time.Time
}

type AdmissionRequest struct {
	NodeID      string
	Source      string
	BindingID   BindingID
	OperationID string
	ActorID     string
}

func NewRegistry(database *storage.DB, auditService *audit.Service, clock func() time.Time) (*Registry, error) {
	if database == nil || auditService == nil {
		return nil, errors.New("nano registry requires database and audit service")
	}
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}
	return &Registry{database: database, audit: auditService, clock: clock}, nil
}

func (registry *Registry) Admit(ctx context.Context, request AdmissionRequest) (storage.NanoWatchdogProgramRecord, error) {
	if registry == nil || !opaque(request.NodeID) || !opaque(request.OperationID) || !opaque(request.ActorID) || strings.TrimSpace(request.Source) == "" {
		return storage.NanoWatchdogProgramRecord{}, errors.New("nano watchdog admission request is invalid")
	}
	source := strings.TrimSpace(request.Source)
	program, err := Compile(source, DefaultLimits)
	if err != nil {
		return storage.NanoWatchdogProgramRecord{}, fmt.Errorf("compile Nano watchdog source: %w", err)
	}
	if err := AdmitWatchdog(program); err != nil {
		return storage.NanoWatchdogProgramRecord{}, err
	}
	if _, err := BindingDigest(request.BindingID); err != nil {
		return storage.NanoWatchdogProgramRecord{}, err
	}
	digest, err := program.Digest()
	if err != nil {
		return storage.NanoWatchdogProgramRecord{}, err
	}
	now := registry.clock().UTC()
	record := storage.NanoWatchdogProgramRecord{
		ID: id.New("watchdog"), NodeID: request.NodeID, Name: program.Name, Source: source, ProgramDigest: digest,
		BindingID: string(request.BindingID), Status: storage.NanoWatchdogAdmitted, OperationID: request.OperationID, CreatedAt: now, UpdatedAt: now,
	}
	_, err = registry.audit.AppendWithMutation(ctx, audit.AppendRequest{
		ActorType: "operator", ActorID: request.ActorID, Action: "nano.watchdog.admit", ResourceType: "nano_watchdog", ResourceID: record.ID, Outcome: "admitted",
		Details: map[string]string{"nodeId": record.NodeID, "programDigest": record.ProgramDigest, "bindingId": record.BindingID, "operationId": record.OperationID},
	}, registry.database.CreateNanoWatchdogProgramMutation(record))
	if errors.Is(err, storage.ErrOperationConflict) {
		existing, lookupErr := registry.database.GetNanoWatchdogProgramByOperation(ctx, request.OperationID)
		if lookupErr != nil {
			return storage.NanoWatchdogProgramRecord{}, lookupErr
		}
		if existing.NodeID == record.NodeID && existing.ProgramDigest == record.ProgramDigest && existing.BindingID == record.BindingID && existing.Source == record.Source {
			return existing, nil
		}
		return storage.NanoWatchdogProgramRecord{}, errors.New("nano watchdog operation id is already bound to different source")
	}
	if errors.Is(err, storage.ErrProgramConflict) {
		existing, lookupErr := registry.programByDigest(ctx, record.NodeID, record.ProgramDigest)
		if lookupErr != nil {
			return storage.NanoWatchdogProgramRecord{}, lookupErr
		}
		if existing.OperationID == record.OperationID && existing.BindingID == record.BindingID && existing.Source == record.Source {
			return existing, nil
		}
		return storage.NanoWatchdogProgramRecord{}, errors.New("nano watchdog program digest is already admitted for this node under a different operation")
	}
	if err != nil {
		return storage.NanoWatchdogProgramRecord{}, err
	}
	return record, nil
}

// programByDigest resolves one node's admitted program by content digest. The
// (node_id, program_digest) uniqueness guarantee means at most one can match.
func (registry *Registry) programByDigest(ctx context.Context, nodeID, digest string) (storage.NanoWatchdogProgramRecord, error) {
	programs, err := registry.database.ListNanoWatchdogPrograms(ctx, nodeID)
	if err != nil {
		return storage.NanoWatchdogProgramRecord{}, err
	}
	for _, program := range programs {
		if program.ProgramDigest == digest {
			return program, nil
		}
	}
	return storage.NanoWatchdogProgramRecord{}, errors.New("admitted nano watchdog program is missing after a digest conflict")
}

func (registry *Registry) List(ctx context.Context, nodeID string) ([]storage.NanoWatchdogProgramRecord, error) {
	if registry == nil {
		return nil, errors.New("nano registry is required")
	}
	return registry.database.ListNanoWatchdogPrograms(ctx, nodeID)
}

const maximumCoreFindingBatch = 128

// FindingRunResult binds a proposal-only result to the Core finding that
// supplied the host-owned input. It contains neither raw evidence nor a
// caller-selected signal.
type FindingRunResult struct {
	FindingID string    `json:"findingId"`
	Result    RunResult `json:"result"`
}

// OpenFindingRunResult is a bounded, deterministic Core-owned watchdog pass.
// It is operator-invoked and proposal-only; it neither authorizes nor executes
// a proposed action.
type OpenFindingRunResult struct {
	ProgramID      string             `json:"programId"`
	NodeID         string             `json:"nodeId"`
	EvaluatedCount int                `json:"evaluatedCount"`
	SkippedStale   int                `json:"skippedStale"`
	Results        []FindingRunResult `json:"results"`
}

func (registry *Registry) RunFinding(ctx context.Context, programID string, finding FindingContext) (RunResult, error) {
	runner, record, err := registry.runnerForProgram(ctx, programID)
	if err != nil {
		return RunResult{}, err
	}
	if record.NodeID != finding.NodeID {
		return RunResult{}, errors.New("nano watchdog program is not admitted for this node")
	}
	return runner.RunFinding(ctx, finding)
}

// RunOpenFindings evaluates an admitted program against already-created Core
// findings. Callers cannot inject a signal: the server builds FindingContext
// values from the current OPEN finding projection. Inputs are sorted and capped
// before cursor advancement so one request has deterministic work bounds.
func (registry *Registry) RunOpenFindings(ctx context.Context, programID string, findings []FindingContext) (OpenFindingRunResult, error) {
	runner, record, err := registry.runnerForProgram(ctx, programID)
	if err != nil {
		return OpenFindingRunResult{}, err
	}
	candidates := make([]FindingContext, 0, len(findings))
	for _, finding := range findings {
		if finding.NodeID == record.NodeID {
			candidates = append(candidates, finding)
		}
	}
	sort.Slice(candidates, func(left, right int) bool {
		if candidates[left].ObservedUnix == candidates[right].ObservedUnix {
			return candidates[left].FindingID < candidates[right].FindingID
		}
		return candidates[left].ObservedUnix < candidates[right].ObservedUnix
	})
	if len(candidates) > maximumCoreFindingBatch {
		return OpenFindingRunResult{}, errors.New("too many open findings for one watchdog pass")
	}
	result := OpenFindingRunResult{ProgramID: programID, NodeID: record.NodeID, Results: make([]FindingRunResult, 0, len(candidates))}
	now := registry.clock().UTC()
	ready := make([]FindingContext, 0, len(candidates))
	for _, finding := range candidates {
		if finding.ObservedUnix <= 0 || !now.Before(time.Unix(finding.ObservedUnix, 0).UTC().Add(runner.proposalTTL)) {
			result.SkippedStale++
			continue
		}
		if _, _, err := FrameForFinding(finding); err != nil {
			return OpenFindingRunResult{}, err
		}
		ready = append(ready, finding)
	}
	for _, finding := range ready {
		run, err := runner.RunFinding(ctx, finding)
		if err != nil {
			return OpenFindingRunResult{}, err
		}
		result.EvaluatedCount++
		result.Results = append(result.Results, FindingRunResult{FindingID: finding.FindingID, Result: run})
	}
	return result, nil
}

func (registry *Registry) runnerForProgram(ctx context.Context, programID string) (*Runner, storage.NanoWatchdogProgramRecord, error) {
	if registry == nil || !opaque(programID) {
		return nil, storage.NanoWatchdogProgramRecord{}, errors.New("nano watchdog run request is invalid")
	}
	record, err := registry.database.GetNanoWatchdogProgram(ctx, programID)
	if err != nil {
		return nil, storage.NanoWatchdogProgramRecord{}, err
	}
	if record.Status != storage.NanoWatchdogAdmitted {
		return nil, storage.NanoWatchdogProgramRecord{}, errors.New("nano watchdog program is not admitted")
	}
	program, err := Compile(record.Source, DefaultLimits)
	if err != nil {
		return nil, storage.NanoWatchdogProgramRecord{}, fmt.Errorf("compile admitted Nano source: %w", err)
	}
	digest, err := program.Digest()
	if err != nil || digest != record.ProgramDigest {
		return nil, storage.NanoWatchdogProgramRecord{}, errors.New("admitted Nano program digest mismatch")
	}
	store, err := NewStorageCursorStore(registry.database, registry.clock)
	if err != nil {
		return nil, storage.NanoWatchdogProgramRecord{}, err
	}
	runner, err := NewRunner(RunnerConfig{Program: program, BindingID: BindingID(record.BindingID), NodeID: record.NodeID, ProposalTTL: 15 * time.Minute, Store: store, Clock: registry.clock})
	if err != nil {
		return nil, storage.NanoWatchdogProgramRecord{}, err
	}
	return runner, record, nil
}
