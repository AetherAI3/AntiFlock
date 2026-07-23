package nano

import (
	"context"
	"errors"
	"fmt"
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
	audit *audit.Service
	clock func() time.Time
}

type AdmissionRequest struct {
	NodeID string
	Source string
	BindingID BindingID
	OperationID string
	ActorID string
}

func NewRegistry(database *storage.DB, auditService *audit.Service, clock func() time.Time) (*Registry, error) {
	if database == nil || auditService == nil { return nil, errors.New("Nano registry requires database and audit service") }
	if clock == nil { clock = func() time.Time { return time.Now().UTC() } }
	return &Registry{database: database, audit: auditService, clock: clock}, nil
}

func (registry *Registry) Admit(ctx context.Context, request AdmissionRequest) (storage.NanoWatchdogProgramRecord, error) {
	if registry == nil || !opaque(request.NodeID) || !opaque(request.OperationID) || !opaque(request.ActorID) || strings.TrimSpace(request.Source) != request.Source {
		return storage.NanoWatchdogProgramRecord{}, errors.New("Nano watchdog admission request is invalid")
	}
	program, err := Compile(request.Source, DefaultLimits)
	if err != nil { return storage.NanoWatchdogProgramRecord{}, fmt.Errorf("compile Nano watchdog source: %w", err) }
	if err := AdmitWatchdog(program); err != nil { return storage.NanoWatchdogProgramRecord{}, err }
	if _, err := BindingDigest(request.BindingID); err != nil { return storage.NanoWatchdogProgramRecord{}, err }
	digest, err := program.Digest(); if err != nil { return storage.NanoWatchdogProgramRecord{}, err }
	now := registry.clock().UTC()
	record := storage.NanoWatchdogProgramRecord{
		ID: id.New("watchdog"), NodeID: request.NodeID, Name: program.Name, Source: request.Source, ProgramDigest: digest,
		BindingID: string(request.BindingID), Status: storage.NanoWatchdogAdmitted, OperationID: request.OperationID, CreatedAt: now, UpdatedAt: now,
	}
	_, err = registry.audit.AppendWithMutation(ctx, audit.AppendRequest{
		ActorType: "operator", ActorID: request.ActorID, Action: "nano.watchdog.admit", ResourceType: "nano_watchdog", ResourceID: record.ID, Outcome: "admitted",
		Details: map[string]string{"nodeId": record.NodeID, "programDigest": record.ProgramDigest, "bindingId": record.BindingID, "operationId": record.OperationID},
	}, registry.database.CreateNanoWatchdogProgramMutation(record))
	if err != nil { return storage.NanoWatchdogProgramRecord{}, err }
	return record, nil
}

func (registry *Registry) List(ctx context.Context, nodeID string) ([]storage.NanoWatchdogProgramRecord, error) {
	if registry == nil { return nil, errors.New("Nano registry is required") }
	return registry.database.ListNanoWatchdogPrograms(ctx, nodeID)
}

func (registry *Registry) RunFinding(ctx context.Context, programID string, finding FindingContext) (RunResult, error) {
	if registry == nil || !opaque(programID) { return RunResult{}, errors.New("Nano watchdog run request is invalid") }
	record, err := registry.database.GetNanoWatchdogProgram(ctx, programID)
	if err != nil { return RunResult{}, err }
	if record.Status != storage.NanoWatchdogAdmitted || record.NodeID != finding.NodeID { return RunResult{}, errors.New("Nano watchdog program is not admitted for this node") }
	program, err := Compile(record.Source, DefaultLimits)
	if err != nil { return RunResult{}, fmt.Errorf("compile admitted Nano source: %w", err) }
	digest, err := program.Digest(); if err != nil || digest != record.ProgramDigest { return RunResult{}, errors.New("admitted Nano program digest mismatch") }
	store, err := NewStorageCursorStore(registry.database, registry.clock); if err != nil { return RunResult{}, err }
	runner, err := NewRunner(RunnerConfig{Program: program, BindingID: BindingID(record.BindingID), NodeID: record.NodeID, ProposalTTL: 15*time.Minute, Store: store, Clock: registry.clock})
	if err != nil { return RunResult{}, err }
	return runner.RunFinding(ctx, finding)
}
