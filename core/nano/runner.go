package nano

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// CursorStore persists a per-program, per-node schedule cursor. Production
// runners must supply durable storage before handling real findings.
type CursorStore interface {
	Load(context.Context, programDigest, nodeID string) (Cursor, error)
	CompareAndSwap(context.Context, programDigest, nodeID string, previous, next Cursor) (bool, error)
}

type RunnerConfig struct {
	Program Program
	BindingID BindingID
	NodeID string
	ProposalTTL time.Duration
	Store CursorStore
	Clock func() time.Time
}

// Runner evaluates one admitted program. It cannot fetch data, contact a
// provider, mutate a host, or submit a proposal to the action gate.
type Runner struct {
	program Program
	programDigest string
	bindingID BindingID
	nodeID string
	proposalTTL time.Duration
	store CursorStore
	clock func() time.Time
}

// RunResult is the stable, proposal-only watchdog response. It never signals
// authorization or execution; a separate operator-approved action flow remains required.
type RunResult struct {
	ProgramDigest string                 `json:"programDigest"`
	InputDigest   string                 `json:"inputDigest"`
	Evaluation    EvaluationResult       `json:"evaluation"`
	Proposals     []SecureActionProposal `json:"proposals"`
}

func NewRunner(config RunnerConfig) (*Runner, error) {
	if config.Store == nil || !opaque(config.NodeID) {
		return nil, errors.New("watchdog runner requires durable cursor storage and a canonical node id")
	}
	if config.ProposalTTL <= 0 || config.ProposalTTL > 15*time.Minute {
		return nil, errors.New("watchdog proposal TTL must be between one nanosecond and 15 minutes")
	}
	if config.Clock == nil {
		config.Clock = func() time.Time { return time.Now().UTC() }
	}
	if err := AdmitWatchdog(config.Program); err != nil {
		return nil, err
	}
	if _, err := BindingDigest(config.BindingID); err != nil {
		return nil, err
	}
	digest, err := config.Program.Digest()
	if err != nil {
		return nil, fmt.Errorf("digest watchdog program: %w", err)
	}
	return &Runner{program: config.Program, programDigest: digest, bindingID: config.BindingID, nodeID: config.NodeID, proposalTTL: config.ProposalTTL, store: config.Store, clock: config.Clock}, nil
}

// RunFinding saves the cursor before returning proposals so a failed persist
// never exposes a proposal that can refire after a process restart.
func (runner *Runner) RunFinding(ctx context.Context, finding FindingContext) (RunResult, error) {
	if runner == nil || runner.store == nil {
		return RunResult{}, errors.New("watchdog runner is required")
	}
	if err := ctx.Err(); err != nil {
		return RunResult{}, err
	}
	if finding.NodeID != runner.nodeID {
		return RunResult{}, errors.New("watchdog finding node does not match runner node")
	}
	frame, inputDigest, err := FrameForFinding(finding)
	if err != nil {
		return RunResult{}, err
	}
	cursor, err := runner.store.Load(ctx, runner.programDigest, runner.nodeID)
	if err != nil {
		return RunResult{}, fmt.Errorf("load watchdog schedule cursor: %w", err)
	}
	evaluation, next, err := Evaluate(runner.program, frame, cursor, DefaultLimits)
	if err != nil {
		return RunResult{}, err
	}
	deadline := time.Unix(finding.ObservedUnix, 0).UTC().Add(runner.proposalTTL)
	if len(evaluation.Intents) != 0 && !runner.clock().UTC().Before(deadline) {
		return RunResult{}, errors.New("watchdog finding is too old to produce a proposal")
	}
	proposals, err := BuildProposals(evaluation, runner.bindingID, runner.programDigest, inputDigest, runner.nodeID, deadline.Format(time.RFC3339Nano))
	if err != nil {
		return RunResult{}, err
	}
	advanced, err := runner.store.CompareAndSwap(ctx, runner.programDigest, runner.nodeID, cursor, next)
	if err != nil { return RunResult{}, fmt.Errorf("persist watchdog schedule cursor: %w", err) }
	if !advanced { return RunResult{}, errors.New("watchdog schedule cursor changed concurrently; retry finding") }
	return RunResult{ProgramDigest: runner.programDigest, InputDigest: inputDigest, Evaluation: evaluation, Proposals: append([]SecureActionProposal(nil), proposals...)}, nil
}

// MemoryCursorStore is for deterministic tests and demos. It is not durable.
type MemoryCursorStore struct {
	mu      sync.Mutex
	cursors map[string]Cursor
}

func NewMemoryCursorStore() *MemoryCursorStore {
	return &MemoryCursorStore{cursors: make(map[string]Cursor)}
}

func (store *MemoryCursorStore) Load(ctx context.Context, programDigest, nodeID string) (Cursor, error) {
	if store == nil {
		return Cursor{}, errors.New("cursor store is required")
	}
	if err := ctx.Err(); err != nil {
		return Cursor{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.cursors[programDigest+"\x00"+nodeID], nil
}

func (store *MemoryCursorStore) CompareAndSwap(ctx context.Context, programDigest, nodeID string, previous, next Cursor) (bool, error) {
	if store == nil { return false, errors.New("cursor store is required") }
	if err := ctx.Err(); err != nil { return false, err }
	store.mu.Lock()
	defer store.mu.Unlock()
	key := programDigest + "\x00" + nodeID
	current := store.cursors[key]
	if current != previous { return false, nil }
	store.cursors[key] = next
	return true, nil
}
