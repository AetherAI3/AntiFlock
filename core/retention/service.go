package retention

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/DBarr3/AntiFlock/core/storage"
	"github.com/DBarr3/AntiFlock/internal/model"
)

// Policy applies a default maximum retention and optional privacy-reducing
// overrides. Overrides must be positive and no longer than Default.
type Policy struct {
	Default          time.Duration
	ByClassification map[model.EvidenceClass]time.Duration
	BySensitivity    map[model.Sensitivity]time.Duration
}

type Service struct {
	database            *storage.DB
	policy              Policy
	requiredProjections []string
	batchSize           int
	clock               func() time.Time
}

type RunReport struct {
	Result storage.RetentionResult
	Err    error
}

type Scheduler struct {
	cancel  context.CancelFunc
	done    chan struct{}
	reports chan RunReport
	once    sync.Once
}

func New(database *storage.DB, eventRetention time.Duration, requiredProjections []string) (*Service, error) {
	return NewWithPolicy(database, Policy{Default: eventRetention}, requiredProjections)
}

func NewWithPolicy(database *storage.DB, policy Policy, requiredProjections []string) (*Service, error) {
	if database == nil {
		return nil, errors.New("retention database is required")
	}
	if err := validatePolicy(policy); err != nil {
		return nil, err
	}
	if len(requiredProjections) == 0 {
		return nil, errors.New("required projections are required")
	}
	seenProjection := make(map[string]struct{}, len(requiredProjections))
	for _, projection := range requiredProjections {
		if strings.TrimSpace(projection) == "" {
			return nil, errors.New("required projection names cannot be empty")
		}
		if _, exists := seenProjection[projection]; exists {
			return nil, fmt.Errorf("required projection %q is duplicated", projection)
		}
		seenProjection[projection] = struct{}{}
	}
	return &Service{
		database: database, policy: clonePolicy(policy),
		requiredProjections: append([]string(nil), requiredProjections...), batchSize: 500,
		clock: func() time.Time { return time.Now().UTC() },
	}, nil
}

func validatePolicy(policy Policy) error {
	if policy.Default <= 0 {
		return errors.New("default event retention must be positive")
	}
	for class, duration := range policy.ByClassification {
		if !class.Valid() {
			return fmt.Errorf("invalid retention evidence classification %q", class)
		}
		if duration <= 0 || duration > policy.Default {
			return fmt.Errorf("retention for evidence classification %q must be positive and no longer than the default", class)
		}
	}
	for sensitivity, duration := range policy.BySensitivity {
		if !sensitivity.Valid() {
			return fmt.Errorf("invalid retention sensitivity %q", sensitivity)
		}
		if duration <= 0 || duration > policy.Default {
			return fmt.Errorf("retention for sensitivity %q must be positive and no longer than the default", sensitivity)
		}
	}
	return nil
}

func clonePolicy(policy Policy) Policy {
	result := Policy{
		Default:          policy.Default,
		ByClassification: make(map[model.EvidenceClass]time.Duration, len(policy.ByClassification)),
		BySensitivity:    make(map[model.Sensitivity]time.Duration, len(policy.BySensitivity)),
	}
	for class, duration := range policy.ByClassification {
		result.ByClassification[class] = duration
	}
	for sensitivity, duration := range policy.BySensitivity {
		result.BySensitivity[sensitivity] = duration
	}
	return result
}

func (service *Service) RunOnce(ctx context.Context) (storage.RetentionResult, error) {
	if ctx == nil {
		return storage.RetentionResult{}, errors.New("retention context is required")
	}
	now := service.clock().UTC()
	cutoffs := storage.EventRetentionCutoffs{
		DefaultBefore:    now.Add(-service.policy.Default),
		ByClassification: make(map[model.EvidenceClass]time.Time, len(service.policy.ByClassification)),
		BySensitivity:    make(map[model.Sensitivity]time.Time, len(service.policy.BySensitivity)),
	}
	for class, duration := range service.policy.ByClassification {
		cutoffs.ByClassification[class] = now.Add(-duration)
	}
	for sensitivity, duration := range service.policy.BySensitivity {
		cutoffs.BySensitivity[sensitivity] = now.Add(-duration)
	}
	return service.database.PruneEventsWithCutoffs(ctx, cutoffs, service.requiredProjections, service.batchSize)
}

// Start launches one immediate retention pass followed by interval-based
// passes. Stop or cancellation waits for an in-flight transaction to finish or
// observe cancellation; there are never overlapping passes.
func (service *Service) Start(parent context.Context, interval time.Duration) (*Scheduler, error) {
	if parent == nil {
		return nil, errors.New("retention scheduler context is required")
	}
	if interval <= 0 {
		return nil, errors.New("retention scheduler interval must be positive")
	}
	ctx, cancel := context.WithCancel(parent)
	scheduler := &Scheduler{
		cancel: cancel, done: make(chan struct{}), reports: make(chan RunReport, 1),
	}
	go scheduler.run(ctx, service, interval)
	return scheduler, nil
}

func (scheduler *Scheduler) Reports() <-chan RunReport {
	return scheduler.reports
}

func (scheduler *Scheduler) Done() <-chan struct{} {
	return scheduler.done
}

func (scheduler *Scheduler) Stop(ctx context.Context) error {
	if ctx == nil {
		return errors.New("retention scheduler stop context is required")
	}
	scheduler.once.Do(scheduler.cancel)
	select {
	case <-scheduler.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (scheduler *Scheduler) run(ctx context.Context, service *Service, interval time.Duration) {
	defer close(scheduler.done)
	defer close(scheduler.reports)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		report := RunReport{}
		report.Result, report.Err = service.RunOnce(ctx)
		select {
		case scheduler.reports <- report:
		case <-ctx.Done():
			return
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			return
		}
	}
}
