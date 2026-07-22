package retention

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/DBarr3/AntiFlock/core/storage"
	"github.com/DBarr3/AntiFlock/internal/model"
)

func retentionDatabase(t *testing.T) *storage.DB {
	t.Helper()
	database, err := storage.Open(context.Background(), filepath.Join(t.TempDir(), "retention.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return database
}

func TestPolicyValidationAndDefensiveCopy(t *testing.T) {
	t.Parallel()
	database := retentionDatabase(t)
	tests := []Policy{
		{},
		{Default: 24 * time.Hour, ByClassification: map[model.EvidenceClass]time.Duration{"CERTAIN": time.Hour}},
		{Default: 24 * time.Hour, ByClassification: map[model.EvidenceClass]time.Duration{model.EvidenceDetected: 48 * time.Hour}},
		{Default: 24 * time.Hour, BySensitivity: map[model.Sensitivity]time.Duration{"EVERYTHING": time.Hour}},
		{Default: 24 * time.Hour, BySensitivity: map[model.Sensitivity]time.Duration{model.SensitivitySecret: 0}},
	}
	for _, policy := range tests {
		if _, err := NewWithPolicy(database, policy, []string{"topology"}); err == nil {
			t.Fatalf("invalid policy was accepted: %#v", policy)
		}
	}

	policy := Policy{
		Default:          30 * 24 * time.Hour,
		ByClassification: map[model.EvidenceClass]time.Duration{model.EvidenceReported: 7 * 24 * time.Hour},
		BySensitivity:    map[model.Sensitivity]time.Duration{model.SensitivitySecret: 24 * time.Hour},
	}
	service, err := NewWithPolicy(database, policy, []string{"topology"})
	if err != nil {
		t.Fatal(err)
	}
	policy.ByClassification[model.EvidenceReported] = time.Minute
	policy.BySensitivity[model.SensitivitySecret] = time.Minute
	if service.policy.ByClassification[model.EvidenceReported] != 7*24*time.Hour || service.policy.BySensitivity[model.SensitivitySecret] != 24*time.Hour {
		t.Fatal("service policy changed after caller mutated its maps")
	}
}

func TestSchedulerRunsImmediatelyAndStopsIdempotently(t *testing.T) {
	t.Parallel()
	database := retentionDatabase(t)
	service, err := New(database, 24*time.Hour, []string{"topology"})
	if err != nil {
		t.Fatal(err)
	}
	scheduler, err := service.Start(context.Background(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case report := <-scheduler.Reports():
		if !errors.Is(report.Err, storage.ErrRetentionProjectionNotReady) {
			t.Fatalf("first scheduler report = %#v", report)
		}
	case <-time.After(time.Second):
		t.Fatal("scheduler did not run immediately")
	}
	stopContext, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := scheduler.Stop(stopContext); err != nil {
		t.Fatal(err)
	}
	if err := scheduler.Stop(stopContext); err != nil {
		t.Fatalf("second stop was not idempotent: %v", err)
	}
	select {
	case <-scheduler.Done():
	default:
		t.Fatal("scheduler done channel was not closed")
	}
	if _, ok := <-scheduler.Reports(); ok {
		t.Fatal("scheduler report channel remained open after stop")
	}
}

func TestSchedulerRejectsInvalidInputs(t *testing.T) {
	t.Parallel()
	database := retentionDatabase(t)
	service, err := New(database, 24*time.Hour, []string{"topology"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Start(nil, time.Hour); err == nil {
		t.Fatal("nil scheduler context was accepted")
	}
	if _, err := service.Start(context.Background(), 0); err == nil {
		t.Fatal("non-positive scheduler interval was accepted")
	}
	if _, err := service.RunOnce(nil); err == nil {
		t.Fatal("nil retention context was accepted")
	}
	if _, err := New(database, 24*time.Hour, []string{"topology", "topology"}); err == nil {
		t.Fatal("duplicate required projection was accepted")
	}
	if _, err := New(database, 24*time.Hour, []string{"   "}); err == nil {
		t.Fatal("blank required projection was accepted")
	}
}
