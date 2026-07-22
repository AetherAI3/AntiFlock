//go:build linux

package enforcement

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
	"google.golang.org/protobuf/proto"
)

func TestFileStateStorePersistsExactReplayBindingAcrossRestart(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	store, err := NewFileStateStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	reservation := Reservation{PlanID: "plan-one", Fingerprint: "sha256:first", PolicyRevision: 7, PlanRevision: 1}
	if existing, err := store.Reserve(context.Background(), reservation); err != nil || existing != nil {
		t.Fatalf("reserve = %#v, %v", existing, err)
	}
	restarted, err := NewFileStateStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.Reserve(context.Background(), reservation); !errors.Is(err, ErrPlanInProgress) {
		t.Fatalf("in-progress restart = %v", err)
	}
	result := &antiflockv1.PlanExecutionResult{PlanId: reservation.PlanID, PlanRevision: reservation.PlanRevision, ReasonCode: "AF-TEST-COMMITTED"}
	if err := restarted.Complete(context.Background(), result); err != nil {
		t.Fatal(err)
	}
	third, err := NewFileStateStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := third.Reserve(context.Background(), reservation)
	if err != nil || !proto.Equal(replayed, result) {
		t.Fatalf("durable replay = %#v, %v", replayed, err)
	}
	changed := reservation
	changed.Fingerprint = "sha256:changed"
	if _, err := third.Reserve(context.Background(), changed); !errors.Is(err, ErrPlanReplay) {
		t.Fatalf("changed replay = %v", err)
	}
	if policyRevision, planRevision, err := third.Revisions(context.Background()); err != nil || policyRevision != 7 || planRevision != 1 {
		t.Fatalf("revisions = %d/%d, %v", policyRevision, planRevision, err)
	}
	for _, name := range []string{fileStateName, fileStateLockName} {
		info, err := os.Stat(filepath.Join(directory, name))
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			t.Fatalf("%s permissions = %v, %v", name, info, err)
		}
	}
	if info, err := os.Stat(directory); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("directory permissions = %v, %v", info, err)
	}
}

func TestEnforcerFileStatePreventsMutationReplayAfterRestart(t *testing.T) {
	fixture := newFixture(t)
	directory := filepath.Join(t.TempDir(), "state")
	store, err := NewFileStateStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	firstDriver := &fakeDriver{observedAt: fixture.now}
	first := fixture.enforcer(t, firstDriver, store)
	committed, err := first.Apply(context.Background(), fixture.plan)
	if err != nil {
		t.Fatal(err)
	}
	restartedStore, err := NewFileStateStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	replayDriver := &fakeDriver{observedAt: fixture.now}
	restarted := fixture.enforcer(t, replayDriver, restartedStore)
	replayed, err := restarted.Apply(context.Background(), fixture.plan)
	if err != nil || !proto.Equal(committed, replayed) {
		t.Fatalf("restart replay = %#v, %v", replayed, err)
	}
	if len(replayDriver.Calls()) != 0 {
		t.Fatalf("restart replay reached mutation driver: %v", replayDriver.Calls())
	}
}

func TestFileStateStoreSerializesCrossInstanceReservations(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	first, err := NewFileStateStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewFileStateStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	reservation := Reservation{PlanID: "plan-concurrent", Fingerprint: "sha256:concurrent", PolicyRevision: 7, PlanRevision: 1}
	stores := []*FileStateStore{first, second}
	errorsSeen := make([]error, len(stores))
	var wait sync.WaitGroup
	for index, store := range stores {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, errorsSeen[index] = store.Reserve(context.Background(), reservation)
		}()
	}
	wait.Wait()
	successes, inProgress := 0, 0
	for _, err := range errorsSeen {
		if err == nil {
			successes++
		} else if errors.Is(err, ErrPlanInProgress) {
			inProgress++
		}
	}
	if successes != 1 || inProgress != 1 {
		t.Fatalf("concurrent reservations = %v", errorsSeen)
	}
}

func TestFileStateStoreRejectsSymlinkedState(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	store, err := NewFileStateStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	reservation := Reservation{PlanID: "plan-one", Fingerprint: "sha256:first", PolicyRevision: 7, PlanRevision: 1}
	if _, err := store.Reserve(context.Background(), reservation); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "attacker-state")
	if err := os.WriteFile(target, []byte(`{"schemaVersion":"antiflock.plan-state/v1","records":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(directory, fileStateName)
	if err := os.Remove(statePath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, statePath); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Reserve(context.Background(), Reservation{PlanID: "plan-two", Fingerprint: "sha256:second", PolicyRevision: 8, PlanRevision: 2}); err == nil {
		t.Fatal("symlinked plan state was accepted")
	}
}
