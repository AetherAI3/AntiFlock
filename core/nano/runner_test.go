package nano_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/DBarr3/AntiFlock/core/nano"
)

func TestRunnerPersistsCursorBeforeReturningProposal(t *testing.T) {
	t.Parallel()
	program, err := nano.Compile(probeWatch, nano.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	runner, err := nano.NewRunner(nano.RunnerConfig{
		Program: program, BindingID: nano.BindingScramblerSimulation, NodeID: "node-test",
		ProposalTTL: time.Minute, Store: nano.NewMemoryCursorStore(), Clock: func() time.Time { return time.Unix(100, 0).UTC() },
	})
	if err != nil {
		t.Fatal(err)
	}
	finding := nano.FindingContext{FindingID: "finding-1", NodeID: "node-test", ReasonCode: "404 probing", Confidence: 0.9, ObservedUnix: 100}
	first, err := runner.RunFinding(context.Background(), finding)
	if err != nil || len(first.Proposals) != 1 {
		t.Fatalf("first=%#v err=%v", first, err)
	}
	second, err := runner.RunFinding(context.Background(), finding)
	if err != nil || len(second.Proposals) != 0 {
		t.Fatalf("duplicate tick was not suppressed: %#v %v", second, err)
	}
}

func TestRunnerRejectsWrongNodeAndExpiredFinding(t *testing.T) {
	t.Parallel()
	program, err := nano.Compile(probeWatch, nano.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	runner, err := nano.NewRunner(nano.RunnerConfig{
		Program: program, BindingID: nano.BindingScramblerSimulation, NodeID: "node-test",
		ProposalTTL: time.Second, Store: nano.NewMemoryCursorStore(), Clock: func() time.Time { return time.Unix(200, 0).UTC() },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.RunFinding(context.Background(), nano.FindingContext{FindingID: "wrong", NodeID: "other", ReasonCode: "404 probing", Confidence: 0.9, ObservedUnix: 200}); err == nil {
		t.Fatal("wrong node finding was accepted")
	}
	if _, err := runner.RunFinding(context.Background(), nano.FindingContext{FindingID: "old", NodeID: "node-test", ReasonCode: "404 probing", Confidence: 0.9, ObservedUnix: 100}); err == nil {
		t.Fatal("expired finding produced a proposal")
	}
}

func TestRunnerDoesNotExposeDuplicateProposalDuringConcurrentTick(t *testing.T) {
	t.Parallel()
	program, err := nano.Compile(probeWatch, nano.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	runner, err := nano.NewRunner(nano.RunnerConfig{Program: program, BindingID: nano.BindingScramblerSimulation, NodeID: "node-test", ProposalTTL: time.Minute, Store: nano.NewMemoryCursorStore(), Clock: func() time.Time { return time.Unix(100, 0).UTC() }})
	if err != nil {
		t.Fatal(err)
	}
	finding := nano.FindingContext{FindingID: "finding-1", NodeID: "node-test", ReasonCode: "404 probing", Confidence: 0.9, ObservedUnix: 100}
	results := make(chan nano.RunResult, 2)
	failures := make(chan error, 2)
	start := make(chan struct{})
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			result, runErr := runner.RunFinding(context.Background(), finding)
			if runErr != nil {
				failures <- runErr
				return
			}
			results <- result
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	close(failures)
	proposals := 0
	for result := range results {
		proposals += len(result.Proposals)
	}
	if proposals != 1 {
		t.Fatalf("concurrent tick proposals = %d, want 1", proposals)
	}
}
