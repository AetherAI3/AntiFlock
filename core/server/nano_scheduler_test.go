package server

import (
	"context"
	"testing"
	"time"

	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
	"github.com/DBarr3/AntiFlock/core/nano"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestConfiguredNanoWatchdogPassAdvancesCursorWithoutExecutingAction(t *testing.T) {
	runtime := newTestRuntime(t)
	registry, err := nano.NewRegistry(runtime.db, runtime.server.audit, func() time.Time { return runtime.now })
	if err != nil {
		t.Fatal(err)
	}
	runtime.server.nano = registry
	_, err = runtime.server.findings.ApplySnapshot(&antiflockv1.ProtectionSnapshot{
		DeploymentId: runtime.deploymentID, NodeId: "node-test", PolicyId: "policy-test", EvaluatedAt: timestamppb.New(runtime.now),
		Reasons: []*antiflockv1.PostureReason{{RuleId: "rule-test", ReasonCode: "404 probing", ContributedState: antiflockv1.ProtectionState_PROTECTION_STATE_DEGRADED, Claim: &antiflockv1.EvidenceClaim{Confidence: .91}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	admit := runtime.request(t, "POST", "/v1/watchdogs", map[string]any{
		"nodeId": "node-test", "source": serverProbeWatch, "bindingId": "scrambler-simulation-v1", "operationId": "watchdog-admit-scheduled",
	}, true)
	programID, _ := decodeObject(t, admit)["id"].(string)
	if programID == "" {
		t.Fatalf("admission response = %d %s", admit.Code, admit.Body.String())
	}

	runtime.server.runConfiguredNanoWatchdogs(context.Background(), []string{programID})
	result, err := runtime.server.runWatchdogOpenFindings(context.Background(), programID)
	if err != nil {
		t.Fatal(err)
	}
	if result.EvaluatedCount != 1 || len(result.Results) != 1 || len(result.Results[0].Result.Proposals) != 0 {
		t.Fatalf("second Core-owned pass should be cursor-suppressed, got %#v", result)
	}
}

func TestNanoWatchdogSchedulerIsOffWithoutExplicitConfiguration(t *testing.T) {
	runtime := newTestRuntime(t)
	done := runtime.server.startNanoWatchdogScheduler(context.Background())
	select {
	case <-done:
	default:
		t.Fatal("scheduler ran without an explicit interval and program allowlist")
	}
}
