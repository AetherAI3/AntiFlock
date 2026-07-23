package server

import (
	"net/http"
	"testing"
	"time"

	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
	"github.com/DBarr3/AntiFlock/core/nano"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const serverProbeWatch = `strategy ProbeWatch {
  agent Watchdog
  every 1s {
    if REASON_404_PROBING == 1
    and CONFIDENCE > 0.8 {
      execute()
    }
  }
}`

func TestWatchdogAdmissionAndRunAPI(t *testing.T) {
	runtime := newTestRuntime(t)
	registry, err := nano.NewRegistry(runtime.db, runtime.server.audit, func() time.Time { return runtime.now })
	if err != nil { t.Fatal(err) }
	runtime.server.nano = registry
	admit := runtime.request(t, http.MethodPost, "/v1/watchdogs", map[string]any{
		"nodeId": "node-test", "source": serverProbeWatch, "bindingId": "scrambler-simulation-v1", "operationId": "watchdog-admit-one",
	}, true)
	if admit.Code != http.StatusCreated { t.Fatalf("admit = %d %s", admit.Code, admit.Body.String()) }
	record := decodeObject(t, admit)
	programID, _ := record["id"].(string); if programID == "" { t.Fatalf("admission response = %#v", record) }
	run := runtime.request(t, http.MethodPost, "/v1/watchdogs/"+programID+"/run", map[string]any{
		"findingId": "finding-404", "nodeId": "node-test", "reasonCode": "404 probing", "confidence": .91, "observedUnix": runtime.now.Unix(),
	}, true)
	if run.Code != http.StatusOK { t.Fatalf("run = %d %s", run.Code, run.Body.String()) }
	result := decodeObject(t, run)
	proposals, ok := result["proposals"].([]any)
	if !ok || len(proposals) != 1 {
		t.Fatalf("run result = %#v", result)
	}
	if _, leaked := result["Proposals"]; leaked {
		t.Fatalf("watchdog response leaked Go field casing: %#v", result)
	}
}

func TestWatchdogRunOpenFindingsUsesCoreProjectionOnly(t *testing.T) {
	runtime := newTestRuntime(t)
	registry, err := nano.NewRegistry(runtime.db, runtime.server.audit, func() time.Time { return runtime.now })
	if err != nil { t.Fatal(err) }
	runtime.server.nano = registry
	_, err = runtime.server.findings.ApplySnapshot(&antiflockv1.ProtectionSnapshot{
		DeploymentId: runtime.deploymentID, NodeId: "node-test", PolicyId: "policy-test", EvaluatedAt: timestamppb.New(runtime.now),
		Reasons: []*antiflockv1.PostureReason{{RuleId: "rule-test", ReasonCode: "404 probing", ContributedState: antiflockv1.ProtectionState_PROTECTION_STATE_DEGRADED, Claim: &antiflockv1.EvidenceClaim{Confidence: .91}}},
	})
	if err != nil { t.Fatal(err) }
	admit := runtime.request(t, http.MethodPost, "/v1/watchdogs", map[string]any{"nodeId": "node-test", "source": serverProbeWatch, "bindingId": "scrambler-simulation-v1", "operationId": "watchdog-admit-core-findings"}, true)
	if admit.Code != http.StatusCreated { t.Fatalf("admit = %d %s", admit.Code, admit.Body.String()) }
	programID, _ := decodeObject(t, admit)["id"].(string)
	run := runtime.request(t, http.MethodPost, "/v1/watchdogs/"+programID+"/run-open-findings", nil, true)
	if run.Code != http.StatusOK { t.Fatalf("core finding run = %d %s", run.Code, run.Body.String()) }
	result := decodeObject(t, run)
	if result["evaluatedCount"] != float64(1) { t.Fatalf("result = %#v", result) }
	values, ok := result["results"].([]any); if !ok || len(values) != 1 { t.Fatalf("result = %#v", result) }
}
