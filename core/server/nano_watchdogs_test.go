package server

import (
	"net/http"
	"testing"
	"time"

	"github.com/DBarr3/AntiFlock/core/nano"
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
	result := decodeObject(t, run); proposals, ok := result["Proposals"].([]any); if !ok || len(proposals) != 1 {
		// Go's JSON encoder preserves the public field name in RunResult.
		proposals, ok = result["proposals"].([]any); if !ok || len(proposals) != 1 { t.Fatalf("run result = %#v", result) }
	}
}
