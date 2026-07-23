package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWatchdogCommandsUsePrivateTokenAndTypedBodies(t *testing.T) {
	directory := t.TempDir()
	token := strings.Repeat("a", 32)
	tokenPath := filepath.Join(directory, "operator.token")
	sourcePath := filepath.Join(directory, "probe.nano")
	if err := os.WriteFile(tokenPath, []byte(token), 0o600); err != nil { t.Fatal(err) }
	if err := os.WriteFile(sourcePath, []byte("strategy ProbeWatch { agent Watchdog every 1s { execute() } }"), 0o600); err != nil { t.Fatal(err) }
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+token { t.Error("operator token was not used as authorization"); http.Error(writer, "unauthorized", http.StatusUnauthorized); return }
		var body map[string]any
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil { t.Errorf("decode request: %v", err); http.Error(writer, "bad request", http.StatusBadRequest); return }
		encoded, _ := json.Marshal(body)
		if bytes.Contains(encoded, []byte(token)) { t.Error("operator token leaked into watchdog JSON payload") }
		switch request.URL.Path {
		case "/v1/watchdogs":
			if request.Method != http.MethodPost || body["nodeId"] != "node-agent-1" || body["operationId"] != "operation-1" { t.Errorf("unexpected admit body %#v", body) }
			writer.WriteHeader(http.StatusCreated); _, _ = fmt.Fprint(writer, `{"id":"watchdog-1","status":"ADMITTED"}`)
		case "/v1/watchdogs/watchdog-1/run":
			if request.Method != http.MethodPost || body["findingId"] != "finding-1" || body["reasonCode"] != "UNEXPECTED_EXPOSURE" { t.Errorf("unexpected run body %#v", body) }
			writer.WriteHeader(http.StatusOK); _, _ = fmt.Fprint(writer, `{"proposals":[]}`)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	base := []string{"--url", server.URL, "--token-file", tokenPath}
	var stdout, stderr bytes.Buffer
	arguments := append([]string{"watchdog", "admit"}, base...)
	arguments = append(arguments, "--node-id", "node-agent-1", "--source-file", sourcePath, "--binding-id", "scrambler-simulation-v1", "--operation-id", "operation-1")
	if code := run(arguments, &stdout, &stderr); code != 0 { t.Fatalf("admit exit=%d stderr=%s", code, stderr.String()) }
	stdout.Reset(); stderr.Reset()
	arguments = append([]string{"watchdog", "run"}, base...)
	arguments = append(arguments, "--program-id", "watchdog-1", "--finding-id", "finding-1", "--node-id", "node-agent-1", "--reason-code", "UNEXPECTED_EXPOSURE", "--confidence", "0.9", "--observed-unix", "1700000000")
	if code := run(arguments, &stdout, &stderr); code != 0 { t.Fatalf("run exit=%d stderr=%s", code, stderr.String()) }
}
