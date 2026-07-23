package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestRunWatchdogOpenFindingsUsesCoreOwnedEndpoint(t *testing.T) {
	tokenPath := filepath.Join(t.TempDir(), "operator.token")
	if err := os.WriteFile(tokenPath, []byte("01234567890123456789012345678901\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/v1/watchdogs/watchdog-1/run-open-findings" {
			http.NotFound(response, request)
			return
		}
		if request.Header.Get("Authorization") != "Bearer 01234567890123456789012345678901" {
			http.Error(response, "missing operator authentication", http.StatusUnauthorized)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`{"programId":"watchdog-1","nodeId":"node-1","evaluatedCount":0,"skippedStale":0,"results":[]}`))
	}))
	defer server.Close()

	var stdout, stderr bytes.Buffer
	exit := runWatchdog([]string{"run-open-findings", "--url", server.URL, "--token-file", tokenPath, "--program-id", "watchdog-1"}, &stdout, &stderr)
	if exit != 0 {
		t.Fatalf("exit=%d stderr=%s", exit, stderr.String())
	}
	if !bytes.Contains(stdout.Bytes(), []byte(`"evaluatedCount": 0`)) {
		t.Fatalf("unexpected stdout: %s", stdout.String())
	}
}
