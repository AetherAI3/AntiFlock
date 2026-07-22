package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHealthCommandAcceptsOnlyExactBoundedAliveResponse(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/healthz" || request.Method != http.MethodGet {
			t.Fatalf("request = %s %s", request.Method, request.URL.Path)
		}
		response.Header().Set("Content-Type", "application/json; charset=utf-8")
		fmt.Fprint(response, `{"status":"alive"}`)
	}))
	defer server.Close()
	var stdout, stderr bytes.Buffer
	if code := run([]string{"health", "--url", server.URL}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit = %d, stderr = %q", code, stderr.String())
	}
	if stdout.String() != "alive\n" || stderr.Len() != 0 {
		t.Fatalf("stdout = %q, stderr = %q", stdout.String(), stderr.String())
	}
}

func TestHealthURLValidationRejectsUnsafePlainHTTPAndAmbiguousURLs(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{
		"", "ftp://127.0.0.1:8787", "http://8.8.8.8:8787", "http://example.com:8787",
		"http://user:secret@127.0.0.1:8787", "http://127.0.0.1:8787/base", "http://127.0.0.1:8787?x=1",
	} {
		if _, err := validateHealthURL(raw); err == nil {
			t.Fatalf("URL %q was accepted", raw)
		}
	}
	for _, raw := range []string{"http://127.0.0.1:8787", "http://10.10.1.2:8787", "https://core.example.test"} {
		endpoint, err := validateHealthURL(raw)
		if err != nil || endpoint.Path != "/healthz" {
			t.Fatalf("URL %q = %#v, %v", raw, endpoint, err)
		}
	}
}

func TestHealthCommandFailsClosedOnStatusShapeSizeAndTimeout(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		status      int
		contentType string
		body        string
	}{
		{"http-status", http.StatusServiceUnavailable, "application/json", `{"status":"alive"}`},
		{"media-type", http.StatusOK, "text/plain", `{"status":"alive"}`},
		{"wrong-status", http.StatusOK, "application/json", `{"status":"ready"}`},
		{"extra-field", http.StatusOK, "application/json", `{"status":"alive","secret":"no"}`},
		{"case-folded-field", http.StatusOK, "application/json", `{"Status":"alive"}`},
		{"duplicate-field", http.StatusOK, "application/json", `{"status":"ready","status":"alive"}`},
		{"trailing-json", http.StatusOK, "application/json", `{"status":"alive"} {}`},
		{"oversized", http.StatusOK, "application/json", strings.Repeat(" ", maximumHealthBody+1)},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
				response.Header().Set("Content-Type", test.contentType)
				response.WriteHeader(test.status)
				fmt.Fprint(response, test.body)
			}))
			defer server.Close()
			var stdout, stderr bytes.Buffer
			if code := run([]string{"health", "--url", server.URL}, &stdout, &stderr); code != 1 || stdout.Len() != 0 || stderr.Len() == 0 {
				t.Fatalf("exit = %d, stdout = %q, stderr = %q", code, stdout.String(), stderr.String())
			}
		})
	}

	t.Run("timeout", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			time.Sleep(250 * time.Millisecond)
			response.Header().Set("Content-Type", "application/json")
			fmt.Fprint(response, `{"status":"alive"}`)
		}))
		defer server.Close()
		var stdout, stderr bytes.Buffer
		if code := run([]string{"health", "--url", server.URL, "--timeout", "100ms"}, &stdout, &stderr); code != 1 {
			t.Fatalf("exit = %d, stderr = %q", code, stderr.String())
		}
	})
}
