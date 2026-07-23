package enrollment

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestEnsureIdentityPersistsOnePrivateKeyAndRequestID(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "enrollment")
	firstKey, firstState, err := ensureIdentity(directory, "agent-lab-1")
	if err != nil { t.Fatal(err) }
	secondKey, secondState, err := ensureIdentity(directory, "agent-lab-1")
	if err != nil { t.Fatal(err) }
	if string(firstKey) != string(secondKey) || firstState.RequestID != secondState.RequestID { t.Fatalf("identity was not stable: %#v %#v", firstState, secondState) }
	for _, name := range []string{"node.seed", "enrollment.json"} {
		info, err := os.Lstat(filepath.Join(directory, name)); if err != nil { t.Fatal(err) }
		if !info.Mode().IsRegular() || info.Mode().Perm() != privateFileMode { t.Fatalf("%s has unsafe mode %o", name, info.Mode().Perm()) }
	}
}

func TestSubmitUsesPersistentIdentityAndLoopbackHTTP(t *testing.T) {
	requests := make(chan *antiflockv1.EnrollNodeRequest, 2)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/v1/enrollment/nodes" { http.NotFound(writer, request); return }
		var input antiflockv1.EnrollNodeRequest
		if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(mustRead(t, request), &input); err != nil { t.Errorf("decode request: %v", err); http.Error(writer, "bad request", http.StatusBadRequest); return }
		requests <- &input
		writer.Header().Set("Content-Type", "application/json")
		output := &antiflockv1.EnrollNodeResponse{Enrollment: &antiflockv1.EnrollmentRequest{Id: "enrollment-1", ProposedNodeId: "agent-lab-1"}}
		encoded, err := (protojson.MarshalOptions{}).Marshal(output); if err != nil { t.Errorf("encode response: %v", err); return }; _, _ = writer.Write(encoded)
	}))
	defer server.Close()
	config := Config{Endpoint: server.URL, Token: "01234567890123456789012345678901", StateDirectory: filepath.Join(t.TempDir(), "state"), NodeID: "agent-lab-1", DisplayName: "Lab agent", Clock: func() time.Time { return time.Date(2026, 7, 23, 0, 0, 0, 0, time.UTC) }}
	first, err := Submit(context.Background(), config); if err != nil { t.Fatal(err) }
	second, err := Submit(context.Background(), config); if err != nil { t.Fatal(err) }
	if first.EnrollmentID != "enrollment-1" || second.EnrollmentID != first.EnrollmentID { t.Fatalf("unexpected enrollment results: %#v %#v", first, second) }
	firstRequest := <-requests; secondRequest := <-requests
	if firstRequest.GetRequestId() != secondRequest.GetRequestId() || string(firstRequest.GetPublicKey()) != string(secondRequest.GetPublicKey()) { t.Fatalf("retry changed identity") }
	if firstRequest.GetTokenValue() != config.Token || len(firstRequest.GetProofOfPossession()) == 0 { t.Fatalf("request omitted enrollment credentials or proof") }
}

func mustRead(t *testing.T, request *http.Request) []byte {
	t.Helper()
	defer request.Body.Close()
	content, err := io.ReadAll(request.Body)
	if err != nil { t.Fatal(err) }
	return content
}
