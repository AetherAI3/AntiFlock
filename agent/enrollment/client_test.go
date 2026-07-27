package enrollment

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
	coreenrollment "github.com/DBarr3/AntiFlock/core/enrollment"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestEnsureIdentityPersistsOnePrivateKeyAndRequestID(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "enrollment")
	firstKey, firstState, err := ensureIdentity(directory, "agent-lab-1")
	if err != nil {
		t.Fatal(err)
	}
	secondKey, secondState, err := ensureIdentity(directory, "agent-lab-1")
	if err != nil {
		t.Fatal(err)
	}
	if string(firstKey) != string(secondKey) || firstState.RequestID != secondState.RequestID {
		t.Fatalf("identity was not stable: %#v %#v", firstState, secondState)
	}
	for _, name := range []string{"node.seed", "enrollment.json"} {
		info, err := os.Lstat(filepath.Join(directory, name))
		if err != nil {
			t.Fatal(err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != privateFileMode {
			t.Fatalf("%s has unsafe mode %o", name, info.Mode().Perm())
		}
	}
}

func TestSubmitUsesPersistentIdentityAndLoopbackHTTP(t *testing.T) {
	requests := make(chan *antiflockv1.EnrollNodeRequest, 2)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/v1/enrollment/nodes" {
			http.NotFound(writer, request)
			return
		}
		var input antiflockv1.EnrollNodeRequest
		if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(mustRead(t, request), &input); err != nil {
			t.Errorf("decode request: %v", err)
			http.Error(writer, "bad request", http.StatusBadRequest)
			return
		}
		requests <- &input
		writer.Header().Set("Content-Type", "application/json")
		output := &antiflockv1.EnrollNodeResponse{Enrollment: &antiflockv1.EnrollmentRequest{Id: "enrollment-1", ProposedNodeId: "agent-lab-1", Status: antiflockv1.EnrollmentStatus_ENROLLMENT_STATUS_PENDING}}
		encoded, err := (protojson.MarshalOptions{}).Marshal(output)
		if err != nil {
			t.Errorf("encode response: %v", err)
			return
		}
		writer.WriteHeader(http.StatusAccepted)
		_, _ = writer.Write(encoded)
	}))
	defer server.Close()
	config := Config{Endpoint: server.URL, Token: "01234567890123456789012345678901", StateDirectory: filepath.Join(t.TempDir(), "state"), NodeID: "agent-lab-1", DisplayName: "Lab agent", Clock: func() time.Time { return time.Date(2026, 7, 23, 0, 0, 0, 0, time.UTC) }}
	first, err := Submit(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Submit(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	if first.EnrollmentID != "enrollment-1" || second.EnrollmentID != first.EnrollmentID {
		t.Fatalf("unexpected enrollment results: %#v %#v", first, second)
	}
	firstRequest := <-requests
	secondRequest := <-requests
	if firstRequest.GetRequestId() != secondRequest.GetRequestId() || string(firstRequest.GetPublicKey()) != string(secondRequest.GetPublicKey()) {
		t.Fatalf("retry changed identity")
	}
	if firstRequest.GetTokenValue() != config.Token || len(firstRequest.GetProofOfPossession()) == 0 {
		t.Fatalf("request omitted enrollment credentials or proof")
	}
	proof, err := coreenrollment.ProofMessage(firstRequest)
	if err != nil || !ed25519.Verify(ed25519.PublicKey(firstRequest.GetPublicKey()), proof, firstRequest.GetProofOfPossession()) {
		t.Fatalf("enrollment proof is invalid: %v", err)
	}
}

func mustRead(t *testing.T, request *http.Request) []byte {
	t.Helper()
	defer request.Body.Close()
	content, err := io.ReadAll(request.Body)
	if err != nil {
		t.Fatal(err)
	}
	return content
}

func TestSaveApprovedCertificateAcceptsOnlyMatchingPrivateIdentity(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	privateKey, _, err := ensureIdentity(directory, "agent-lab-1")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "agent-lab-1"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, privateKey.Public(), privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificatePath := filepath.Join(directory, "node.pem")
	if err := SaveApprovedCertificate(filepath.Join(directory, "node.seed"), certificatePath, der); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(certificatePath)
	if err != nil || info.Mode().Perm() != privateFileMode {
		t.Fatalf("certificate file = %#v, err = %v", info, err)
	}
	content, err := os.ReadFile(certificatePath)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(content)
	if block == nil || string(block.Bytes) != string(der) {
		t.Fatal("certificate was not written as expected PEM")
	}
	if err := SaveApprovedCertificate(filepath.Join(directory, "node.seed"), certificatePath, der); err != nil {
		t.Fatalf("idempotent certificate save: %v", err)
	}
	_, otherKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherDER, err := x509.CreateCertificate(rand.Reader, template, template, otherKey.Public(), otherKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveApprovedCertificate(filepath.Join(directory, "node.seed"), certificatePath, otherDER); err == nil {
		t.Fatal("accepted a certificate for another identity")
	}
}

func TestSubmitReturnsOnlyAnApprovedMatchingCertificate(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	privateKey, _, err := ensureIdentity(directory, "agent-lab-1")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		template := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "agent-lab-1"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, BasicConstraintsValid: true}
		der, err := x509.CreateCertificate(rand.Reader, template, template, privateKey.Public(), privateKey)
		if err != nil {
			t.Errorf("issue test certificate: %v", err)
			http.Error(writer, "certificate", http.StatusInternalServerError)
			return
		}
		output := &antiflockv1.EnrollNodeResponse{Enrollment: &antiflockv1.EnrollmentRequest{Id: "enrollment-approved", ProposedNodeId: "agent-lab-1", Status: antiflockv1.EnrollmentStatus_ENROLLMENT_STATUS_APPROVED}, NodeCertificateChainDer: der}
		encoded, err := (protojson.MarshalOptions{}).Marshal(output)
		if err != nil {
			t.Errorf("encode response: %v", err)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusAccepted)
		_, _ = writer.Write(encoded)
	}))
	defer server.Close()
	result, err := Submit(context.Background(), Config{Endpoint: server.URL, Token: "01234567890123456789012345678901", StateDirectory: directory, NodeID: "agent-lab-1", DisplayName: "Lab agent"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != antiflockv1.EnrollmentStatus_ENROLLMENT_STATUS_APPROVED || len(result.CertificateChainDER) == 0 {
		t.Fatalf("approval result = %#v", result)
	}
}
