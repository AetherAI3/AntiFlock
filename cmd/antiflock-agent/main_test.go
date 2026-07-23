package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestAgentExecutableExposesReadOnlyCollectionOnly(t *testing.T) {
	t.Parallel()
	var help bytes.Buffer
	err := run(context.Background(), []string{"-help"}, &bytes.Buffer{}, &help)
	if err != flag.ErrHelp {
		t.Fatalf("help result = %v", err)
	}
	for _, forbidden := range []string{"nft", "apply", "enforce", "rollback", "mutate"} {
		if strings.Contains(strings.ToLower(help.String()), forbidden) {
			t.Fatalf("agent help exposed mutation surface %q: %s", forbidden, help.String())
		}
	}
	if err := run(context.Background(), []string{"-nft-apply"}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("agent accepted an nftables mutation flag")
	}
}

func TestEnrollRetrievesMatchingCertificateOverPrivateCA(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "agent")
	if err := os.MkdirAll(directory, 0o700); err != nil { t.Fatal(err) }
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader); if err != nil { t.Fatal(err) }
	if err := os.WriteFile(filepath.Join(directory, "node.seed"), privateKey.Seed(), 0o600); err != nil { t.Fatal(err) }
	state := `{"schemaVersion":"antiflock.agent-enrollment/v1","nodeId":"agent-lab-1","requestId":"enroll-test"}`
	if err := os.WriteFile(filepath.Join(directory, "enrollment.json"), []byte(state), 0o600); err != nil { t.Fatal(err) }
	now := time.Now().UTC()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "agent-lab-1"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, BasicConstraintsValid: true}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey); if err != nil { t.Fatal(err) }
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/v1/enrollment/nodes" { http.NotFound(writer, request); return }
		response := &antiflockv1.EnrollNodeResponse{Enrollment: &antiflockv1.EnrollmentRequest{Id: "enrollment-approved", ProposedNodeId: "agent-lab-1", Status: antiflockv1.EnrollmentStatus_ENROLLMENT_STATUS_APPROVED}, NodeCertificateChainDer: certificateDER}
		content, err := (protojson.MarshalOptions{}).Marshal(response); if err != nil { t.Errorf("marshal response: %v", err); return }
		writer.Header().Set("Content-Type", "application/json"); writer.WriteHeader(http.StatusAccepted); _, _ = writer.Write(content)
	}))
	defer server.Close()
	caPath := filepath.Join(directory, "core-ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0o600); err != nil { t.Fatal(err) }
	tokenPath := filepath.Join(directory, "enrollment.token")
	if err := os.WriteFile(tokenPath, []byte("01234567890123456789012345678901"), 0o600); err != nil { t.Fatal(err) }
	var stdout, stderr bytes.Buffer
	err = run(context.Background(), []string{"enroll", "--core-url", server.URL, "--enrollment-token-file", tokenPath, "--state-dir", directory, "--node-id", "agent-lab-1", "--display-name", "Lab agent", "--ca-cert", caPath}, &stdout, &stderr)
	if err != nil { t.Fatalf("enroll: %v; stderr=%s", err, stderr.String()) }
	var output enrollmentOutput
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil { t.Fatal(err) }
	if output.Status != "approved-ready-to-submit" || output.CertificatePath != filepath.Join(directory, "node.pem") { t.Fatalf("enrollment output = %#v", output) }
	content, err := os.ReadFile(output.CertificatePath); if err != nil { t.Fatal(err) }
	block, _ := pem.Decode(content)
	if block == nil || string(block.Bytes) != string(certificateDER) { t.Fatal("approved certificate was not installed") }
}
