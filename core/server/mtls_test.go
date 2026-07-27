package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestApprovedNodeCanAuthenticateWithVerifiedMTLSCertificate(t *testing.T) {
	runtime := newTestRuntime(t)
	node, err := runtime.db.GetNode(context.Background(), "node-test")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(node.CertificatePEM))
	if block == nil {
		t.Fatal("decode enrolled node certificate")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodPost, "/v1/events/batch", nil)
	request.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{certificate}}}
	response := httptest.NewRecorder()
	runtime.server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("certificate-only enrolled request = %d %s", response.Code, response.Body.String())
	}
}
