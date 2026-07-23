package runtime

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadNodeCertificateUsesSameEnrolledSeed(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil { t.Fatal(err) }
	directory := t.TempDir(); seedPath := filepath.Join(directory, "node.seed"); certPath := filepath.Join(directory, "node.pem")
	if err := os.WriteFile(seedPath, privateKey.Seed(), 0o600); err != nil { t.Fatal(err) }
	now := time.Now().UTC()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "node-test"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil { t.Fatal(err) }
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil { t.Fatal(err) }
	certificate, err := LoadNodeCertificate(certPath, seedPath)
	if err != nil || len(certificate.Certificate) != 1 || certificate.Leaf == nil { t.Fatalf("certificate=%#v err=%v", certificate, err) }
}
