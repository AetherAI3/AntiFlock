package identity_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DBarr3/AntiFlock/core/identity"
)

func TestEnsurePersistsStableDeploymentAndKeys(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	createdAt := time.Date(2026, time.July, 22, 12, 0, 0, 0, time.UTC)
	first, err := identity.Ensure(directory, createdAt)
	if err != nil {
		t.Fatal(err)
	}
	recoveryContent, err := os.ReadFile(first.RecoveryCredentialPath())
	if err != nil {
		t.Fatal(err)
	}
	credential := strings.TrimSpace(string(recoveryContent))
	decodedCredential, err := base64.RawURLEncoding.DecodeString(credential)
	if err != nil || len(decodedCredential) != 32 {
		t.Fatalf("recovery credential is not a 256-bit URL-safe value: length=%d err=%v", len(decodedCredential), err)
	}
	digest := sha256.Sum256([]byte(credential))
	if first.Deployment.RecoveryCredentialHash != hex.EncodeToString(digest[:]) {
		t.Fatal("deployment did not persist the recovery credential SHA-256 hash")
	}
	if !first.VerifyRecoveryCredential(credential) {
		t.Fatal("generated recovery credential was not accepted")
	}
	if first.VerifyRecoveryCredential(credential + "-wrong") {
		t.Fatal("incorrect recovery credential was accepted")
	}
	assertPrivatePathProtection(t, directory, true)
	for _, protectedPath := range []string{
		first.RecoveryCredentialPath(),
		filepath.Join(directory, "ca.key"),
		filepath.Join(directory, "audit.key"),
		filepath.Join(directory, "verification-keyring.json"),
	} {
		assertPrivatePathProtection(t, protectedPath, false)
	}
	if filepath.Base(first.AuditAnchorPath()) != "audit-anchor.jsonl" {
		t.Fatalf("audit anchor path = %q, want audit-anchor.jsonl", first.AuditAnchorPath())
	}
	stateJSON, err := os.ReadFile(filepath.Join(directory, "deployment.json"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stateJSON, []byte(credential)) {
		t.Fatal("deployment state contains the plaintext recovery credential")
	}
	if first.Deployment.VerificationKeyringHash == "" {
		t.Fatal("deployment state does not bind its verification keyring")
	}
	auditKeyring := first.AuditVerificationKeys()
	if len(auditKeyring) != 1 || !bytes.Equal(auditKeyring[first.Deployment.AuditKeyID], first.AuditPublicKey()) {
		t.Fatal("audit verification keyring does not contain the active audit key")
	}
	auditKeyring[first.Deployment.AuditKeyID][0] ^= 0xff
	if bytes.Equal(auditKeyring[first.Deployment.AuditKeyID], first.AuditVerificationKeys()[first.Deployment.AuditKeyID]) {
		t.Fatal("audit verification keyring accessor did not return a defensive copy")
	}
	if len(first.HistoricalAuditPublicKeys()) != 0 {
		t.Fatal("new deployment unexpectedly has historical audit keys")
	}
	authorityKeyring := first.AuthorityCertificates()
	if len(authorityKeyring) != 1 || !bytes.Equal(authorityKeyring[first.Deployment.AuthorityKeyID].Raw, first.CACert.Raw) {
		t.Fatal("authority certificate keyring does not contain the active CA")
	}

	second, err := identity.Ensure(directory, createdAt.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if first.Deployment.DeploymentID != second.Deployment.DeploymentID {
		t.Fatal("deployment identity changed after reload")
	}
	if !bytes.Equal(first.AuditPublicKey(), second.AuditPublicKey()) {
		t.Fatal("audit key changed after reload")
	}
	reloadedRecoveryContent, err := os.ReadFile(second.RecoveryCredentialPath())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(recoveryContent, reloadedRecoveryContent) {
		t.Fatal("recovery credential was rewritten during reload")
	}
	if err := os.Remove(second.RecoveryCredentialPath()); err != nil {
		t.Fatal(err)
	}
	third, err := identity.Ensure(directory, createdAt.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(third.RecoveryCredentialPath()); !os.IsNotExist(err) {
		t.Fatalf("reload re-emitted a removed recovery credential: %v", err)
	}
	if !third.VerifyRecoveryCredential(credential) {
		t.Fatal("reloaded deployment could not verify the original recovery credential")
	}
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM, err := first.IssueNodeCertificate("node_test", public, createdAt.Add(3*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(certificatePEM))
	if block == nil {
		t.Fatal("node certificate was not PEM")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if certificate.Subject.CommonName != "node_test" {
		t.Fatalf("node certificate subject = %q", certificate.Subject.CommonName)
	}
	if _, err := first.IssueNodeCertificate("bad", ed25519.PublicKey{1}, createdAt.Add(3*time.Hour)); err == nil {
		t.Fatal("invalid public key was accepted")
	}
}

func TestEnsureRejectsTamperedVerificationKeyring(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	now := time.Date(2026, time.July, 22, 12, 0, 0, 0, time.UTC)
	if _, err := identity.Ensure(directory, now); err != nil {
		t.Fatal(err)
	}
	keyringPath := filepath.Join(directory, "verification-keyring.json")
	keyring, err := os.ReadFile(keyringPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyringPath, append(keyring, byte(' ')), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := identity.Ensure(directory, now.Add(time.Minute)); err == nil || !strings.Contains(err.Error(), "keyring hash") {
		t.Fatalf("Ensure error = %v, want signed keyring hash failure", err)
	}
}

func TestEnsureConcurrentCallsProduceOneCoherentIdentity(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	now := time.Date(2026, time.July, 22, 12, 0, 0, 0, time.UTC)
	const callers = 16

	start := make(chan struct{})
	authorities := make([]*identity.Authority, callers)
	errorsByCaller := make([]error, callers)
	var group sync.WaitGroup
	group.Add(callers)
	for index := 0; index < callers; index++ {
		index := index
		go func() {
			defer group.Done()
			<-start
			authorities[index], errorsByCaller[index] = identity.Ensure(directory, now)
		}()
	}
	close(start)
	group.Wait()

	for index, err := range errorsByCaller {
		if err != nil {
			t.Fatalf("Ensure caller %d: %v", index, err)
		}
	}
	first := authorities[0]
	for index, candidate := range authorities {
		if candidate.Deployment != first.Deployment {
			t.Fatalf("Ensure caller %d observed a different deployment", index)
		}
		if !bytes.Equal(candidate.CACert.Raw, first.CACert.Raw) {
			t.Fatalf("Ensure caller %d observed a different CA certificate", index)
		}
		if !bytes.Equal(candidate.AuditPublicKey(), first.AuditPublicKey()) {
			t.Fatalf("Ensure caller %d observed a different audit key", index)
		}
	}

	recoveryContent, err := os.ReadFile(first.RecoveryCredentialPath())
	if err != nil {
		t.Fatal(err)
	}
	credential := strings.TrimSpace(string(recoveryContent))
	for index, authority := range authorities {
		if !authority.VerifyRecoveryCredential(credential) {
			t.Fatalf("Ensure caller %d cannot verify the one recovery credential", index)
		}
	}
}

func TestEnsureNeverOverwritesExistingRecoveryCredential(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	credentialPath := filepath.Join(directory, "recovery-credential.txt")
	const existing = "operator-controlled-existing-value\n"
	if err := os.WriteFile(credentialPath, []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := identity.Ensure(directory, time.Date(2026, time.July, 22, 12, 0, 0, 0, time.UTC)); err == nil {
		t.Fatal("Ensure overwrote an existing recovery credential")
	}
	content, err := os.ReadFile(credentialPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != existing {
		t.Fatal("existing recovery credential content changed")
	}
}
