package identity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPersistentVerificationKeyringLoadsHistoricalAuditKeys(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	now := time.Date(2026, time.July, 22, 15, 0, 0, 0, time.UTC)
	authority, err := Ensure(directory, now)
	if err != nil {
		t.Fatal(err)
	}
	keyringPath := filepath.Join(directory, verificationKeyringName)
	keyringContent, err := os.ReadFile(keyringPath)
	if err != nil {
		t.Fatal(err)
	}
	var keyring verificationKeyring
	if err := json.Unmarshal(keyringContent, &keyring); err != nil {
		t.Fatal(err)
	}
	historicalPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := publicKeyFingerprint(historicalPublic)
	if err != nil {
		t.Fatal(err)
	}
	retiredAt := now.Add(2 * time.Hour)
	keyring.AuditKeys = append(keyring.AuditKeys, auditVerificationKeyRecord{
		KeyID:       "audit:" + fingerprint,
		PublicKey:   base64.RawURLEncoding.EncodeToString(historicalPublic),
		ActivatedAt: now.Add(time.Hour),
		RetiredAt:   &retiredAt,
	})
	keyringContent, err = encodeVerificationKeyring(keyring)
	if err != nil {
		t.Fatal(err)
	}
	deployment := authority.Deployment
	digest := sha256.Sum256(keyringContent)
	deployment.VerificationKeyringHash = hex.EncodeToString(digest[:])
	if err := signDeploymentState(&deployment, authority.AuditPrivateKey()); err != nil {
		t.Fatal(err)
	}
	stateContent, err := json.MarshalIndent(deployment, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyringPath, keyringContent, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, stateFileName), append(stateContent, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}

	reloaded, err := Ensure(directory, now.Add(3*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	historical := reloaded.HistoricalAuditPublicKeys()
	if len(historical) != 1 || !bytes.Equal(historical[0], historicalPublic) {
		t.Fatal("historical audit verification key was not restored from the signed keyring")
	}
}

func TestInitializationResumesAfterCommittedStageAndPartialInstall(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	now := time.Date(2026, time.July, 22, 15, 0, 0, 0, time.UTC)
	if err := ensureIdentityDirectory(directory); err != nil {
		t.Fatal(err)
	}
	stage, err := buildInitializationStage(directory, now)
	if err != nil {
		t.Fatal(err)
	}

	// Simulate a process stopping after every non-state artifact was installed.
	// The one-time recovery credential is deliberately included: resumption must
	// reuse it, never generate or overwrite another value.
	for _, name := range initializationInstallOrder[:len(initializationInstallOrder)-1] {
		content, err := readIdentityFile(filepath.Join(stage.path, name), initializationArtifactModes[name])
		if err != nil {
			t.Fatal(err)
		}
		if err := writeAtomic(filepath.Join(directory, name), content, initializationArtifactModes[name]); err != nil {
			t.Fatal(err)
		}
	}
	recoveryBefore, err := os.ReadFile(filepath.Join(directory, recoveryCredentialFileName))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(directory, stateFileName)); !os.IsNotExist(err) {
		t.Fatalf("deployment state was installed before the simulated commit: %v", err)
	}

	authority, err := Ensure(directory, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	recoveryAfter, err := os.ReadFile(filepath.Join(directory, recoveryCredentialFileName))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(recoveryBefore, recoveryAfter) {
		t.Fatal("recovery credential changed while resuming initialization")
	}
	if !authority.VerifyRecoveryCredential(strings.TrimSpace(string(recoveryAfter))) {
		t.Fatal("resumed authority does not verify its original recovery credential")
	}
	if _, err := os.Stat(filepath.Join(directory, initializationStageName)); !os.IsNotExist(err) {
		t.Fatalf("committed initialization stage was not cleaned up: %v", err)
	}
}

func TestInitializationRejectsTamperedCommittedStage(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	now := time.Date(2026, time.July, 22, 15, 0, 0, 0, time.UTC)
	if err := ensureIdentityDirectory(directory); err != nil {
		t.Fatal(err)
	}
	stage, err := buildInitializationStage(directory, now)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(stage.path, caKeyFileName)
	key, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, append(key, byte('x')), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Ensure(directory, now.Add(time.Minute)); err == nil || !strings.Contains(err.Error(), "does not match its manifest digest") {
		t.Fatalf("Ensure error = %v, want manifest digest failure", err)
	}
	if _, err := os.Stat(filepath.Join(directory, stateFileName)); !os.IsNotExist(err) {
		t.Fatalf("tampered stage unexpectedly committed deployment state: %v", err)
	}
}

func TestInitializationRecoversManifestlessStageOnlyWhenNothingWasInstalled(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	now := time.Date(2026, time.July, 22, 15, 0, 0, 0, time.UTC)
	if err := ensureIdentityDirectory(directory); err != nil {
		t.Fatal(err)
	}
	stagePath := filepath.Join(directory, initializationStageName)
	if err := os.Mkdir(stagePath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stagePath, "interrupted.tmp"), []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Ensure(directory, now); err != nil {
		t.Fatalf("resume manifest-less pre-install stage: %v", err)
	}

	directory = t.TempDir()
	if err := ensureIdentityDirectory(directory); err != nil {
		t.Fatal(err)
	}
	stagePath = filepath.Join(directory, initializationStageName)
	if err := os.Mkdir(stagePath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, caCertFileName), []byte("unprovable partial install"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Ensure(directory, now); err == nil || !strings.Contains(err.Error(), "cannot be recovered safely") {
		t.Fatalf("Ensure error = %v, want unsafe recovery refusal", err)
	}
}

func TestInitializationIgnoresStaleLockFileContents(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	if err := ensureIdentityDirectory(directory); err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(directory, initializationLockName)
	if err := os.WriteFile(lockPath, []byte("abandoned metadata from a stopped process"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Ensure(directory, time.Date(2026, time.July, 22, 15, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("kernel lock did not recover from stale lock-file contents: %v", err)
	}
	content, err := os.ReadFile(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "abandoned metadata from a stopped process" {
		t.Fatal("acquiring the kernel lock overwrote stale diagnostic contents")
	}
}

func TestInitializationRejectsMismatchedPartialInstallWithoutOverwrite(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	now := time.Date(2026, time.July, 22, 15, 0, 0, 0, time.UTC)
	if err := ensureIdentityDirectory(directory); err != nil {
		t.Fatal(err)
	}
	if _, err := buildInitializationStage(directory, now); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(directory, caCertFileName)
	const existing = "operator-controlled-existing-certificate"
	if err := os.WriteFile(target, []byte(existing), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Ensure(directory, now); err == nil || !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Fatalf("Ensure error = %v, want no-overwrite refusal", err)
	}
	content, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != existing {
		t.Fatal("mismatched partial identity artifact was overwritten")
	}
}
