package identity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/DBarr3/AntiFlock/internal/id"
)

const (
	initializationManifestName    = "manifest.json"
	initializationManifestVersion = 1
	initializationManifestDomain  = "AntiFlock-Identity-Initialization-v1"
)

type initializationManifest struct {
	Version   int                              `json:"version"`
	Artifacts []initializationManifestArtifact `json:"artifacts"`
	Signature string                           `json:"signature"`
}

type initializationManifestArtifact struct {
	Name   string `json:"name"`
	Mode   uint32 `json:"mode"`
	SHA256 string `json:"sha256"`
}

type initializationStage struct {
	path     string
	manifest initializationManifest
}

var initializationArtifactModes = map[string]os.FileMode{
	caCertFileName:             0o644,
	caKeyFileName:              0o600,
	auditKeyFileName:           0o600,
	verificationKeyringName:    0o600,
	recoveryCredentialFileName: 0o600,
	stateFileName:              0o600,
}

var initializationInstallOrder = []string{
	caCertFileName,
	caKeyFileName,
	auditKeyFileName,
	verificationKeyringName,
	recoveryCredentialFileName,
	stateFileName, // The signed state is the commit marker and is always installed last.
}

func ensureIdentityDirectory(directory string) error {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create identity state directory: %w", err)
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return fmt.Errorf("inspect identity state directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("identity state path must be a real directory")
	}
	if err := protectIdentityDirectory(directory); err != nil {
		return fmt.Errorf("protect identity state directory: %w", err)
	}
	return nil
}

func prepareInitializationStage(directory string, now time.Time) (*initializationStage, error) {
	stagePath := filepath.Join(directory, initializationStageName)
	exists, err := directoryExists(stagePath)
	if err != nil {
		return nil, fmt.Errorf("inspect identity initialization stage: %w", err)
	}
	if exists {
		stage, err := readInitializationStage(stagePath, now)
		if err == nil {
			return stage, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		// A manifest is written only after every staged artifact is durable. A
		// manifest-less stage therefore cannot have been installed by this
		// implementation. Refuse cleanup if any final artifact exists, since
		// that would make an unprovable partial state look resumable.
		if err := assertNoInstalledArtifacts(directory); err != nil {
			return nil, fmt.Errorf("incomplete identity stage cannot be recovered safely: %w", err)
		}
		if err := removeInitializationStage(directory); err != nil {
			return nil, err
		}
	}
	return buildInitializationStage(directory, now)
}

func buildInitializationStage(directory string, now time.Time) (*initializationStage, error) {
	if err := assertNoInstalledArtifacts(directory); err != nil {
		return nil, err
	}
	stagePath := filepath.Join(directory, initializationStageName)
	if err := os.Mkdir(stagePath, 0o700); err != nil {
		return nil, fmt.Errorf("create identity initialization stage: %w", err)
	}
	if err := protectIdentityDirectory(stagePath); err != nil {
		return nil, fmt.Errorf("protect identity initialization stage: %w", err)
	}
	if err := syncDirectory(directory); err != nil {
		return nil, fmt.Errorf("sync identity directory after staging directory creation: %w", err)
	}

	artifacts, auditPrivate, err := generateInitializationArtifacts(now)
	if err != nil {
		return nil, err
	}
	manifest := initializationManifest{Version: initializationManifestVersion}
	names := make([]string, 0, len(artifacts))
	for name := range artifacts {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		mode, ok := initializationArtifactModes[name]
		if !ok {
			return nil, fmt.Errorf("identity initialization generated unknown artifact %q", name)
		}
		if err := writeAtomic(filepath.Join(stagePath, name), artifacts[name], mode); err != nil {
			return nil, fmt.Errorf("stage identity artifact %s: %w", name, err)
		}
		digest := sha256.Sum256(artifacts[name])
		manifest.Artifacts = append(manifest.Artifacts, initializationManifestArtifact{
			Name: name, Mode: uint32(mode.Perm()), SHA256: hex.EncodeToString(digest[:]),
		})
	}
	if err := signInitializationManifest(&manifest, auditPrivate); err != nil {
		return nil, err
	}
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode identity initialization manifest: %w", err)
	}
	if err := writeAtomic(filepath.Join(stagePath, initializationManifestName), append(encoded, '\n'), 0o600); err != nil {
		return nil, fmt.Errorf("commit identity initialization stage: %w", err)
	}
	return readInitializationStage(stagePath, now)
}

func generateInitializationArtifacts(now time.Time) (map[string][]byte, ed25519.PrivateKey, error) {
	deployment := Deployment{
		DeploymentID: id.New("deployment"),
		OperatorID:   id.New("operator"),
		CreatedAt:    now.UTC(),
	}
	recoveryCredential, err := generateRecoveryCredential()
	if err != nil {
		return nil, nil, err
	}
	recoveryCredentialDigest := sha256.Sum256([]byte(recoveryCredential))
	deployment.RecoveryCredentialHash = hex.EncodeToString(recoveryCredentialDigest[:])

	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate CA key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "AntiFlock Local Deployment CA", Organization: []string{deployment.DeploymentID}},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, caPublic, caPrivate)
	if err != nil {
		return nil, nil, fmt.Errorf("create local CA certificate: %w", err)
	}
	_, auditPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate audit key: %w", err)
	}
	deployment.CAPublicKeyHash, err = publicKeyFingerprint(caPublic)
	if err != nil {
		return nil, nil, err
	}
	deployment.AuditPublicKeyHash, err = publicKeyFingerprint(auditPrivate.Public())
	if err != nil {
		return nil, nil, err
	}
	deployment.AuthorityKeyID = "ca:" + deployment.CAPublicKeyHash
	deployment.AuditKeyID = "audit:" + deployment.AuditPublicKeyHash
	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		return nil, nil, fmt.Errorf("parse local CA certificate: %w", err)
	}
	keyringContent, err := encodeVerificationKeyring(newVerificationKeyring(deployment, certificate, auditPrivate.Public().(ed25519.PublicKey)))
	if err != nil {
		return nil, nil, err
	}
	keyringDigest := sha256.Sum256(keyringContent)
	deployment.VerificationKeyringHash = hex.EncodeToString(keyringDigest[:])
	if err := signDeploymentState(&deployment, auditPrivate); err != nil {
		return nil, nil, err
	}

	caPrivateDER, err := x509.MarshalPKCS8PrivateKey(caPrivate)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal CA key: %w", err)
	}
	auditPrivateDER, err := x509.MarshalPKCS8PrivateKey(auditPrivate)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal audit key: %w", err)
	}
	stateJSON, err := json.MarshalIndent(deployment, "", "  ")
	if err != nil {
		return nil, nil, fmt.Errorf("encode deployment identity: %w", err)
	}
	return map[string][]byte{
		caCertFileName:             pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}),
		caKeyFileName:              pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: caPrivateDER}),
		auditKeyFileName:           pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: auditPrivateDER}),
		verificationKeyringName:    keyringContent,
		recoveryCredentialFileName: []byte(recoveryCredential + "\n"),
		stateFileName:              append(stateJSON, '\n'),
	}, auditPrivate, nil
}

func readInitializationStage(stagePath string, now time.Time) (*initializationStage, error) {
	info, err := os.Lstat(stagePath)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("identity initialization stage must be a real directory")
	}
	if err := protectIdentityDirectory(stagePath); err != nil {
		return nil, fmt.Errorf("protect identity initialization stage: %w", err)
	}
	manifestContent, err := readIdentityFile(filepath.Join(stagePath, initializationManifestName), 0o600)
	if err != nil {
		return nil, err
	}
	var manifest initializationManifest
	decoder := json.NewDecoder(bytes.NewReader(manifestContent))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return nil, fmt.Errorf("decode identity initialization manifest: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("identity initialization manifest has trailing JSON data")
		}
		return nil, fmt.Errorf("decode trailing identity initialization manifest data: %w", err)
	}
	if err := verifyInitializationManifest(stagePath, manifest, now); err != nil {
		return nil, err
	}
	return &initializationStage{path: stagePath, manifest: manifest}, nil
}

func verifyInitializationManifest(stagePath string, manifest initializationManifest, now time.Time) error {
	if manifest.Version != initializationManifestVersion {
		return fmt.Errorf("unsupported identity initialization manifest version %d", manifest.Version)
	}
	if len(manifest.Artifacts) != len(initializationArtifactModes) {
		return errors.New("identity initialization manifest has an incomplete artifact set")
	}
	seen := make(map[string]bool, len(manifest.Artifacts))
	for index, artifact := range manifest.Artifacts {
		mode, ok := initializationArtifactModes[artifact.Name]
		if !ok || seen[artifact.Name] || artifact.Mode != uint32(mode.Perm()) {
			return fmt.Errorf("identity initialization manifest artifact %d is invalid", index)
		}
		if index > 0 && manifest.Artifacts[index-1].Name >= artifact.Name {
			return errors.New("identity initialization manifest artifacts are not uniquely sorted")
		}
		seen[artifact.Name] = true
		content, err := readIdentityFile(filepath.Join(stagePath, artifact.Name), mode)
		if err != nil {
			return fmt.Errorf("read staged identity artifact %s: %w", artifact.Name, err)
		}
		digest := sha256.Sum256(content)
		if artifact.SHA256 != hex.EncodeToString(digest[:]) {
			return fmt.Errorf("staged identity artifact %s does not match its manifest digest", artifact.Name)
		}
	}
	entries, err := os.ReadDir(stagePath)
	if err != nil {
		return fmt.Errorf("list identity initialization stage: %w", err)
	}
	if len(entries) != len(initializationArtifactModes)+1 {
		return errors.New("identity initialization stage contains unexpected files")
	}
	for _, entry := range entries {
		if entry.Name() != initializationManifestName && !seen[entry.Name()] {
			return fmt.Errorf("identity initialization stage contains unexpected artifact %q", entry.Name())
		}
	}

	auditKey, err := readPrivateKey(filepath.Join(stagePath, auditKeyFileName))
	if err != nil {
		return err
	}
	if err := verifyInitializationManifestSignature(manifest, auditKey.Public().(ed25519.PublicKey)); err != nil {
		return err
	}
	deploymentContent, err := readIdentityFile(filepath.Join(stagePath, stateFileName), 0o600)
	if err != nil {
		return err
	}
	var deployment Deployment
	if err := decodeDeployment(deploymentContent, &deployment); err != nil {
		return fmt.Errorf("decode staged deployment identity: %w", err)
	}
	certificate, err := readCertificate(filepath.Join(stagePath, caCertFileName))
	if err != nil {
		return err
	}
	caKey, err := readPrivateKey(filepath.Join(stagePath, caKeyFileName))
	if err != nil {
		return err
	}
	if err := verifyCoherence(deployment, certificate, caKey, auditKey, now.UTC()); err != nil {
		return fmt.Errorf("verify staged deployment identity: %w", err)
	}
	keyringContent, err := readIdentityFile(filepath.Join(stagePath, verificationKeyringName), 0o600)
	if err != nil {
		return err
	}
	if _, _, err := verifyAndDecodeVerificationKeyring(deployment, certificate, auditKey.Public().(ed25519.PublicKey), keyringContent); err != nil {
		return fmt.Errorf("verify staged identity verification keyring: %w", err)
	}
	recoveryContent, err := readIdentityFile(filepath.Join(stagePath, recoveryCredentialFileName), 0o600)
	if err != nil {
		return err
	}
	recoveryCredential := string(bytes.TrimSuffix(recoveryContent, []byte{'\n'}))
	if recoveryCredential == string(recoveryContent) || !deployment.VerifyRecoveryCredential(recoveryCredential) {
		return errors.New("staged recovery credential does not match signed deployment state")
	}
	return nil
}

func signInitializationManifest(manifest *initializationManifest, key ed25519.PrivateKey) error {
	if manifest == nil || len(key) != ed25519.PrivateKeySize {
		return errors.New("identity initialization manifest and audit key are required")
	}
	preimage, err := initializationManifestPreimage(*manifest)
	if err != nil {
		return err
	}
	manifest.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, preimage))
	return nil
}

func verifyInitializationManifestSignature(manifest initializationManifest, key ed25519.PublicKey) error {
	signature, err := base64.RawURLEncoding.DecodeString(manifest.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("identity initialization manifest signature is invalid")
	}
	preimage, err := initializationManifestPreimage(manifest)
	if err != nil {
		return err
	}
	if !ed25519.Verify(key, preimage, signature) {
		return errors.New("identity initialization manifest signature verification failed")
	}
	return nil
}

func initializationManifestPreimage(manifest initializationManifest) ([]byte, error) {
	manifest.Signature = ""
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return nil, fmt.Errorf("encode identity initialization manifest signature input: %w", err)
	}
	preimage := make([]byte, 0, len(initializationManifestDomain)+1+len(encoded))
	preimage = append(preimage, initializationManifestDomain...)
	preimage = append(preimage, 0)
	return append(preimage, encoded...), nil
}

func installInitializationStage(directory string, stage *initializationStage) error {
	if stage == nil || filepath.Clean(stage.path) != filepath.Join(filepath.Clean(directory), initializationStageName) {
		return errors.New("identity initialization stage path is invalid")
	}
	for _, name := range initializationInstallOrder {
		mode := initializationArtifactModes[name]
		stagedContent, err := readIdentityFile(filepath.Join(stage.path, name), mode)
		if err != nil {
			return fmt.Errorf("read staged identity artifact %s: %w", name, err)
		}
		target := filepath.Join(directory, name)
		exists, err := regularFileExists(target)
		if err != nil {
			return fmt.Errorf("inspect installed identity artifact %s: %w", name, err)
		}
		if exists {
			installedContent, err := readIdentityFile(target, mode)
			if err != nil {
				return fmt.Errorf("read installed identity artifact %s: %w", name, err)
			}
			if !bytes.Equal(installedContent, stagedContent) {
				return fmt.Errorf("installed identity artifact %s differs from the committed stage; refusing to overwrite", name)
			}
			continue
		}
		if err := writeAtomic(target, stagedContent, mode); err != nil {
			return fmt.Errorf("install identity artifact %s: %w", name, err)
		}
	}
	return nil
}

func cleanupCommittedInitializationStage(directory string, now time.Time) error {
	stagePath := filepath.Join(directory, initializationStageName)
	exists, err := directoryExists(stagePath)
	if err != nil || !exists {
		return err
	}
	stage, err := readInitializationStage(stagePath, now)
	if err != nil {
		return fmt.Errorf("verify committed identity initialization stage before cleanup: %w", err)
	}
	for _, name := range initializationInstallOrder {
		mode := initializationArtifactModes[name]
		staged, err := readIdentityFile(filepath.Join(stage.path, name), mode)
		if err != nil {
			return err
		}
		installed, err := readIdentityFile(filepath.Join(directory, name), mode)
		if err != nil {
			return err
		}
		if !bytes.Equal(staged, installed) {
			return fmt.Errorf("committed identity artifact %s differs from initialization stage; refusing cleanup", name)
		}
	}
	return removeInitializationStage(directory)
}

func removeInitializationStage(directory string) error {
	stagePath := filepath.Join(directory, initializationStageName)
	info, err := os.Lstat(stagePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect identity initialization stage for cleanup: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("refusing to remove an identity initialization stage that is not a real directory")
	}
	if err := os.RemoveAll(stagePath); err != nil {
		return fmt.Errorf("remove identity initialization stage: %w", err)
	}
	if err := syncDirectory(directory); err != nil {
		return fmt.Errorf("sync identity directory after stage cleanup: %w", err)
	}
	return nil
}

func assertNoInstalledArtifacts(directory string) error {
	for _, name := range initializationInstallOrder {
		path := filepath.Join(directory, name)
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("identity artifact %s already exists without committed deployment state; refusing to overwrite", name)
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect identity artifact %s: %w", name, err)
		}
	}
	return nil
}

func readCertificate(path string) (*x509.Certificate, error) {
	certificatePEM, err := readIdentityFile(path, 0o644)
	if err != nil {
		return nil, fmt.Errorf("read CA certificate: %w", err)
	}
	block, rest := pem.Decode(certificatePEM)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("identity CA certificate is invalid")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA certificate: %w", err)
	}
	return certificate, nil
}

func readIdentityFile(path string, mode os.FileMode) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("identity path %s must be a regular non-symlink file", filepath.Base(path))
	}
	if err := protectIdentityFile(path, mode); err != nil {
		return nil, fmt.Errorf("protect identity file %s: %w", filepath.Base(path), err)
	}
	return os.ReadFile(path)
}

func regularFileExists(path string) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return false, fmt.Errorf("%s must be a regular non-symlink file", filepath.Base(path))
	}
	return true, nil
}

func directoryExists(path string) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return false, fmt.Errorf("%s must be a real directory", filepath.Base(path))
	}
	return true, nil
}

func writeAtomic(path string, content []byte, mode os.FileMode) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".antiflock-identity-*")
	if err != nil {
		return fmt.Errorf("create temporary identity file: %w", err)
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := protectIdentityFile(temporaryName, mode); err != nil {
		temporary.Close()
		return fmt.Errorf("protect temporary identity file: %w", err)
	}
	if _, err := temporary.Write(content); err != nil {
		temporary.Close()
		return fmt.Errorf("write identity file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync identity file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close identity file: %w", err)
	}
	if err := installNoReplace(temporaryName, path); err != nil {
		return fmt.Errorf("install identity file without replacement: %w", err)
	}
	return nil
}

func acquireInitializationLock(directory string, timeout time.Duration) (func(), error) {
	lockPath := filepath.Join(directory, initializationLockName)
	if info, err := os.Lstat(lockPath); err == nil && !info.Mode().IsRegular() {
		return nil, errors.New("identity initialization lock path is not a regular file; refusing unsafe stale-lock replacement")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect identity initialization lock: %w", err)
	}
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open identity initialization lock: %w", err)
	}
	if err := protectIdentityFile(lockPath, 0o600); err != nil {
		lock.Close()
		return nil, fmt.Errorf("protect identity initialization lock: %w", err)
	}
	if err := syncDirectory(directory); err != nil {
		lock.Close()
		return nil, fmt.Errorf("sync identity initialization lock creation: %w", err)
	}
	deadline := time.Now().Add(timeout)
	for {
		acquired, err := tryLockIdentityFile(lock)
		if err != nil {
			lock.Close()
			return nil, fmt.Errorf("acquire identity initialization lock: %w", err)
		}
		if acquired {
			return func() {
				_ = unlockIdentityFile(lock)
				_ = lock.Close()
			}, nil
		}
		if time.Now().After(deadline) {
			lock.Close()
			return nil, errors.New("timed out waiting for active identity initialization")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
