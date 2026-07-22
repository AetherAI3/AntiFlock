package identity

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"
)

const (
	stateFileName              = "deployment.json"
	caCertFileName             = "ca.crt"
	caKeyFileName              = "ca.key"
	auditKeyFileName           = "audit.key"
	verificationKeyringName    = "verification-keyring.json"
	recoveryCredentialFileName = "recovery-credential.txt"
	initializationLockName     = ".initialization.lock"
	initializationStageName    = ".initialization.stage"
	auditAnchorFileName        = "audit-anchor.jsonl"
	recoveryCredentialBytes    = 32
)

type Deployment struct {
	DeploymentID            string    `json:"deploymentId"`
	OperatorID              string    `json:"operatorId"`
	AuthorityKeyID          string    `json:"authorityKeyId"`
	AuditKeyID              string    `json:"auditKeyId"`
	CAPublicKeyHash         string    `json:"caPublicKeyHash"`
	AuditPublicKeyHash      string    `json:"auditPublicKeyHash"`
	VerificationKeyringHash string    `json:"verificationKeyringHash"`
	RecoveryCredentialHash  string    `json:"recoveryCredentialHash"`
	CreatedAt               time.Time `json:"createdAt"`
	StateSignature          string    `json:"stateSignature"`
}

type Authority struct {
	Deployment            Deployment
	CACert                *x509.Certificate
	caKey                 ed25519.PrivateKey
	auditKey              ed25519.PrivateKey
	auditVerificationKeys map[string]ed25519.PublicKey
	authorityCertificates map[string]*x509.Certificate
	directory             string
}

func Ensure(directory string, now time.Time) (*Authority, error) {
	if directory == "" {
		return nil, errors.New("identity state directory is required")
	}
	if err := ensureIdentityDirectory(directory); err != nil {
		return nil, err
	}
	statePath := filepath.Join(directory, stateFileName)
	stateExists, err := regularFileExists(statePath)
	if err != nil {
		return nil, fmt.Errorf("inspect identity state: %w", err)
	}
	stageExists, err := directoryExists(filepath.Join(directory, initializationStageName))
	if err != nil {
		return nil, fmt.Errorf("inspect identity initialization stage: %w", err)
	}
	if stateExists && !stageExists {
		return load(directory, now.UTC())
	}
	release, err := acquireInitializationLock(directory, 15*time.Second)
	if err != nil {
		return nil, err
	}
	defer release()
	stateExists, err = regularFileExists(statePath)
	if err != nil {
		return nil, fmt.Errorf("inspect identity state after lock: %w", err)
	}
	if stateExists {
		authority, err := load(directory, now.UTC())
		if err != nil {
			return nil, err
		}
		if err := cleanupCommittedInitializationStage(directory, now.UTC()); err != nil {
			return nil, err
		}
		return authority, nil
	}
	return create(directory, now.UTC())
}

func create(directory string, now time.Time) (*Authority, error) {
	stage, err := prepareInitializationStage(directory, now)
	if err != nil {
		return nil, err
	}
	if err := installInitializationStage(directory, stage); err != nil {
		return nil, err
	}
	authority, err := load(directory, now)
	if err != nil {
		return nil, fmt.Errorf("verify installed deployment identity: %w", err)
	}
	if err := removeInitializationStage(directory); err != nil {
		return nil, err
	}
	return authority, nil
}

func load(directory string, now time.Time) (*Authority, error) {
	var deployment Deployment
	stateJSON, err := readIdentityFile(filepath.Join(directory, stateFileName), 0o600)
	if err != nil {
		return nil, fmt.Errorf("read deployment identity: %w", err)
	}
	if err := decodeDeployment(stateJSON, &deployment); err != nil {
		return nil, fmt.Errorf("decode deployment identity: %w", err)
	}
	certificate, err := readCertificate(filepath.Join(directory, caCertFileName))
	if err != nil {
		return nil, err
	}
	caKey, err := readPrivateKey(filepath.Join(directory, caKeyFileName))
	if err != nil {
		return nil, err
	}
	auditKey, err := readPrivateKey(filepath.Join(directory, auditKeyFileName))
	if err != nil {
		return nil, err
	}
	if err := verifyCoherence(deployment, certificate, caKey, auditKey, now); err != nil {
		return nil, err
	}
	keyringContent, err := readIdentityFile(filepath.Join(directory, verificationKeyringName), 0o600)
	if err != nil {
		return nil, fmt.Errorf("read identity verification keyring: %w", err)
	}
	auditVerificationKeys, authorityCertificates, err := verifyAndDecodeVerificationKeyring(deployment, certificate, auditKey.Public().(ed25519.PublicKey), keyringContent)
	if err != nil {
		return nil, err
	}
	recoveryPath := filepath.Join(directory, recoveryCredentialFileName)
	if exists, inspectErr := regularFileExists(recoveryPath); inspectErr != nil {
		return nil, fmt.Errorf("inspect recovery credential: %w", inspectErr)
	} else if exists {
		recoveryContent, readErr := readIdentityFile(recoveryPath, 0o600)
		if readErr != nil {
			return nil, fmt.Errorf("read recovery credential: %w", readErr)
		}
		credential := strings.TrimSuffix(string(recoveryContent), "\n")
		if credential == string(recoveryContent) || strings.Contains(credential, "\n") || !deployment.VerifyRecoveryCredential(credential) {
			return nil, errors.New("recovery credential does not match signed deployment state")
		}
	}
	return &Authority{
		Deployment: deployment, CACert: certificate, caKey: caKey, auditKey: auditKey,
		auditVerificationKeys: auditVerificationKeys, authorityCertificates: authorityCertificates,
		directory: directory,
	}, nil
}

func (authority *Authority) IssueNodeCertificate(nodeID string, publicKey ed25519.PublicKey, now time.Time) (string, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return "", errors.New("node public key must be Ed25519")
	}
	now = now.UTC()
	if now.Before(authority.CACert.NotBefore) || !now.Before(authority.CACert.NotAfter) {
		return "", errors.New("deployment CA is outside its validity window")
	}
	serial, err := randomSerial()
	if err != nil {
		return "", err
	}
	notBefore := now.Add(-5 * time.Minute)
	if notBefore.Before(authority.CACert.NotBefore) {
		notBefore = authority.CACert.NotBefore
	}
	notAfter := now.AddDate(1, 0, 0)
	if notAfter.After(authority.CACert.NotAfter) {
		notAfter = authority.CACert.NotAfter
	}
	if !notAfter.After(notBefore) {
		return "", errors.New("deployment CA has insufficient remaining validity")
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: nodeID, Organization: []string{authority.Deployment.DeploymentID}},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, authority.CACert, publicKey, authority.caKey)
	if err != nil {
		return "", fmt.Errorf("issue node certificate: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})), nil
}

func (authority *Authority) AuditPrivateKey() ed25519.PrivateKey {
	if authority == nil {
		return nil
	}
	return append(ed25519.PrivateKey(nil), authority.auditKey...)
}

func (authority *Authority) AuditPublicKey() ed25519.PublicKey {
	return authority.auditKey.Public().(ed25519.PublicKey)
}

// AuditVerificationKeys returns defensive copies of every current and
// historical audit public key retained by this deployment. Callers can use it
// to verify persisted audit entries across future key rotations.
func (authority *Authority) AuditVerificationKeys() map[string]ed25519.PublicKey {
	if authority == nil {
		return nil
	}
	result := make(map[string]ed25519.PublicKey, len(authority.auditVerificationKeys))
	for keyID, publicKey := range authority.auditVerificationKeys {
		result[keyID] = append(ed25519.PublicKey(nil), publicKey...)
	}
	return result
}

// HistoricalAuditPublicKeys is the verification-only slice accepted by
// audit.NewWithKeyring. The currently active audit public key is omitted.
func (authority *Authority) HistoricalAuditPublicKeys() []ed25519.PublicKey {
	if authority == nil {
		return nil
	}
	keyIDs := make([]string, 0, len(authority.auditVerificationKeys))
	for keyID := range authority.auditVerificationKeys {
		if keyID != authority.Deployment.AuditKeyID {
			keyIDs = append(keyIDs, keyID)
		}
	}
	sort.Strings(keyIDs)
	result := make([]ed25519.PublicKey, 0, len(keyIDs))
	for _, keyID := range keyIDs {
		result = append(result, append(ed25519.PublicKey(nil), authority.auditVerificationKeys[keyID]...))
	}
	return result
}

// AuthorityCertificates returns defensive certificate copies indexed by their
// stable authority key IDs. Historical CA certificates remain available for
// certificate and signature verification after a future CA rotation.
func (authority *Authority) AuthorityCertificates() map[string]*x509.Certificate {
	if authority == nil {
		return nil
	}
	result := make(map[string]*x509.Certificate, len(authority.authorityCertificates))
	for keyID, certificate := range authority.authorityCertificates {
		clone, err := x509.ParseCertificate(certificate.Raw)
		if err == nil {
			result[keyID] = clone
		}
	}
	return result
}

func (authority *Authority) AuditAnchorPath() string {
	return filepath.Join(authority.directory, auditAnchorFileName)
}

// DeriveEnrollmentToken returns a deterministic 64-byte secret for one
// authenticated operator operation. This keeps one-time token plaintext out
// of durable storage while making a lost response safely retryable.
func (authority *Authority) DeriveEnrollmentToken(actorID, operationID string) ([]byte, error) {
	if authority == nil || len(authority.auditKey) != ed25519.PrivateKeySize || actorID == "" || operationID == "" {
		return nil, errors.New("enrollment token derivation requires an authority, actor, and operation")
	}
	mac := hmac.New(sha512.New, authority.auditKey.Seed())
	mac.Write([]byte("AntiFlock-Enrollment-Derivation-v1"))
	var length [4]byte
	for _, value := range []string{actorID, operationID} {
		binary.BigEndian.PutUint32(length[:], uint32(len(value)))
		mac.Write(length[:])
		mac.Write([]byte(value))
	}
	return mac.Sum(nil), nil
}

func (authority *Authority) RecoveryCredentialPath() string {
	return filepath.Join(authority.directory, recoveryCredentialFileName)
}

// VerifyRecoveryCredential compares a candidate with the stored digest without
// retaining or re-reading the one-time plaintext credential.
func (authority *Authority) VerifyRecoveryCredential(credential string) bool {
	if authority == nil {
		return false
	}
	return authority.Deployment.VerifyRecoveryCredential(credential)
}

// VerifyRecoveryCredential performs the candidate comparison in constant time
// once the persisted SHA-256 digest has been validated.
func (deployment Deployment) VerifyRecoveryCredential(credential string) bool {
	expected, err := hex.DecodeString(deployment.RecoveryCredentialHash)
	if err != nil || len(expected) != sha256.Size {
		return false
	}
	actual := sha256.Sum256([]byte(credential))
	return subtle.ConstantTimeCompare(expected, actual[:]) == 1
}

func verifyCoherence(deployment Deployment, certificate *x509.Certificate, caKey, auditKey ed25519.PrivateKey, now time.Time) error {
	if deployment.DeploymentID == "" || deployment.OperatorID == "" || deployment.CreatedAt.IsZero() || deployment.AuthorityKeyID == "" || deployment.AuditKeyID == "" || deployment.CAPublicKeyHash == "" || deployment.AuditPublicKeyHash == "" || deployment.VerificationKeyringHash == "" || deployment.RecoveryCredentialHash == "" || deployment.StateSignature == "" {
		return errors.New("deployment identity is missing cryptographic bindings")
	}
	recoveryCredentialHash, err := hex.DecodeString(deployment.RecoveryCredentialHash)
	if err != nil || len(recoveryCredentialHash) != sha256.Size {
		return errors.New("deployment recovery credential hash is invalid")
	}
	if !certificate.IsCA || certificate.CheckSignatureFrom(certificate) != nil {
		return errors.New("deployment CA is not a valid self-signed CA")
	}
	if now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) {
		return errors.New("deployment CA is outside its validity window")
	}
	if !slices.Contains(certificate.Subject.Organization, deployment.DeploymentID) {
		return errors.New("deployment CA is not bound to the deployment id")
	}
	caCertificateKey, ok := certificate.PublicKey.(ed25519.PublicKey)
	if !ok || !caCertificateKey.Equal(caKey.Public()) {
		return errors.New("deployment CA certificate and private key do not match")
	}
	caHash, err := publicKeyFingerprint(caKey.Public())
	if err != nil || caHash != deployment.CAPublicKeyHash {
		return errors.New("deployment CA fingerprint does not match deployment state")
	}
	auditHash, err := publicKeyFingerprint(auditKey.Public())
	if err != nil || auditHash != deployment.AuditPublicKeyHash {
		return errors.New("audit key fingerprint does not match deployment state")
	}
	if deployment.AuthorityKeyID != "ca:"+caHash || deployment.AuditKeyID != "audit:"+auditHash {
		return errors.New("deployment key ids do not match the active public keys")
	}
	if err := verifyDeploymentState(deployment, auditKey.Public().(ed25519.PublicKey)); err != nil {
		return err
	}
	return nil
}

func signDeploymentState(deployment *Deployment, key ed25519.PrivateKey) error {
	if deployment == nil || len(key) != ed25519.PrivateKeySize {
		return errors.New("deployment state and audit key are required")
	}
	preimage, err := deploymentStatePreimage(*deployment)
	if err != nil {
		return err
	}
	deployment.StateSignature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, preimage))
	return nil
}

func verifyDeploymentState(deployment Deployment, key ed25519.PublicKey) error {
	signature, err := base64.RawURLEncoding.DecodeString(deployment.StateSignature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("deployment state signature is invalid")
	}
	preimage, err := deploymentStatePreimage(deployment)
	if err != nil {
		return err
	}
	if !ed25519.Verify(key, preimage, signature) {
		return errors.New("deployment state signature verification failed")
	}
	return nil
}

func deploymentStatePreimage(deployment Deployment) ([]byte, error) {
	deployment.StateSignature = ""
	encoded, err := json.Marshal(deployment)
	if err != nil {
		return nil, fmt.Errorf("encode deployment state signature input: %w", err)
	}
	result := make([]byte, 0, len(encoded)+40)
	result = append(result, []byte("AntiFlock-Deployment-State-v1")...)
	result = append(result, 0)
	return append(result, encoded...), nil
}

func publicKeyFingerprint(key any) (string, error) {
	encoded, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", fmt.Errorf("marshal public key fingerprint: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("generate certificate serial: %w", err)
	}
	return serial, nil
}

func generateRecoveryCredential() (string, error) {
	value := make([]byte, recoveryCredentialBytes)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate recovery credential: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func readPrivateKey(path string) (ed25519.PrivateKey, error) {
	keyPEM, err := readIdentityFile(path, 0o600)
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}
	return parsePrivateKey(keyPEM)
}

func parsePrivateKey(keyPEM []byte) (ed25519.PrivateKey, error) {
	block, rest := pem.Decode(keyPEM)
	if block == nil || block.Type != "PRIVATE KEY" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("identity private key is invalid")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("identity private key is not Ed25519")
	}
	return key, nil
}

func decodeDeployment(content []byte, deployment *Deployment) error {
	decoder := json.NewDecoder(strings.NewReader(string(content)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(deployment); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("deployment identity has trailing JSON data")
		}
		return err
	}
	return nil
}
