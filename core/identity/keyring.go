package identity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"
)

const verificationKeyringVersion = 1

type verificationKeyring struct {
	Version     int                              `json:"version"`
	Authorities []authorityVerificationKeyRecord `json:"authorities"`
	AuditKeys   []auditVerificationKeyRecord     `json:"auditKeys"`
}

type authorityVerificationKeyRecord struct {
	KeyID          string     `json:"keyId"`
	CertificateDER string     `json:"certificateDer"`
	ActivatedAt    time.Time  `json:"activatedAt"`
	RetiredAt      *time.Time `json:"retiredAt,omitempty"`
}

type auditVerificationKeyRecord struct {
	KeyID       string     `json:"keyId"`
	PublicKey   string     `json:"publicKey"`
	ActivatedAt time.Time  `json:"activatedAt"`
	RetiredAt   *time.Time `json:"retiredAt,omitempty"`
}

func newVerificationKeyring(deployment Deployment, certificate *x509.Certificate, auditPublicKey ed25519.PublicKey) verificationKeyring {
	return verificationKeyring{
		Version: verificationKeyringVersion,
		Authorities: []authorityVerificationKeyRecord{{
			KeyID: deployment.AuthorityKeyID, CertificateDER: base64.RawURLEncoding.EncodeToString(certificate.Raw), ActivatedAt: deployment.CreatedAt,
		}},
		AuditKeys: []auditVerificationKeyRecord{{
			KeyID: deployment.AuditKeyID, PublicKey: base64.RawURLEncoding.EncodeToString(auditPublicKey), ActivatedAt: deployment.CreatedAt,
		}},
	}
}

func encodeVerificationKeyring(keyring verificationKeyring) ([]byte, error) {
	encoded, err := json.MarshalIndent(keyring, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode identity verification keyring: %w", err)
	}
	return append(encoded, '\n'), nil
}

func verifyAndDecodeVerificationKeyring(
	deployment Deployment,
	currentCertificate *x509.Certificate,
	currentAuditPublicKey ed25519.PublicKey,
	content []byte,
) (map[string]ed25519.PublicKey, map[string]*x509.Certificate, error) {
	digest := sha256.Sum256(content)
	if !strings.EqualFold(deployment.VerificationKeyringHash, hex.EncodeToString(digest[:])) {
		return nil, nil, errors.New("identity verification keyring hash does not match signed deployment state")
	}
	var keyring verificationKeyring
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&keyring); err != nil {
		return nil, nil, fmt.Errorf("decode identity verification keyring: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, nil, errors.New("identity verification keyring has trailing JSON data")
		}
		return nil, nil, fmt.Errorf("decode trailing identity verification keyring data: %w", err)
	}
	if keyring.Version != verificationKeyringVersion {
		return nil, nil, fmt.Errorf("unsupported identity verification keyring version %d", keyring.Version)
	}
	if len(keyring.Authorities) == 0 || len(keyring.AuditKeys) == 0 {
		return nil, nil, errors.New("identity verification keyring must retain authority and audit keys")
	}

	authorityCertificates := make(map[string]*x509.Certificate, len(keyring.Authorities))
	activeAuthorities := 0
	for index, record := range keyring.Authorities {
		if record.KeyID == "" || record.ActivatedAt.IsZero() {
			return nil, nil, fmt.Errorf("authority verification key record %d is incomplete", index)
		}
		if _, exists := authorityCertificates[record.KeyID]; exists {
			return nil, nil, fmt.Errorf("authority verification key id %q is duplicated", record.KeyID)
		}
		certificateDER, err := base64.RawURLEncoding.DecodeString(record.CertificateDER)
		if err != nil {
			return nil, nil, fmt.Errorf("decode authority verification certificate %q: %w", record.KeyID, err)
		}
		certificate, err := x509.ParseCertificate(certificateDER)
		if err != nil {
			return nil, nil, fmt.Errorf("parse authority verification certificate %q: %w", record.KeyID, err)
		}
		if !certificate.IsCA || certificate.CheckSignatureFrom(certificate) != nil || !slices.Contains(certificate.Subject.Organization, deployment.DeploymentID) {
			return nil, nil, fmt.Errorf("authority verification certificate %q is not a coherent deployment CA", record.KeyID)
		}
		fingerprint, err := publicKeyFingerprint(certificate.PublicKey)
		if err != nil || record.KeyID != "ca:"+fingerprint {
			return nil, nil, fmt.Errorf("authority verification certificate %q has an invalid key id", record.KeyID)
		}
		if record.RetiredAt == nil {
			activeAuthorities++
			if record.KeyID != deployment.AuthorityKeyID || !bytes.Equal(certificate.Raw, currentCertificate.Raw) {
				return nil, nil, errors.New("active authority verification certificate does not match signed deployment state")
			}
		} else if !record.RetiredAt.After(record.ActivatedAt) {
			return nil, nil, fmt.Errorf("authority verification certificate %q has an invalid retirement time", record.KeyID)
		}
		authorityCertificates[record.KeyID] = certificate
	}
	if activeAuthorities != 1 {
		return nil, nil, errors.New("identity verification keyring must have exactly one active authority certificate")
	}

	auditVerificationKeys := make(map[string]ed25519.PublicKey, len(keyring.AuditKeys))
	activeAuditKeys := 0
	for index, record := range keyring.AuditKeys {
		if record.KeyID == "" || record.ActivatedAt.IsZero() {
			return nil, nil, fmt.Errorf("audit verification key record %d is incomplete", index)
		}
		if _, exists := auditVerificationKeys[record.KeyID]; exists {
			return nil, nil, fmt.Errorf("audit verification key id %q is duplicated", record.KeyID)
		}
		publicKey, err := base64.RawURLEncoding.DecodeString(record.PublicKey)
		if err != nil || len(publicKey) != ed25519.PublicKeySize {
			return nil, nil, fmt.Errorf("audit verification key %q is not Ed25519", record.KeyID)
		}
		fingerprint, err := publicKeyFingerprint(ed25519.PublicKey(publicKey))
		if err != nil || record.KeyID != "audit:"+fingerprint {
			return nil, nil, fmt.Errorf("audit verification key %q has an invalid key id", record.KeyID)
		}
		if record.RetiredAt == nil {
			activeAuditKeys++
			if record.KeyID != deployment.AuditKeyID || !bytes.Equal(publicKey, currentAuditPublicKey) {
				return nil, nil, errors.New("active audit verification key does not match signed deployment state")
			}
		} else if !record.RetiredAt.After(record.ActivatedAt) {
			return nil, nil, fmt.Errorf("audit verification key %q has an invalid retirement time", record.KeyID)
		}
		auditVerificationKeys[record.KeyID] = append(ed25519.PublicKey(nil), publicKey...)
	}
	if activeAuditKeys != 1 {
		return nil, nil, errors.New("identity verification keyring must have exactly one active audit key")
	}
	return auditVerificationKeys, authorityCertificates, nil
}
