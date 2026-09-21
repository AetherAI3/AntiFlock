package integration

import (
	"context"
	"fmt"
	"time"
)

// CredentialKind names a generic credential shape. No provider-specific
// protocol (OAuth flows, token introspection endpoints, SAML assertions) is
// part of the seam; an adapter maps its provider onto one of these kinds.
type CredentialKind string

const (
	// CredentialBearer is an opaque bearer secret presented by a caller.
	CredentialBearer CredentialKind = "bearer"
	// CredentialCertificateFingerprint is the hex SHA-256 of the DER leaf
	// certificate a caller presented over mTLS. Core has already verified the
	// chain; the provider only maps the fingerprint to a principal.
	CredentialCertificateFingerprint CredentialKind = "mtls-cert-fingerprint"
)

// MaxCredentialLength bounds a credential value.
const MaxCredentialLength = 4096

// MaxScopes bounds the scopes on a Principal.
const MaxScopes = 64

// Credential is what a caller presented. It is the one value crossing any
// seam that may contain a secret, and it is handed only to the
// IdentityProvider that authenticates it.
//
// InterfaceVersion = 1.
type Credential struct {
	Kind CredentialKind
	// Value is the bearer secret or the certificate fingerprint. It is never
	// logged: String redacts it.
	Value string
}

// String redacts the credential value.
func (credential Credential) String() string {
	return fmt.Sprintf("Credential{Kind:%s Value:<redacted>}", credential.Kind)
}

// Validate reports whether the credential satisfies the seam contract.
func (credential Credential) Validate() error {
	switch credential.Kind {
	case CredentialBearer:
		if !ValidIdentifierLen(credential.Value, MaxCredentialLength) {
			return fmt.Errorf("%w: bearer credential must be a canonical bounded secret", ErrInvalidInput)
		}
	case CredentialCertificateFingerprint:
		if !ValidDigest(credential.Value) {
			return fmt.Errorf("%w: certificate fingerprint must be a hex SHA-256", ErrInvalidInput)
		}
	default:
		return fmt.Errorf("%w: credential kind %q is not recognised", ErrInvalidInput, string(credential.Kind))
	}
	return nil
}

// Principal is the authenticated identity an IdentityProvider returns.
//
// Privacy rule: SubjectDigest is a one-way reference; the provider never
// returns a username, email, or display name across the seam.
//
// InterfaceVersion = 1.
type Principal struct {
	// SubjectDigest is DigestString of the provider's stable subject
	// identifier.
	SubjectDigest string
	// Scopes are sorted, unique, canonical scope identifiers. Core maps them
	// to its own authorization; the provider never decides what a scope
	// permits.
	Scopes []string
	// ExpiresAt is when the authentication stops being valid.
	ExpiresAt time.Time
}

// Validate reports whether the principal satisfies the seam contract.
func (principal Principal) Validate(now time.Time) error {
	switch {
	case !ValidDigest(principal.SubjectDigest):
		return fmt.Errorf("%w: principal subject digest must be a hex SHA-256", ErrInvalidInput)
	case !validStringList(principal.Scopes, MaxScopes):
		return fmt.Errorf("%w: principal scopes must be sorted, unique, bounded identifiers", ErrInvalidInput)
	case principal.ExpiresAt.IsZero() || !principal.ExpiresAt.After(now):
		return fmt.Errorf("%w: principal must expire in the future", ErrInvalidInput)
	}
	return nil
}

// IdentityProvider authenticates a generic credential into a Principal.
//
// Guarantees: Authenticate is called only with a Credential that passes
// Validate. A returned Principal passes Principal.Validate at the time of the
// call. The provider performs authentication only; authorization stays in
// core.
//
// Failure semantics: a wrapped ErrUnauthenticated means the credential is not
// valid and must not be retried unchanged; a wrapped ErrUnavailable means the
// provider could not decide and the caller fails closed (treat as
// unauthenticated) but may retry. Any other error is treated as
// unauthenticated.
//
// Privacy rule: the provider receives the credential and nothing about the
// request it authenticates; it returns a subject digest, scopes, and an
// expiry, and nothing that identifies a person.
//
// InterfaceVersion = 1.
type IdentityProvider interface {
	Authenticate(ctx context.Context, credential Credential) (Principal, error)
}
