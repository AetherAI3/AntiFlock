package integration

import (
	"context"
	"fmt"
)

// MaxPolicyPayload bounds a SignedPolicy payload. It matches the wire limit
// core/policy enforces on a protection profile.
const MaxPolicyPayload = 256 * 1024

// PolicyRef names one revision of one policy.
//
// InterfaceVersion = 1.
type PolicyRef struct {
	// ID is the policy identifier (a canonical identifier).
	ID string
	// Revision is the positive policy revision.
	Revision uint64
}

// Validate reports whether the reference satisfies the seam contract.
func (ref PolicyRef) Validate() error {
	if !ValidIdentifier(ref.ID) {
		return fmt.Errorf("%w: policy id must be a canonical identifier", ErrInvalidInput)
	}
	if ref.Revision == 0 {
		return fmt.Errorf("%w: policy revision must be positive", ErrInvalidInput)
	}
	return nil
}

// SignedPolicy is opaque signed policy material. The source returns bytes, a
// signature, and a key id; it never interprets or verifies them. Verification
// (signature under a key core trusts, then core/policy validation of the
// decoded profile) happens in core after Fetch returns.
//
// InterfaceVersion = 1.
type SignedPolicy struct {
	Ref PolicyRef
	// Payload is the encoded policy (at most MaxPolicyPayload bytes).
	Payload []byte
	// Signature is the producer's signature over Payload, in the producer's
	// signing contract (docs/signing-contracts.md). The source does not check it.
	Signature []byte
	// KeyID names the signing key. Core resolves it against its own keyring;
	// an unknown key id fails closed.
	KeyID string
}

// Validate reports whether the signed policy satisfies the seam's shape
// contract. It does not verify the signature.
func (policy SignedPolicy) Validate() error {
	if err := policy.Ref.Validate(); err != nil {
		return err
	}
	switch {
	case len(policy.Payload) == 0 || len(policy.Payload) > MaxPolicyPayload:
		return fmt.Errorf("%w: policy payload must be non-empty and at most %d bytes", ErrInvalidInput, MaxPolicyPayload)
	case len(policy.Signature) == 0 || len(policy.Signature) > 1024:
		return fmt.Errorf("%w: policy signature must be non-empty and bounded", ErrInvalidInput)
	case !ValidIdentifier(policy.KeyID):
		return fmt.Errorf("%w: policy key id must be a canonical identifier", ErrInvalidInput)
	}
	return nil
}

// Clone returns a deep copy so a caller can never share buffers with the
// source.
func (policy SignedPolicy) Clone() SignedPolicy {
	return SignedPolicy{
		Ref: policy.Ref, KeyID: policy.KeyID,
		Payload:   append([]byte(nil), policy.Payload...),
		Signature: append([]byte(nil), policy.Signature...),
	}
}

// PolicySource delivers signed policy material from outside core.
//
// Guarantees: Fetch is called only with a PolicyRef that passes Validate and
// returns a SignedPolicy that passes Validate whose Ref equals the request.
// Returned buffers are owned by the caller. Watch returns a channel that
// delivers references the source believes are new; the channel is closed when
// ctx is done. Watch notifications are hints: core always Fetches and
// verifies before acting on one.
//
// Failure semantics: a wrapped ErrNotFound means the reference does not
// exist at the source; a wrapped ErrUnavailable allows retry; any other error
// is permanent for that reference. A source never returns partial material.
//
// Privacy rule: the source learns which policy id and revision were
// requested and nothing about the deployment that asked.
//
// InterfaceVersion = 1.
type PolicySource interface {
	Fetch(ctx context.Context, ref PolicyRef) (SignedPolicy, error)
	Watch(ctx context.Context) (<-chan PolicyRef, error)
}
