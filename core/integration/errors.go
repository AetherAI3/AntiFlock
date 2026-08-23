package integration

import "errors"

// Sentinel errors shared by every seam. Adapters wrap these so callers can
// branch with errors.Is without depending on adapter-specific types.
var (
	// ErrInvalidInput marks a value that failed validation before or inside an
	// adapter call. The operation was not attempted.
	ErrInvalidInput = errors.New("integration: invalid input")
	// ErrUnavailable marks a transient transport or remote failure. The
	// operation may be retried with the same input.
	ErrUnavailable = errors.New("integration: remote unavailable")
	// ErrNotFound marks a reference the adapter does not know.
	ErrNotFound = errors.New("integration: not found")
	// ErrUnauthenticated marks a credential the identity provider rejected.
	ErrUnauthenticated = errors.New("integration: unauthenticated")
	// ErrInvalidReceipt marks a witness receipt whose signature, key id, or
	// digest binding does not verify.
	ErrInvalidReceipt = errors.New("integration: invalid witness receipt")
	// ErrInvalidSignature marks a signed record whose signature does not
	// verify under the supplied public key.
	ErrInvalidSignature = errors.New("integration: invalid signature")
	// ErrBatchTooLarge marks a batch exceeding MaxEventBatch.
	ErrBatchTooLarge = errors.New("integration: batch too large")
	// ErrVersionMismatch marks a registration for a different InterfaceVersion.
	ErrVersionMismatch = errors.New("integration: interface version mismatch")
	// ErrUnknownIntegration marks a Resolve for a name that was never registered.
	ErrUnknownIntegration = errors.New("integration: unknown integration")
	// ErrDuplicateIntegration marks a second Register for the same name.
	ErrDuplicateIntegration = errors.New("integration: duplicate integration")
	// ErrKindMismatch marks a Resolve whose requested Kind differs from the
	// registered Kind, or a factory that produced a value of the wrong type.
	ErrKindMismatch = errors.New("integration: kind mismatch")
)
