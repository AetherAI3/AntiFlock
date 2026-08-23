package integration

import (
	"context"
	"fmt"
	"time"
)

// RecoveryOperation names the enforcement transition whose recovery path is
// being checked.
type RecoveryOperation string

// Recovery operations accepted in a RecoveryClaim.
const (
	RecoveryAfterApply    RecoveryOperation = "apply"
	RecoveryAfterRollback RecoveryOperation = "rollback"
)

// VerdictClass is the evidence class of a RecoveryVerdict. It is a two-value
// subset of the evidence model: OBSERVED corresponds to DETECTED (the
// verifier itself reached the node) and REPORTED means the verifier relays a
// third party's statement.
type VerdictClass string

// Verdict classes.
const (
	VerdictObserved VerdictClass = "OBSERVED"
	VerdictReported VerdictClass = "REPORTED"
)

func validVerdictClass(class VerdictClass) bool {
	return class == VerdictObserved || class == VerdictReported
}

// RecoveryClaim asks an out-of-band party whether a node is still reachable
// via its recovery path after an enforcement transition. The claim carries a
// fresh nonce so a verdict cannot be replayed for a later transition.
//
// Privacy rule: node and deployment are referenced by digest; the recovery
// path is referenced by the digest of its policy entry, never by address. The
// field set is pinned by TestRecoveryClaimFieldAllowlist.
//
// InterfaceVersion = 1.
type RecoveryClaim struct {
	DeploymentDigest string
	NodeDigest       string
	// RecoveryPathDigest is the hex SHA-256 of the policy recovery
	// destination entry the node is expected to remain reachable through.
	RecoveryPathDigest string
	Operation          RecoveryOperation
	ClaimedAt          time.Time
	// Nonce is a hex SHA-256-sized random value chosen by core per claim.
	Nonce string
}

// Validate reports whether the claim satisfies the seam contract.
func (claim RecoveryClaim) Validate() error {
	switch {
	case !ValidDigest(claim.DeploymentDigest):
		return fmt.Errorf("%w: recovery claim deployment digest must be a hex SHA-256", ErrInvalidInput)
	case !ValidDigest(claim.NodeDigest):
		return fmt.Errorf("%w: recovery claim node digest must be a hex SHA-256", ErrInvalidInput)
	case !ValidDigest(claim.RecoveryPathDigest):
		return fmt.Errorf("%w: recovery path digest must be a hex SHA-256", ErrInvalidInput)
	case claim.Operation != RecoveryAfterApply && claim.Operation != RecoveryAfterRollback:
		return fmt.Errorf("%w: recovery operation is not recognised", ErrInvalidInput)
	case claim.ClaimedAt.IsZero():
		return fmt.Errorf("%w: recovery claim time is required", ErrInvalidInput)
	case !ValidDigest(claim.Nonce):
		return fmt.Errorf("%w: recovery claim nonce must be 32 hex bytes", ErrInvalidInput)
	}
	return nil
}

// RecoveryVerdict is evidence about reachability. It is never authorization:
// core decides what to do with it under its own policy, and a verdict cannot
// approve, apply, or roll back anything.
//
// InterfaceVersion = 1.
type RecoveryVerdict struct {
	// VerifierID is the verifier's self-chosen canonical identifier.
	VerifierID string
	// Nonce echoes the claim nonce so the verdict binds to one claim.
	Nonce string
	// Class states how the verifier knows: OBSERVED or REPORTED.
	Class VerdictClass
	// Reachable is the verifier's statement.
	Reachable bool
	// ObservedAt is the verifier's clock reading.
	ObservedAt time.Time
}

// Validate reports whether the verdict satisfies the seam contract for claim.
func (verdict RecoveryVerdict) Validate(claim RecoveryClaim) error {
	switch {
	case !ValidIdentifier(verdict.VerifierID):
		return fmt.Errorf("%w: recovery verifier id must be a canonical identifier", ErrInvalidInput)
	case verdict.Nonce != claim.Nonce:
		return fmt.Errorf("%w: recovery verdict does not echo the claim nonce", ErrInvalidInput)
	case !validVerdictClass(verdict.Class):
		return fmt.Errorf("%w: recovery verdict class must be OBSERVED or REPORTED", ErrInvalidInput)
	case verdict.ObservedAt.IsZero():
		return fmt.Errorf("%w: recovery verdict observation time is required", ErrInvalidInput)
	}
	return nil
}

// RecoveryVerifier confirms, from outside the node, that a recovery path
// still works after an enforcement apply or rollback.
//
// Guarantees: VerifyRecovery is called only with a RecoveryClaim that passes
// Validate. A returned verdict passes RecoveryVerdict.Validate for that claim
// and echoes its nonce. The verifier never receives, and never returns,
// anything that authorizes an enforcement change.
//
// Failure semantics: a wrapped ErrUnavailable means no verdict could be
// formed and the caller treats reachability as UNKNOWN; any other error is a
// permanent refusal for that claim. Core never converts a missing verdict
// into "reachable".
//
// Privacy rule: see RecoveryClaim.
//
// InterfaceVersion = 1.
type RecoveryVerifier interface {
	VerifyRecovery(ctx context.Context, claim RecoveryClaim) (RecoveryVerdict, error)
}
