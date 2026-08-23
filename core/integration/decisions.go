package integration

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"time"
)

// DecisionKeyPrefix prefixes every decision KeyID (see KeyID).
const DecisionKeyPrefix = "decision"

// DecisionType mirrors the protected-action decision ladder in core/actions.
type DecisionType string

// Decision types accepted in a Decision.
const (
	DecisionAllow DecisionType = "ALLOW"
	DecisionHold  DecisionType = "HOLD"
	DecisionBlock DecisionType = "BLOCK"
)

// MaxReasonCodes bounds the reason codes on a Decision.
const MaxReasonCodes = 32

func validDecisionType(kind DecisionType) bool {
	switch kind {
	case DecisionAllow, DecisionHold, DecisionBlock:
		return true
	}
	return false
}

// Decision is a signed record of one protected-action decision made by the
// core/actions gate. It is delivered to a DecisionConsumer by value and
// carries its own digest and signature, so a consumer can neither alter it
// nor forge one: any change invalidates DecisionDigest and the signature.
//
// Privacy rule: the action, node, and application are referenced by digest
// only. Destinations, request bodies, and snapshots never cross the seam.
//
// InterfaceVersion = 1.
type Decision struct {
	// DecisionID is the core decision identifier.
	DecisionID string
	// ActionDigest is DigestString of the action id the decision answers.
	ActionDigest string
	// NodeDigest is DigestString of the node the action originated from.
	NodeDigest string
	// Type is the decision outcome.
	Type DecisionType
	// ReasonCodes are the sorted, unique AF-* reason codes.
	ReasonCodes []string
	// IssuedAt and ExpiresAt bound the decision's validity. ExpiresAt is zero
	// for decisions that do not expire.
	IssuedAt  time.Time
	ExpiresAt time.Time
	// DecisionDigest is ComputeDecisionDigest of the fields above.
	DecisionDigest string
	// KeyID is KeyID(DecisionKeyPrefix, publicKey) of the signing key.
	KeyID string
	// Signature is the Ed25519 signature over DecisionDigest.
	Signature []byte
}

// validateShape checks every field except digest and signature.
func (decision Decision) validateShape() error {
	switch {
	case !ValidIdentifier(decision.DecisionID):
		return fmt.Errorf("%w: decision id must be a canonical identifier", ErrInvalidInput)
	case !ValidDigest(decision.ActionDigest):
		return fmt.Errorf("%w: decision action digest must be a hex SHA-256", ErrInvalidInput)
	case !ValidDigest(decision.NodeDigest):
		return fmt.Errorf("%w: decision node digest must be a hex SHA-256", ErrInvalidInput)
	case !validDecisionType(decision.Type):
		return fmt.Errorf("%w: decision type is not recognised", ErrInvalidInput)
	case !validStringList(decision.ReasonCodes, MaxReasonCodes):
		return fmt.Errorf("%w: decision reason codes must be sorted, unique, bounded identifiers", ErrInvalidInput)
	case decision.IssuedAt.IsZero():
		return fmt.Errorf("%w: decision issue time is required", ErrInvalidInput)
	case !decision.ExpiresAt.IsZero() && !decision.ExpiresAt.After(decision.IssuedAt):
		return fmt.Errorf("%w: decision expiry must follow issue time", ErrInvalidInput)
	}
	return nil
}

// ComputeDecisionDigest returns the canonical digest of the decision's
// content fields. Signature, KeyID, and DecisionDigest are excluded.
func ComputeDecisionDigest(decision Decision) (string, error) {
	if err := decision.validateShape(); err != nil {
		return "", err
	}
	expires := ""
	if !decision.ExpiresAt.IsZero() {
		expires = canonicalTime(decision.ExpiresAt)
	}
	encoded, err := canonicalJSON(struct {
		Version      int      `json:"version"`
		DecisionID   string   `json:"decisionId"`
		ActionDigest string   `json:"actionDigest"`
		NodeDigest   string   `json:"nodeDigest"`
		Type         string   `json:"type"`
		ReasonCodes  []string `json:"reasonCodes"`
		IssuedAt     string   `json:"issuedAt"`
		ExpiresAt    string   `json:"expiresAt"`
	}{
		InterfaceVersion, decision.DecisionID, decision.ActionDigest, decision.NodeDigest,
		string(decision.Type), append([]string{}, decision.ReasonCodes...), canonicalTime(decision.IssuedAt), expires,
	})
	if err != nil {
		return "", err
	}
	return Digest(encoded), nil
}

// SignDecision fills DecisionDigest, KeyID, and Signature.
func SignDecision(decision Decision, privateKey ed25519.PrivateKey) (Decision, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return Decision{}, fmt.Errorf("%w: decision signing key must be Ed25519", ErrInvalidInput)
	}
	digest, err := ComputeDecisionDigest(decision)
	if err != nil {
		return Decision{}, err
	}
	keyID, err := KeyID(DecisionKeyPrefix, privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		return Decision{}, err
	}
	decision.ReasonCodes = append([]string(nil), decision.ReasonCodes...)
	decision.DecisionDigest = digest
	decision.KeyID = keyID
	decision.Signature = ed25519.Sign(privateKey, []byte(digest))
	return decision, nil
}

// VerifyDecision checks the digest binding and the signature under publicKey.
func VerifyDecision(decision Decision, publicKey ed25519.PublicKey) error {
	if len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: decision public key must be Ed25519", ErrInvalidInput)
	}
	digest, err := ComputeDecisionDigest(decision)
	if err != nil {
		return err
	}
	if decision.DecisionDigest != digest {
		return fmt.Errorf("%w: decision digest does not match content", ErrInvalidSignature)
	}
	expectedKeyID, err := KeyID(DecisionKeyPrefix, publicKey)
	if err != nil {
		return err
	}
	if decision.KeyID != expectedKeyID {
		return fmt.Errorf("%w: decision key id does not name the verification key", ErrInvalidSignature)
	}
	if len(decision.Signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, []byte(digest), decision.Signature) {
		return fmt.Errorf("%w: decision signature does not verify", ErrInvalidSignature)
	}
	return nil
}

// DecisionConsumer receives signed protected-action decisions for external
// processing (ticketing, notification, archival).
//
// Guarantees: Consume is called only with a Decision that verifies under the
// deployment's decision key (VerifyDecision). The consumer receives a value
// copy; nothing it does can change the decision core holds or its digest.
// Delivery is at-least-once, keyed on DecisionID.
//
// Failure semantics: on error the decision is considered undelivered; a
// wrapped ErrUnavailable allows retry. A consumer that detects a digest or
// signature mismatch returns a wrapped ErrInvalidSignature and records
// nothing. Consumer failure never changes the decision outcome.
//
// Privacy rule: see Decision.
//
// InterfaceVersion = 1.
type DecisionConsumer interface {
	Consume(ctx context.Context, decision Decision) error
}
