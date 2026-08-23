package integration

import (
	"context"
	"fmt"
	"time"
)

// EvidenceClass mirrors docs/evidence-model.md. A sink receives the class
// core assigned and must never relabel it.
type EvidenceClass string

// Evidence classes accepted across the seams.
const (
	EvidenceDetected  EvidenceClass = "DETECTED"
	EvidenceVerified  EvidenceClass = "VERIFIED"
	EvidenceReported  EvidenceClass = "REPORTED"
	EvidenceInferred  EvidenceClass = "INFERRED"
	EvidenceSuspected EvidenceClass = "SUSPECTED"
	EvidenceUnknown   EvidenceClass = "UNKNOWN"
)

// ValidEvidenceClass reports whether class is one of the documented classes.
func ValidEvidenceClass(class EvidenceClass) bool {
	switch class {
	case EvidenceDetected, EvidenceVerified, EvidenceReported, EvidenceInferred, EvidenceSuspected, EvidenceUnknown:
		return true
	}
	return false
}

// MaxEventBatch bounds one EmitBatch call.
const MaxEventBatch = 256

// Event is the privacy-minimal projection of a core event that an EventSink
// receives. It carries classification and references, never content.
//
// Privacy rule: no payload, no node id, no labels, no addresses. The trust
// envelope (internal/trust) and the event body are referenced by digest only;
// a consumer that needs more must obtain it through an authorized core API.
// The field set is pinned by TestEventFieldAllowlist.
//
// InterfaceVersion = 1.
type Event struct {
	// ID is the core event identifier.
	ID string
	// Kind is the registered event kind (for example "network.route_changed").
	Kind string
	// EvidenceClass is the class core assigned.
	EvidenceClass EvidenceClass
	// OccurredAt is the event time core recorded.
	OccurredAt time.Time
	// TrustEnvelopeDigest is the hex SHA-256 of the trust envelope that
	// classified this event, or empty when no envelope was attached.
	TrustEnvelopeDigest string
	// PayloadDigest is the hex SHA-256 of the canonical event body.
	PayloadDigest string
}

// Validate reports whether the event satisfies the seam contract.
func (event Event) Validate() error {
	switch {
	case !ValidIdentifier(event.ID):
		return fmt.Errorf("%w: event id must be a canonical identifier", ErrInvalidInput)
	case !ValidIdentifier(event.Kind):
		return fmt.Errorf("%w: event kind must be a canonical identifier", ErrInvalidInput)
	case !ValidEvidenceClass(event.EvidenceClass):
		return fmt.Errorf("%w: event evidence class is not recognised", ErrInvalidInput)
	case event.OccurredAt.IsZero():
		return fmt.Errorf("%w: event time is required", ErrInvalidInput)
	case event.TrustEnvelopeDigest != "" && !ValidDigest(event.TrustEnvelopeDigest):
		return fmt.Errorf("%w: trust envelope digest must be a hex SHA-256", ErrInvalidInput)
	case !ValidDigest(event.PayloadDigest):
		return fmt.Errorf("%w: payload digest must be a hex SHA-256", ErrInvalidInput)
	}
	return nil
}

// ValidateBatch validates a bounded batch.
func ValidateBatch(events []Event) error {
	if len(events) == 0 {
		return fmt.Errorf("%w: event batch is empty", ErrInvalidInput)
	}
	if len(events) > MaxEventBatch {
		return fmt.Errorf("%w: %d events exceed %d", ErrBatchTooLarge, len(events), MaxEventBatch)
	}
	for index, event := range events {
		if err := event.Validate(); err != nil {
			return fmt.Errorf("event %d: %w", index, err)
		}
	}
	return nil
}

// EventSink receives classified event references for external processing
// (dashboards, SIEM forwarding, archival).
//
// Guarantees: Emit is called only with an Event that passes Validate;
// EmitBatch only with a batch that passes ValidateBatch (at most
// MaxEventBatch). Delivery is at-least-once: a sink must tolerate duplicate
// IDs. A sink never acknowledges an event it did not durably accept.
//
// Failure semantics: on error nothing in the call is considered delivered; a
// wrapped ErrUnavailable allows retry of the same call; a wrapped
// ErrBatchTooLarge means the caller must split the batch. Sink failure never
// blocks local detection or enforcement.
//
// Privacy rule: see Event.
//
// InterfaceVersion = 1.
type EventSink interface {
	Emit(ctx context.Context, event Event) error
	EmitBatch(ctx context.Context, events []Event) error
}
