package integration

import (
	"context"
	"fmt"
	"time"
)

// FindingSeverity mirrors the finding severity ladder in core/findings.
type FindingSeverity string

// FindingStatus mirrors the finding lifecycle in core/findings.
type FindingStatus string

// Severities and statuses accepted in a FindingSummary.
const (
	SeverityInformational FindingSeverity = "INFORMATIONAL"
	SeverityLow           FindingSeverity = "LOW"
	SeverityMedium        FindingSeverity = "MEDIUM"
	SeverityHigh          FindingSeverity = "HIGH"
	SeverityCritical      FindingSeverity = "CRITICAL"

	StatusOpen         FindingStatus = "OPEN"
	StatusAcknowledged FindingStatus = "ACKNOWLEDGED"
	StatusResolved     FindingStatus = "RESOLVED"
	StatusDismissed    FindingStatus = "DISMISSED"
	StatusSuppressed   FindingStatus = "SUPPRESSED_BY_EXCEPTION"
)

func validSeverity(severity FindingSeverity) bool {
	switch severity {
	case SeverityInformational, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return true
	}
	return false
}

func validStatus(status FindingStatus) bool {
	switch status {
	case StatusOpen, StatusAcknowledged, StatusResolved, StatusDismissed, StatusSuppressed:
		return true
	}
	return false
}

// FindingSummary is the only finding projection a FindingSink receives:
// identity, severity, lifecycle, evidence class, and a digest of the full
// record. Title, condition, facts, node, policy, and rule identifiers stay in
// core.
//
// Privacy rule: the field set is pinned by TestFindingSummaryFieldAllowlist.
//
// InterfaceVersion = 1.
type FindingSummary struct {
	ID            string
	Severity      FindingSeverity
	Status        FindingStatus
	EvidenceClass EvidenceClass
	// Digest is the hex SHA-256 of the canonical full finding record at this
	// revision, so a consumer can later prove which record it saw.
	Digest    string
	UpdatedAt time.Time
}

// Validate reports whether the summary satisfies the seam contract.
func (summary FindingSummary) Validate() error {
	switch {
	case !ValidIdentifier(summary.ID):
		return fmt.Errorf("%w: finding id must be a canonical identifier", ErrInvalidInput)
	case !validSeverity(summary.Severity):
		return fmt.Errorf("%w: finding severity is not recognised", ErrInvalidInput)
	case !validStatus(summary.Status):
		return fmt.Errorf("%w: finding status is not recognised", ErrInvalidInput)
	case !ValidEvidenceClass(summary.EvidenceClass):
		return fmt.Errorf("%w: finding evidence class is not recognised", ErrInvalidInput)
	case !ValidDigest(summary.Digest):
		return fmt.Errorf("%w: finding digest must be a hex SHA-256", ErrInvalidInput)
	case summary.UpdatedAt.IsZero():
		return fmt.Errorf("%w: finding update time is required", ErrInvalidInput)
	}
	return nil
}

// FindingSink receives finding lifecycle summaries.
//
// Guarantees: Publish is called only with a FindingSummary that passes
// Validate. Publication is at-least-once and may arrive out of order; the
// sink keys on ID and keeps the latest UpdatedAt. A sink never changes a
// severity, status, or evidence class.
//
// Failure semantics: on error the summary is considered undelivered; a
// wrapped ErrUnavailable allows retry. Sink failure never blocks core.
//
// Privacy rule: see FindingSummary.
//
// InterfaceVersion = 1.
type FindingSink interface {
	Publish(ctx context.Context, summary FindingSummary) error
}
