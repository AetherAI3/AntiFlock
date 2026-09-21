// Package driver defines the frozen host-mutation boundary of the AntiFlock
// agent. This file is the capability probe seam: it is the only way a driver
// may report what it can do, and it is frozen by the integration controller
// (ANTIFL0CK-OSS-COMPLETION-02, 2026-08-23). Additive changes require a new
// ProbeSchemaVersion; field removal or renaming is not permitted.
//
// A ProbeResult is evidence produced by driver code running on the node. It is
// never accepted from a caller, a plan, a manifest file, or the network. The
// capability and readiness packages consume it; they do not construct it.
package driver

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"

	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
)

// ProbeSchemaVersion is the version of the ProbeResult digest layout. Consumers
// must reject results whose SchemaVersion they do not recognise.
const ProbeSchemaVersion uint32 = 1

// Bounds applied by Validate. They are deliberately small: a probe describes
// one capability of one driver, not a host inventory.
const (
	MaxProbeKeyLength        = 128
	MaxProbeIdentifierLength = 128
	MaxProbeReasonCodes      = 32
	MaxProbeConstraints      = 32
	MaxProbeConstraintLength = 256
	MaxProbeValidity         = 24 * time.Hour
)

// HealthStatus is the driver's own view of whether it can currently perform
// the capability it reports. It is independent of support level: a driver can
// fully support a capability and still be UNAVAILABLE right now.
type HealthStatus uint8

const (
	HealthUnknown HealthStatus = iota
	HealthHealthy
	HealthDegraded
	HealthUnavailable
)

// String returns the stable wire spelling of the health status.
func (status HealthStatus) String() string {
	switch status {
	case HealthHealthy:
		return "HEALTHY"
	case HealthDegraded:
		return "DEGRADED"
	case HealthUnavailable:
		return "UNAVAILABLE"
	default:
		return "UNKNOWN"
	}
}

// Reason codes shared by every driver. Drivers may add their own codes using
// the prefix "AF-DRIVER-<NAME>-"; they must not reuse these spellings for a
// different meaning.
const (
	ReasonProbeOK               = "AF-PROBE-OK"
	ReasonProbeTimeout          = "AF-PROBE-TIMEOUT"
	ReasonProbeNotImplemented   = "AF-PROBE-NOT-IMPLEMENTED"
	ReasonProbeBinaryMissing    = "AF-PROBE-BINARY-MISSING"
	ReasonProbeBinaryUntrusted  = "AF-PROBE-BINARY-UNTRUSTED"
	ReasonProbePrivilegeMissing = "AF-PROBE-PRIVILEGE-MISSING"
	ReasonProbePlatform         = "AF-PROBE-PLATFORM-UNSUPPORTED"
	ReasonProbeJournalMissing   = "AF-PROBE-JOURNAL-MISSING"
	ReasonProbeJournalCorrupt   = "AF-PROBE-JOURNAL-CORRUPT"
	ReasonProbeRecoveryMissing  = "AF-PROBE-RECOVERY-PATH-MISSING"
	ReasonProbeConflict         = "AF-PROBE-HOST-CONFLICT"
	ReasonProbeExpired          = "AF-PROBE-EXPIRED"
	ReasonProbeInvalid          = "AF-PROBE-INVALID"
)

// ProbeResult is the authenticated unit of capability discovery.
//
// Invariants (enforced by Validate):
//   - Key is a lower-case dotted identifier such as firewall.nftables.enforce.
//   - Operations are unique and never UNSPECIFIED.
//   - ProbedAt precedes ExpiresAt by at most MaxProbeValidity.
//   - Every string is printable ASCII; no control or format characters.
//   - A HealthUnavailable or HealthUnknown result cannot claim RecoveryReady.
type ProbeResult struct {
	SchemaVersion uint32
	Key           string
	Domain        antiflockv1.CapabilityDomain
	Operations    []antiflockv1.CapabilityOperation
	SupportLevel  antiflockv1.CapabilitySupportLevel
	DriverName    string
	DriverVersion string
	Health        HealthStatus
	RecoveryReady bool
	ReasonCodes   []string
	Constraints   []string
	ProbedAt      time.Time
	ExpiresAt     time.Time
}

// Prober is implemented by every driver. Probe must be read-only with respect
// to host state, must honour ctx, and must complete within the driver's
// declared bound. It reports what the driver observed, never what a caller
// asked it to report.
type Prober interface {
	Probe(ctx context.Context) ([]ProbeResult, error)
}

// ErrProbeInvalid wraps every validation failure so callers can fail closed on
// a single sentinel.
var ErrProbeInvalid = errors.New("driver probe result is invalid")

// Validate applies the ProbeResult invariants and returns a wrapped
// ErrProbeInvalid naming the first violation.
func (result ProbeResult) Validate() error {
	fail := func(format string, args ...any) error {
		return fmt.Errorf("%w: %s", ErrProbeInvalid, fmt.Sprintf(format, args...))
	}
	if result.SchemaVersion != ProbeSchemaVersion {
		return fail("schema version %d is not %d", result.SchemaVersion, ProbeSchemaVersion)
	}
	if !validKey(result.Key) {
		return fail("key is not a bounded lower-case dotted identifier")
	}
	if result.Domain == antiflockv1.CapabilityDomain_CAPABILITY_DOMAIN_UNSPECIFIED ||
		antiflockv1.CapabilityDomain_name[int32(result.Domain)] == "" {
		return fail("domain is unspecified or unknown")
	}
	if len(result.Operations) == 0 {
		return fail("at least one operation is required")
	}
	seen := make(map[antiflockv1.CapabilityOperation]struct{}, len(result.Operations))
	for _, operation := range result.Operations {
		if operation == antiflockv1.CapabilityOperation_CAPABILITY_OPERATION_UNSPECIFIED ||
			antiflockv1.CapabilityOperation_name[int32(operation)] == "" {
			return fail("operation is unspecified or unknown")
		}
		if _, duplicate := seen[operation]; duplicate {
			return fail("operation %s is duplicated", operation)
		}
		seen[operation] = struct{}{}
	}
	if result.SupportLevel == antiflockv1.CapabilitySupportLevel_CAPABILITY_SUPPORT_LEVEL_UNSPECIFIED ||
		antiflockv1.CapabilitySupportLevel_name[int32(result.SupportLevel)] == "" {
		return fail("support level is unspecified or unknown")
	}
	if !validIdentifier(result.DriverName) || !validIdentifier(result.DriverVersion) {
		return fail("driver name and version must be bounded printable identifiers")
	}
	if result.Health > HealthUnavailable {
		return fail("health status %d is unknown", result.Health)
	}
	if result.RecoveryReady && (result.Health == HealthUnavailable || result.Health == HealthUnknown) {
		return fail("recovery cannot be ready while health is %s", result.Health)
	}
	if len(result.ReasonCodes) == 0 || len(result.ReasonCodes) > MaxProbeReasonCodes {
		return fail("between 1 and %d reason codes are required", MaxProbeReasonCodes)
	}
	for _, code := range result.ReasonCodes {
		if !validReasonCode(code) {
			return fail("reason code is not a bounded AF- identifier")
		}
	}
	if len(result.Constraints) > MaxProbeConstraints {
		return fail("more than %d constraints", MaxProbeConstraints)
	}
	for _, constraint := range result.Constraints {
		if constraint == "" || len(constraint) > MaxProbeConstraintLength || !printableASCII(constraint) {
			return fail("constraint is empty, oversized, or not printable ASCII")
		}
	}
	if result.ProbedAt.IsZero() || result.ExpiresAt.IsZero() {
		return fail("probed-at and expires-at are required")
	}
	if !result.ExpiresAt.After(result.ProbedAt) {
		return fail("expires-at must follow probed-at")
	}
	if result.ExpiresAt.Sub(result.ProbedAt) > MaxProbeValidity {
		return fail("validity exceeds %s", MaxProbeValidity)
	}
	return nil
}

// Expired reports whether the result is no longer current at now.
func (result ProbeResult) Expired(now time.Time) bool {
	return !now.Before(result.ExpiresAt)
}

// Digest returns the deterministic SHA-256 digest of the result. Two results
// with the same observable content produce the same digest regardless of slice
// ordering of operations, reason codes, or constraints. The digest is the
// identity consumers bind into manifests and receipts.
func (result ProbeResult) Digest() (string, error) {
	if err := result.Validate(); err != nil {
		return "", err
	}
	hash := sha256.New()
	write := func(value []byte) {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(value)))
		hash.Write(length[:])
		hash.Write(value)
	}
	writeString := func(value string) { write([]byte(value)) }
	writeUint := func(value uint64) {
		var buffer [8]byte
		binary.BigEndian.PutUint64(buffer[:], value)
		write(buffer[:])
	}
	writeString("AntiFlock-DriverProbe-v1")
	writeUint(uint64(result.SchemaVersion))
	writeString(result.Key)
	writeUint(uint64(result.Domain))
	operations := slices.Clone(result.Operations)
	slices.Sort(operations)
	writeUint(uint64(len(operations)))
	for _, operation := range operations {
		writeUint(uint64(operation))
	}
	writeUint(uint64(result.SupportLevel))
	writeString(result.DriverName)
	writeString(result.DriverVersion)
	writeUint(uint64(result.Health))
	if result.RecoveryReady {
		writeUint(1)
	} else {
		writeUint(0)
	}
	codes := slices.Clone(result.ReasonCodes)
	slices.Sort(codes)
	writeUint(uint64(len(codes)))
	for _, code := range codes {
		writeString(code)
	}
	constraints := slices.Clone(result.Constraints)
	slices.Sort(constraints)
	writeUint(uint64(len(constraints)))
	for _, constraint := range constraints {
		writeString(constraint)
	}
	writeUint(uint64(result.ProbedAt.UTC().Unix()))
	writeUint(uint64(result.ProbedAt.UTC().Nanosecond()))
	writeUint(uint64(result.ExpiresAt.UTC().Unix()))
	writeUint(uint64(result.ExpiresAt.UTC().Nanosecond()))
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func validKey(value string) bool {
	if value == "" || len(value) > MaxProbeKeyLength || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") || strings.Contains(value, "..") {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

func validIdentifier(value string) bool {
	if value == "" || len(value) > MaxProbeIdentifierLength || !printableASCII(value) {
		return false
	}
	return !strings.ContainsAny(value, " \t")
}

func validReasonCode(value string) bool {
	if !strings.HasPrefix(value, "AF-") || len(value) > MaxProbeIdentifierLength {
		return false
	}
	for _, r := range value {
		if !(r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}

func printableASCII(value string) bool {
	for _, r := range value {
		if r > unicode.MaxASCII || !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}
