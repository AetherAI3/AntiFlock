package capability

// Reason codes emitted by this package. Codes are stable identifiers: their
// spelling is part of the agent's external contract and must never be reused
// for a different meaning. Every code must have an entry in ReasonCodes; a
// test enforces that.
const (
	// Readiness verdict codes.
	ReasonOK                 = "AF-CAP-OK"
	ReasonMissing            = "AF-CAP-MISSING"
	ReasonSupportLevel       = "AF-CAP-SUPPORT-LEVEL"
	ReasonOperationMissing   = "AF-CAP-OPERATION-MISSING"
	ReasonExpired            = "AF-CAP-EXPIRED"
	ReasonNotYetValid        = "AF-CAP-NOT-YET-VALID"
	ReasonHealthUnknown      = "AF-CAP-HEALTH-UNKNOWN"
	ReasonHealthDegraded     = "AF-CAP-HEALTH-DEGRADED"
	ReasonHealthUnavailable  = "AF-CAP-HEALTH-UNAVAILABLE"
	ReasonRecoveryNotReady   = "AF-CAP-RECOVERY-NOT-READY"
	ReasonRequirementInvalid = "AF-CAP-REQUIREMENT-INVALID"

	// Authentication and schema codes (loader and evaluator).
	ReasonNodeMismatch     = "AF-CAP-NODE-MISMATCH"
	ReasonSignatureInvalid = "AF-CAP-SIGNATURE-INVALID"
	ReasonSchema           = "AF-CAP-SCHEMA"
	ReasonOptionsInvalid   = "AF-CAP-OPTIONS-INVALID"

	// Discovery codes.
	ReasonDuplicateKey   = "AF-CAP-DUPLICATE-KEY"
	ReasonDriverMismatch = "AF-CAP-DRIVER-MISMATCH"
	ReasonProbeFailed    = "AF-CAP-PROBE-FAILED"
	ReasonProbeTimeout   = "AF-CAP-PROBE-TIMEOUT"
	ReasonProbeInvalid   = "AF-CAP-PROBE-INVALID"
	ReasonNoCapabilities = "AF-CAP-NO-CAPABILITIES"

	// Loader codes.
	ReasonFileOpen            = "AF-CAP-FILE-OPEN"
	ReasonFileType            = "AF-CAP-FILE-TYPE"
	ReasonFilePermissions     = "AF-CAP-FILE-PERMISSIONS"
	ReasonFileOversize        = "AF-CAP-FILE-OVERSIZE"
	ReasonFileChanged         = "AF-CAP-FILE-CHANGED"
	ReasonJSONSyntax          = "AF-CAP-JSON-SYNTAX"
	ReasonJSONTrailing        = "AF-CAP-JSON-TRAILING"
	ReasonJSONUnknownField    = "AF-CAP-JSON-UNKNOWN-FIELD"
	ReasonJSONDuplicateKey    = "AF-CAP-JSON-DUPLICATE-KEY"
	ReasonJSONNesting         = "AF-CAP-JSON-NESTING"
	ReasonJSONString          = "AF-CAP-JSON-STRING"
	ReasonPlatformUnsupported = "AF-CAP-PLATFORM-UNSUPPORTED"
)

// ReasonDescription documents one reason code.
type ReasonDescription struct {
	Code    string
	Meaning string
	// FailsClosed is true when the code is only ever attached to a negative
	// verdict or an error. ReasonOK is the single code that is not.
	FailsClosed bool
}

// ReasonCodes returns the documented table of every code this package emits,
// in stable order. It is the source of truth for operator documentation.
func ReasonCodes() []ReasonDescription {
	return []ReasonDescription{
		{ReasonOK, "The requirement is satisfied on every axis: compatible, driver healthy and current, recovery ready.", false},
		{ReasonMissing, "No manifest entry has the requirement's key.", true},
		{ReasonSupportLevel, "The entry's support level does not satisfy the requirement's minimum support level.", true},
		{ReasonOperationMissing, "The entry does not list every operation the requirement demands.", true},
		{ReasonExpired, "The manifest, or the entry, is no longer valid at the evaluation time.", true},
		{ReasonNotYetValid, "The manifest's issued-at is further in the future than the permitted clock skew.", true},
		{ReasonHealthUnknown, "The driver did not report a health status; the driver is not ready.", true},
		{ReasonHealthDegraded, "The driver reported DEGRADED health; the driver is not ready for mutation.", true},
		{ReasonHealthUnavailable, "The driver reported UNAVAILABLE health; the driver is not ready.", true},
		{ReasonRecoveryNotReady, "The driver did not attest a usable recovery (rollback) path.", true},
		{ReasonRequirementInvalid, "The requirement is nil, has no key, no operations, or an unspecified minimum support level; or no requirements were supplied.", true},
		{ReasonNodeMismatch, "The manifest's node id is not the node id the caller expected.", true},
		{ReasonSignatureInvalid, "The manifest carries no node signature, an unsupported algorithm, a foreign key id, or a signature that does not verify.", true},
		{ReasonSchema, "The manifest violates a structural invariant (schema version, bounds, entry validity, digest mismatch, ordering of times).", true},
		{ReasonOptionsInvalid, "The caller's options are incomplete: an expected node id and an Ed25519 node public key are required.", true},
		{ReasonDuplicateKey, "Two probe results, from the same or different drivers, report the same capability key.", true},
		{ReasonDriverMismatch, "A probe result names a driver other than the one it was registered under.", true},
		{ReasonProbeFailed, "A registered prober returned an error; discovery fails closed rather than publishing a partial manifest.", true},
		{ReasonProbeTimeout, "A registered prober did not complete within its bounded timeout.", true},
		{ReasonProbeInvalid, "A probe result failed driver.ProbeResult.Validate.", true},
		{ReasonNoCapabilities, "Discovery produced no capabilities; a manifest with no entries is never issued.", true},
		{ReasonFileOpen, "The manifest file could not be opened without following a symlink.", true},
		{ReasonFileType, "The opened path is not a regular file (directory, FIFO, device, socket, symlink, or reparse point).", true},
		{ReasonFilePermissions, "The file is group- or world-writable, or is not owned by the effective user, while RequireOwner is set.", true},
		{ReasonFileOversize, "The file is larger than MaxManifestBytes.", true},
		{ReasonFileChanged, "The file's size, modification time, or identity changed between open, read, and re-stat; or the read was short.", true},
		{ReasonJSONSyntax, "The file is not a single well-formed JSON object.", true},
		{ReasonJSONTrailing, "Bytes follow the JSON object.", true},
		{ReasonJSONUnknownField, "The JSON object contains a field the manifest schema does not define.", true},
		{ReasonJSONDuplicateKey, "A JSON object repeats a member name.", true},
		{ReasonJSONNesting, "JSON nesting is deeper than MaxJSONDepth.", true},
		{ReasonJSONString, "A JSON string contains a control, C1, format (bidi), or other non-printable rune.", true},
		{ReasonPlatformUnsupported, "The hardened loader has no implementation, or no owner check, for this platform.", true},
	}
}
