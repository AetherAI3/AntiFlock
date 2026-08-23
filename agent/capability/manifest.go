package capability

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/DBarr3/AntiFlock/agent/driver"
	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// SchemaVersion is the version of the Manifest digest and JSON layout.
const SchemaVersion uint32 = 1

// Bounds applied by Manifest.Validate.
const (
	MaxManifestEntries      = 256
	MaxManifestValidity     = driver.MaxProbeValidity
	MaxNodeIDLength         = 128
	MaxAttestationRefLength = 512

	// signatureDomain separates manifest signatures from every other Ed25519
	// use of the node key.
	signatureDomain = "AntiFlock-CapabilityManifest-v1"
	digestDomain    = "AntiFlock-CapabilityManifest-Digest-v1"
	// SignatureAlgorithm is the only algorithm Verify accepts.
	SignatureAlgorithm = "ed25519"
)

// Sentinel errors. Every error returned by this file wraps exactly one of them.
var (
	ErrManifestInvalid  = errors.New("capability manifest is invalid")
	ErrSignatureInvalid = errors.New("capability manifest signature is invalid")
)

// Entry is one discovered capability. It carries every field of the
// driver.ProbeResult it was produced from plus the probe digest, so a consumer
// can re-derive and check the digest without trusting the manifest author.
//
// Enumerations are stored as their antiflock.v1 numeric values; Health uses
// the driver.HealthStatus numbering.
type Entry struct {
	SchemaVersion uint32    `json:"schemaVersion"`
	Key           string    `json:"key"`
	Domain        int32     `json:"domain"`
	Operations    []int32   `json:"operations"`
	SupportLevel  int32     `json:"supportLevel"`
	DriverName    string    `json:"driverName"`
	DriverVersion string    `json:"driverVersion"`
	Health        uint8     `json:"health"`
	RecoveryReady bool      `json:"recoveryReady"`
	ReasonCodes   []string  `json:"reasonCodes"`
	Constraints   []string  `json:"constraints,omitempty"`
	ProbedAt      time.Time `json:"probedAt"`
	ExpiresAt     time.Time `json:"expiresAt"`
	ProbeDigest   string    `json:"probeDigest"`
}

// Signature is the node's Ed25519 signature over the manifest digest.
type Signature struct {
	KeyID     string `json:"keyId"`
	Algorithm string `json:"algorithm"`
	Value     []byte `json:"value"`
}

// Manifest is the authenticated unit of node capability. It is this package's
// own type, not the wire CapabilityManifest; ToProto derives the wire form.
type Manifest struct {
	SchemaVersion uint32    `json:"schemaVersion"`
	NodeID        string    `json:"nodeId"`
	Revision      uint64    `json:"revision"`
	IssuedAt      time.Time `json:"issuedAt"`
	ExpiresAt     time.Time `json:"expiresAt"`
	Capabilities  []Entry   `json:"capabilities"`
	// PolicyKeyID identifies the policy public key this node trusts. It is
	// data for operators and receipts, not authority: nothing in this package
	// grants or checks authorization based on it.
	PolicyKeyID string `json:"policyKeyId"`
	// AttestationRef is an opaque, printable reference to external attestation
	// evidence (for example "tpm2:pcr-quote:<digest>"). It is validated for
	// shape only and never interpreted.
	AttestationRef string     `json:"attestationRef,omitempty"`
	Signature      *Signature `json:"signature,omitempty"`
}

// EntryFromProbe converts a validated probe result into a manifest entry bound
// to its digest.
func EntryFromProbe(result driver.ProbeResult) (Entry, error) {
	digest, err := result.Digest()
	if err != nil {
		return Entry{}, err
	}
	operations := make([]int32, 0, len(result.Operations))
	for _, operation := range result.Operations {
		operations = append(operations, int32(operation))
	}
	return Entry{
		SchemaVersion: result.SchemaVersion,
		Key:           result.Key,
		Domain:        int32(result.Domain),
		Operations:    operations,
		SupportLevel:  int32(result.SupportLevel),
		DriverName:    result.DriverName,
		DriverVersion: result.DriverVersion,
		Health:        uint8(result.Health),
		RecoveryReady: result.RecoveryReady,
		ReasonCodes:   slices.Clone(result.ReasonCodes),
		Constraints:   slices.Clone(result.Constraints),
		ProbedAt:      result.ProbedAt.UTC(),
		ExpiresAt:     result.ExpiresAt.UTC(),
		ProbeDigest:   digest,
	}, nil
}

// Probe reconstructs the driver.ProbeResult view of the entry. The view is not
// validated; callers use Validate.
func (entry Entry) Probe() driver.ProbeResult {
	operations := make([]antiflockv1.CapabilityOperation, 0, len(entry.Operations))
	for _, operation := range entry.Operations {
		operations = append(operations, antiflockv1.CapabilityOperation(operation))
	}
	return driver.ProbeResult{
		SchemaVersion: entry.SchemaVersion,
		Key:           entry.Key,
		Domain:        antiflockv1.CapabilityDomain(entry.Domain),
		Operations:    operations,
		SupportLevel:  antiflockv1.CapabilitySupportLevel(entry.SupportLevel),
		DriverName:    entry.DriverName,
		DriverVersion: entry.DriverVersion,
		Health:        driver.HealthStatus(entry.Health),
		RecoveryReady: entry.RecoveryReady,
		ReasonCodes:   slices.Clone(entry.ReasonCodes),
		Constraints:   slices.Clone(entry.Constraints),
		ProbedAt:      entry.ProbedAt,
		ExpiresAt:     entry.ExpiresAt,
	}
}

// Validate applies the probe invariants to the entry and checks that
// ProbeDigest is the digest of the entry's own content.
func (entry Entry) Validate() error {
	digest, err := entry.Probe().Digest()
	if err != nil {
		return fmt.Errorf("%w: entry %q: %w", ErrManifestInvalid, entry.Key, err)
	}
	if subtle.ConstantTimeCompare([]byte(digest), []byte(entry.ProbeDigest)) != 1 {
		return fmt.Errorf("%w: entry %q: probe digest does not match content", ErrManifestInvalid, entry.Key)
	}
	return nil
}

// Validate applies every structural invariant of the manifest. It does not
// check the signature, the node binding, or expiry; those are decisions for
// Verify, LoadManifestFile, and Evaluate respectively.
func (manifest *Manifest) Validate() error {
	fail := func(format string, args ...any) error {
		return fmt.Errorf("%w: %s", ErrManifestInvalid, fmt.Sprintf(format, args...))
	}
	if manifest == nil {
		return fail("manifest is nil")
	}
	if manifest.SchemaVersion != SchemaVersion {
		return fail("schema version %d is not %d", manifest.SchemaVersion, SchemaVersion)
	}
	if !validIdentifier(manifest.NodeID, MaxNodeIDLength) {
		return fail("node id must be a bounded printable identifier")
	}
	if manifest.Revision == 0 {
		return fail("revision must be positive")
	}
	if manifest.IssuedAt.IsZero() || manifest.ExpiresAt.IsZero() {
		return fail("issued-at and expires-at are required")
	}
	if !manifest.ExpiresAt.After(manifest.IssuedAt) {
		return fail("expires-at must follow issued-at")
	}
	if manifest.ExpiresAt.Sub(manifest.IssuedAt) > MaxManifestValidity {
		return fail("validity exceeds %s", MaxManifestValidity)
	}
	if len(manifest.Capabilities) == 0 || len(manifest.Capabilities) > MaxManifestEntries {
		return fail("between 1 and %d capabilities are required", MaxManifestEntries)
	}
	seen := make(map[string]struct{}, len(manifest.Capabilities))
	for _, entry := range manifest.Capabilities {
		if err := entry.Validate(); err != nil {
			return err
		}
		if _, duplicate := seen[entry.Key]; duplicate {
			return fail("capability %q is duplicated", entry.Key)
		}
		seen[entry.Key] = struct{}{}
		if entry.ExpiresAt.Before(manifest.ExpiresAt) {
			return fail("capability %q expires before the manifest", entry.Key)
		}
	}
	if !validIdentifier(manifest.PolicyKeyID, MaxNodeIDLength) {
		return fail("policy key id must be a bounded printable identifier")
	}
	if manifest.AttestationRef != "" && (len(manifest.AttestationRef) > MaxAttestationRefLength || !printableASCII(manifest.AttestationRef)) {
		return fail("attestation reference is oversized or not printable ASCII")
	}
	if manifest.Signature != nil {
		if manifest.Signature.Algorithm != SignatureAlgorithm || !validIdentifier(manifest.Signature.KeyID, MaxNodeIDLength) || len(manifest.Signature.Value) != ed25519.SignatureSize {
			return fail("signature must be an Ed25519 signature with a bounded key id")
		}
	}
	return nil
}

// Digest returns the deterministic SHA-256 digest of the manifest content,
// excluding the signature. Entries are sorted by key, so entry order in the
// file does not change the digest. Validation failures fail closed.
func (manifest *Manifest) Digest() ([]byte, error) {
	if err := manifest.Validate(); err != nil {
		return nil, err
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
	writeTime := func(value time.Time) {
		writeUint(uint64(value.UTC().Unix()))
		writeUint(uint64(value.UTC().Nanosecond()))
	}
	writeString(digestDomain)
	writeUint(uint64(manifest.SchemaVersion))
	writeString(manifest.NodeID)
	writeUint(manifest.Revision)
	writeTime(manifest.IssuedAt)
	writeTime(manifest.ExpiresAt)
	writeString(manifest.PolicyKeyID)
	writeString(manifest.AttestationRef)
	entries := slices.Clone(manifest.Capabilities)
	slices.SortFunc(entries, func(a, b Entry) int { return strings.Compare(a.Key, b.Key) })
	writeUint(uint64(len(entries)))
	for _, entry := range entries {
		writeString(entry.Key)
		// The probe digest already binds every other entry field; Validate
		// proved it matches the entry content.
		writeString(entry.ProbeDigest)
	}
	return hash.Sum(nil), nil
}

// DigestHex is Digest in lower-case hexadecimal.
func (manifest *Manifest) DigestHex() (string, error) {
	digest, err := manifest.Digest()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(digest), nil
}

func signatureMessage(digest []byte) []byte {
	message := make([]byte, 0, len(signatureDomain)+len(digest))
	message = append(message, signatureDomain...)
	return append(message, digest...)
}

// Sign sets Signature using the node's Ed25519 private key. The signature key
// id is the node id, mirroring the enforcer's rule that the node signing key id
// equals the node id.
func (manifest *Manifest) Sign(nodeKey ed25519.PrivateKey) error {
	if len(nodeKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("%w: node key must be an Ed25519 private key", ErrSignatureInvalid)
	}
	manifest.Signature = nil
	digest, err := manifest.Digest()
	if err != nil {
		return err
	}
	manifest.Signature = &Signature{
		KeyID:     manifest.NodeID,
		Algorithm: SignatureAlgorithm,
		Value:     ed25519.Sign(nodeKey, signatureMessage(digest)),
	}
	return nil
}

// Verify checks the manifest signature against the node public key. It fails
// closed when the manifest is structurally invalid, unsigned, signed under a
// key id other than the node id, or signed with any other key.
func (manifest *Manifest) Verify(nodePublicKey ed25519.PublicKey) error {
	if len(nodePublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: node public key must be Ed25519", ErrSignatureInvalid)
	}
	digest, err := manifest.Digest()
	if err != nil {
		return err
	}
	signature := manifest.Signature
	if signature == nil {
		return fmt.Errorf("%w: manifest is unsigned", ErrSignatureInvalid)
	}
	if signature.Algorithm != SignatureAlgorithm || signature.KeyID != manifest.NodeID {
		return fmt.Errorf("%w: signature algorithm or key id is not the node's", ErrSignatureInvalid)
	}
	if !ed25519.Verify(nodePublicKey, signatureMessage(digest), signature.Value) {
		return fmt.Errorf("%w: signature does not verify", ErrSignatureInvalid)
	}
	return nil
}

// Constraint keys ToProto adds so existing wire consumers see probe-derived
// facts without a proto change.
const (
	ConstraintProbeDigest   = "probe-digest"
	ConstraintHealth        = "health"
	ConstraintRecoveryReady = "recovery-ready"
)

// ToProto derives the wire CapabilityManifest. The wire signature is left
// empty: internal/model has no reusable CapabilityManifest signing helper, and
// this package must not duplicate a signing profile owned elsewhere. The
// authenticated form is the Manifest itself (Sign/Verify); the wire form is a
// projection for consumers that only understand antiflock.v1.
func (manifest *Manifest) ToProto() (*antiflockv1.CapabilityManifest, error) {
	if err := manifest.Validate(); err != nil {
		return nil, err
	}
	output := &antiflockv1.CapabilityManifest{
		NodeId:    manifest.NodeID,
		Revision:  manifest.Revision,
		IssuedAt:  timestamppb.New(manifest.IssuedAt.UTC()),
		ExpiresAt: timestamppb.New(manifest.ExpiresAt.UTC()),
	}
	entries := slices.Clone(manifest.Capabilities)
	slices.SortFunc(entries, func(a, b Entry) int { return strings.Compare(a.Key, b.Key) })
	for _, entry := range entries {
		probe := entry.Probe()
		constraints := slices.Clone(probe.Constraints)
		constraints = append(constraints,
			ConstraintProbeDigest+"="+entry.ProbeDigest,
			ConstraintHealth+"="+probe.Health.String(),
			ConstraintRecoveryReady+"="+fmt.Sprint(probe.RecoveryReady),
		)
		output.Capabilities = append(output.Capabilities, &antiflockv1.Capability{
			Key:                   probe.Key,
			Domain:                probe.Domain,
			Operations:            slices.Clone(probe.Operations),
			SupportLevel:          probe.SupportLevel,
			Implementation:        probe.DriverName,
			ImplementationVersion: probe.DriverVersion,
			Constraints:           constraints,
			ObservedAt:            timestamppb.New(probe.ProbedAt.UTC()),
		})
	}
	return output, nil
}

func validIdentifier(value string, maximum int) bool {
	if value == "" || len(value) > maximum || !printableASCII(value) {
		return false
	}
	return !strings.ContainsAny(value, " \t")
}

func printableASCII(value string) bool {
	for _, r := range value {
		if r > unicode.MaxASCII || !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}
