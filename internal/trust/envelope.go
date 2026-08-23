package trust

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Origin records where bytes came from. It is descriptive only; no origin is
// trusted more than another for rendering or parsing purposes.
type Origin uint8

// Origin values. The String spellings are stable and may be persisted.
const (
	OriginUnknown Origin = iota
	OriginPlan
	OriginDryRun
	OriginCapabilityMetadata
	OriginNodeLabel
	OriginProvider
	OriginGitMetadata
	OriginToolOutput
	OriginModelOutput
	OriginImportedFinding
	OriginWitnessResponse
	OriginLog
	OriginOperatorInput
)

var originNames = [...]string{
	OriginUnknown:            "UNKNOWN",
	OriginPlan:               "PLAN",
	OriginDryRun:             "DRY_RUN",
	OriginCapabilityMetadata: "CAPABILITY_METADATA",
	OriginNodeLabel:          "NODE_LABEL",
	OriginProvider:           "PROVIDER",
	OriginGitMetadata:        "GIT_METADATA",
	OriginToolOutput:         "TOOL_OUTPUT",
	OriginModelOutput:        "MODEL_OUTPUT",
	OriginImportedFinding:    "IMPORTED_FINDING",
	OriginWitnessResponse:    "WITNESS_RESPONSE",
	OriginLog:                "LOG",
	OriginOperatorInput:      "OPERATOR_INPUT",
}

// String returns the stable spelling; unknown numeric values render as UNKNOWN.
func (o Origin) String() string {
	if int(o) < len(originNames) {
		return originNames[o]
	}
	return originNames[OriginUnknown]
}

// ParseOrigin maps a stable spelling back to an Origin. Unrecognised input
// yields OriginUnknown and false.
func ParseOrigin(name string) (Origin, bool) {
	for index, candidate := range originNames {
		if candidate == name {
			return Origin(index), true
		}
	}
	return OriginUnknown, false
}

// Authenticity records what cryptography or local observation proves about
// the bytes. It says nothing about whether the bytes are safe or authorized.
type Authenticity uint8

// Authenticity values.
const (
	// Unauthenticated: no signature was checked or none was present.
	Unauthenticated Authenticity = iota
	// SignatureValid: a signature verified against a pinned key. Proves
	// provenance and integrity of the bytes only.
	SignatureValid
	// SignatureInvalid: a signature was present and failed verification.
	SignatureInvalid
	// LocallyObserved: the bytes were produced by this process reading local
	// state (a file, a socket, a kernel table). Local observation is not a
	// trust grant; local state can be attacker-influenced.
	LocallyObserved
)

var authenticityNames = [...]string{
	Unauthenticated:  "UNAUTHENTICATED",
	SignatureValid:   "SIGNATURE_VALID",
	SignatureInvalid: "SIGNATURE_INVALID",
	LocallyObserved:  "LOCALLY_OBSERVED",
}

// String returns the stable spelling; unknown values render as UNAUTHENTICATED.
func (a Authenticity) String() string {
	if int(a) < len(authenticityNames) {
		return authenticityNames[a]
	}
	return authenticityNames[Unauthenticated]
}

// ParseAuthenticity maps a stable spelling back to an Authenticity.
func ParseAuthenticity(name string) (Authenticity, bool) {
	for index, candidate := range authenticityNames {
		if candidate == name {
			return Authenticity(index), true
		}
	}
	return Unauthenticated, false
}

// EvidenceClass mirrors antiflock.v1.EvidenceClass from
// api/proto/antiflock/v1/evidence.proto. The numeric values and String
// spellings are identical to the generated proto enum so the two can be
// converted with a plain cast and compared by name.
type EvidenceClass int32

// EvidenceClass values (proto parity).
const (
	EvidenceClassUnspecified EvidenceClass = 0
	EvidenceClassDetected    EvidenceClass = 1
	EvidenceClassVerified    EvidenceClass = 2
	EvidenceClassReported    EvidenceClass = 3
	EvidenceClassInferred    EvidenceClass = 4
	EvidenceClassSuspected   EvidenceClass = 5
	EvidenceClassUnknown     EvidenceClass = 6
)

var evidenceClassNames = [...]string{
	EvidenceClassUnspecified: "EVIDENCE_CLASS_UNSPECIFIED",
	EvidenceClassDetected:    "EVIDENCE_CLASS_DETECTED",
	EvidenceClassVerified:    "EVIDENCE_CLASS_VERIFIED",
	EvidenceClassReported:    "EVIDENCE_CLASS_REPORTED",
	EvidenceClassInferred:    "EVIDENCE_CLASS_INFERRED",
	EvidenceClassSuspected:   "EVIDENCE_CLASS_SUSPECTED",
	EvidenceClassUnknown:     "EVIDENCE_CLASS_UNKNOWN",
}

// String returns the proto enum spelling; out-of-range values render as
// EVIDENCE_CLASS_UNSPECIFIED.
func (e EvidenceClass) String() string {
	if e >= 0 && int(e) < len(evidenceClassNames) {
		return evidenceClassNames[e]
	}
	return evidenceClassNames[EvidenceClassUnspecified]
}

// ParseEvidenceClass maps a proto spelling back to an EvidenceClass.
func ParseEvidenceClass(name string) (EvidenceClass, bool) {
	for index, candidate := range evidenceClassNames {
		if candidate == name {
			return EvidenceClass(index), true
		}
	}
	return EvidenceClassUnspecified, false
}

// ControlClass is the authority dimension of an envelope, and it has exactly
// one value: DataOnly.
//
// Why a one-value type exists at all: the point of the envelope is that the
// content it carries can never be promoted into a capability grant, a policy
// change, or an execution authorization, no matter what it says, who signed
// it, or how it is classified. Authority in AntiFlock comes from elsewhere
// (pinned keys, node-bound manifests, operator action), never from text.
// Making the dimension explicit lets callers and reviewers see that the
// question was asked and answered in the type system, and lets a future
// capability type live in a different package without this one ever being
// able to carry it. Because the type is an empty struct, every value of it
// is equal to DataOnly and GrantsCapability is false by construction, not by
// a runtime check.
type ControlClass struct{ _ struct{} }

// DataOnly is the only ControlClass value.
var DataOnly = ControlClass{}

// String returns "DATA_ONLY".
func (ControlClass) String() string { return "DATA_ONLY" }

// GrantsCapability reports whether the envelope content can confer any
// capability. It is constant: an envelope never grants capability.
func (ControlClass) GrantsCapability() bool { return false }

// Taint is a bit set describing hostile or suspicious shapes found in the
// bytes or their delivery. Taint is monotonic: nothing in this package clears
// a bit once set, and a valid signature in particular does not.
type Taint uint32

// Taint bits.
const (
	// TaintUntrusted is set on every envelope. Its presence documents that the
	// content did not originate from this process's own constants.
	TaintUntrusted Taint = 1 << iota
	// TaintContainsControlChars: C0/C1 controls, ESC/CSI/OSC/DCS sequences,
	// DEL, NUL, zero-width or other format runes, line/paragraph separators,
	// BOM, or invalid UTF-8 were found.
	TaintContainsControlChars
	// TaintContainsBidi: bidirectional override, embedding, isolate, or mark
	// runes were found.
	TaintContainsBidi
	// TaintContainsInstructionLike: the text is shaped like an instruction to
	// an operator or a model. Advisory only; never blocks by itself.
	TaintContainsInstructionLike
	// TaintOversized: the input exceeded a size or structural limit.
	TaintOversized
	// TaintTruncated: the rendering was cut and carries a truncation marker.
	TaintTruncated
	// TaintDuplicateFields: a JSON object repeated a key.
	TaintDuplicateFields
	// TaintStale: a receipt is expired, too old, unissued, or from the future.
	TaintStale
	// TaintReplayed: a receipt digest was seen before.
	TaintReplayed
	// TaintSignedButUnauthorized: the signature verified, but the signer or
	// binding is not authorized for this node or purpose.
	TaintSignedButUnauthorized
)

var taintNames = []struct {
	bit  Taint
	name string
}{
	{TaintUntrusted, "UNTRUSTED"},
	{TaintContainsControlChars, "CONTAINS_CONTROL_CHARS"},
	{TaintContainsBidi, "CONTAINS_BIDI"},
	{TaintContainsInstructionLike, "CONTAINS_INSTRUCTION_LIKE"},
	{TaintOversized, "OVERSIZED"},
	{TaintTruncated, "TRUNCATED"},
	{TaintDuplicateFields, "DUPLICATE_FIELDS"},
	{TaintStale, "STALE"},
	{TaintReplayed, "REPLAYED"},
	{TaintSignedButUnauthorized, "SIGNED_BUT_UNAUTHORIZED"},
}

// Has reports whether every bit in mask is set.
func (t Taint) Has(mask Taint) bool { return t&mask == mask }

// With returns t with the given bits added.
func (t Taint) With(mask Taint) Taint { return t | mask }

// Names returns the stable spellings of the set bits in bit order.
func (t Taint) Names() []string {
	names := make([]string, 0, len(taintNames))
	for _, entry := range taintNames {
		if t&entry.bit != 0 {
			names = append(names, entry.name)
		}
	}
	return names
}

// String joins Names with "|"; an empty set renders as "NONE".
func (t Taint) String() string {
	names := t.Names()
	if len(names) == 0 {
		return "NONE"
	}
	return strings.Join(names, "|")
}

// ParseTaint maps one stable spelling to its bit.
func ParseTaint(name string) (Taint, bool) {
	for _, entry := range taintNames {
		if entry.name == name {
			return entry.bit, true
		}
	}
	return 0, false
}

// ParseTaints maps a list of spellings to a set. The first unknown name
// produces an error.
func ParseTaints(names []string) (Taint, error) {
	var set Taint
	for _, name := range names {
		bit, ok := ParseTaint(name)
		if !ok {
			return 0, fmt.Errorf("trust: unknown taint %q", name)
		}
		set |= bit
	}
	return set, nil
}

// Payload holds the raw bytes and their sanitized rendering. The raw bytes are
// never rendered by this package: String, Format, and MarshalJSON all emit the
// sanitized text only. Raw is available for parsers and digest verification.
type Payload struct {
	raw      []byte
	Rendered Rendered
}

// Raw returns a copy of the original bytes. Callers must not print it.
func (p Payload) Raw() []byte {
	out := make([]byte, len(p.raw))
	copy(out, p.raw)
	return out
}

// RawLen returns the original byte length without exposing the bytes.
func (p Payload) RawLen() int { return len(p.raw) }

// String returns the sanitized rendering.
func (p Payload) String() string { return p.Rendered.Text }

// MarshalJSON emits the sanitized rendering as a JSON string.
func (p Payload) MarshalJSON() ([]byte, error) { return json.Marshal(p.Rendered.Text) }

// Envelope carries one external string with its trust dimensions tracked
// separately. Construct with Wrap; mutate only through the With* methods.
type Envelope struct {
	Origin        Origin
	Authenticity  Authenticity
	EvidenceClass EvidenceClass
	ControlClass  ControlClass
	Taint         Taint
	// Digest is "sha256:" followed by the lowercase hex SHA-256 of the raw bytes.
	Digest        string
	SchemaVersion uint32
	ParserVersion uint32
	Payload       Payload
}

// WrapOptions tunes Wrap. The zero value is a safe default.
type WrapOptions struct {
	// Policy controls rendering; nil selects DefaultPolicy().
	Policy *RenderPolicy
	// EvidenceClass classifies the claim carried by the bytes.
	EvidenceClass EvidenceClass
	// SchemaVersion and ParserVersion identify the schema the bytes claim to
	// follow and the parser that will consume them; informational.
	SchemaVersion uint32
	ParserVersion uint32
	// ExtraTaint adds bits the caller established out of band (for example
	// TaintStale from a receipt check).
	ExtraTaint Taint
	// SkipInstructionScan disables LooksInstructionLike. Use for content that
	// is known to be prose about instructions (documentation) where the
	// advisory bit would only add noise. The bit is advisory either way.
	SkipInstructionScan bool
}

// Wrap builds an Envelope. It computes the digest over the raw bytes,
// renders them under the policy, classifies taint, and stores both. raw may
// be a string or a byte slice (or a named type of either). The ControlClass
// is always DataOnly and TaintUntrusted is always set.
func Wrap[R ~string | ~[]byte](origin Origin, authenticity Authenticity, raw R, opts WrapOptions) Envelope {
	bytes := []byte(raw)
	policy := DefaultPolicy()
	if opts.Policy != nil {
		policy = *opts.Policy
	}
	rendered, err := Render(string(bytes), policy)
	if err != nil {
		// Invalid policy: fall back to the default so the envelope is still
		// safe to render.
		rendered, _ = Render(string(bytes), DefaultPolicy())
	}
	taint := TaintUntrusted | rendered.Taints | opts.ExtraTaint
	if !opts.SkipInstructionScan {
		if hit, _ := LooksInstructionLike(string(bytes)); hit {
			taint |= TaintContainsInstructionLike
		}
	}
	sum := sha256.Sum256(bytes)
	return Envelope{
		Origin:        origin,
		Authenticity:  authenticity,
		EvidenceClass: opts.EvidenceClass,
		ControlClass:  DataOnly,
		Taint:         taint,
		Digest:        "sha256:" + hex.EncodeToString(sum[:]),
		SchemaVersion: opts.SchemaVersion,
		ParserVersion: opts.ParserVersion,
		Payload:       Payload{raw: bytes, Rendered: rendered},
	}
}

// Text returns the sanitized rendering. Safe for terminals and JSON.
func (e Envelope) Text() string { return e.Payload.Rendered.Text }

// WithAuthenticity returns a copy with only Authenticity changed. Taint,
// ControlClass, EvidenceClass, and Payload are preserved exactly: signature
// validity never clears a taint bit.
func (e Envelope) WithAuthenticity(authenticity Authenticity) Envelope {
	e.Authenticity = authenticity
	return e
}

// WithTaint returns a copy with the given bits added. Bits are never removed.
func (e Envelope) WithTaint(mask Taint) Envelope {
	e.Taint |= mask
	return e
}

// WithEvidenceClass returns a copy with the evidence class replaced.
func (e Envelope) WithEvidenceClass(class EvidenceClass) Envelope {
	e.EvidenceClass = class
	return e
}

// Summary is the JSON/log shape of an envelope: every field is safe text.
type Summary struct {
	Origin        string   `json:"origin"`
	Authenticity  string   `json:"authenticity"`
	EvidenceClass string   `json:"evidenceClass"`
	ControlClass  string   `json:"controlClass"`
	Taint         []string `json:"taint"`
	Digest        string   `json:"digest"`
	SchemaVersion uint32   `json:"schemaVersion"`
	ParserVersion uint32   `json:"parserVersion"`
	RawBytes      int      `json:"rawBytes"`
	Text          string   `json:"text"`
}

// Summary returns the safe representation.
func (e Envelope) Summary() Summary {
	return Summary{
		Origin:        e.Origin.String(),
		Authenticity:  e.Authenticity.String(),
		EvidenceClass: e.EvidenceClass.String(),
		ControlClass:  e.ControlClass.String(),
		Taint:         e.Taint.Names(),
		Digest:        e.Digest,
		SchemaVersion: e.SchemaVersion,
		ParserVersion: e.ParserVersion,
		RawBytes:      e.Payload.RawLen(),
		Text:          e.Text(),
	}
}

// MarshalJSON emits Summary; raw bytes never appear.
func (e Envelope) MarshalJSON() ([]byte, error) { return json.Marshal(e.Summary()) }

// String renders a one-line safe description for logs.
func (e Envelope) String() string {
	return fmt.Sprintf("%s/%s/%s taint=%s digest=%s text=%s",
		e.Origin, e.Authenticity, e.ControlClass, e.Taint, e.Digest, QuoteForTerminal(e.Text()))
}

// SortedTaintNames returns the set's spellings in lexical order.
func SortedTaintNames(set Taint) []string {
	names := set.Names()
	sort.Strings(names)
	return names
}
