// Package integration defines the versioned, infrastructure-neutral seams
// through which a downstream deployment attaches external services to an
// AntiFlock core without modifying it.
//
// # Scope
//
// Every seam in this package is an interface plus the value types that cross
// it. The public repository never depends on a specific external service: an
// adapter lives out of tree (or under adapters/ as a generic reference
// implementation), is constructed through a Registry, and receives only the
// privacy-minimal data documented on each type. Verification of anything an
// adapter returns stays inside core; an adapter is a transport, never an
// authority.
//
// # Versioning
//
// InterfaceVersion identifies the shape of every interface and value type in
// this package. A registration whose declared version differs is rejected by
// Registry.Register, so an adapter compiled against a different contract fails
// closed at wiring time rather than at first use.
//
// # Common guarantees
//
//   - Inputs are validated by core before they reach an adapter; adapters may
//     re-validate but must never widen what they accept.
//   - Every method honours context cancellation and returns ctx.Err() (or an
//     error wrapping it) once the context is done.
//   - Errors returned by adapters are opaque to callers except for the
//     sentinels defined in errors.go; adapters wrap those sentinels so callers
//     can branch on errors.Is.
//   - Adapters never receive secrets beyond the credential they are explicitly
//     handed to authenticate themselves, and never receive raw telemetry,
//     node identifiers, labels, or user content (see privacy_test.go, which
//     pins the field allowlist of every outbound value type).
//   - Nothing an adapter returns is authorization. Receipts, verdicts, and
//     principals are evidence that core evaluates under its own policy.
package integration

// InterfaceVersion is the contract version of every interface and value type
// in this package. Registry.Register rejects registrations that declare any
// other version.
const InterfaceVersion = 1
