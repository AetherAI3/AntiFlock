# Capability discovery and readiness

Package: `agent/capability`. Status: Wave 0 of ANTIFL0CK-OSS-COMPLETION-02
(lane S3). Consumes the frozen probe seam in `agent/driver/probe.go`
(PR #61); the enforcer adaptation is a scheduled follow-up (see the last
section), not part of this change.

## 1. Threat model: what a caller-asserted manifest allowed

Before this package, a node's capabilities were whatever the caller said they
were:

- `agent/enrollment/client.go` and `agent/sim/live.go` construct
  `CapabilityManifest` literals by hand. Core records them `CLAIMED`
  (`core/enrollment/service.go`) and no code path ever sets `VERIFIED`.
- `agent/enforcement.Config.Capabilities` accepts any `CapabilityManifest`
  from the caller (the CLI reads it from a `--capabilities` file).
  `Enforcer.supportsAll` string- and enum-matches plan requirements against
  that manifest. The manifest `signature` field is never verified on the agent.
- Nothing probes the host. "Supported" meant "present in a file".

What an attacker who controls the manifest input (a writable capabilities
file, a compromised enrollment client, or a hostile operator tool) could do:

| Attack | Effect under the old model |
| --- | --- |
| Claim `FULL` support for `firewall.nftables.enforce` on a host with no `nft` binary or no privilege | Plan validation passes; apply fails late, after preconditions, possibly after partial mutation. Rollback depends on the same unverified claim. |
| Claim `ROLLBACK` for a driver that has no recovery path | The enforcer accepts a plan whose rollback section cannot execute; a failed apply strands the host. |
| Claim capabilities for another node (`node_id` of a different node) | `New` only compares `NodeId` to the configured node id. A manifest copied between nodes with the id rewritten passes. |
| Replace the manifest file between the enforcer's open and read, or swap a symlink | Plain `os.ReadFile` follows symlinks and has no change detection. |
| Inject bidi or zero-width characters into keys or driver names | Manifest text that reads one way to a reviewer and matches another way in code. |
| Declare an unbounded validity window | A stale manifest is honoured indefinitely. |

None of these required breaking a signature, because no signature was checked.

## 2. New trust chain

```text
driver.Prober.Probe            read-only, context-bound, registered explicitly
  -> driver.ProbeResult.Validate   bounded fields, printable ASCII, health/recovery invariant
  -> ProbeResult.Digest            deterministic identity of the observation
  -> capability.Entry              probe fields + ProbeDigest (re-derivable by any consumer)
  -> capability.Manifest           node-bound, revisioned, expiry = min(probe expiry) <= 24h
  -> Manifest.Sign(nodeKey)        Ed25519 over "AntiFlock-CapabilityManifest-v1" || Digest()
  -> LoadManifestFile              hardened open, bounded read, change detection, strict JSON,
                                   node binding, signature, validity window
  -> capability.Evaluate           independent per-requirement verdicts, fail closed
```

Each step rejects rather than repairs. Specifically:

- **Discovery** (`Discover`): probers are supplied in `Options.Probers`
  keyed by driver name; there is no global registry. Every probe runs under
  its own timeout (default 5s, maximum 60s). A prober that errors, panics, or
  ignores its context fails the whole discovery (`AF-CAP-PROBE-FAILED`,
  `AF-CAP-PROBE-TIMEOUT`); no partial manifest is issued. A result whose
  `DriverName` differs from its registration name is rejected
  (`AF-CAP-DRIVER-MISMATCH`). The same key from any two results is rejected
  (`AF-CAP-DUPLICATE-KEY`). Prober error text is never copied into the
  returned error.
- **Manifest** (`Manifest.Validate`): schema version 1, bounded node id and
  policy key id, positive revision, issued-before-expires with validity at
  most `driver.MaxProbeValidity`, 1..256 entries with unique keys, every
  entry passing `driver.ProbeResult.Validate` and carrying a `ProbeDigest`
  equal to the digest of its own content, manifest expiry not later than any
  entry expiry, optional printable `AttestationRef` of at most 512 bytes.
- **Digest**: length-prefixed fields, entries sorted by key, each entry
  contributing `key` and `probeDigest` (the probe digest already binds every
  other entry field). Entry order in the file cannot change the digest.
- **Signature**: `Sign` sets `{keyId: NodeID, algorithm: "ed25519", value}`;
  `Verify` requires the key id to equal the node id and rejects any other
  algorithm. This mirrors the enforcer's rule that the node signing key id is
  the node id.
- **Loader** (`LoadManifestFile`), in order: open with `O_NOFOLLOW |
  O_NONBLOCK | O_CLOEXEC` (unix) or `FILE_FLAG_OPEN_REPARSE_POINT` (windows);
  reject anything that is not a regular file; with `RequireOwner`, reject
  files not owned by the effective uid or writable by group/world (windows:
  fails closed as unsupported); reject stat size over 256 KiB; read through
  `io.LimitReader(256 KiB + 1)`; require read length == stat size; re-stat the
  open descriptor and require identical size, mtime, inode, and device;
  pre-scan JSON tokens for depth > 8, duplicate member names, and any string
  containing C0/C1 controls, DEL, `unicode.Cf` (bidi overrides, zero-width
  joiners), invalid UTF-8, or non-printable runes; decode with
  `DisallowUnknownFields`; require `io.EOF` after the object; `Validate`;
  node binding; signature; validity window (expired, or issued more than five
  minutes in the future).
- **Evaluate**: see section 4.

## 3. What a valid manifest does not prove

A plan that is correctly signed by the policy key, targeting a node whose
loaded manifest is node-signed, current, and compatible with every
requirement, still does not establish:

- **Authorization.** The manifest is evidence about drivers, not a grant.
  `PolicyKeyID` records which policy key the node trusts; it is data for
  receipts and operators, and nothing in this package grants or checks
  authority based on it. Authorization remains the enforcer's plan
  verification and Core's policy.
- **Host readiness at execution time.** A probe is an observation at
  `ProbedAt`. `Evaluate` reports `DriverReady` for a `HEALTHY`, current entry,
  which is the best available evidence, not a reservation. Preconditions and
  verifications in the plan remain mandatory.
- **Attestation.** `AttestationRef` is an opaque, printable reference. It is
  validated for shape only and never interpreted; no component derives trust
  from it.
- **Core verification.** Core still records enrollment manifests as
  `CLAIMED`. Moving a node to `VERIFIED` requires Core to receive and verify a
  node-signed manifest, which is outside this package (and outside this lane).

## 4. Readiness verdicts

`Evaluate(manifest, requirements, now)` returns one `Verdict` per
requirement, in input order, plus aggregates. The three axes are independent
and never collapsed into one boolean:

| Axis | True when |
| --- | --- |
| `Compatible` | An entry with the requirement's key exists, its support level satisfies the minimum (same lattice as the enforcer: PARTIAL accepts PARTIAL or FULL, FULL accepts only FULL, EXPERIMENTAL accepts only EXPERIMENTAL, UNSUPPORTED accepts any specified level), and every required operation is listed. This is exactly what `supportsAll` used to compute. |
| `DriverReady` | `Compatible`, the entry is not expired at `now`, and the driver reported `HEALTHY`. `DEGRADED`, `UNAVAILABLE`, and `UNKNOWN` all fail closed. |
| `RecoveryReady` | `DriverReady` and the driver attested `RecoveryReady`. |

`AllCompatible`, `AllDriverReady`, `AllRecoveryReady` are true only when at
least one requirement was supplied and every verdict passed that axis. An
empty requirement list fails every aggregate (`AF-CAP-REQUIREMENT-INVALID`),
matching `supportsAll`'s behaviour on empty input. A manifest that fails
`Validate`, is expired, or is issued in the future fails every verdict with
the manifest-level code and sets `Readiness.ReasonCodes`.

`Evaluate` does not verify the signature or the node binding. Those are
authentication decisions, made by `LoadManifestFile` (or by the caller via
`Manifest.Verify`) before a manifest is handed to `Evaluate`.

### Reason codes

The table below is generated from `capability.ReasonCodes()`; a test asserts
that every `AF-CAP-` literal in the package appears in it and vice versa.

| Code | Meaning |
| --- | --- |
| `AF-CAP-OK` | The requirement is satisfied on every axis. |
| `AF-CAP-MISSING` | No manifest entry has the requirement's key. |
| `AF-CAP-SUPPORT-LEVEL` | The entry's support level does not satisfy the minimum. |
| `AF-CAP-OPERATION-MISSING` | The entry does not list every required operation. |
| `AF-CAP-EXPIRED` | The manifest, or the entry, is no longer valid at the evaluation time. |
| `AF-CAP-NOT-YET-VALID` | The manifest's issued-at is further in the future than the permitted clock skew. |
| `AF-CAP-HEALTH-UNKNOWN` | The driver did not report a health status. |
| `AF-CAP-HEALTH-DEGRADED` | The driver reported DEGRADED health. |
| `AF-CAP-HEALTH-UNAVAILABLE` | The driver reported UNAVAILABLE health. |
| `AF-CAP-RECOVERY-NOT-READY` | The driver did not attest a usable recovery path. |
| `AF-CAP-REQUIREMENT-INVALID` | The requirement is nil or malformed, or no requirements were supplied. |
| `AF-CAP-NODE-MISMATCH` | The manifest's node id is not the expected node id. |
| `AF-CAP-SIGNATURE-INVALID` | Unsigned, unsupported algorithm, foreign key id, or the signature does not verify. |
| `AF-CAP-SCHEMA` | A structural invariant failed (schema version, bounds, entry validity, digest mismatch, time ordering). |
| `AF-CAP-OPTIONS-INVALID` | The caller's options are incomplete. |
| `AF-CAP-DUPLICATE-KEY` | Two probe results report the same capability key. |
| `AF-CAP-DRIVER-MISMATCH` | A probe result names a driver other than the one it was registered under. |
| `AF-CAP-PROBE-FAILED` | A prober returned an error or panicked; discovery fails closed. |
| `AF-CAP-PROBE-TIMEOUT` | A prober did not complete within its bounded timeout. |
| `AF-CAP-PROBE-INVALID` | A probe result failed `driver.ProbeResult.Validate`. |
| `AF-CAP-NO-CAPABILITIES` | Discovery produced no capabilities. |
| `AF-CAP-FILE-OPEN` | The file could not be opened without following a symlink. |
| `AF-CAP-FILE-TYPE` | The path is not a regular file. |
| `AF-CAP-FILE-PERMISSIONS` | Group/world-writable or not owned by the effective user, under `RequireOwner`. |
| `AF-CAP-FILE-OVERSIZE` | Larger than `MaxManifestBytes` (256 KiB). |
| `AF-CAP-FILE-CHANGED` | Size, mtime, or identity changed between open, read, and re-stat; or the read was short. |
| `AF-CAP-JSON-SYNTAX` | Not a single well-formed JSON object matching the schema types. |
| `AF-CAP-JSON-TRAILING` | Bytes follow the JSON object. |
| `AF-CAP-JSON-UNKNOWN-FIELD` | A field the schema does not define. |
| `AF-CAP-JSON-DUPLICATE-KEY` | A JSON object repeats a member name. |
| `AF-CAP-JSON-NESTING` | Nesting deeper than `MaxJSONDepth` (8). |
| `AF-CAP-JSON-STRING` | A string contains a control, C1, format (bidi), invalid, or non-printable rune. |
| `AF-CAP-PLATFORM-UNSUPPORTED` | No hardened loader, or no owner check, on this platform. |

## 5. Wire projection and the proto signature

`Manifest.ToProto` derives an `antiflock.v1.CapabilityManifest` for existing
consumers. Each `Capability` carries `key`, `domain`, `operations`,
`support_level`, `implementation` (driver name), `implementation_version`,
`observed_at` (probe time), and `constraints` = the probe's constraints plus:

```text
probe-digest=<64 hex>
health=HEALTHY|DEGRADED|UNAVAILABLE|UNKNOWN
recovery-ready=true|false
```

The wire `signature` is left empty. `internal/model` exposes no reusable
`CapabilityManifest` signer (its helpers are event-specific, and the plan and
plan-result signers live in `core/policy` and `agent/enforcement`, the latter
of which this package must not import because the enforcer will import this
package). Duplicating the deterministic-protobuf signing profile here would
create a second implementation of a contract owned elsewhere. The
authenticated object is therefore the `Manifest` (JSON form, `Sign`/`Verify`);
the wire form is a projection. When a shared signer for
`antiflock.capability-manifest.v1` lands in `internal/model`, `ToProto` should
call it; nothing else changes.

## 6. Proposed proto additions (not made; ADR-gated)

The projection above carries probe facts in `constraints` so that no proto
change is required now. When an ADR approves a schema change, the following
additive fields make those facts first-class:

```proto
message Capability {
  // ... existing fields 1-8 unchanged ...
  // Hex SHA-256 of the driver probe result this capability was derived from.
  string probe_digest = 9;
  // Driver health at observed_at.
  CapabilityHealth health = 10;
  // The driver attested a usable recovery path for this capability.
  bool recovery_ready = 11;
}

enum CapabilityHealth {
  CAPABILITY_HEALTH_UNSPECIFIED = 0;
  CAPABILITY_HEALTH_HEALTHY = 1;
  CAPABILITY_HEALTH_DEGRADED = 2;
  CAPABILITY_HEALTH_UNAVAILABLE = 3;
}

message CapabilityManifest {
  // ... existing fields 1-6 unchanged ...
  // Key id of the policy public key this node trusts. Data, not authority.
  string policy_key_id = 7;
  // Opaque attestation reference (for example "tpm2:pcr-quote:<digest>").
  string attestation_ref = 8;
  // Hex SHA-256 of the node-side capability.Manifest digest.
  string manifest_digest = 9;
}
```

Until then, consumers read `probe-digest=`, `health=`, and `recovery-ready=`
from `constraints`. `core/server/provenance.go` already scans constraints; it
must not treat these three as provenance markers.

## 7. Follow-up: enforcer adaptation after PR #60 merges

Lease note: this lane may not edit `agent/enforcement/**` while #60 is open.
The diff below is written against #60's head (`6e58031b`) and is scheduled by
A0 after #60 lands. It replaces the caller-asserted manifest with a loaded,
verified `capability.Manifest`, and replaces `supportsAll` with
`capability.Evaluate`. No behaviour of #60's contract binding
(`matchesCapabilityContracts`, `validCapabilityRequirements`) changes.

```diff
--- a/agent/enforcement/enforcer.go
+++ b/agent/enforcement/enforcer.go
@@
 import (
 	...
+	"github.com/DBarr3/AntiFlock/agent/capability"
 	antiflockv1 "github.com/DBarr3/AntiFlock/api/gen/go/antiflock/v1"
 	...
 )
@@ type Config struct {
 	NodeKeyID          string
 	NodePrivateKey     ed25519.PrivateKey
-	Capabilities       *antiflockv1.CapabilityManifest
+	// Manifest is the node-signed capability manifest produced by
+	// capability.Discover or loaded by capability.LoadManifestFile. It is
+	// verified against the node public key derived from NodePrivateKey.
+	Manifest           *capability.Manifest
 	Driver             Driver
@@ type Enforcer struct {
-	capabilities       *antiflockv1.CapabilityManifest
+	manifest           *capability.Manifest
+	capabilities       *antiflockv1.CapabilityManifest // wire projection for receipts
@@ func New(config Config) (*Enforcer, error) {
-	if config.Capabilities == nil || config.Capabilities.NodeId != config.NodeID || config.Driver == nil {
-		return nil, errors.New("enforcer requires node-bound capabilities and a driver")
-	}
-	if err := model.RejectUnknownFields(config.Capabilities); err != nil {
-		return nil, fmt.Errorf("capability manifest: %w", err)
-	}
+	if config.Manifest == nil || config.Driver == nil {
+		return nil, errors.New("enforcer requires a node-signed capability manifest and a driver")
+	}
+	if config.Manifest.NodeID != config.NodeID {
+		return nil, errors.New("enforcer capability manifest belongs to another node")
+	}
+	nodePublicKey := config.NodePrivateKey.Public().(ed25519.PublicKey)
+	if err := config.Manifest.Verify(nodePublicKey); err != nil {
+		return nil, fmt.Errorf("capability manifest: %w", err)
+	}
+	wire, err := config.Manifest.ToProto()
+	if err != nil {
+		return nil, fmt.Errorf("capability manifest: %w", err)
+	}
@@ return &Enforcer{
-		capabilities:   proto.Clone(config.Capabilities).(*antiflockv1.CapabilityManifest),
+		manifest:       config.Manifest,
+		capabilities:   wire,
@@ func (enforcer *Enforcer) validatePlanMode(plan *antiflockv1.Plan, now time.Time, requireCapabilities bool) *validationError {
+	if requireCapabilities {
+		if !now.Before(enforcer.manifest.ExpiresAt) {
+			return reject("AF-PLAN-CAPABILITY-EXPIRED")
+		}
+	}
@@ (precondition and verification checks)
-			if requireCapabilities && !enforcer.supportsAll(check.RequiredCapabilities) {
-				return reject("AF-PLAN-CAPABILITY-UNSUPPORTED")
-			}
+			if requireCapabilities {
+				if code := enforcer.capabilityVerdict(check.RequiredCapabilities, now, false); code != "" {
+					return reject(code)
+				}
+			}
@@ (actions and rollback operations)
-			if requireCapabilities && !enforcer.supportsAll(operation.RequiredCapabilities) {
-				return reject("AF-PLAN-CAPABILITY-UNSUPPORTED")
-			}
+			if requireCapabilities {
+				if code := enforcer.capabilityVerdict(operation.RequiredCapabilities, now, operationSetIndex == 1); code != "" {
+					return reject(code)
+				}
+			}
@@
-func (enforcer *Enforcer) supportsAll(requirements []*antiflockv1.CapabilityRequirement) bool {
-	... (whole function removed) ...
-}
-
-func supportSatisfies(actual, minimum antiflockv1.CapabilitySupportLevel) bool {
-	... (whole function removed; capability.Evaluate owns the lattice) ...
-}
+// capabilityVerdict maps capability.Evaluate onto plan rejection codes.
+// Compatibility failures keep the existing AF-PLAN-CAPABILITY-UNSUPPORTED
+// code; readiness failures are new, distinct codes so operators can tell a
+// mis-targeted plan from an unhealthy host. Rollback steps additionally
+// require RecoveryReady.
+func (enforcer *Enforcer) capabilityVerdict(requirements []*antiflockv1.CapabilityRequirement, now time.Time, rollback bool) string {
+	if !validCapabilityRequirements(requirements) {
+		return "AF-PLAN-CAPABILITY-UNSUPPORTED"
+	}
+	readiness := capability.Evaluate(enforcer.manifest, requirements, now)
+	switch {
+	case readiness.Expired:
+		return "AF-PLAN-CAPABILITY-EXPIRED"
+	case !readiness.AllCompatible:
+		return "AF-PLAN-CAPABILITY-UNSUPPORTED"
+	case !readiness.AllDriverReady:
+		return "AF-PLAN-CAPABILITY-NOT-READY"
+	case rollback && !readiness.AllRecoveryReady:
+		return "AF-PLAN-CAPABILITY-RECOVERY-NOT-READY"
+	}
+	return ""
+}
```

Companion changes in the same follow-up PR:

- `cmd/antiflock-agent` (or wherever `--capabilities` is parsed): replace the
  `protojson` read with `capability.LoadManifestFile(path, capability.LoadOptions{
  ExpectedNodeID: nodeID, NodePublicKey: nodeKey.Public().(ed25519.PublicKey),
  RequireOwner: true})`, and add a `discover` subcommand that calls
  `capability.Discover` with the real probers and writes the signed JSON
  manifest with `0600` permissions via the existing atomic-write helpers.
- `agent/enforcement/enforcer_test.go`: fixtures build a
  `capability.Manifest` from `driver.ProbeResult`s and sign it with the test
  node key; the `supportsAll` table tests move to `capability.Evaluate`
  (already covered in `agent/capability/readiness_test.go`) and the enforcer
  keeps one test per new rejection code.
- `docs/signing-contracts.md`: add a row for the node-side manifest signature
  (domain `AntiFlock-CapabilityManifest-v1`, message = domain || digest) and
  note that the wire `signature` is produced by a separate Core-facing
  profile.
- The `Drivers` literal table introduced by #60 stays; it describes plan
  contracts, not host readiness, and is unaffected.

Rejection codes introduced by the follow-up: `AF-PLAN-CAPABILITY-EXPIRED`,
`AF-PLAN-CAPABILITY-NOT-READY`, `AF-PLAN-CAPABILITY-RECOVERY-NOT-READY`.
`AF-PLAN-CAPABILITY-UNSUPPORTED` keeps its meaning (not compatible).
