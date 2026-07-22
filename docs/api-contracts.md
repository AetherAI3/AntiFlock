# API contracts

The canonical wire model is `antiflock.v1` under `api/proto/antiflock/v1`.
REST and SDK surfaces are projections of these messages and MUST preserve IDs,
evidence, timestamps, sensitivity, and unknown enum values rather than silently
reclassifying them.

## Compatibility

- APIs are versioned by protobuf package. Fields are additive within `v1`.
- Published field numbers, enum numbers, service names, and semantic meanings
  are never reused. Removed items are reserved.
- Unknown fields and event kinds are retained when a component proxies or
  stores them. Unknown enum values fail safe and render as unknown, not as the
  first known value.
- IDs are opaque strings and unique within a deployment unless a field states
  a broader scope. Clients do not infer type or authority from an ID prefix.
- Timestamps are UTC instants. `observed_at` describes the source observation;
  `received_at` describes ingestion. Zero timestamps mean absent, never "now."
- Confidence is finite and within `[0,1]`; ingress rejects values outside that
  range. Empty reason codes, missing required evidence, expired plans, or
  unsupported capabilities fail validation.
- Sensitive values, token secrets, private keys, payload content, and exact
  location are absent unless a specific contract authorizes them.

## Authentication and authorization

Agent channels use mutually authenticated deployment and node credentials.
Dashboard and local SDK endpoints bind to loopback or approved mesh interfaces
by default and authenticate the calling principal. Authorization is scoped by
deployment, node, resource, operation, and sensitivity; possession of a mesh
identity alone is insufficient.

Enrollment tokens are short-lived and single-use. Endpoint keys are generated
locally, and enrollment includes proof of possession. Revocation takes effect
immediately when Core is reachable and is included in the next local policy
evaluation.

## Idempotency and concurrency

Mutating requests carry a request or operation ID. Reuse with identical input
returns the original result; reuse with different input is rejected. Resource
updates use expected revision or an equivalent precondition. Event submission
deduplicates by `(deployment_id, event_id)` while preserving node sequence gaps
as visible findings rather than inventing missing data.

Plan application is idempotent by plan ID and target revision. An endpoint may
acknowledge a previously committed result, but MUST NOT execute actions twice.

## Core service groups

| Service | Responsibility |
| --- | --- |
| `EnrollmentService` | Create single-use tokens, enroll a node public key and capability manifest, approve/deny pending enrollment. |
| `NodeService` | Read, rename, tag, suspend, revoke, and inspect nodes. |
| `AgentControlService` | Heartbeat, receive signed plans, and report plan results. A future bidirectional stream may multiplex these frames without changing their semantics. |
| `TelemetryService` | Submit immutable events and observation snapshots/batches. |
| `TopologyService` | Read operator assets, observers, relationships, and logical paths. |
| `FindingService` | Read and transition findings without deleting their evidence history. |
| `PostureService` | Read deterministic protection snapshots. |
| `PolicyService` | Validate and compile operator intent into capability-specific dry runs. |
| `PlanService` | Read, apply, and roll back signed plans. |
| `ActionGateService` | Evaluate a protected action and authorize a narrow held action. |
| `IntelligenceService` | Retrieve signed, licensed, expiring regional packs and intelligence records. |
| `FieldReportService` | Submit, query, dispute, and moderate infrastructure reports under community policy. |
| `FootprintService` | Manage operator-authorized assets and proofs. No arbitrary-person search exists. |
| `ScramblerService` | Simulate, activate, observe, and roll back constrained transitions. |

Adding a Footprint asset may create a private pending inventory record, but no
connector, enrichment, public-record lookup, or network scan may run until an
approved ownership or delegation method records `VERIFIED` status. A caller's
scope attestation alone is not proof.

## Errors

Transport status identifies a stable class: invalid input, unauthenticated,
unauthorized, not found, conflict/revision mismatch, unsupported capability,
expired, failed precondition, rate limited, or internal failure. A structured
error detail includes a safe reason code, operation ID, retryability, and field
violations. Errors never echo token values, keys, private identifiers, full
paths, or raw provider responses.

## Secure Action Gate

`EvaluateSecureAction` returns `ALLOW`, `HOLD`, `BLOCK`, or `REQUIRE_CONSENT`.
`ALLOW_ONCE` is produced only after explicit consent for the exact held action.
Authorizations are opaque, application- and destination-bound, single-use,
short-lived, and auditable. A timeout, unavailable evaluator, or ambiguous
destination follows the policy's explicit fail mode; it is never silently
treated as `ALLOW`.

Universal network enforcement can block an application's egress but cannot
claim to understand the application's send operation or inject UI into an
unintegrated app. The richer hold/retry contract applies only to integrated
applications.

## REST projection

Initial dashboard routes include overview, nodes, topology, paths, events,
findings, posture, enrollment tokens, policy validation/compile, plan
apply/rollback, action evaluation/authorization, field reports, footprint
assets, and Scrambler state/simulation/activation. State-changing REST calls
apply the same authentication, idempotency, revision, and audit contracts as
gRPC; REST is not an administrative bypass.
