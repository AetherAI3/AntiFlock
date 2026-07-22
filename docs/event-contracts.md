# Event contracts

## Envelope

Every source event is carried by `EventEnvelope` with:

- immutable event ID and schema version;
- deployment and source node IDs;
- stable lower-case event kind;
- source observation and Core receipt times;
- monotonic per-node sequence and boot/session ID;
- evidence class, confidence, and sensitivity;
- typed protobuf payload (`google.protobuf.Any`);
- evidence references and optional integrity metadata; and
- correlation and causation IDs.

The payload type URL is part of the schema contract. A producer MUST NOT use an
event kind with an unrelated payload type. Unknown kinds are stored and may be
displayed generically; they do not drive enforcement until explicitly
supported.

## Initial event kinds

```text
node.enrolled                 node.heartbeat
node.capabilities_changed     node.suspended
node.revoked

network.interface_changed     network.gateway_changed
network.wifi_changed          network.route_changed
network.dns_changed           flow.started
flow.updated                  flow.ended
service.listening

mesh.peer_changed             mesh.path_changed
mesh.exit_changed             mesh.connection_lost

posture.changed               policy.compiled
policy.applied                policy.failed
policy.rolled_back            finding.opened
finding.updated               finding.resolved

action.held                   action.allowed
action.blocked                action.bypassed

field.report_imported         field.report_submitted
field.report_verified         field.report_expired
field.report_disputed         field.report_removed

scrambler.state_proposed      scrambler.state_applied
scrambler.state_failed        scrambler.state_rolled_back
```

New kinds are additive. Renaming a kind requires producing the old kind until
all supported consumers can process the new one or introducing a new API
version.

## Payload registry

The initial kind-to-`Any` message mapping is normative:

| Kinds | Payload message |
| --- | --- |
| `node.enrolled`, `node.suspended`, `node.revoked` | `antiflock.v1.Node` |
| `node.heartbeat` | `antiflock.v1.NodeHeartbeat` |
| `node.capabilities_changed` | `antiflock.v1.CapabilityManifest` |
| `network.interface_changed` | `antiflock.v1.NetworkInterfaceObservation` |
| `network.gateway_changed` | `antiflock.v1.GatewayObservation` |
| `network.wifi_changed` | `antiflock.v1.WifiObservation` |
| `network.route_changed` | `antiflock.v1.RouteObservation` |
| `network.dns_changed` | `antiflock.v1.DnsObservation` |
| `flow.started`, `flow.updated`, `flow.ended` | `antiflock.v1.FlowObservation` |
| `service.listening` | `antiflock.v1.ListeningServiceObservation` |
| `mesh.peer_changed` | `antiflock.v1.MeshPeerObservation` |
| `mesh.path_changed`, `mesh.exit_changed`, `mesh.connection_lost` | `antiflock.v1.MeshPathObservation` |
| `posture.changed` | `antiflock.v1.ProtectionSnapshot` |
| `policy.compiled` | `antiflock.v1.Plan` |
| `policy.applied`, `policy.failed`, `policy.rolled_back` | `antiflock.v1.PlanExecutionResult` |
| `finding.opened`, `finding.updated`, `finding.resolved` | `antiflock.v1.Finding` |
| `action.held`, `action.allowed`, `action.blocked`, `action.bypassed` | `antiflock.v1.SecureActionDecision` |
| all `field.report_*` kinds | `antiflock.v1.FieldReport` |
| all `scrambler.state_*` kinds | `antiflock.v1.ScramblerTransition` |

Type URLs use the standard `type.googleapis.com/` prefix followed by the fully
qualified protobuf message name. A future kind or payload version is
registered before it drives a projection or decision.

## Delivery semantics

Delivery is at least once. Ingestion authenticates the source, validates size
and schema, and deduplicates by event ID. Sequence gaps, regressions, duplicated
IDs with different content, invalid timestamps, or signatures produce audit
findings. Core acknowledges the highest contiguous accepted sequence plus
explicit rejects so an agent does not assume a gap was accepted.

Agents queue while offline within a configured byte and age bound. Queue
pressure drops the least security-critical records first according to an
explicit policy, emits a loss summary, and never silently drops enrollment,
revocation, policy, plan, bypass, rollback, posture transition, or finding
events.

## Time, ordering, and replay

Ordering is guaranteed only within one node sequence. Cross-node views use
observation time with receipt time and clock-quality metadata visible. A late
event updates a replayed projection but does not rewrite the historical audit
decision. Projection code is deterministic for a declared version, records a
cursor, and can rebuild from the append-only store.

Corrections and redactions are new events referencing affected IDs. When data
must be deleted, a non-sensitive tombstone may preserve deduplication and audit
integrity without retaining the deleted content.

## Evidence and privacy

An envelope's evidence class describes the payload claim, not the transport's
authenticity. A signed node can submit a `REPORTED` claim. Authentication does
not promote it to `VERIFIED`.

Payloads follow the privacy invariants: flow events contain metadata and
best-effort process attribution, not packet content; field proximity checks do
not carry a continuous exact-location trail; private keys and enrollment token
values are never events; sensitive identifiers are minimized or referenced by
opaque local IDs.

## Live UI stream

Live messages are projections, not a second source of truth. Reconnection uses
a cursor and resumes from durable events. Initial topics are `posture.changed`,
`finding.opened`, `finding.resolved`, `node.changed`, `path.changed`,
`action.held`, and `scrambler.changed`. A dropped live connection cannot change
endpoint enforcement.
