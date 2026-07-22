# Architecture

## Locked shape

AntiFlock Core is the control, intelligence, and policy plane, not the packet
data plane. Established mesh software transports encrypted packets directly
between endpoints. Core manages AntiFlock identity, ingests events, projects
state, compiles policy, signs plans, serves the UI, and explains results.

The first implementation is a modular monolith:

```text
Endpoint collectors and provider adapters
                 |
        authenticated event ingestion
                 v
   append-only event store --> replayable projections
                 |              |-- asset and observer topology
                 |              |-- network state and paths
                 |              |-- posture and findings
                 |              `-- activity stream
                 v
 deterministic policy compiler --> signed, expiring per-node plans
                 |                         |
                 |                         v
                 `----------------> endpoint enforcer
                                             |
                                    verify or roll back
```

One `antiflock-core` process, one `antiflock-agent` per endpoint, a separate
least-privilege helper where elevated OS access is required, one web UI, and a
relational local database are sufficient for the first vertical slice.
Microservices, a graph database, and a custom mesh transport are deferred.

## Failure domains

Core outages MUST NOT disable already-established mesh traffic or endpoint
protection. Each agent retains:

- its stable device identity and private key;
- the last valid signed policy and monotonic revision;
- the current enforcement plan and rollback state;
- explicit expiry and emergency recovery rules;
- a bounded local event queue; and
- a deterministic local posture evaluator.

Agents reject unsigned, expired, replayed, wrongly targeted, or lower-revision
plans. A stale policy may continue only within its declared offline validity.
When that validity ends, behavior follows the policy's explicit fail mode; the
agent never silently converts fail-closed to fail-open.

## Component boundaries

Domain code depends on contracts and capability interfaces, never directly on
Tailscale commands, nftables, Android APIs, or a particular database driver.
Adapters implement observation and mutation interfaces. Provider identity is
an association on an AntiFlock node, not the node's canonical identity.

Every device publishes a capability manifest describing what it can observe,
enforce, and verify, including limitations such as partial process
attribution. The compiler MUST NOT emit an operation that the target does not
declare and prove it supports.

## Event and state model

Authenticated agents and adapters submit immutable, idempotent event
envelopes. The event store is append-only; corrections are new events.
Projection cursors allow deterministic replay into relational entities and
relationships. Received time never replaces observed time, and delayed events
must not silently rewrite decisions made with the evidence then available.

Posture is a derived snapshot, not a mutable truth flag. Findings link a
deterministic reason code to current and expected facts, evidence, confidence,
wording, response, and false-positive context.

Nano v0.1 sits above that decision state as a deterministic proposal layer.
Typed findings become bounded numeric signals; admitted programs may emit only
trace-only observations or immutable proposals for the existing Secure Action
gate. Nano never receives a mutation or provider capability. See
[the Nano watchdog boundary](nano-watchdog.md).

## Plan transaction

Mutating behavior uses one transaction shape for Guard and Scrambler:

1. Validate policy and node capabilities.
2. Compare desired and observed state.
3. Produce a human-readable dry run.
4. Sign a targeted plan containing nonce, monotonic revision, expiry,
   preconditions, actions, verification checks, and rollback steps.
5. Revalidate locally, capture rollback state, and apply.
6. Verify from the endpoint's actual path.
7. Commit on success or roll back on failure.
8. Emit signed audit events for every transition and exception.

Recovery and coordination traffic is narrowly allowlisted. Local CLI recovery,
safe-mode startup, an expiring one-time bypass, and physical-local override
prevent a malformed remote policy from permanently locking an operator out.

## Data locality

Exact continuous device location remains local by default. Devices download
signed regional intelligence packs and perform nearby matching on-device.
Only deliberate report submissions leave the device, using the minimum useful
precision. Private keys and recovery secrets never leave their origin in
plaintext. Standard collectors record connection metadata, not payloads.

## First vertical slice

The reference proof joins a simulated endpoint to an untrusted network, loses
the approved route, evaluates locally, records fail-closed enforcement intent,
reports the broken path without alleging interception, holds an integrated
sensitive action, restores and verifies simulation-labeled mesh/DNS/exit state,
releases the action, and leaves a complete durable local audit trail.

Production readiness is a separate gate. It requires a real packet transport,
privileged platform enforcement, real-network and real-device validation, and
independent security and privacy review; see
[release status](release-status.md).
