# Protection states

Protection state is a deterministic conclusion about a policy at a point in
time. It is not a fear score and not an assertion about an attacker's intent.

| State | Meaning | Example wording |
| --- | --- | --- |
| `PROTECTED` | Every required control that can make the conclusion is freshly verified. | "Required mesh, exit, and DNS controls are verified." |
| `DEGRADED` | Protection still operates, but a non-critical requirement is unmet or reduced. | "Protection remains active, but process attribution is partial." |
| `SUSPICIOUS` | Evidence is consistent with a possible active security event but is inconclusive. | "Gateway behavior is unusual; interception is suspected, not confirmed." |
| `EXPOSED` | A required protection is definitively absent, bypassed, or violated. | "The approved exit is not active; protected egress is blocked." |
| `UNKNOWN` | Fresh facts or capabilities are insufficient to evaluate one or more required controls. | "DNS path cannot be verified with current telemetry." |
| `UNAVAILABLE` | The evaluator or protection service cannot provide a current result. This is operational availability, not evidence that the path is safe or unsafe. | "Protection status is unavailable on this device." |

`BLOCKED`, `VERIFYING`, and `CONNECTING` are enforcement or lifecycle states,
not protection conclusions. A UI may show both, for example `EXPOSED / BLOCKED`.

## Precedence

For one evaluated policy, state precedence is:

1. `EXPOSED` when a definitive required-control failure exists.
2. `SUSPICIOUS` when no exposure is established but active-event indicators
   satisfy a suspicion rule.
3. `UNKNOWN` when neither of the above applies and required evidence is absent
   or stale.
4. `DEGRADED` when evidence is sufficient and protection is partially
   functional but a lesser requirement is unmet.
5. `PROTECTED` only when all required controls are freshly verified.

`UNAVAILABLE` is returned only when evaluation itself cannot run or no valid
snapshot exists. It MUST NOT be used to hide a known `EXPOSED` state retained
within its valid lifetime.

## Required snapshot fields

A protection snapshot includes policy and node IDs, policy revision, state,
evaluation time, valid-until time, capabilities considered, reason codes,
current facts, expected facts, evidence references, confidence, enforcement
state, and the recommended response. Every transition is emitted as an event.

## Freshness and recovery

Each rule declares telemetry freshness. Stale inputs transition to `UNKNOWN`,
not `PROTECTED`. Core disconnection alone does not force exposure: an endpoint
may keep evaluating cached policy locally. When a protected path is restored,
the endpoint verifies mesh, route, DNS, external exit identity, and applicable
health checks before releasing held actions or reporting `PROTECTED`.
