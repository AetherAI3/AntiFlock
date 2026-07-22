# Scrambler safety model

## Purpose and non-claims

Scrambler reduces the persistence of selected, approved observable network
state through controlled transitions. It does not promise anonymity,
undetectability, legality in every jurisdiction, defense against a global
observer, or evasion of lawful controls. Ordinary WireGuard session rekeying
is transport behavior and MUST NOT be marketed as a unique Scrambler feature.

## Authority boundary

Scrambler has no privileged back door. It uses the same capability,
policy, signed-plan, dry-run, precondition, verification, audit, recovery, and
rollback contracts as Guard. A driver may act only on explicitly enabled state
dimensions and approved candidate pools for the target node.

Lower-risk initial dimensions are approved exit selection, DNS profile, relay
preference, route set, and controlled service-instance movement. Overlay
address or identity changes require additional identity, peer-reachability,
and recovery review. Aggressive rotation and adaptive reconnaissance response
remain disabled until bounded disruption and rollback are proven.

## State machine

```text
IDLE -> PLANNING -> PREFLIGHT
                    | reject -> IDLE
                    v
                 DRAINING -> APPLYING -> VERIFYING
                                           | success -> ACTIVE
                                           ` failure -> ROLLING_BACK -> IDLE
```

Every transition is monotonic within one attempt and emits an audit event.
Concurrent transitions for the same scope are forbidden. A transition has a
maximum latency, an overall deadline, and a previous-state snapshot retained
until post-activation verification succeeds.

## Preconditions and verification

Before applying, Scrambler MUST establish that:

- the candidate is policy-allowed, node-supported, healthy, and distinct;
- Core and local recovery remain reachable through approved paths;
- critical sessions are drained or explicitly accepted for disruption;
- rollback actions are complete, local, and validated;
- no candidate exposes a direct-route or DNS leak; and
- operator consent requirements for the profile are met.

After applying, endpoint-local checks verify Core and required peers, DNS,
approved destinations, absence of direct-route leak, expected external exit
identity, critical application health, and transition latency. A failed or
indeterminate required check triggers rollback. `UNKNOWN` is not success.

## Safety response

Rollback is automatic and bounded. If rollback also fails, the endpoint enters
a safe recovery mode, preserves the narrow recovery allowlist, stops further
Scrambler attempts, emits a critical finding, and requires operator action.
Scrambler never keeps rotating to escape a failed verification.

Candidate generation cannot use a person's location, community reports, or a
model-generated suspicion to target or evade specific equipment. Environmental
intelligence may be displayed beside a transition but does not authorize it.

## Commercial trust boundary

Paid Scrambler infrastructure may add more trusted exits, availability,
automation, and managed profiles. It MUST NOT change the underlying evidence
class, protection conclusion, warning honesty, or rollback requirement.
