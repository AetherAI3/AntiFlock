# Data retention

## Principles

Retention is purpose-limited, configurable downward, and enforced by data
class. "Forever" is not a default. Expiry of a claim and deletion of its
underlying record are distinct: a field report may become stale before its
minimal moderation history is deleted.

The following initial defaults are conservative product contracts, not legal
retention advice:

| Data class | Default local retention | Hosted default | Notes |
| --- | ---: | ---: | --- |
| Raw network/flow metadata | 14 days | Off | No payloads. Aggregate before deletion only if the aggregate cannot reconstruct sensitive detail. |
| Interface, route, DNS, mesh, and posture events | 30 days | Off | Security history may be reduced by the operator. |
| Open findings and evidence | While open; 30 days after resolution | Off | Preserve source expiry and dispute state. |
| Policy, plan, bypass, rollback, enrollment, and revocation audit | 90 days | Off | Security-relevant minimal audit; secrets and token values excluded. |
| Local exact location used for matching | Ephemeral | Never uploaded by default | Do not persist a continuous location trail merely to render nearby markers. |
| Deliberately submitted field report | Until source expiry/removal policy | Optional | Store submitted precision only; strip metadata and PII. |
| Downloaded regional packs | Until manifest expiry or replacement | N/A | Delete revoked/expired packs after rollback safety window. |
| Footprint assets and connector data | Until authorization revoked or asset removed | Optional | Re-verify ownership; delete connector tokens immediately on revocation. |
| Enrollment token value | Memory/display once | Never | Store only a verifier/hash until single use or expiry. |
| Private keys and recovery credentials | Until rotation/revocation | Never in telemetry | Protected storage; deletion follows cryptographic lifecycle. |

Hosted retention MUST be opt-in by data class and clearly distinguish local
from uploaded history. A paid plan may offer longer operator-selected
retention, never covert collection.

## Deletion and holds

Scheduled deletion runs even if a projection or integration fails; failures
produce a visible audit finding. Backups inherit the same class and are
cryptographically expired or deleted on a disclosed bounded schedule.
Security incident preservation or a valid legal requirement may temporarily
hold narrowly identified records. The operator is informed when legally and
operationally permitted, and unrelated data continues expiring.

Exports include schema version, provenance, sensitivity, and expiry metadata.
Deletion removes derived projections as well as source records unless a
minimal non-identifying tombstone is required to prevent replay or re-import.
