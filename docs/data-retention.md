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
| Local event envelopes, including flow metadata, route, DNS, mesh, and posture events | 14 days | Off | No payloads. Classification and sensitivity overrides may shorten this maximum but cannot extend it. |
| Open findings and evidence | While open; 30 days after resolution | Off | Preserve source expiry and dispute state. |
| Policy, plan, bypass, rollback, enrollment, and revocation audit | No automatic compaction in v1 | Off | Security-relevant minimal audit; secrets and token values excluded. A future 90-day compactor requires an externally witnessed checkpoint design. |
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

Scheduled event deletion never advances ahead of a required durable projection.
A lagging projection pauses source-event deletion and produces a visible audit
finding; this is an explicit temporary retention extension, not silent data
loss. Backups inherit the same class and are
cryptographically expired or deleted on a disclosed bounded schedule.
Security incident preservation or a valid legal requirement may temporarily
hold narrowly identified records. The operator is informed when legally and
operationally permitted, and unrelated data continues expiring.

Exports include schema version, provenance, sensitivity, and expiry metadata.
Deletion removes source records only after every required projection has
durably consumed them. A canonical chained tombstone records the deleted
ordinal range, count, policy, and batch digest without retaining event
contents. SQLite secure deletion and a truncated WAL checkpoint remove the
committed record bytes from the active database and journal; backup retention
remains a separate operator responsibility. Independently persisted derived
projections are outside this event-pruning transaction and require their own
class-specific deletion before they can be represented as erased.

Audit compaction is disabled in v1. The local signed anchor journal detects
database-only truncation while it remains intact. Detecting coordinated
rollback of both the database and local anchor requires a TPM monotonic
counter, remote witness, or separately protected export and is not claimed.
The retention tombstone chain has the same whole-database rollback limitation.
