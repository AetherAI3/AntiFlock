# Signing contracts

Signatures protect authority and integrity; they do not upgrade an evidence
class. A signed community report remains `REPORTED` unless a documented
verification method changes its claim.

## Deterministic signing profile v1

`SIGNATURE_ENCODING_PROTOBUF_DETERMINISTIC_V1` uses this profile:

1. Construct the signable view defined below and reject unknown fields in a
   signed object. The producer and verifier use the same `antiflock.v1` schema.
2. Serialize that view with deterministic protobuf binary serialization.
3. Hash the bytes using the algorithm in `signed_content_digest` (initially
   SHA-256) and compare the recomputed digest in constant time.
4. Sign and verify the following byte strings in order: ASCII
   `AntiFlock-Signature-v1`; UTF-8 signature domain; signature algorithm enum
   number as unsigned 32-bit network byte order; UTF-8 digest algorithm name;
   digest bytes; and `signed_at` as signed 64-bit UTC seconds followed by
   unsigned 32-bit nanoseconds, both network byte order. Prefix every byte
   string with its unsigned 32-bit network-byte-order length.
5. Verify key purpose, deployment, subject, status, issue/expiry, revocation,
   and algorithm policy in addition to the cryptographic signature.

An unspecified encoding, domain, digest, algorithm, or key fails closed.
Implementations MUST NOT fall back to a language's default protobuf encoding.

## Signable views and domains

| Object | Domain | Signable view |
| --- | --- | --- |
| `CapabilityManifest` | `antiflock.capability-manifest.v1` | Entire message with `signature` cleared. |
| `EventEnvelope` | `antiflock.event.v1` | Entire source-submitted message with `source_signature` and Core-assigned `received_at` cleared. Core sets `received_at` once after successful verification; the stored envelope is then immutable. |
| `Plan` | `antiflock.plan.v1` | Entire message with `signature`, mutable `status`, and display-only `human_readable_dry_run` cleared. Executable content, target, revisions, nonce, expiry, checks, actions, rollback, recovery allowlist, and sensitivity are covered. |
| `PlanExecutionResult` | `antiflock.plan-result.v1` | Entire message with `node_signature` cleared. |
| `IntelligencePackManifest` | `antiflock.intelligence-pack.v1` | Entire message with `signature` cleared. The manifest digest separately covers the exact downloaded pack bytes. |

Credential certificates use their certificate format's signing rules, not this
profile. At-rest audit chaining may add a separate signature, but cannot remove
or replace source signatures.

## Replay protections

A valid signature is necessary but not sufficient. Plan acceptance also checks
deployment and node target, nonce, monotonic policy and plan revisions, issue
and expiry time with bounded clock-skew policy, capability requirements, and
whether the plan ID already has a terminal result. Event ingestion binds the
authenticated channel to `deployment_id` and `node_id`, checks event ID and
sequence, and rejects a duplicate ID with different content.

Key rotation preserves old public verification material for the disclosed
audit-retention window. Revocation prevents new acceptance immediately when
reachable; historical signatures retain a record of what key signed them and
whether that key was valid at the signing time.
