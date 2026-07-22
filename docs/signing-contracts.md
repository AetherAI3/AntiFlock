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
   digest bytes; signed 64-bit UTC seconds; and unsigned 32-bit nanoseconds,
   all integers in network byte order. Seconds and nanoseconds are two distinct
   byte strings. Prefix each of these seven byte strings independently with its
   unsigned 32-bit network-byte-order length.
5. Verify key purpose, deployment, subject, status, issue/expiry, revocation,
   and algorithm policy in addition to the cryptographic signature.

An unspecified encoding, domain, digest, algorithm, or key fails closed.
Implementations MUST NOT fall back to a language's default protobuf encoding.

### Cross-language event vector

The repository test vector uses Ed25519 seed bytes `00` through `1f`, whose
raw public key is
`03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8`.
For its `EventEnvelope`, the deterministic signable-view SHA-256 digest is
`5379a5dc61df6b8b81a69a9227dd5a4ed747def3ca2cdb9d49e0ad60ab4b53fb`.
At `2026-07-21T19:04:05.123456789Z`, the exact signature preimage is:

```text
00000016416e7469466c6f636b2d5369676e61747572652d763100000012616e7469666c6f636b2e6576656e742e7631000000040000000100000006736861323536000000205379a5dc61df6b8b81a69a9227dd5a4ed747def3ca2cdb9d49e0ad60ab4b53fb00000008000000006a5fc2a500000004075bcd15
```

The resulting signature is
`5e3e0d84b8f4cab09dbba9ecde69bdf27fdc4312c9d1c105963302b6b2371e075349bb5c311f4c5a89d155cb2d69d8314cb3ce44e8df936972cfe5a18191c102`.

## Enrollment proof of possession

The enrollment token wire value is ASCII `af_enroll_v1.` followed by the
canonical unpadded base64url encoding of exactly 64 pseudorandom bytes. Core
derives those bytes with HMAC-SHA-512 from its protected local authority secret,
the domain `AntiFlock-Enrollment-Derivation-v1`, and independently
length-prefixed authenticated actor and idempotency-operation IDs. This makes
an identical response retryable without storing plaintext. Core stores only
`SHA-256("AntiFlock-Enrollment-Token-v1\\x00" || raw_token_bytes)` and never
logs or persists the wire value. Changing the actor or requested scope for the
same operation ID fails with an idempotency conflict.

To construct `proof_of_possession`, clone the exact canonical
`antiflock.v1.EnrollNodeRequest`, reject unknown protobuf fields, and clear
only `proof_of_possession`. Deterministically protobuf-serialize the clone.
The proof preimage is the unsigned 32-bit network-byte-order length and ASCII
bytes of `AntiFlock-Enrollment-PoP-v1`, followed by the same length prefix and
the serialized request. The endpoint signs the SHA-256 digest of that preimage
with the submitted Ed25519 private key. Core accepts only an exact 64-byte
signature and never normalizes or defaults a signed request field.

The initial capability manifest has no assigned node ID yet. Enrollment
therefore requires its `node_id` and manifest `signature` to be empty, covers
the entire manifest with the outer proof, and records its contents as
`CLAIMED`. A later node-bound manifest may use the capability-manifest signing
profile; a node cannot self-upgrade a capability to verified.

## Signable views and domains

| Object | Domain | Signable view |
| --- | --- | --- |
| `CapabilityManifest` | `antiflock.capability-manifest.v1` | Entire message with `signature` cleared. |
| `EventEnvelope` | `antiflock.event.v1` | Entire source-submitted message with `source_signature` and Core-assigned `received_at` cleared. Core sets `received_at` once after successful verification; the stored envelope is then immutable. |
| `Plan` | `antiflock.plan.v1` | Entire message with only `signature` and mutable execution `status` cleared. Executable content, human-readable dry run, target, revisions, nonce, expiry, checks, actions, rollback, recovery allowlist, and sensitivity are covered. |
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

## Deployment identity persistence

First initialization is a crash-resumable transaction. Core writes a
current-user-only staging directory, hashes every staged artifact into a
manifest signed by the audit key, makes the stage durable, and installs
`deployment.json` last as the commit marker. A restart may reuse a verified
stage and byte-identical partial installation; it never overwrites a differing
key, certificate, recovery credential, or signed state. The initialization
lock is an OS-held file lock, so process exit releases it without deleting or
rewriting a possibly reused lock path.

The signed deployment state binds the digest of
`verification-keyring.json`. That keyring retains stable key IDs and current
plus historical audit public keys and CA certificates. Private keys are not
placed in the verification keyring. Rotation is not complete until the new
current key, retired key's public verification material, key IDs, and signed
state have been durably committed together; consumers must pass retained audit
public keys to the audit verifier for historical entry and anchor validation.

On POSIX systems the identity directory and sensitive files are restricted to
the owning user and parent-directory mutations are synchronized. On Windows,
Core installs a protected, non-inheriting DACL granting access only to the
current user and uses write-through, no-replace moves for first installation.
