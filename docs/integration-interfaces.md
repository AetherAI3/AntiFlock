# Integration interfaces

AntiFlock is infrastructure-neutral. The public repository depends on no
hosted service, control plane, or vendor account, and a downstream deployment
attaches its own services through the seams in `core/integration` without
modifying core. This document is the contract for those seams: what crosses
each one, what core guarantees to an adapter, what an adapter must guarantee
back, and how to write one out of tree.

Code: `core/integration` (interfaces, value types, registry),
`core/integration/fake` (in-memory implementations),
`core/integration/conformance` (executable contract),
`adapters/witness/file` and `adapters/witness/http` (reference witnesses).

## Versioning

`integration.InterfaceVersion = 1` covers every interface and value type in
the package. A `Registry` rejects a registration that declares another
version (`ErrVersionMismatch`), so a mismatched adapter fails at wiring time.
Breaking changes bump the version; additive changes to an outbound value type
are **not** considered additive here (see "Privacy-minimal data"), so they
bump it too.

## Seams

| Kind | Interface | Direction | Carries |
| --- | --- | --- | --- |
| `external-witness` | `ExternalWitness.Submit(ctx, Checkpoint) (WitnessReceipt, error)` | core → out | audit-head checkpoint; signed receipt back |
| `identity-provider` | `IdentityProvider.Authenticate(ctx, Credential) (Principal, error)` | core → out | one generic credential; subject digest + scopes back |
| `policy-source` | `PolicySource.Fetch(ctx, PolicyRef) (SignedPolicy, error)`, `Watch(ctx) (<-chan PolicyRef, error)` | out → core | opaque signed bytes; core verifies |
| `event-sink` | `EventSink.Emit(ctx, Event)`, `EmitBatch(ctx, []Event)` (≤ `MaxEventBatch` = 256) | core → out | event references with evidence class and trust-envelope digest |
| `finding-sink` | `FindingSink.Publish(ctx, FindingSummary)` | core → out | id, severity, status, evidence class, digest |
| `decision-consumer` | `DecisionConsumer.Consume(ctx, Decision)` | core → out | signed, digest-bound protected-action decision |
| `recovery-verifier` | `RecoveryVerifier.VerifyRecovery(ctx, RecoveryClaim) (RecoveryVerdict, error)` | core → out → core | nonce-bound reachability claim; evidence verdict back |

Every interface's Go doc comment states its version, guarantees, failure
semantics, and privacy rule; this table is the index, the doc comment is the
contract.

### Failure semantics (all seams)

- `ErrInvalidInput`: refused before any side effect; do not retry unchanged.
- `ErrUnavailable`: outcome unknown; retry with the same input is safe.
  `integration.IsRetryable(err)` tests for it.
- `ErrNotFound`, `ErrUnauthenticated`, `ErrInvalidReceipt`,
  `ErrInvalidSignature`, `ErrBatchTooLarge`: permanent for that input.
- Every method returns `ctx.Err()` once the context is done.
- No adapter failure blocks local detection or enforcement. Witness, sink,
  and consumer failures degrade *evidence*; identity-provider failure fails
  closed to *unauthenticated*; a missing recovery verdict is *UNKNOWN*, never
  *reachable*.

### What core guarantees to an adapter

1. Inputs arrive validated (`Validate()` has passed). An adapter may
   re-validate and must never accept more than the seam defines.
2. Values are passed by value or as caller-owned copies; an adapter never
   shares memory with core state.
3. Core never hands an adapter a secret except the `Credential` an
   `IdentityProvider` exists to authenticate, and the option values the
   operator configured for that adapter.
4. Core verifies everything that comes back: receipts under the witness key,
   policies under core's keyring and `core/policy` rules, decision digests and
   signatures, verdict nonces. An adapter is a transport, never an authority.
5. Construction goes through an explicit `Registry` (no globals, no `init()`
   registration). Unknown names, duplicate names, kind mismatches, wrong
   versions, nil factories, and factories returning the wrong type all fail
   closed.

## Privacy-minimal data

Each outbound value type has a pinned field allowlist in
`core/integration/privacy_test.go`. The test reflects over the struct and
compares name and type with the allowlist, then rejects any field whose name
suggests raw content (`NodeID`, `Label`, `Address`, `Payload`, `Body`,
`Content`, `Telemetry`, `Email`, `Name`) unless it is a `...Digest`. Adding a
field fails the build until the allowlist, this document, and the threat
model are updated together.

Rules the allowlists encode:

- Identifiers that name a deployment, node, subject, or action cross as
  `sha256` hex digests (`integration.DigestString`), never raw.
- Deployment size crosses as a bucket (`0`, `1-9`, `10-99`, `100-999`,
  `1000+`) or not at all.
- Event bodies, finding titles and facts, request destinations, and trust
  envelopes cross as digests. `internal/trust` is referenced by digest string
  only; the seams do not import it.
- Evidence classes (`DETECTED`, `VERIFIED`, `REPORTED`, `INFERRED`,
  `SUSPECTED`, `UNKNOWN`) are carried verbatim and may never be relabelled by
  an adapter.
- A `RecoveryVerdict` has no authorization field by construction; it is
  evidence with a class of `OBSERVED` (the verifier reached the node itself;
  maps to `DETECTED`) or `REPORTED`.

### The witness checkpoint

```
Checkpoint{
  DeploymentDigest string          // sha256(deployment id)
  AuditHeadDigest  string          // audit head EntryHash
  Sequence         uint64          // > 0
  IssuedAt         time.Time
  NodeCountBucket  NodeCountBucket // optional
}
```

That is the complete set. A witness learns that *some* deployment's audit
head had *this* digest at *this* sequence at *this* time. It learns no node,
no label, no actor, no event, and cannot correlate two deployments except by
digest equality.

## Witness wire format (HTTP reference)

`adapters/witness/http` POSTs `application/json`:

```json
{"version":1,"checkpoint":{"deploymentDigest":"…","auditHeadDigest":"…","sequence":42,"issuedAt":"2026-08-23T12:00:00Z","nodeCountBucket":"1-9"}}
```

and expects `200`/`201` with at most 64 KiB of:

```json
{"witnessId":"…","checkpointDigest":"…","witnessedAt":"…","signature":"<base64url raw Ed25519>","keyId":"witness:<sha256 of PKIX public key>"}
```

`checkpointDigest` is `sha256` of the canonical JSON
`{"version":1,"deploymentDigest","auditHeadDigest","sequence","issuedAt"(RFC 3339 nano, UTC),"nodeCountBucket"}`;
the signature covers the ASCII hex of `sha256` of the canonical JSON
`{"version":1,"witnessId","checkpointDigest","witnessedAt","keyId"}`.
`409`/`422` map to `ErrInvalidInput` (refused, e.g. sequence regression);
`429`/`5xx` map to `ErrUnavailable`. Unknown fields and trailing data are
rejected. HTTPS is mandatory except for loopback hosts; an optional pinned CA
replaces the system roots; redirects are disabled; a bearer token, when
configured, is sent and never appears in `DryRun()`.

`adapters/witness/file` is the same witness as an append-only JSONL journal
plus a 0600 Ed25519 seed file. It verifies every journal line under its own
key on open, refuses per-deployment sequence regressions, truncates a torn
trailing line, and never rewrites history.

## Writing a downstream adapter out of tree

A deployment that runs its own control plane, ledger, identity service, or
notification bus writes one Go package per seam it needs, in its own module:

1. Import `github.com/DBarr3/AntiFlock/core/integration` only. Do not import
   `core/audit`, `core/policy`, or `internal/*`; everything an adapter needs
   is in the seam package.
2. Implement the interface. Wrap the sentinel errors (`fmt.Errorf("%w: …",
   integration.ErrUnavailable)`) so core can classify failures.
3. Keep the transport rules of the reference adapters: TLS or loopback only,
   bounded responses, `DisallowUnknownFields`, no redirects, timeouts,
   injected `HTTPDoer` for tests.
4. Prove conformance from the adapter's own test package:

   ```go
   func TestMyWitness(t *testing.T) {
       conformance.RunExternalWitness(t, func(t *testing.T) (integration.ExternalWitness, ed25519.PublicKey) {
           w := mywitness.New(...)   // typically against an httptest.NewTLSServer
           return w, w.PublicKey()
       })
   }
   ```

   `RunIdentityProvider`, `RunPolicySource`, `RunEventSink`,
   `RunFindingSink`, `RunDecisionConsumer`, and `RunRecoveryVerifier` are the
   equivalents for the other kinds.
5. Expose a `Factory func(ctx, integration.Options) (any, error)` and register
   it in the deployment's composition root:

   ```go
   registry := integration.NewRegistry()
   _ = registry.Register("file", integration.KindExternalWitness, file.Factory)
   _ = registry.Register("https", integration.KindExternalWitness, witnesshttp.Factory)
   _ = registry.Register("my-ledger", integration.KindExternalWitness, mywitness.Factory)
   witness, err := registry.NewExternalWitness(ctx, cfg.WitnessName, cfg.WitnessOptions)
   ```

   Names are lowercase `[a-z0-9][a-z0-9._-]{0,63}`; `Options` is a bounded
   `map[string]string` copied before the factory sees it.

Nothing in this flow names a server, route, or topology: a private
deployment's adapter is a detail of that deployment, and the public
repository neither knows nor needs to know it exists.

## Wiring status

The seams, fakes, conformance suites, and the two reference witnesses are
complete and tested. `core/audit` does not yet call an `ExternalWitness`; the
follow-up that adds an optional witness to the audit service (submit a
`Checkpoint` after each anchor advance, record the receipt, treat witness
failure as degraded evidence) is described in the pull request that
introduced this document and is owned by the same lane.
