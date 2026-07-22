# AntiFlock Secure Action SDK for TypeScript

This package lets an AntiFlock-aware application describe a sensitive action,
ask a local AntiFlock agent for a deterministic decision, and execute only when
that decision permits it. The SDK never sends the action payload to the agent.

Supported decisions are `ALLOW`, `HOLD`, `BLOCK`, `REQUIRE_CONSENT`, and
`ALLOW_ONCE`. A `HOLD` can wait for a protection-restored signal and is then
re-evaluated before release. An `ALLOW_ONCE` grant is bound to the request ID,
application, action type, and exact destination set; it is claimed before the
operation begins and cannot be reused by the same client instance.

```ts
import {
  FetchLoopbackTransport,
  SecureActionClient,
} from "@aether/antiflock-secure-action";

const token = process.env.ANTIFLOCK_TOKEN;
if (!token) throw new Error("ANTIFLOCK_TOKEN is required");

const antiflock = new SecureActionClient(
  new FetchLoopbackTransport({ bearerToken: token }),
);

const result = await antiflock.execute(
  {
    id: crypto.randomUUID(),
    applicationId: "aether-code",
    nodeId: "operator-laptop",
    actionType: "git.push",
    destinations: ["github.com"],
    dataClass: "repository-source",
    sensitivity: "CONFIDENTIAL",
    operationId: crypto.randomUUID(),
  },
  async () => pushRepository(),
  { retryOnProtectionRestored: true },
);
```

## Local transport boundary

`AgentTransport` is deliberately platform-neutral. `FetchLoopbackTransport`
implements an authenticated loopback protocol, requires a bearer token by
default, and refuses non-loopback hosts by default. Native applications can
supply transports backed by Unix-domain sockets, Windows named pipes, or mobile
app services without changing the decision engine.

Core separates application execution from operator consent. The ordinary
`bearerToken` can evaluate, wait, and append lifecycle audit, but cannot call
the one-time authorization endpoint. A trusted local consent host may provide
`authorizationBearerToken`; ordinary applications should omit it and use an
external operator flow such as Third-Eye, then re-evaluate the exact request.

The evaluate and authorize payloads are projections of canonical
`antiflock.v1.ActionGateService` messages: evaluate sends
`EvaluateSecureActionRequest` as `{ "action": ... }`, and authorize sends the
fields from `AuthorizeSecureActionRequest`. Protobuf enum names are used on the
wire and translated to the SDK's concise decision names.

The loopback adapter uses:

- `POST /v1/actions/evaluate` — canonical evaluate projection
- `POST /v1/actions/{id}/authorize` — canonical authorize projection
- `POST /v1/actions/{id}/wait` — REST extension that durably waits for a newer
  protection snapshot
- `POST /v1/actions/{id}/audit` — idempotent REST extension keyed by `eventId`

`wait` and `audit` are intentionally identified as REST extensions; they are
not claimed as methods in the canonical gRPC service. An agent may implement
the same `AgentTransport` semantics with a local stream and append-only audit
queue instead.

The local agent remains authoritative: it must authenticate clients, persist
decision/audit history, issue opaque one-time tokens, and atomically reject
replayed grants. Client-side scope and replay checks add defense in depth; they
do not replace agent-side enforcement.

Every returned decision must carry an `actionId` equal to the evaluated request
ID. The SDK rejects crossed or cached responses, and it rejects a plain `ALLOW`
unless the accompanying posture is `PROTECTED`. Immediately before calling
application code it rechecks the request deadline, cancellation signal, and any
one-time expiry after the execution-start audit/consume await.

The canonical decision does not carry a separate audit object. The HTTP adapter
derives correlation metadata from the operation ID and canonical protection
snapshot (snapshot ID, node ID, policy revision, and evaluation time), labels
its evidence class `UNKNOWN`, and preserves the server's reason codes. Native
transports may return richer audit metadata directly.

Audit writes are required by default. Set `auditMode: "best-effort"` only for a
deliberately degraded integration. The execution-start append for an
`ALLOW_ONCE` grant remains mandatory in every mode because Core consumes the
grant atomically with that append. If a completion audit fails after an action
ran, `AuditAppendError.actionMayHaveExecuted` is `true` so callers do not retry
the underlying operation blindly.
