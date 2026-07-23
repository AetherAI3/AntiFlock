# Continuous agent and Nano watchdog loop

This branch begins the production integration path without expanding AntiFlock's authority.

## What is implemented in this increment

- `agent/ingest` submits an already-signed protobuf event batch to Core's existing `POST /v1/events/batch` endpoint. It uses the node-scoped bearer token, accepts only an all-or-nothing acknowledgement, bounds responses, and requires HTTPS except for an explicit loopback development Core.
- `core/nano.Runner` evaluates one admitted Nano program against one typed finding, persists its schedule cursor before exposing a result, rejects stale findings, and returns only existing immutable `SecureActionProposal` values.
- Neither component collects packets, changes a Tailscale/Headscale configuration, calls a live provider, executes an action, or makes a provider credential available to Nano.

## Why this split matters

```text
collector -> enrolled identity signs event -> agent/ingest -> Core event store
finding -> admitted Nano source -> persisted cursor -> proposal -> existing consent gate
```

The transport is intentionally separate from identity enrollment and the Nano runner is intentionally separate from action execution. That keeps credential rotation, queue durability, provider contracts, and operator consent independently reviewable.

## Next implementation increments

1. Persist an enrolled agent identity, sequence allocator, and offline queue on each endpoint; then wire the current Linux collector and Tailscale probe into the transport.
2. Add a durable Core-backed cursor store, signed/versioned watchdog-program admission, and an operator proposal/audit view.
3. Add an opt-in, metadata-only Linux flow collector. It must exclude payloads, use bounded retention, explain process-attribution limits, and be independently privacy reviewed.
4. Add one live provider at a time behind a narrow BYOK contract: local secret reference, least-privilege scope, outbound allowlist, rotation/revocation, provenance, and failure tests.
5. Add Third-Eye setup cards only after the corresponding agent and provider contracts are executable end-to-end.

No step above authorizes privileged enforcement, packet capture, live scraping, Android VPN operation, or a real-world protection claim.
