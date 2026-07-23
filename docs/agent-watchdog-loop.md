# Enrolled agent, metadata flow monitor, and Nano watchdog

This is the first executable real-agent path. It is deliberately observation-only:
the agent never captures packets, reads application payloads, mutates a mesh
provider, or performs a host/network action.

## What is wired

```text
operator enrollment token -> private Ed25519 seed + signed proof -> pending operator approval
    -> approved mTLS client certificate -> signed event + private durable queue -> Core -> Third-Eye

Linux metadata + optional socket tables + optional Tailscale or Headscale observation
    -> signed event -> private durable queue -> HTTPS/mTLS Core batch -> Third-Eye projections

typed finding -> admitted Nano program -> SQLite cursor -> expiring proposal -> existing consent gate
```

- `antiflock-agent enroll` creates one private Ed25519 seed and a retry-stable signed enrollment proof, then submits a pending request. It does not self-approve, fetch a certificate, or turn on telemetry.
- `antiflock-agent --submit` collects at a fixed interval, signs each event with the enrolled Ed25519 key, writes it to a private bounded queue, and removes it only after Core gives a rejection-free acknowledgement.
- Core accepts an active enrolled node through a verified mTLS client certificate; a bearer token remains only for a loopback/development path.
- `--include-flow-metadata` reads `/proc/net/tcp`, `tcp6`, `udp`, and `udp6` only when opted in on Linux. It emits current endpoint/protocol metadata as `flow.updated`; it intentionally reports no payload, byte counter, start time, direction, egress interface, or process identity. Non-Linux package builds preserve the collector boundary and return `AF-COLLECTOR-FLOW-UNSUPPORTED`; the CLI itself refuses non-Linux collection.
- `--mesh-provider tailscale --submit` runs only `tailscale status --json` and sends peer/path observations through the same queue. It never invokes a Tailscale mutating command.
- `--mesh-provider headscale --submit` calls only Headscale’s `GET /api/v1/node` using a read-only API key from a private file. It reports only explicitly associated peers; it cannot create, move, tag, expire, rename, or delete a Headscale node.
- Nano watchdog admission is a signed-audit Core record: source is compiled against the constrained profile, saved with its immutable digest/binding, and exposed at `POST /v1/watchdogs`. `POST /v1/watchdogs/{id}/run` accepts a typed finding and returns only expiring proposals; it cannot execute an action. `antiflockctl watchdog admit/run` provides the private-token operator command path. Its SQLite cursor is atomically compare-and-swap advanced before a proposal is returned, so a restart or concurrent Core request cannot refire the same scheduled finding.

## Run an enrolled Linux agent

### 1. Request enrollment

Core must be reachable over HTTPS. An operator creates a short-lived agent enrollment token and writes it into a private local file; the token is never sent to the dashboard, queue, or Nano.

```bash
chmod 600 /etc/antiflock/enrollment.token
antiflock-agent enroll \\
  --core-url https://core.example.test \\
  --enrollment-token-file /etc/antiflock/enrollment.token \\
  --state-dir /var/lib/antiflock \\
  --ca-cert /etc/antiflock/node-ca.pem \\
  --node-id node_laptop_01 \\
  --display-name "Laptop 01"
```

Use `--ca-cert` only when the Core certificate is anchored in a private CA. The first command returns a `pending-operator-approval` document. Retrying it reuses the same seed and request ID. An authorized Core operator must approve the request. Then rerun this exact command with the original private token file: Core returns the approved certificate on the authenticated replay, and the agent verifies it matches `/var/lib/antiflock/node.seed` before saving it privately at `/var/lib/antiflock/node.pem`. It never needs a second private key copy or a manual certificate transfer.

### 2. Submit read-only observations

Set the real deployment and node IDs used during enrollment, then run one safe smoke-test cycle:

```bash
# One collection / delivery cycle. This is safe to use as a deployment smoke test.
antiflock-agent \
  --node-id node_laptop_01 \
  --boot-id "$(cat /proc/sys/kernel/random/boot_id)" \
  --deployment-id DEPLOYMENT_ID \
  --submit --once \
  --core-url https://core.example.test \
  --node-key-file /var/lib/antiflock/node.seed \
  --queue-dir /var/lib/antiflock/queue \
  --client-cert /var/lib/antiflock/node.pem \
  --ca-cert /etc/antiflock/node-ca.pem \
  --include-flow-metadata \
  --mesh-provider tailscale
```

Omit the flow flag to avoid endpoint metadata. Omit the mesh flag to avoid the
provider probe. To use Headscale instead of Tailscale, save the read-only API key
in a `0600` file and pass an explicit association map. For a private Headscale certificate, pass its CA PEM with `--headscale-ca-cert`:

```json
{ "headscale-provider-id": "node_laptop_01" }
```

```bash
antiflock-agent --node-id node_laptop_01 --deployment-id DEPLOYMENT_ID --submit --once \
  --core-url https://core.example.test --node-key-file /var/lib/antiflock/node.seed \
  --queue-dir /var/lib/antiflock/queue --client-cert /var/lib/antiflock/node.pem \
  --mesh-provider headscale \
  --headscale-url https://headscale.example.test --headscale-api-key-file /etc/antiflock/headscale.token \
  --headscale-associations-file /etc/antiflock/headscale-associations.json
```

Without `--submit`, the same binary retains its inspect-only
JSON mode. For a loopback development Core, a private `--agent-token-file` can be
used instead of the client certificate; it is rejected for a remote HTTP endpoint.

## Failure behavior

- Core unavailable: signed events stay in the node-bound queue. `--once` returns an error for a supervisor; continuous `--submit` waits for its next interval and retries the exact signed batch.
- Agent reboot: queued telemetry is drained one boot ID at a time, so Core never receives a mixed-boot batch.
- Queue full: that collection cycle is not partially persisted and stops with an error. The agent does not discard older telemetry to make room.
- A malformed/partial Core acknowledgement: no events are removed.
- A suspended or revoked node: Core rejects its mTLS identity before event processing.

## Still OPEN

| Area | Remaining work |
| --- | --- |
| Agent enrollment UX | Service manager packages and status endpoint. Endpoint key generation, retry-safe pending submission, and post-approval certificate retrieval are wired; approval remains deliberately operator-gated. |
| Queue operations | Cross-process lock, retention/health metrics, and a tested recovery procedure for a full queue. |
| Flow monitor | Process attribution, bytes/duration, retention controls, non-Linux collectors, and independent privacy review. |
| Tailscale / Headscale | Roaming/partition tests and live setup/status polling. Both read-only probes are wired into the agent loop; Third-Eye has static setup cards. |
| Nano | Automatic finding-to-program scheduling, disable/version lifecycle, proposal audit projection, and replay fixtures. Audited admission plus the deterministic proposal-only API are wired. |
| BYOK providers | Key rotation/revocation, platform-keystore references, outbound egress controls, audit records, and integration tests. The Headscale key is read only from a local private file and never sent to Core/Nano. |

No OPEN item can be enabled by a boolean. Each must gain its own least-privilege
contract, tests, and security/privacy review before it affects a real system.
