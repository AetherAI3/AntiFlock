# Enrolled agent, metadata flow monitor, and Nano watchdog

This is the first executable real-agent path. It is deliberately observation-only:
the agent never captures packets, reads application payloads, mutates a mesh
provider, or performs a host/network action.

## What is wired

```text
Linux metadata + optional socket tables + optional Tailscale status
    -> signed event -> private durable queue -> HTTPS/mTLS Core batch -> Third-Eye projections

typed finding -> admitted Nano program -> SQLite cursor -> expiring proposal -> existing consent gate
```

- `antiflock-agent --submit` collects at a fixed interval, signs each event with the enrolled Ed25519 key, writes it to a private bounded queue, and removes it only after Core gives a rejection-free acknowledgement.
- Core accepts an active enrolled node through a verified mTLS client certificate; a bearer token remains only for a loopback/development path.
- `--include-flow-metadata` reads `/proc/net/tcp`, `tcp6`, `udp`, and `udp6` only when opted in. It emits current endpoint/protocol metadata as `flow.updated`; it intentionally reports no payload, byte counter, start time, direction, egress interface, or process identity.
- `--mesh-provider tailscale --submit` runs only `tailscale status --json` and sends peer/path observations through the same queue. It never invokes a Tailscale mutating command.
- `--mesh-provider headscale --submit` calls only Headscale’s `GET /api/v1/node` using a read-only API key from a private file. It reports only explicitly associated peers; it cannot create, move, tag, expire, rename, or delete a Headscale node.
- Nano watchdog admission is a signed-audit Core record: source is compiled against the constrained profile, saved with its immutable digest/binding, and exposed at `POST /v1/watchdogs`. `POST /v1/watchdogs/{id}/run` accepts a typed finding and returns only expiring proposals; it cannot execute an action. Its SQLite cursor is saved before a proposal is returned, so a restart cannot refire the same scheduled finding.

## Run an enrolled Linux agent

Prerequisites:

1. Core is reachable over HTTPS and has its node client CA configured.
2. The node was approved through Core enrollment. Keep the matching Ed25519 seed and issued node client certificate in private files with mode `0600`. The agent uses that same seed for signing and mTLS; do not create a second key copy.
3. Set the real deployment and node IDs used during enrollment. The agent does not synthesize either value.

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
  --client-cert /etc/antiflock/node.pem \
  --ca-cert /etc/antiflock/node-ca.pem \
  --include-flow-metadata \
  --mesh-provider tailscale
```

Omit the flow flag to avoid endpoint metadata. Omit the mesh flag to avoid the
provider probe. To use Headscale instead of Tailscale, save the read-only API key
in a `0600` file and pass an explicit association map:

```json
{ "headscale-provider-id": "node_laptop_01" }
```

```bash
antiflock-agent --node-id node_laptop_01 --deployment-id DEPLOYMENT_ID --submit --once \
  --core-url https://core.example.test --node-key-file /var/lib/antiflock/node.seed \
  --queue-dir /var/lib/antiflock/queue --client-cert /etc/antiflock/node.pem \
  --mesh-provider headscale \
  --headscale-url https://headscale.example.test --headscale-api-key-file /etc/antiflock/headscale.token \
  --headscale-associations-file /etc/antiflock/headscale-associations.json
```

Without `--submit`, the same binary retains its inspect-only
JSON mode. For a loopback development Core, a private `--agent-token-file` can be
used instead of the client certificate; it is rejected for a remote HTTP endpoint.

## Failure behavior

- Core unavailable: signed events stay in the node-bound queue; the agent exits the current cycle with an error and retries on the next invocation/interval.
- Agent reboot: queued telemetry is drained one boot ID at a time, so Core never receives a mixed-boot batch.
- Queue full: collection stops with an error. The agent does not discard older telemetry to make room.
- A malformed/partial Core acknowledgement: no events are removed.
- A suspended or revoked node: Core rejects its mTLS identity before event processing.

## Still OPEN

| Area | Remaining work |
| --- | --- |
| Agent enrollment UX | Generate/import identity and retrieve the approved certificate without a manual handoff; service manager packages and status endpoint. |
| Queue operations | Cross-process lock, retention/health metrics, and a tested recovery procedure for a full queue. |
| Flow monitor | Process attribution, bytes/duration, retention controls, non-Linux collectors, and independent privacy review. |
| Tailscale / Headscale | Roaming/partition tests and dashboard setup/status cards. Both read-only probes are wired into the agent loop. |
| Nano | Automatic finding-to-program scheduling, disable/version lifecycle, proposal audit projection, and replay fixtures. Audited admission plus the deterministic proposal-only API are wired. |
| BYOK providers | Key rotation/revocation, platform-keystore references, outbound egress controls, audit records, and integration tests. The Headscale key is read only from a local private file and never sent to Core/Nano. |

No OPEN item can be enabled by a boolean. Each must gain its own least-privilege
contract, tests, and security/privacy review before it affects a real system.
