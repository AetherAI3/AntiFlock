# Live TypeScript SDK acceptance

`npm run test:sdk:live` is the deterministic acceptance for the real
TypeScript Secure Action SDK boundary. It builds the SDK, runs Core and the
signed simulator against the persistent private Compose volumes, and proves:

- `FetchLoopbackTransport` receives `HOLD` from live Core while posture is
  explicitly `EXPOSED`;
- signed, simulation-labeled recovery evidence releases the wait and forces a
  fresh evaluation to `ALLOW`;
- the harness explicitly opts into simulation execution and the protected
  operation callback runs exactly once;
- all six SDK lifecycle records survive a Core restart; the five non-start
  records accept byte-for-byte idempotent replay while a replayed execution
  start fails closed with HTTP `409`; and
- changed-content probes for every lifecycle ID fail with HTTP `409`, proving
  the durable IDs cannot be reused with different content.

The harness never enables the transport's non-loopback escape hatch. A
least-privilege Compose-profile bridge forwards a script-selected temporary
`127.0.0.1` port to Core's internal-only network. The harness removes that
bridge in `finally`, verifies that Core itself has no host port, and restores
the prior service state.

This is a deterministic simulation acceptance. It does not claim that a host
VPN, DNS route, or external egress was measured or changed.

The SDK rejects simulation evidence by default. The harness passes
`allowSimulationExecution: true` for this one controlled callback so a green
result cannot be mistaken for the SDK accepting simulation evidence in an
ordinary integration. Unknown evidence provenance is never executable.
