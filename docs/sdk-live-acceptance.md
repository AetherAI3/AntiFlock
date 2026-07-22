# Live TypeScript SDK acceptance

`npm run test:sdk:live` is the deterministic acceptance for the real
TypeScript Secure Action SDK boundary. It builds the SDK, runs Core and the
signed simulator against the persistent private Compose volumes, and proves:

- `FetchLoopbackTransport` receives `HOLD` from live Core while posture is
  explicitly `EXPOSED`;
- signed, simulation-labeled recovery evidence releases the wait and forces a
  fresh evaluation to `ALLOW`;
- the protected operation callback runs exactly once;
- all six SDK lifecycle records survive a Core restart and accept byte-for-byte
  idempotent replay; and
- changed-content probes for every executable (`ALLOW`) lifecycle ID fail with
  HTTP `409` before exact replay, proving they already existed after restart.

The harness never enables the transport's non-loopback escape hatch. A
least-privilege Compose-profile bridge forwards a script-selected temporary
`127.0.0.1` port to Core's internal-only network. The harness removes that
bridge in `finally`, verifies that Core itself has no host port, and restores
the prior service state.

This is a deterministic simulation acceptance. It does not claim that a host
VPN, DNS route, or external egress was measured or changed.
