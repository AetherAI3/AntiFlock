# Mesh driver (`adapters/mesh/driver`) — WIP design contract

Status: WIP (lane S7A, ANTIFL0CK-OSS-COMPLETION-02). No code yet; this file is the CONTRACT step.

## Provider interface (no vendor dependency)
`driver.Driver` is implemented once, generically, over a `MeshProvider`:
`Status`, `Peers`, `Connect(InterfaceConfig)`, `Disconnect`, `RotateKey`, `RevokedPeers`.
Implementations: `wireguard` (real; trusted `wg` + `ip` via injected runner, config on stdin <= 64 KiB),
`tailscalestatus` (observe-only over `adapters/mesh/tailscale`; mutators return
`AF-DRIVER-MESH-PROVIDER-OBSERVE-ONLY`), `fake` (in-memory; conformance, partition, roaming tests).
No control plane is required; partition is reported as DEGRADED + `AF-DRIVER-MESH-PARTITION`, never
as a successful verify.

## Privilege boundary
One trusted binary per provider (absolute, root-owned, non-writable path, copied from
`agent/enforcement/nftables.go:278-330`); `wg setconf <iface> /dev/stdin`; `ip link/addr` helper
declared in the boundary description. Private keys: generated with stdlib `crypto/ecdh` X25519, held
in process memory only; never logged, never in snapshots, receipts, journal or safe messages — only
sha256-truncated fingerprints.

## Recovery statement
The address used to reach the node must not be served by the mesh interface or a peer AllowedIP
unless a recovery allowlist route covers it; Simulate flags `AF-DRIVER-MESH-RECOVERY-LOSS`.
Revoked peers are removed on apply and never re-added by rollback or recovery.

## Probe keys
`mesh.connect.observe`, `mesh.connect.enforce`.

## Environment finding (2026-08-23)
WSL Ubuntu-22.04: `unshare -rn` works, `ip link add wg0 type wireguard` succeeds (kernel module
present), but no `wg` userspace binary is installed and root-owned files appear as uid 65534 inside
the rootless namespace, so the root-ownership trust check must be relaxed test-only for the netns
proof.
