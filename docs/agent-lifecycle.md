# antiflock-agent lifecycle

This document describes the product command surface of `antiflock-agent`:
what each command does, what it reads and writes, what it refuses, and how
the commands fit together from a clean host to removal. The exit-code and
JSON contract is in `docs/exit-codes.md`; the step-by-step install is in
`docs/quickstart-linux.md`.

## Boundary

- The agent in this release is an **observer**. It reads interface, route,
  resolver, and (opt-in) socket metadata, signs it with the node key, queues
  it durably, and submits it to Core. Nothing here changes firewall, route,
  DNS, mesh, or systemd state on the host.
- Enforcement drivers and a verified host recovery path are **not wired into
  this binary**. Every command that touches that subject says so with an
  explicit reason code (`AF-STATUS-DRIVER-NOT-WIRED`,
  `AF-STATUS-RECOVERY-NOT-WIRED`, `AF-DOCTOR-RECOVERY-NOT-WIRED`,
  `AF-CLI-NOT-AVAILABLE-YET`) rather than omitting it.
- Metadata is data. A release manifest, a config file, or a doctor result
  never grants readiness; readiness is computed by code that is not in this
  binary yet, and until then it is reported as `UNAVAILABLE`.

## Layout

`init` creates and every other command reads this layout. Paths are the
Linux defaults and are all overridable through the config file.

| Path | Mode | Owner | Purpose |
| --- | --- | --- | --- |
| `/etc/antiflock/agent.yaml` | `0644` | root | config (no secrets) |
| `/var/lib/antiflock/` | `0700` | antiflock | state directory |
| `/var/lib/antiflock/node.seed` | `0600` | antiflock | Ed25519 seed, the node identity (`agent/runtime` signer format) |
| `/var/lib/antiflock/enrollment.json` | `0600` | antiflock | enrollment request state (`agent/enrollment` format) |
| `/var/lib/antiflock/node.pem` | `0600` | antiflock | approved client certificate, written by `enroll` |
| `/var/lib/antiflock/queue/` | `0700` | antiflock | durable signed event queue (`agent/runtime` format) |
| `/usr/lib/systemd/system/antiflock-agent.service` | `0644` | root | packaged unit |

The node key deliberately lives in the state directory, not a separate keys
directory: `agent/enrollment` owns the `node.seed`/`enrollment.json`/`node.pem`
trio and `init` writes the first two in exactly that format so `enroll`
reuses the identity instead of creating a second one.

Config file (`antiflock.agent-config/v1`):

```yaml
schemaVersion: antiflock.agent-config/v1
nodeId: lab-node-1           # canonical identifier, at most 128 bytes
displayName: Lab node        # optional, printable ASCII
deploymentId: deploy-1
coreUrl: https://core.example.test:8787   # https, or http on loopback only
stateDir: /var/lib/antiflock
queueDir: /var/lib/antiflock/queue
caCert: ""                   # optional absolute path to the Core CA PEM
interval: 30s                # 5s to 1h
```

Unknown fields, a second YAML document, relative or `..` paths, a filesystem
root as a directory, and non-loopback `http` are all rejected.

## Commands

### `init`

```
antiflock-agent init --node-id <id> --deployment-id <id> --core-url <url>
    [--config PATH] [--display-name NAME] [--state-dir DIR] [--queue-dir DIR]
    [--ca-cert PATH] [--interval 30s] [--force] [--json]
```

Creates the state and queue directories (`0700`), generates the node key
(`0600`, created with `O_EXCL`) plus the matching enrollment state, and writes
the validated config atomically (`.tmp` then rename). An existing config is
refused (exit `6`) unless `--force`; an existing key is **never** replaced,
with or without `--force`, and is reported as `keyCreated: false`. Output
carries the key id (`ed25519:<first 8 bytes of sha256(pubkey)>`), never the
seed.

### `doctor`

```
antiflock-agent doctor [--config PATH] [--offline] [--json]
```

Runs independent checks, each `PASS`/`WARN`/`FAIL`/`UNKNOWN` with an
`AF-DOCTOR-*` reason code: OS, privilege, config, key presence and
permissions, state and queue directory permissions, queue writability, free
disk space, Core TCP reachability (`--offline` skips it), clock plausibility,
`nft` and `ip` presence at a trusted system path (absolute, no symlink,
root-owned, not group/world writable, same for every parent), resolver
configuration readability, systemd presence, and, only as root and only
through an injected runner that permits `nft list tables`, whether an
AntiFlock nftables table exists. Output ends with an explicit list of
missing recovery requirements; `recovery-driver
(AF-DOCTOR-RECOVERY-NOT-WIRED)` is always on it in this release. Exit `3` on
any `FAIL`, `7` on `WARN` only. Observe mode needs no privilege, so running
unprivileged is a `PASS`, with root-only checks reported `UNKNOWN`.

### `enroll --config`

```
antiflock-agent enroll --config PATH --enrollment-token-file PATH
    [--display-name NAME] [--certificate-file PATH] [--json]
```

Reads the config and delegates to the existing enrollment path
(`enroll --core-url ... --state-dir ... --node-id ...`) unchanged. The
existing `antiflock.agent-enrollment-result/v1` document becomes the
envelope's `result`. Exit `0` when approved and the certificate was saved,
`5` while pending operator approval (re-run the same command later), `6`
when denied or expired, `1` on transport errors. The token file must be a
private regular file (`0600`); its contents never reach the output.

### `observe --config`

```
antiflock-agent observe --config PATH [--submit] [--once] [...observe flags]
```

Expands the config into the flags the existing observer expects
(`--node-id`; with `--submit` also `--core-url`, `--deployment-id`,
`--node-key-file`, `--queue-dir`, `--interval`, `--client-cert` unless an
`--agent-token-file` or `--client-cert` is given, and `--ca-cert` when
configured) and passes every other flag through. Output is the existing
observation document, not the envelope. The flag-only form without
`--config` is unchanged.

### `status`

```
antiflock-agent status [--config PATH] [--json]
```

Read-only: enrollment state (`ready`, `pending-operator-approval`,
`incomplete-or-unsafe`, `not-enrolled`), key id, config digest, queue depth
and sequence, the queue file's last write time, and a per-domain driver table
(`firewall`, `mesh`, `route`, `dns`, `recovery`) that is `UNAVAILABLE` with a
reason in this release. Exit `7` when the key or queue is unusable, `3` when
the config is. The observe loop does not record a completion marker yet;
`lastObservationAt` is therefore empty and
`AF-STATUS-OBSERVATION-NOT-RECORDED` explains why.

### `plan simulate`, `plan readiness`

Registered so the command surface is complete, and honest: both exit `5`
with `AF-CLI-NOT-AVAILABLE-YET` naming the missing dependency (the
`plan.go` verifier from PR #60 and the driver/readiness packages). `plan
verify` is owned by `plan.go` and is not routed through the registry.

### `update`

```
antiflock-agent update --check --manifest PATH [--target PATH] [--json]
antiflock-agent update --from-file PATH --manifest PATH [--target PATH] [--json]
antiflock-agent update --rollback [--target PATH] [--json]
```

`update` never downloads. The manifest is a local
`antiflock.release-manifest/v1` JSON file:

```json
{
  "document": "antiflock.release-manifest/v1",
  "version": "0.2.0",
  "artifacts": [ { "name": "antiflock-agent", "sha256": "<64 hex>" } ],
  "signature": { "type": "cosign-bundle-out-of-band", "verified": false }
}
```

The `signature` field is a placeholder: provenance is verified against
`SHA256SUMS` with cosign per `docs/release-policy.md`, outside this command,
and the envelope always reports `signatureVerified: false`. `--check` hashes
the running binary (`os.Executable`, must be a regular non-symlink file) and
compares it with the manifest: exit `0` current, `7` update available, `4`
manifest invalid, `6` target not regular. `--from-file` hashes the candidate,
refuses on mismatch (exit `4`) before writing anything, stages a copy next to
the target, re-hashes the staged copy, renames the target to
`<target>.previous`, and renames the staged copy into place. `--rollback`
swaps `<target>.previous` back and keeps the replaced binary as
`.previous` so the rollback can itself be undone once. Restart the service
after either.

### `uninstall`

```
antiflock-agent uninstall [--config PATH] [--yes] [--systemd] [--json]
```

Dry run by default: prints every path it would remove. With `--yes` it
removes the state and queue directories (deepest first) and the config file.
Every path is checked for containment against the configured roots, lexically
(`..` rejected) and physically (no symlink at the root or any intermediate
component; a symlink entry is removed as a link and never followed). A root
that is a well-known system directory (`/`, `/etc`, `/var/lib`, ...) or a
symlink is refused and nothing is removed (exit `6`). Unit removal commands
are printed; they run only with `--systemd` as root. **Firewall state is
never touched**: removing an AntiFlock nftables table requires an explicit,
verified recovery plan, which this release does not have.

### `version`

Prints `antiflock-agent <version> (<vcs revision>[, modified]) go<ver> os/arch`
from the binary's embedded build information (`-buildvcs=true` in the release
pipeline). `--json` returns the same fields.

## Lifecycle

```
package install ──▶ init ──▶ doctor ──▶ enroll (pending) ──▶ operator approves
                                            │
                                            ▼
                                 enroll (approved, node.pem)
                                            │
                                            ▼
                          systemctl enable --now antiflock-agent
                                            │
                               status / doctor (read-only, any time)
                                            │
             update --check ──▶ update --from-file ──▶ restart ──▶ (rollback)
                                            │
                                            ▼
                         uninstall (dry run) ──▶ uninstall --yes [--systemd]
```

## Registry and `main.go`

Commands are self-registering handlers in `cmd/antiflock-agent/commands_*.go`
behind `cmd/antiflock-agent/registry.go`. `main.go` is unchanged in the PR
that introduces them; the wiring is one line at the top of `main()`:

```go
if code, ok := dispatch(context.Background(), os.Args[1:], os.Stdout, os.Stderr); ok {
	os.Exit(code)
}
```

`dispatch` claims only what the registry owns: `plan verify`, the flag-only
`observe`/`enroll`/`status` forms, and anything unknown fall through to the
existing `run` dispatcher, so existing invocations and tests keep their
behaviour.

## Packaging status

`deploy/systemd/antiflock-agent.service` is a hardened observe-mode unit
(dedicated `antiflock` user, empty capability bounding set,
`NoNewPrivileges`, `ProtectSystem=strict`, writable only under
`/var/lib/antiflock`). `deploy/packaging/nfpm.yaml` with
`postinstall.sh`/`preremove.sh` describes deb and rpm packages. Package
builds are **not** part of the release workflow yet; the release artifact
set in `docs/release-policy.md` is the source of truth, and packages built
from it must be verified the same way before install.
