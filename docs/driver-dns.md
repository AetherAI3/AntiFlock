# DNS resolver driver (`adapters/dns/resolver`) — WIP design contract

Status: design only (lane S7C, ANTIFL0CK-OSS-COMPLETION-02). No Go code landed yet.
Implements `agent/driver.Driver` (contract v1, PR #64) for protected resolver configuration.

## Binding
- One driver instance binds to exactly one target at construction:
  - `resolvconf` backend: target == root-relative resolv path (default `/etc/resolv.conf`), resolved
    under `Config.Root` (production `/`; tests always a temp dir so the host is never touched).
  - `resolved` backend: target == link name (`eth0`), driven through a trusted `resolvectl`
    (`/usr/bin/resolvectl`, root-owned, non-writable path, nftables.go:278-330 checks) via an
    injected runner; fixed argument patterns `status`, `dns <link> ...`, `domain <link> ...`, `revert <link>`.
- Operation type is echoed from the scope (type routing is the planner's job); Simulate rejects a
  type that differs from the captured scope with `AF-DRIVER-DNS-TYPE-MISMATCH`.
- Protected config comes from `Config.Protected` (nameservers, search, options, per-link domains);
  operation parameters may override `nameservers`, `searchDomains`, `options`, `domains`.

## Probe keys / reason codes
- `dns.resolver.observe`, `dns.resolver.enforce` (domain DNS).
- `AF-DRIVER-DNS-MANAGED-BY-RESOLVED` (resolv path is the systemd-resolved stub symlink; never rewritten),
  `AF-DRIVER-DNS-SYMLINK`, `AF-DRIVER-DNS-RECOVERY-LOSS`, `AF-DRIVER-DNS-CAPTIVE-PORTAL`,
  `AF-DRIVER-DNS-TAMPERED`, `AF-DRIVER-DNS-RESOLVE-FAILED`, `AF-DRIVER-DNS-TARGET-UNBOUND`,
  plus shared `AF-PROBE-*` (binary missing/untrusted, privilege missing, journal corrupt, platform unsupported on !linux).

## Snapshot entries (resolvconf)
`file.present`, `file.mode`, `file.owner` (uid:gid), `file.symlink`, `file.digest` (sha256 of bytes),
`nameserver.N`, `search`, `options`. Resolved: `link.<name>.dns`, `link.<name>.domains`, `global.dns`.

## Durable ownership
Before journal BEGIN the driver persists an ownership record under `Config.StateDir/ownership/<token>.json`
holding the full original config (bytes + mode + owner, or per-link dns/domains), the applied content
digest and state (applied|rolled|tampered). Rollback and Recover read only this record and the journal,
never DNS. Recovery networks are literal IPs; DNS recovery = original resolver preserved in the record
(and optionally appended as fallback via `Protected.KeepOriginalFallback`, which clears RECOVERY-LOSS).

## Apply / Verify / Rollback / Recover
- Apply: validate, journal health, capture, simulate (reject on RECOVERY-LOSS), persist ownership,
  journal BEGIN, atomic write (dir opened O_NOFOLLOW|O_DIRECTORY, fstatat refuses a symlink target,
  temp O_EXCL|O_NOFOLLOW, write, fsync, fchmod/fchown to original, renameat, fsync dir) or resolvectl
  dns+domain, re-capture, journal FINISH COMMIT.
- Verify: re-read digest must equal receipt; then optional `CaptivePortalDetector` (HTTP GET to probe
  URL via injected client expecting exact status+body; mismatch => Verified=false, CAPTIVE-PORTAL);
  then optional `Resolver` (default net.Resolver dialing the protected server, bounded timeout) must
  resolve the configured probe name.
- Rollback: restore journaled bytes + mode (+owner) / `resolvectl revert` then re-set original if it
  differs; idempotent (`AF-DRIVER-ALREADY-ROLLED-BACK`).
- Recover: journal-driven; host == applied content => restore; host == original => close; anything else
  => `AF-DRIVER-DNS-TAMPERED`, journal closed, record kept, host NOT clobbered.

## Tests planned
Conformance (memory + file journal, temp root, fake runner), disk-full/rename/partial-write faults,
symlinked target, mode/owner mismatch, resolved stub detection, captive-portal mismatch, split-DNS via
fake runner, lost-process recovery, tamper, netns proof (`unshare -rn`, in-process UDP responder on
127.0.0.1:<port>, skip precisely when unavailable). Mutations: rollback ignores mode restoration;
captive-portal mismatch still reports verified.
