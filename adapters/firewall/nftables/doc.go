// Package nftables will be the driver.Driver for Linux nftables (lane S6,
// ANTIFL0CK-OSS-COMPLETION-02). WIP: design only, no implementation yet.
//
// Planned shape (frozen contracts: agent/driver/probe.go, contract.go):
//
//   - Runner seam: Run(ctx, executable, args, stdin) -> (bounded stdout, exit
//     code); ExecRunner (linux) allows exactly /usr/sbin/nft-style trusted
//     binaries (re-implemented trust checks from agent/enforcement/nftables.go:
//     absolute canonical path, trusted system path, no symlinks, root-owned
//     regular file 0o022-clean, root-owned 0o022-clean directories) and only
//     the argument vectors ["--version"], ["-j","list","ruleset"],
//     ["-c","-f","-"], ["-f","-"]; stdin <= 64 KiB; stdout <= 1 MiB, never
//     copied into messages. Non-linux stub reports AF-PROBE-PLATFORM-UNSUPPORTED.
//   - EnableApply=false (default) executes nothing; Probe reports the keys as
//     UNAVAILABLE with AF-DRIVER-NFTABLES-APPLY-DISABLED (no lie, no runner call).
//   - Policy: isolated table "inet antiflock_<scope>", output hook priority
//     -150 policy drop; accept lo, accept ct established/related, accept
//     literal recovery networks (sets recovery_v4/recovery_v6), drop rest.
//     Batch = add table; flush table; add chain/set/element/rule. Pre-flight
//     with -c -f - then real -f -. Empty recovery allowlist ->
//     AF-DRIVER-NFTABLES-RECOVERY-EMPTY; table present but not journaled ours
//     -> AF-DRIVER-NFTABLES-FOREIGN-TABLE.
//   - Capture: nft -j list ruleset parsed by a depth/size-bounded decoder;
//     snapshot entries are the canonical (handle-free, sorted-key JSON) lines of
//     the owned table(s); untargeted captures add "ruleset.digest" over the
//     full ruleset for drift detection.
//   - Verify: re-capture owned table and compare canonical digest; any added,
//     removed or changed rule -> AF-DRIVER-NFTABLES-TAMPERED.
//   - Ownership: durable store beside the journal (memory or file) keyed by
//     driver.OwnershipTokenFor; Rollback deletes only a journaled table and is
//     idempotent; Recover reverts open BEGIN entries (conformance requires
//     revert; "applied-awaiting-verify" is the lifecycle's call, not the
//     driver's) and is idempotent.
//   - Tests: fake runner over an in-memory nft-batch interpreter for
//     conformance (memory + file journal); rootless unshare -rn re-exec netns
//     proof (apply, verify, tamper, rollback, coexistence with "inet other",
//     lost-process recovery via a second instance over the same directory).
package nftables
