# Route driver (`adapters/route/iproute2`) — WIP design note

Status: DESIGN ONLY. No Go code landed yet (lane S7B stopped by A0 before implementation).

Contract: `agent/driver` v1 (PR #64 @ 9717079). Probe keys `network.route.observe`,
`network.route.enforce`. Reason codes `AF-DRIVER-ROUTE-*` plus shared `AF-PROBE-*`.

## Decisions verified in a rootless netns (`unshare -rn`, iproute2 5.15)
- Trusted binary: one of `/bin/ip`, `/sbin/ip`, `/usr/bin/ip`, `/usr/sbin/ip`; absolute, no symlink
  traversal, root-owned, non-writable dir (checks copied from `agent/enforcement/nftables.go:278-330`).
  On Ubuntu 22.04 `/usr/sbin/ip` and `/sbin/ip` are symlinks; `/bin/ip` validates.
- Capture (read-only, JSON, bounded 2 MiB, per family): `ip -4|-6 -j route show table all`,
  `ip -4|-6 -j rule show`, `ip -j link show`, `ip -j addr show`. Snapshot keys
  `route/<table>/<dst>/m<metric>`, `rule/<family>/<pref>/<table>`, `link/<ifname>`,
  `addr/<ifname>/<family>/<local>/<len>`; sorted, printable ASCII, digest per contract.
- Ownership marker lives in the host: dedicated table `7301` + `ip rule pref 7301 lookup 7301`
  + route `proto 250` (unassigned rtm_protocol). `ip route del ... proto 250` and
  `ip route flush table 7301 proto 250` only touch marked routes (verified: foreign routes survive).
- Mutation: `ip -4|-6 -batch -` with validated literal lines on stdin (`route add <cidr> [via <addr>]
  dev <ifname> table 7301 metric <n> proto 250`, rule line last). Batch stops at first error;
  ownership record drives the revert. Rule added last, deleted first on rollback.
- Simulate: pure diff; `AF-DRIVER-ROUTE-CONFLICT` when same dst/table/metric exists without
  proto 250; `AF-DRIVER-ROUTE-RECOVERY-LOSS` when an intended prefix overlaps a configured
  recovery network or contains the gateway of the main-table route currently serving it.
  Max routes per plan configurable, <= 64.
- Verify: re-capture owned view (table 7301 + rule), digest compare, `ip -j route get <host>` for
  each recovery network must not resolve via table 7301 (`AF-DRIVER-ROUTE-RECOVERY-UNREACHABLE`);
  a route in table 7301 without proto 250 is tamper.
- Scope: empty targets = observe-all view; named targets = owned view (table 7301 + our rule).
- Conformance fixture uses `PLAN_OPERATION_TYPE_FIREWALL`; driver needs a config knob for the
  accepted operation type (default ROUTE). Flagged for A0: all Wave-2 drivers will hit this.
- Privilege: `unshare -rn` gives uid 0 and CAP_NET_ADMIN on a throwaway stack; `dummy` links,
  tables, rules and `route get` all work there without sudo.

## Not done
Everything in the package: runner, trusted-exec checks, JSON model/parser, driver, fake runner,
conformance, netns proof, tamper/lost-process tests, mutations, PR body per LANE-BRIEF.
