// Package fixtures holds deterministic, side-effect-free test fixtures shared
// by the adversarial suites under tests/hostile, tests/fuzz, and tests/replay.
//
// Contract:
//   - Every fixture is built from fixed seeds so a failure reproduces byte for
//     byte; nothing here reads the developer host (no nft, ip, resolv.conf,
//     mesh daemons, or network) and nothing here mutates it.
//   - Fixtures only use exported production APIs. When a production signing
//     profile must be re-implemented (ResignPlan) it follows
//     docs/signing-contracts.md exactly so a divergence is itself a finding.
//   - Helpers fail the calling test on fixture errors; they never skip.
//
// Targets present on main today: agent/enforcement (Enforcer, MemoryStateStore),
// core/policy (Compiler, VerifyPlan), core/server (full REST surface), and the
// identity/storage/audit/events stack the server needs.
package fixtures
