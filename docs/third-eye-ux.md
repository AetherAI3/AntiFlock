# Third-Eye readiness/driver/recovery UX (S9) — WIP

Status: recon complete, no code landed yet. Session closed by A0 before implementation.

Planned (all inside `apps/web/**` + this file):
1. `src/api/contracts.ts` additive types: NodeHealth, PlanVerification (#60 `valid`/`capabilityCompatible`/`executable` + drivers table), SimulationDiff (#64 `Diff`), CapabilityReadiness (#65 `Verdict`/`Readiness`/`Manifest`), DriverHealth (#64 `HealthReport`, HEALTHY/DEGRADED/UNAVAILABLE/UNKNOWN), RecoveryRequirements (#67 doctor `missingRecoveryRequirements`), DefensiveState, AuditWitnessHealth (#63 `Checkpoint`/`WitnessReceipt` digests only), FindingWithEvidence (#66 Origin/Authenticity/Taint names), StatusLadder (nine independent yes/no/unknown + reasonCodes) with a TruthRule guard.
2. `src/test-fixtures/readiness.ts` scenarios with `AF-*` reason codes.
3. New sections `readiness`, `plans`, `recovery`, `doctor`; `SafeText` component (ESC strip, control-char escape, `dir="auto"` + `unicode-bidi: isolate`).
4. `scripts/print-status.mjs` (`npm run print:status`) + in-app text view.
5. Snapshots under `tests/__snapshots__/`, tests for ladder/SafeText/fixtures/contracts, mutations (a) ladder collapse, (b) ESC strip removal.

Reference Go shapes read from: s3-capability `agent/capability` (`manifest.go`, `readiness.go`, `reasons.go`), s5-driver `agent/driver` (`contract.go`, `probe.go`, `journal.go`, `receipt.go`), s2-agent `internal/agentcli` (`envelope.go`, `doctor.go`), r0-pr60 `cmd/antiflock-agent/plan.go`, s4-taint `internal/trust/envelope.go`, s8-integration `core/integration/witness.go`.
