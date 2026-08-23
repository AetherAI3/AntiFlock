# Driver contract (`agent/driver`, contract version 1)

A *driver* is the only code in the AntiFlock agent that is allowed to change
host state. This document is the human-readable statement of the contract that
`agent/driver/contract.go` encodes in Go and that `agent/driver/conformance`
enforces as tests. A driver that does not pass `conformance.RunConformance` is
not a driver.

The contract is generic and infrastructure-neutral: it names no product, no
vendor, no host, and no deployment topology. Reference implementation:
`agent/driver/memory` (an in-memory fake host; it never touches the real
machine).

## Parts

| File | Owns |
|---|---|
| `probe.go` (frozen, schema v1) | `ProbeResult`, `Prober`: what the driver observed about its own capability |
| `contract.go` | Interfaces and value types; `ValidateTarget`; sentinel errors |
| `lifecycle.go` | `Lifecycle` state machine, `Approval`, `StepTimeouts` |
| `journal.go`, `journal_file.go` | `Journal`, `MemoryJournal`, `FileJournal` |
| `reservation.go` | `ReservationStore`, `MemoryReservationStore` |
| `receipt.go` | `Receipt`, `ReceiptStore`, `MemoryReceiptStore` |
| `memory/` | Reference `Driver` over a fake host |
| `conformance/` | `RunConformance(t, factory)` |

## Lifecycle

Every operation of every plan runs through exactly this order. The
`Lifecycle` type refuses any step invoked early with `ErrLifecycleOrder`, and
refuses a second plan while one is active with `ErrPlanActive`.

```
            +----------------------------------------------------------+
            |                      Lifecycle                           |
            |                                                          |
 Begin ---> | BEGUN --Capture--> CAPTURED --Simulate--> SIMULATED       |
            |                                              |            |
            |                       external Approval ---> Approve     |
            |                                              v            |
            |    RESERVED <--Reserve-- APPROVED                         |
            |       |                                                   |
            |     Apply  (re-capture; ErrHostDrift if changed;          |
            |       |     journal before mutation)                      |
            |       v                                                   |
            |    APPLIED --Verify--> VERIFIED --Record--> RECORDED       |
            |                                                |          |
            |                                             Commit        |
            |                                                v          |
            |                                           COMMITTED       |
            |                                                          |
            |   any active state --Rollback--> ROLLED_BACK              |
            |   any failed step  --> FAILED (only Rollback permitted)   |
            +----------------------------------------------------------+
```

Step semantics:

| Step | Who acts | Host effect | Journalled | Failure lands in |
|---|---|---|---|---|
| Begin | lifecycle | none | `BEGIN` at CAPTURE | IDLE |
| Capture | `HostStateCapturer` | read-only | no | FAILED |
| Simulate | `Simulator` | none (pure) | `ADVANCE` SIMULATE | FAILED (`ErrSimulationRejected`) |
| Approve | caller supplies `Approval` | none | `ADVANCE` APPROVE | stays SIMULATED (`ErrApprovalMismatch`) |
| Reserve | `ReservationStore` | none | `ADVANCE` RESERVE | FAILED |
| Apply | `Applier` | mutates exactly `Target` | `ADVANCE` APPLY before the driver is called | FAILED |
| Verify | `PostApplyVerifier` | read-only | `ADVANCE` VERIFY with ownership token | FAILED (`ErrVerificationFailed`) |
| Record | `ReceiptStore` | none | `ADVANCE` RECORD | FAILED |
| Commit | reservation release + receipt | none | `FINISH` COMMIT | FAILED |
| Rollback | `RollbackDriver` (if applied) + release | reverts owned change | `FINISH` ROLLBACK | FAILED |

Every step runs under its own bounded context from `StepTimeouts`; each value
must be in `(0, 2m]` (`MaxStepTimeout`, equal to the enforcer's step ceiling).

## Approval

The driver never approves its own work. `Approval` is an opaque value the
caller obtains elsewhere; it carries `PlanID`, `PlanRevision`, `OperationID`,
`Target`, `ApproverKind`, and a digest (`ApprovalDigest`) over those fields.
The lifecycle checks only that the approval binds to the exact plan id,
revision, operation and simulated target. Who may approve, and how the
approval is transported or signed, is out of scope for this package.

## Guarantees

| Interface | Guarantee |
|---|---|
| `Prober.Probe` | Read-only. Reports what the driver observed, never what a caller asked for. Result digests are stable (`ProbeResult.Digest`). |
| `HostStateCapturer.Capture` | Read-only, driver-scoped, bounded to `MaxSnapshotEntries`. `Snapshot.Digest` is deterministic and excludes the capture time, so an unchanged host yields the same digest. |
| `Simulator.Simulate` | Pure function of `(Snapshot, PlanOperation)`. Never reads or writes the host. `Diff.Lines` are data: printable ASCII, bounded; never interpreted. |
| `PreconditionChecker.Check` | Read-only. Returns the enforcement-compatible `CheckObservation` (`Outcome`, `ReasonCode`, `SafeMessage`, `Evidence`). Unsupported check types yield `UNKNOWN` + `AF-DRIVER-CHECK-UNSUPPORTED`, never a silent pass. |
| `Applier.Apply` | Validates the whole request before any boundary is crossed; `Target` must equal `Operation.Target` (`ErrTargetMismatch`); the reservation token must derive from its key and name the same plan id and revision (`ErrReservationInvalid`); persists its ownership record and journals `BEGIN` before mutating; an expired context before mutation leaves the host untouched. |
| `PostApplyVerifier.Verify` | Read-only. `Verified` is true only when the observed digest equals `AppliedDigest`. Foreign ownership tokens are `ErrUnknownOwnership`. |
| `RollbackDriver.Rollback` | Idempotent: a second rollback of the same token is a success with `AlreadyRolledBack=true` and no host change. Unknown tokens are `ErrUnknownOwnership`. |
| `CrashRecoverer.Recover` | Idempotent. Reads the journal, reverts or finishes every open entry, closes it. Never depends on the host being in the post-apply state. A corrupt journal is `ErrJournalCorrupt` with no host access. |
| `HealthReporter.Health` | Read-only. A corrupt journal reports `UNAVAILABLE` + `AF-PROBE-JOURNAL-CORRUPT`; an open journal entry reports `DEGRADED`. |
| `RecoveryAccess.RecoveryPaths` | Read-only. Every path returned must stay reachable regardless of the plan; applying a plan must not change the list. A driver with no path returns an empty list and the caller refuses to enforce. |
| `CommandPlanner.CommandPlan` | Read-only dry run: one executable, an explicit argument vector, stdin input. No argument may contain shell metacharacters. |
| `Journal` | Append-only; every write durable before return; at most one open entry per `(plan, revision, operation)`; `FINISH` only at a terminal step; corrupt on load is `ErrJournalCorrupt` and is never repaired. |
| `ReservationStore` | Durable before return. Same key or same plan id again: `ErrAlreadyReserved`. Revision at or below the floor: `ErrStaleRevision`. `Release` only at a terminal step, and the key is remembered forever so a released plan cannot be replayed. |
| `ReceiptStore` | Append-only; duplicates (same `ContentDigest`) are `ErrReceiptDuplicate`. `Receipt.ContentDigest` is the value a node key signs; it is pinned by test. |

## Target and string rules

`ValidateTarget` is applied to every target, snapshot key, recovery address
and command argument: non-empty, at most 256 bytes, printable ASCII, no
whitespace, and none of `; | & $ ` < > ( ) { } [ ] * ? ! ~ ' " \ #`. Every
other driver-emitted string (values, diff lines, safe messages, descriptions)
must be printable ASCII and bounded. Raw command output, secrets, and
unescaped untrusted text never enter a snapshot, diff, receipt or reason code.

## Privilege boundary statement

Every driver publishes a `PrivilegeBoundary`: the one binary it may execute,
the exact argument pattern, the privilege it needs, and `ShellFree=true`. A
boundary with `ShellFree=false` fails validation and the lifecycle refuses to
construct. The `CommandPlan` a driver exposes for an operation is the
reviewable form of what `Apply` will run. Drivers that execute nothing (the
memory reference driver) say so explicitly.

## Recovery statement

**Recovery access must not depend on the network being changed.** A driver's
`Recover` reads its own journal and ownership records; it never needs the
host to be in the post-apply state, and it never needs the network to be in
any particular state. `RecoveryPaths` enumerates the out-of-band paths (for
example literal recovery networks or a local console) that the plan is not
permitted to cut; the conformance suite asserts they are unchanged after an
apply.

## Crash model

The journal is written before the host changes. A process that dies between
`BEGIN` and `FINISH` leaves an open entry. On the next start, `Health` is
`DEGRADED`, and `Recover` reverts the entry using the durable ownership
record. The conformance suite proves this against every driver by arming
`CrashSimulator.InjectCrash`, applying, reopening the driver over the same
durable state (`Reopener.Reopen`), and requiring `Recover` to restore the
pre-apply digest. Running `Recover` again must find nothing.

## What a driver must never do

- Spawn a shell, or pass a target or argument containing shell metacharacters
  to anything.
- Mutate anything other than the exact `Target` of the reserved, approved
  operation.
- Mutate before the journal `BEGIN` and the ownership record are durable.
- Approve, reserve, or verify its own work without a caller-supplied
  `Approval` and a durable reservation.
- Decide recovery by reading the network instead of its journal.
- Repair, rewrite, or discard a corrupt journal.
- Report a health or probe result a caller asked it to report.
- Emit raw command output, secrets, control characters, or non-ASCII text in
  any structured field.
- Depend on the conformance suite being skipped.

## Adapting the enforcer

`enforcement.Driver` (`Check`/`Apply`/`Rollback` over `PlanOperation`) and
`enforcement.StateStore` (`Reserve`/`Complete`) can be adapted onto this
contract without changing their semantics: `CheckObservation` has the same
fields; `ReservationStore.Reserve` maps `ErrAlreadyReserved` onto
`ErrPlanReplay`/`ErrPlanInProgress` and `ErrStaleRevision` onto
`ErrPlanReplay`; `Release` at `StepCommit`/`StepRollback` corresponds to
`Complete` with the terminal signed result. That adapter belongs to the
enforcement package and is not part of this lane.
