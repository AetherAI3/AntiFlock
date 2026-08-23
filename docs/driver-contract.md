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
| `contract.go` | Interfaces and value types; `ValidateTarget`; `OwnershipTokenFor`; sentinel errors |
| `lifecycle.go` | `Lifecycle` state machine with `Recover`/`Health`, `Approval`, `StepTimeouts` |
| `journal.go`, `journal_file.go` | `Journal`, `MemoryJournal`, `FileJournal` |
| `reservation.go` | `ReservationStore`, `MemoryReservationStore` |
| `receipt.go` | `Receipt`, `ReceiptStore`, `MemoryReceiptStore` |
| `memory/` | Reference `Driver` over a fake host |
| `conformance/` | `RunConformance(t, factory)` (driver + lifecycle-over-driver), `RunReservationStore`, `RunJournal` |

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
| Simulate | `Simulator` | none (pure) | `ADVANCE` SIMULATE, digest = predicted after-digest, target | FAILED (`ErrSimulationRejected`) |
| Approve | caller supplies `Approval` | none | `ADVANCE` APPROVE | stays SIMULATED (`ErrApprovalMismatch`) |
| Reserve | `ReservationStore` | none | `ADVANCE` RESERVE with the full `ReservationKey` | FAILED |
| Apply | `Applier` | mutates exactly `Target` | `ADVANCE` APPLY (before-digest, key, target) before the driver is called; `ADVANCE` VERIFY (ownership token, applied digest) as soon as the driver returns | FAILED |
| Verify | `PostApplyVerifier` | read-only | nothing (read-only step) | FAILED (`ErrVerificationFailed`) |
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
| `Journal` | Append-only; every write durable before return; at most one open entry per `(plan, revision, operation)`; `FINISH` only at a terminal step; records carry plan identity, step, ownership token, digest, target and the full reservation key; finished entries are compacted once the journal exceeds `JournalCompactionThreshold` (open entries are never dropped); corrupt on load, or any schema other than `antiflock.driver-journal/v2`, is `ErrJournalCorrupt` and is never repaired or migrated. |
| `ReservationStore` | Durable before return. `ReservationKey` carries `PolicyRevision` and `PlanRevision`; the store keeps both as monotonic floors exactly like `enforcement.StateStore`: policy revision below the floor, or plan revision at or below the floor, is `ErrStaleRevision`. Same plan id under a different key, or the identical key while in progress: `ErrAlreadyReserved`. The identical key redelivered after release returns `Reservation{Replayed: true, Terminal, Result}`, the stored terminal result, so redelivery is idempotent. `Release` only at a terminal step with an opaque bounded result; a second release must match (`ErrReservationConflict` otherwise); the key is remembered forever. |
| `Lifecycle.Recover` | Reads the lifecycle journal; finishes or reverts every in-flight entry deterministically (see Crash model); idempotent; refuses while a plan is active. `Begin` refuses with `ErrRecoveryPending` until it has run. |
| `Lifecycle.Health` | `UNAVAILABLE` + `AF-PROBE-JOURNAL-CORRUPT` on a corrupt lifecycle journal, `DEGRADED` + `AF-DRIVER-RECOVERY-PENDING` while an in-flight entry exists, otherwise the driver's own health. |
| `OwnershipTokenFor` | Every driver issues exactly `OwnershipTokenFor(planID, planRevision, operationID, target, reservationToken)` so a lifecycle can re-derive the token from its journal after a crash. |
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

There are two journals. The driver journal covers the window inside `Apply`;
the lifecycle journal covers every orchestration step. Both are written
before the action they describe takes effect, and both are read on restart.

**Driver window.** `Apply` persists its ownership record and journals `BEGIN`
before the host changes. A process that dies between that `BEGIN` and the
driver's `FINISH` leaves an open driver entry; the driver's `Health` is
`DEGRADED` and its `Recover` reverts the entry from the ownership record.

**Lifecycle window.** `Lifecycle.Recover` reads the lifecycle journal's
in-flight entries and, for each, acts on the step alone:

| In-flight step | What happened | Recovery action | Reason code |
|---|---|---|---|
| CAPTURE, SIMULATE, APPROVE | nothing reserved or applied | close as ROLLBACK | `AF-DRIVER-RECOVERY-ABORTED` |
| RESERVE | reserved, nothing applied | release reservation as ROLLBACK, close | `AF-DRIVER-RECOVERY-ABORTED` |
| APPLY | driver may have mutated | driver `Recover`; re-derive token with `OwnershipTokenFor`; `Verify` against the SIMULATE after-digest; verified: append receipts, release as COMMIT, close; else driver `Rollback`, release as ROLLBACK, close | `AF-DRIVER-RECOVERY-COMMITTED` / `AF-DRIVER-RECOVERY-ROLLED-BACK` |
| VERIFY, RECORD | applied, receipt journalled | same as APPLY but against the journalled applied digest | as above |

Recovery never reads the host to decide what it owns: ownership comes from the
journal and `OwnershipTokenFor`; the host is touched only through the
read-only `Verify` and the idempotent `Rollback`. Running `Recover` again
finds nothing. While an entry is open, `Health` is `DEGRADED` and `Begin`
refuses with `ErrRecoveryPending`, so an operator sees the condition and the
next plan cannot start on top of it.

The conformance suite proves both windows against every driver: crash inside
`Apply` (`CrashSimulator.InjectCrash`) with driver-level `Recover`, and two
lifecycle crashes (after `Apply` returned, and inside `Apply`) with a fresh
`Lifecycle` over the same journal, reservation and receipt stores and a
reopened driver (`Reopener.Reopen`).

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
`enforcement.StateStore` (`Reserve`/`Complete`) adapt onto this contract
without changing their semantics:

- `CheckObservation` has the same fields.
- `enforcement.Reservation{PlanID, Fingerprint, PolicyRevision, PlanRevision}`
  maps onto `ReservationKey` one to one (the nonce is the plan nonce as a
  printable string). Both floors behave identically: `ErrStaleRevision` is
  the enforcer's `ErrPlanReplay`; `ErrAlreadyReserved` for the identical
  in-progress key is `ErrPlanInProgress`, and for a different key under the
  same plan id is `ErrPlanReplay`.
- `StateStore.Complete(result)` is `Release(token, terminal, result)` with the
  deterministic encoding of the signed `PlanExecutionResult` as the opaque
  result; a redelivered identical reservation returns it through
  `Reservation.Result`, exactly as `Reserve` returns the persisted signed
  result today. The `Lifecycle` stores its commit/rollback receipt digest as
  the result; an adapter that needs the signed plan result as the result of
  record releases through the store itself, or wraps the store.
- One `Lifecycle` per node, one run per plan operation; `Recover` on agent
  start before any plan is delivered.

That adapter belongs to the enforcement package and is not part of this lane.
