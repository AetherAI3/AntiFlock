# Adversarial qualification

Status date: 2026-08-23. Owner lane: S10 (adversarial CI and release
qualification). Base: `main` 30c4197.

This document is the release-qualification ledger for hostile-input,
replay, crash, and environment gates. It lists every gate the objective
requires, whether it exists on `main` today, the exact command that runs it,
and what "unavailable" means for it. The rule for every row is the same:

> A gate that cannot run is a failed gate. Unavailable is never a pass.

Companion code: `tests/hostile` (failing-first security fixtures),
`tests/fuzz` (stdlib fuzz targets with seed corpora), `tests/replay`
(deterministic property tests for plan replay), `tests/netns` (rootless
network-namespace harness), `tests/fixtures` (shared deterministic fixtures),
`tests/ci/adversarial.yml` (workflow for S1 to commit), and acceptance gates
11 and 12 in `scripts/acceptance.mjs`.

## Skip discipline

A test under `tests/hostile` or `tests/replay` may skip in exactly two ways:

| Form | Meaning | Gate 11 treatment |
|---|---|---|
| `t.Skip("KNOWN-GAP AF-GAP-nnn: ...")` | The invariant is stated and `main` does not satisfy it yet. The id must appear in the table below with an owner lane. The skip is conditional: when the owner lands the fix the test turns green without edits. | Allowed only when `AF-GAP-nnn` is documented here; a file must still contain at least one test that is not skipped unconditionally. |
| `t.Skip("ENV-UNAVAILABLE: ...")` | A precondition of the environment is absent (non-Linux, no symlinks, `-short`, `unshare -rn` blocked). | Allowed. The CI job named in the gate table is responsible for running the test in an environment where the precondition holds; the job, not the skip, is the evidence. |

Any other skip text fails gate 11 (`scripts/acceptance.mjs`, `adversarial-fixtures`).

## Gate ledger

Status vocabulary: **EXISTS** (on `main` 30c4197 before this PR),
**ADDED-THIS-PR** (landed by S10), **PLANNED** (not yet runnable; owner named).
Commands run from the repository root; Go commands assume Go 1.26.6.

| # | Gate | Status | Command | "Unavailable" means |
|---|---|---|---|---|
| 1 | Acceptance gates 1-10 (contracts, schemas, core, event-spine, decision-plane, agent, web, secure-action-sdk, android, coffee-shop) | EXISTS | `node scripts/acceptance.mjs --strict` | Missing Go/Docker/Java/npm: gate reports `passed:false`; `--strict` exits 1. Not a pass. |
| 2 | Full Go suite | EXISTS | `go test ./adapters/... ./agent/... ./api/gen/go/... ./cmd/... ./core/... ./internal/... ./tests/...` (`verify.mjs --section go`) | No Go and no Docker fallback image: `runGoStep` fails the section. |
| 3 | Race detector | EXISTS | `go test -race` over the same patterns (`verify.mjs --section go`); `tests/...` also under `--section adversarial` | Same as above. CGO unavailable makes `-race` fail outright. |
| 4 | Vet | EXISTS | `go vet <patterns>` | Same as above. |
| 5 | Staticcheck 2026.1 | EXISTS | `staticcheck <patterns>` (bootstrapped by `go run honnef.co/go/tools/cmd/staticcheck@2026.1`) | Network-less bootstrap failure fails the section. |
| 6 | govulncheck v1.1.4 | EXISTS | `govulncheck <patterns>` | A database fetch failure is a failed gate, not a clean scan. |
| 7 | JS workspaces (build, test, lint) | EXISTS | `node scripts/verify.mjs --section javascript --install` | Node < 24 or missing lockfile fails the section. |
| 8 | Android JVM tests | EXISTS | `node scripts/verify.mjs --section android` | No JDK 17 and no Docker: `missingTool` fails the section. |
| 9 | Protobuf compatibility (format, lint, build, `buf breaking` against `main`) | EXISTS (format/lint/build); `buf breaking` PLANNED, owner S1 (`.github/**`) | `node scripts/verify.mjs --section proto`; planned: `buf breaking --against .git#branch=main` in CI | No buf and no Docker: `missingTool` fails. |
| 10 | Generated-code parity | EXISTS | `verify.mjs --section proto` (`verifyGeneratedCode`) | Regeneration into `.cache/` fails or differs: section fails. |
| 11 | CodeQL (go, javascript-typescript) | EXISTS (`.github/workflows/codeql.yml`, required contexts `analyze (go)`, `analyze (javascript-typescript)`) | GitHub-hosted only | A missing check reading is "pending", never a pass; the ruleset requires both contexts. |
| 12 | gitleaks (full history) | EXISTS (`.github/workflows/gitleaks.yml`, required context `scan`) | GitHub-hosted only | Same as 11. |
| 13 | Dependency scan | EXISTS partially: govulncheck (Go) + Dependabot (`.github/dependabot.yml`); npm/Gradle audit PLANNED, owner S1 | `govulncheck`; planned `npm audit --audit-level=high` per workspace | Absent audit is a gap, listed as AF-GAP-010. |
| 14 | Parser fuzzing | ADDED-THIS-PR | Seeds: `go test -count=1 ./tests/fuzz/`. Fuzzing: `node scripts/verify.mjs --section adversarial` runs `go test -run '^$' -fuzz='^<Target>$' -fuzztime=20s -parallel=2 ./tests/fuzz/` per target, sequentially (`ANTIFLOCK_FUZZTIME` overrides). Targets: `FuzzHeadscaleListNodes`, `FuzzRouteTable`, `FuzzResolvConf`, `FuzzSocketTable`, `FuzzRejectUnknownFields`, `FuzzVerifyPlan`, `FuzzVerifyExecutionResult`, `FuzzVerifySource`, `FuzzQueueFile`, `FuzzCoreRequestDecoding` | Zero targets discovered, or a target that cannot start, fails the section ("Fuzz targets" failure). |
| 15 | Property tests | ADDED-THIS-PR | `go test -race -count=1 ./tests/replay/` (seeded PCG PRNG; seed printed per test) | Included in gate 11 (`adversarial-fixtures`); missing package fails gate 11. |
| 16 | Host-state replay (captured `state.capture` snapshots replayed through rollback) | PLANNED, owner S5 (`agent/driver` recovery contract) + S6 (nftables driver). Fixture target: `tests/replay/hoststate_test.go` against `agent/driver` once #61/#64 merge | Will run under `tests/replay` | Until landed: listed as AF-GAP-008. |
| 17 | Plan replay | ADDED-THIS-PR | `go test -race -count=1 -run '^TestProperty(SamePlanMutatesOnce|RevisionMonotonicity|TimeWindowEdges)$' ./tests/replay/` | Part of gate 11. |
| 18 | Capability spoofing | ADDED-THIS-PR (failing-first) | `go test -count=1 -run '^TestProperty(ManifestShortfallIsRefused|CapabilitySpoofIsDetected)$' ./tests/replay/` | Shortfall refusal passes today; spoof detection is AF-GAP-006 (S3). |
| 19 | Crash recovery (agent restarts mid-transaction, ownership record replays rollback) | PLANNED, owner S5 (`agent/driver/recovery.go`) with S6 consuming. Fixture target: `tests/hostile/crash_recovery_test.go` driving `FileStateStore` + driver ownership record through a killed child process | `go test -race -run '^TestCrashRecovery' ./tests/hostile/` once landed | Listed as AF-GAP-009. `NftablesAdapter` today only rolls back tables created by the same process instance (`agent/enforcement/nftables.go:166-169`). |
| 20 | Queue saturation | ADDED-THIS-PR | `go test -race -count=1 -run '^TestQueueSaturationUnderConcurrentWriters$' ./tests/hostile/` (also an explicit `verify.mjs --section adversarial` step; 60 s bound, 8 writers, 10000-event cap) | `-short` skips with ENV-UNAVAILABLE; the adversarial section never passes `-short`. |
| 21 | Network namespaces (rootless) | ADDED-THIS-PR | `go test -race -count=1 ./tests/netns/` (harness self-test: re-exec under `unshare -rn`, `nft list ruleset` empty, only `lo`, table created inside is invisible to the host). CI: `tests/ci/adversarial.yml` job `netns-smoke` | Skips with ENV-UNAVAILABLE when `unshare -rn` is blocked; the `netns-smoke` job runs `unshare -rn -- nft list ruleset` directly and **fails** (no skip) when user namespaces are unavailable on the runner. |
| 22 | Disposable Linux VM (install, enroll, enforce, uninstall against a throwaway VM) | PLANNED, owner S2 (packaging) with S10 providing the driver; candidate: GitHub-hosted `ubuntu-24.04` + `lxd`/`multipass` or a nested-virt matrix | To be defined in `tests/ci/adversarial.yml` job `vm-drill` | Until landed: AF-GAP-011. External CI must report `pass` through gate 12. |
| 23 | Partition / captive-portal drill (Core unreachable, DNS hijacked, portal redirect; agent must hold fail-closed and report `EXPOSED`/`UNAVAILABLE`, never `PROTECTED`) | PLANNED, owner S7 (mesh/route/dns drivers) using `tests/netns` (veth pair + hostile resolver inside the namespace) | `go test -run '^TestPartition' ./tests/netns/...` once landed | AF-GAP-012. |
| 24 | Upgrade / uninstall (state files and queue survive a binary upgrade; uninstall removes nft tables it owns and nothing else) | PLANNED, owner S2 with S5 (ownership record) | Part of the VM drill | AF-GAP-013. |
| 25 | Supply-chain verification (SHA-pinned actions, pinned container digests, reproducible generated code, `go mod tidy -diff`, lockfile installs) | EXISTS partially: all actions SHA-pinned (`ci.yml`, `codeql.yml`, `gitleaks.yml`), images digest-pinned (`scripts/tooling.mjs`), `go mod tidy -diff`, `npm ci`; SLSA provenance / signed release artifacts PLANNED, owner S1 | `verify.mjs --section go` (mod tidy), `--section proto` (parity), `npm ci` | Release signing absent: AF-GAP-014. |
| 26 | External adversarial CI report | ADDED-THIS-PR (gate 12, default FAIL) | `ADVERSARIAL_CI_RESULT=pass node scripts/acceptance.mjs --strict`, or `ADVERSARIAL_CI_RESULT_FILE=<path>` containing `pass` | Absent, empty, or any value other than `pass` fails the gate with "external adversarial CI unavailable is not a pass". |

### Gate 12 "required-once-configured"

Gate 12 (`external-adversarial-ci`) always reports `passed:false` unless the
external CI reported `pass`. It is marked `requiredOnceConfigured:true` and
`required:false` while neither `ADVERSARIAL_CI_RESULT` nor
`ADVERSARIAL_CI_RESULT_FILE` is present. `--strict` exits non-zero only when a
required gate fails, so the existing required check "Strict acceptance gates"
stays green until S1 wires the external CI to export the variable; from that
moment the gate is required and any value other than `pass` breaks the build.
The acceptance report exposes `required`, `requiredPassed`, and
`strictPassed` alongside `value`/`total` so the 11/12 state is visible, never
hidden. The live ruleset cannot require the external context yet because the
workflow that would produce it is not committed (S1 owns `.github/**`).

## Adversarial section of `scripts/verify.mjs`

`node scripts/verify.mjs --section adversarial` runs, in order:

1. `go test -race -count=1 ./tests/...` (hostile, fuzz seeds, replay, netns,
   end-to-end);
2. `go test -race -count=1 -run '^TestQueueSaturationUnderConcurrentWriters$' ./tests/hostile/`;
3. one bounded `-fuzz` run per discovered target (20 s each, sequential).

It is part of the default full verification (`npm run verify`). Node 22+ is
sufficient for this section; Go must be on `PATH` or Docker must be able to
run the pinned Go image.

## KNOWN-GAP table

| Id | Invariant (what the fixture asserts) | What `main` does today | Evidence | Owner lane |
|---|---|---|---|---|
| AF-GAP-001 | Identifiers (event ids, operation ids) reject control characters (CR, LF, NUL, ESC) at the boundary. | `internal/model.boundedString` and `core/server.bounded` only trim surrounding whitespace; `POST /v1/enrollment/tokens` with `operationId` `"op\r\nX: 1"` returns 201 and persists the id into audit. `PATCH /v1/nodes/{id}` is covered by `core/enrollment` validation and already refuses. | `tests/hostile/model_test.go` (`id-control-chars`), `tests/hostile/server_test.go` (`TestCoreRejectsControlCharactersInIdentifiers`) | S8 (core boundary) for `core/server` + `core/enrollment`; `internal/model` via S4 trust envelope |
| AF-GAP-002 | Duplicate JSON object keys are rejected by every request decoder. | `core/server.decodeJSON` (encoding/json) keeps the last duplicate; `PATCH /v1/nodes/{id}` with two `operationId` keys returns 200. The protojson decoders (`decodeProtoJSON`, event batch) already reject duplicates. | `tests/hostile/server_test.go` (`TestCoreJSONDecoderRejectsDuplicateKeys`) | S8 |
| AF-GAP-003 | `identity.IssueNodeCertificate` refuses empty, whitespace, control-character, or oversize node ids. | Any string is accepted into the certificate CN; canonical form is enforced only at enrollment (`core/enrollment`). | `tests/hostile/identity_test.go` (`TestIssueNodeCertificateRejectsHostileNodeIDs`) | S8 (core identity hardening) |
| AF-GAP-004 | World-readable identity artifacts (`deployment.json`, `ca.key`, `audit.key`) are treated as a compromise signal and refused. | `readIdentityFile` chmods the file back to 0600 and loads it. | `tests/hostile/identity_test.go` (`TestIdentityEnsureRefusesWorldReadableState`) | S8; needs an ADR-level decision (repair vs refuse) |
| AF-GAP-005 | One corrupt queue entry cannot block delivery of every other event. | `agent/runtime.Queue.load` validates the JSON envelope but not each `wire`; `Batch` then fails for the whole queue on the first bad entry (`queued event is invalid`), so healthy events behind it are never delivered and the queue fills. | `tests/hostile/queue_test.go` (`TestQueuePoisonEntryDoesNotBlockDeliveryForever`) | S2 (agent runtime; owner of `cmd/antiflock-agent` wiring) with S5 review |
| AF-GAP-006 | A caller-supplied capability manifest is not believed without signature, expiry, node binding, and driver probe. | `agent/enforcement.New` accepts any manifest whose `node_id` string matches; an expired, unsigned manifest with `implementation=none` and constraint `no-host-mutation` claiming FULL commits a plan with 4 driver mutations. | `tests/replay/replay_test.go` (`TestPropertyCapabilitySpoofIsDetected`) | S3 (`agent/enforcement/manifest.go`, readiness) with S5 probes (#61/#64) |
| AF-GAP-007 | A plan nonce is single-use across plan ids and revisions. | `MemoryStateStore` keys replay protection on plan id, fingerprint, and revisions only; a new id at a higher revision reusing a committed nonce commits. | `tests/replay/replay_test.go` (`TestPropertyNonceReuseIsRefused`) | S3 (state store contract) with S5 (`FileStateStore`) |
| AF-GAP-008 | Captured host state (`state.capture`) replays deterministically through rollback. | No `state.capture` implementation exists; check types are named but unimplemented (`enforcer.go:545-547`). | gate 16 above | S5 + S6 |
| AF-GAP-009 | An agent killed mid-transaction recovers and rolls back from a durable ownership record. | `NftablesAdapter` rollback only deletes tables created by the same process instance; no ownership record on disk. | gate 19 above | S5 |
| AF-GAP-010 | npm and Gradle dependency trees are audited in CI. | Only govulncheck (Go) and Dependabot bumps exist. | gate 13 above | S1 |
| AF-GAP-011 | A disposable Linux VM drill installs, enrolls, enforces, and uninstalls. | No packaging or VM job exists (`release workflow: not present`). | gate 22 above | S2 + S10 |
| AF-GAP-012 | Partition / captive-portal drill proves fail-closed hold. | No driver implements `mesh.connected`/`route.egress`/`dns.path`; nothing to drill yet. | gate 23 above | S7 |
| AF-GAP-013 | Upgrade and uninstall preserve state and remove only owned tables. | No packaging exists. | gate 24 above | S2 + S5 |
| AF-GAP-014 | Release artifacts carry verifiable provenance. | No release workflow, no signing. | gate 25 above | S1 |

Gap ids are allocated sequentially and never reused. Closing a gap means: the
owner lane lands the fix, the skipped fixture turns green without edits, and
the row is moved to a "Closed" section with the closing PR number.

## Post-merge fixture targets (not on `main` yet)

The following packages are open lane PRs. Fixtures for them are planned here
so the first PR that lands each package also lands its hostile coverage:

| PR | Package | Planned fixtures (S10 lease: `tests/**`) |
|---|---|---|
| #61 | `agent/driver` probe seam | `tests/hostile/driver_probe_test.go`: probe output with control chars, oversized, claims beyond manifest, probe timeout, probe panic; each must surface as `Readiness{Available:false, ReasonCode:...}` and never as FULL. |
| #64 | `agent/driver` contract + conformance | `tests/replay/driver_conformance_test.go`: run the conformance suite against a hostile driver double (lies about rollback success, returns VERIFIED evidence, mutates before Check) and assert the enforcer downgrades or rejects. |
| #65 | `agent/capability` hardened loader | `tests/fuzz/capability_test.go`: `FuzzLoadManifest` (JSON and wire), symlink/oversize/loose-mode loader cases mirroring `queue_test.go`; replaces AF-GAP-006's skip with a live assertion. |
| #66 | `internal/trust` taint + hostile corpus | `tests/hostile/taint_test.go`: every `tests/hostile` input is wrapped in a taint envelope and must fail to reach a structured-output sink untainted; reuse `internal/trust/testdata/hostile/**`. Closes the `internal/model` half of AF-GAP-001. |
| #63 | `core/integration` witness | `tests/replay/witness_test.go`: witness anchor replay with reordered, duplicated, and back-dated anchors; a witness that disagrees with the local chain must produce a finding, not a silent overwrite. |

## Counts at this PR

Run with `go test -race -count=1 -v ./tests/...` on Linux (WSL Ubuntu 22.04,
Go 1.26.6):

| Package | Top-level tests | Passing | Skipped (KNOWN-GAP) | Skipped (ENV) |
|---|---|---|---|---|
| `tests/hostile` | 27 | 22 | 4 whole tests (AF-GAP-002, -003, -004 and AF-GAP-001 in `TestCoreRejectsControlCharactersInIdentifiers`) + subtests under AF-GAP-001 (`id-control-chars`) and AF-GAP-005 (7 poison-entry subtests) | 0 on Linux |
| `tests/replay` | 7 | 5 | 2 (AF-GAP-006, AF-GAP-007) | 0 |
| `tests/fuzz` | 10 seed-corpus targets | 10 | 0 | 0 |
| `tests/netns` | 3 | 3 | 0 | 0 where `unshare -rn` works |
| `tests/end-to-end` | 1 | 1 | 0 | 0 |

Exact per-test names and the reason codes they assert are in the test files;
the invariant is the doc comment above each test.
