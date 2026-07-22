# Contributing

Thank you for helping build AntiFlock. This repository is security- and
privacy-sensitive; a change is complete only when its behavior, evidence, and
failure modes are understandable.

## Before changing code

1. Read `docs/README.md`, the relevant contract documents, and accepted ADRs.
2. Open or reference an issue for substantial behavior or wire changes.
3. For security, privacy, evidence, community-safety, or Scrambler design,
   propose an ADR before implementation.
4. Never include real credentials, private identifiers, packet payloads, exact
   personal location, or unredacted field-report media in fixtures or logs.

## Change expectations

- Keep Core domain logic independent of provider and platform implementations.
- Observe before advise; advise before mutate. Every mutation needs dry-run,
  capability checks, verification, recovery, and rollback.
- Keep enforcement deterministic. Model output may explain but may not decide.
- Use evidence-honest wording and preserve evidence class, confidence,
  freshness, source, sensitivity, and false-positive context.
- Add tests for normal behavior, failure, replay/idempotency, offline behavior,
  and privacy boundaries on the touched surface.
- Treat protobuf fields and enum values as published once released. Add rather
  than renumber; reserve removed identifiers.
- Keep commits focused and explain the security or privacy consequence.

## Protobuf contracts

Canonical schemas live in `api/proto/antiflock/v1`. From `api/proto`, run
`buf lint` when Buf is available. A change to a released schema must also pass
`buf breaking` against the supported baseline. Generated code is not edited by
hand.

## Pull requests

A pull request should state:

- the operator outcome and threat or failure considered;
- contracts and capabilities affected;
- tests and manual verification performed;
- collected, transmitted, retained, or deleted data changes;
- compatibility and migration impact;
- rollback or recovery behavior; and
- known limitations and evidence that remains unavailable.

Maintainers may request focused security, privacy, accessibility, or abuse-case
review. Use private vulnerability reporting for exploitable issues.

By intentionally submitting a contribution, you agree that it is licensed
under the repository's Apache License 2.0 unless you conspicuously mark it as
not a contribution before submission.
