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

## Review and merge

`main` is protected by a repository ruleset with no bypass actors: one
approving review of the last push, every thread resolved, linear history, and
eight required status checks that must pass on the exact commit being merged
(`GOVERNANCE.md` lists them). Merges are squash or rebase only; keep your
branch rebased on `main` because the checks are strict (up to date required).

Do not rename the CI jobs in `.github/workflows/ci.yml`, `codeql.yml`, or
`gitleaks.yml`: their job names are the required status-check contexts, and a
rename silently detaches the gate until the ruleset is edited.

Reviews from AI agents or automated tools are welcome as advisory evidence on
a pull request; they never count as the approving review. Two accounts
operated by the same person are one reviewer. Dependency additions (Go
modules, npm packages, new GitHub Actions) are called out explicitly in the
pull request; every action is pinned to a full commit SHA with a version
comment. See `docs/supply-chain.md` and `docs/release-policy.md`.

By intentionally submitting a contribution, you agree that it is licensed
under the repository's Apache License 2.0 unless you conspicuously mark it as
not a contribution before submission.
