# Governance

AntiFlock is governed as safety-sensitive open-source infrastructure. The
current name is an internal working title and is not cleared for public launch;
governance under this file does not claim a trademark or affiliation with any
existing project.

## Roles

- **Contributors** propose code, documentation, research, reports, and review.
- **Maintainers** merge changes, cut releases, and steward one or more domains.
- **Security and privacy maintainers** review identity, authorization,
  privileged execution, evidence, data collection, retention, community abuse,
  and Scrambler changes.
- **Project lead** resolves decisions that remain blocked after documented
  alternatives and objections. Until named in the repository, this role is
  held by the repository owner and may not be inferred from commit access.

Repository permissions are not permission to override safety contracts.

### Current accounts

The repository currently has two collaborators:

- `AetherAI3` — repository admin. This account authors most changes and runs
  the project's automation; treat it as the bot/author account.
- `dbarrante` — write access. This is the human maintainer.

Both accounts are operated by the same person today. See the independence
rule below for what that means for review.

## Decisions

Routine, reversible changes use normal review. Architecture, wire-compatibility,
privacy, security, evidence semantics, community-safety, naming, and governance
changes require an ADR or equivalent design record with consequences and
explicit domain-maintainer approval. Maintainers seek rough consensus, record
material objections, and favor the narrower, privacy-preserving, reversible
choice when evidence is incomplete.

No maintainer may unilaterally:

- weaken the prohibition on tracking or targeting people;
- permit equipment interference, harassment, or automatic evasion routes;
- put model output into the blocking path;
- upload exact continuous location or collect payloads by default;
- make truthful evidence semantics subscription-dependent;
- bypass signed plans, verification, or rollback for Scrambler; or
- publicly launch under the working name without documented clearance.

## The `main` gate

`main` is the only release branch. It is protected by a GitHub **repository
ruleset**, not classic branch protection: ruleset `21237783`,
"Protect main release gate", enforcement `active`, target `~DEFAULT_BRANCH`.
Anyone can read it with
`gh api repos/AetherAI3/AntiFlock/rulesets/21237783`. As of 2026-08-23 it
enforces exactly the following; this document is updated in the same pull
request as any change to the ruleset.

**Bypass actors: none.** No account, app, role, or team may bypass the
ruleset, including repository admins.

Branch rules:

- deletion blocked;
- non-fast-forward (force) pushes blocked;
- linear history required (squash or rebase merges only; merge commits are
  refused).

Pull-request rule:

- at least **1 approving review**;
- **approval of the last push is required** (a new push after approval
  invalidates it);
- stale reviews are dismissed on push;
- every review thread must be resolved;
- changes with unattributed commits require an extra approval;
- allowed merge methods: squash and rebase;
- code-owner review is **not** required (`.github/CODEOWNERS` is advisory and
  drives reviewer assignment only).

Required status checks, **strict** (the branch must be up to date with `main`
before merging), by exact context name:

| Context                          | Workflow / job                                                 |
| -------------------------------- | -------------------------------------------------------------- |
| `Protobuf contracts`             | `ci.yml` → `contracts`                                         |
| `Go 1.26.6`                      | `ci.yml` → `go` (gofmt, tidy, test, race, vet, staticcheck, govulncheck) |
| `Node.js 24 workspaces`          | `ci.yml` → `javascript`                                        |
| `Android reference JVM tests`    | `ci.yml` → `android`                                           |
| `Strict acceptance gates`        | `ci.yml` → `acceptance` (ten-gate strict harness)              |
| `analyze (go)`                   | `codeql.yml` → `analyze` matrix                                |
| `analyze (javascript-typescript)`| `codeql.yml` → `analyze` matrix                                |
| `scan`                           | `gitleaks.yml` → `scan` (full-history secret scan)             |

Because the contexts are matched by name, **renaming a CI job, or changing
the Go version in the `Go 1.26.6` job name, silently detaches the required
check** until the ruleset is edited in the same change. Do not rename these
jobs without updating the ruleset and this table together.

Additional workflows (`dependency-review.yml`, `release.yml`, and any
adversarial gate) are advisory until they are added to the ruleset; adding a
context to the ruleset is a governance change recorded here.

### Independence rule

A review counts as the approving review only when it is **independent** of
the change:

- Two accounts operated by the same person are one reviewer. Approval from
  `dbarrante` on a pull request authored by `AetherAI3` (or the reverse) satisfies
  the ruleset mechanically but is **not** independent security review, and is
  recorded as self-review in the controller ledger that accompanies each
  merge train. Until a second, unaffiliated maintainer exists, every merge to
  `main` is self-reviewed and the project says so plainly in `SECURITY.md`.
- Reviews produced by AI agents or automated reviewers are **advisory
  evidence**. They may be attached to a pull request and cited, but they are
  never the approving review and never substitute for a human maintainer.
- A reviewer who authored any commit in the pull request is not independent
  for that pull request.

The ruleset enforces the mechanics; this rule governs what the mechanics may
be taken to mean.

## Changes and releases

All changes are reviewed through branches and pull requests against `main`;
nobody pushes to `main` directly. A release requires passing tests, schema
compatibility review, dependency and artifact provenance, known-risk notes, and
security/privacy sign-off proportional to the touched surface. Critical
findings block release unless the project lead and security maintainers
document an explicit, time-bounded exception that does not put users or third
parties at unreasonable risk.

Generated contracts derive from the checked-in protobuf sources. Published
field or enum numbers are never reused. Security corrections remain visible in
history; confidential exploit detail may be embargoed until coordinated
disclosure.

### Release baseline

No release-qualified tag exists yet. `v0.1.0-alpha` marks an engineering
completion boundary and predates this gate; it is not a supported release.

**The first release-qualified tag will be cut only from a `main` commit whose
required status checks (all eight contexts above) passed on that exact SHA.**
A green run on a predecessor commit, on a pull-request merge ref, or on a
rebased copy of the same diff does not qualify. `release.yml` checks this
mechanically and refuses to build otherwise; see `docs/release-policy.md` for
the flow, artifact set, and rollback rules.

### Release signing

Release artifacts are signed with **sigstore cosign, keyless**, using the
GitHub Actions OIDC identity of `release.yml` on this repository. There is no
long-lived signing key to lose or rotate; verification pins the certificate
identity `https://github.com/AetherAI3/AntiFlock/.github/workflows/release.yml@refs/tags/<tag>`
and the issuer `https://token.actions.githubusercontent.com`. A signature made
by any other identity, including a maintainer's personal key, is not a release
signature.

### SBOM and checksums

Every artifact set ships with a CycloneDX JSON SBOM generated by `syft`
(`anchore/sbom-action`, pinned by commit) and a `SHA256SUMS` file covering
every binary and the SBOM. `SHA256SUMS` is the signed object; a cosign
provenance attestation binds it to the source commit, the workflow ref, and
the Go toolchain. Consumers verify the bundle, then the checksums, then use
the binaries; any other order proves nothing.

### Supply chain

- Every GitHub Action is pinned to a full commit SHA with a version comment.
  Dependabot (`.github/dependabot.yml`) proposes pin updates weekly.
- New Go module dependencies require maintainer sign-off in the pull request
  and must pass `govulncheck` and the dependency-review workflow.
- Release builds use `-trimpath -buildvcs=true` with CGO disabled so the
  binary records the exact source revision and whether the tree was clean.
- Release workflows use only the ephemeral `GITHUB_TOKEN` and OIDC token.
  There are no repository secrets involved in building, signing, or
  publishing.

## Community intelligence moderation

Moderation follows `docs/community-intelligence-policy.md`. Reports are judged
by evidence, public-interest value, privacy, freshness, and safety rather than
commercial tier or viewpoint. Appeals and corrections are documented. Access
to non-public reporter information is least-privilege and audited.

## Conflicts and conduct

Maintainers disclose material employment, financial, vendor, dataset, or
personal conflicts and recuse when impartial review is doubtful. Conduct is
governed by `CODE_OF_CONDUCT.md`. Retaliation for good-faith security, privacy,
or safety concerns is prohibited.

## Amendments

Governance amendments require a public proposal, review period once a public
community exists, approval by a majority of active maintainers including one
security/privacy maintainer, and a recorded decision. Before that body exists,
the repository owner may bootstrap roles but may not weaken the locked safety
boundaries above, and may not add bypass actors to the `main` ruleset.
