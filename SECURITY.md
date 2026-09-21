# Security policy

AntiFlock is pre-release security software. Do not rely on it as the sole
control for life safety, emergency communication, legal compliance, anonymity,
or protection against a determined observer.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting for this repository:
<https://github.com/AetherAI3/AntiFlock/security/advisories/new>. Do not open a
public issue for a suspected vulnerability. If private reporting is
unavailable, contact a listed maintainer through a private channel and disclose
only enough to establish a secure reporting path; do not include exploit
details in a public forum.

Include, when safe:

- affected version, commit, platform, and component;
- impact and preconditions;
- minimal reproduction or proof of concept;
- whether enrollment, identity, plan signing/replay, privileged enforcement,
  location, community safety, or Scrambler rollback is involved; and
- a safe way to contact you.

Do not test against systems, accounts, people, monitoring equipment, or
networks you do not own or have explicit authorization to assess. Do not access
or retain other people's data, disrupt service, degrade emergency access,
publish precise sensitive locations, or use AntiFlock to interfere with
equipment.

## Response targets

The project is maintained by one person today (see "Who reviews" below), so
these are targets, not guarantees:

| Step                                                 | Target                    |
| ---------------------------------------------------- | ------------------------- |
| Acknowledge a complete private report                | 3 business days           |
| Initial severity classification and reproduction     | 7 days                    |
| Fix or documented mitigation for critical/high       | 30 days from acknowledgement |
| Fix or documented mitigation for medium/low          | 90 days from acknowledgement |
| Coordinated public disclosure                        | at fix release, or 90 days, whichever is first, unless agreed otherwise |

Reports affecting private keys, authentication, authorization, enrollment,
signed plans, bypass, rollback, payload or precise-location exposure, or
community abuse controls are treated as release-blocking until assessed.
Maintainers preserve evidence and credit reporters who want credit.

## Supported versions

| Version                                   | Supported                                   |
| ----------------------------------------- | ------------------------------------------- |
| `main` (latest commit)                    | yes — receives all fixes                    |
| `v0.1.0-alpha` and earlier                | no — engineering boundary, not a release    |
| release-qualified tags (none cut yet)     | the latest patch of the latest minor only   |

There is no release-qualified tag yet. When one exists, only the latest patch
release of the latest minor line is supported; older lines receive fixes only
when a maintainer explicitly commits to a backport in the advisory.

## Who reviews, and what a merge proves

`main` is protected by repository ruleset `21237783` with no bypass actors:
one approving review of the last push, all review threads resolved, linear
history, and eight required status checks that must pass on the exact commit
(`Protobuf contracts`, `Go 1.26.6`, `Node.js 24 workspaces`,
`Android reference JVM tests`, `Strict acceptance gates`, `analyze (go)`,
`analyze (javascript-typescript)`, `scan`). `GOVERNANCE.md` lists the full
rule set.

Be clear about what that proves. The two collaborator accounts (`AetherAI3`,
the automation/author account, and `dbarrante`, the human maintainer) are
operated by the same person. An approval from one on the other's pull request
satisfies the ruleset mechanically but is **not independent security review**.
Reviews from AI agents are advisory evidence attached to the pull request and
are never the approving review. Until an unaffiliated maintainer joins, every
merge is self-reviewed, and external review of security-sensitive code is
welcome and solicited.

## Release integrity

- The first release-qualified tag will be cut only from a `main` commit whose
  required checks passed on that exact SHA; `release.yml` refuses otherwise.
- Artifacts are signed with sigstore cosign **keyless** under the identity of
  `.github/workflows/release.yml` on this repository. Verify with:

  ```sh
  cosign verify-blob --bundle SHA256SUMS.sigstore.json \
    --certificate-identity "https://github.com/AetherAI3/AntiFlock/.github/workflows/release.yml@refs/tags/<tag>" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    SHA256SUMS
  sha256sum -c SHA256SUMS
  ```

- Every release carries a CycloneDX SBOM and a provenance attestation on
  `SHA256SUMS`. An artifact that is not listed in a verified `SHA256SUMS` is
  not a release artifact, whatever its file name says.
- Releases are created as drafts and published by a human; see
  `docs/release-policy.md` for rollback.

## Security invariants

- Never submit private keys, recovery credentials, enrollment token values,
  operator identifiers, exact location, or packet payloads in an issue or log.
- Never weaken evidence labels or warning honesty as a mitigation shortcut.
- Never force-push or silently rewrite a security audit trail.
- Security fixes that change a public contract require a compatibility and
  migration note.
