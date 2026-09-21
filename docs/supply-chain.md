# Supply chain

How third-party code and build tooling enter this repository, and what a
consumer can verify about what leaves it. `GOVERNANCE.md` is the policy;
this is the inventory.

## Inputs

| Input                        | Control                                                                 |
| ---------------------------- | ----------------------------------------------------------------------- |
| Go modules (`go.mod`, `go.sum`) | `go mod tidy -diff` and `govulncheck` in the `Go 1.26.6` required check; new modules need maintainer sign-off in the pull request; Dependabot group `go-dependencies` weekly |
| npm workspaces (`apps/web`, `apps/aether-demo`, `sdk/typescript`) | lockfiles required (`scripts/install-js.mjs` installs with `npm ci`); Dependabot one group per workspace; there is no root npm entry because the root has no lockfile |
| GitHub Actions               | every `uses:` pinned to a full commit SHA with a `# vX.Y.Z` comment; Dependabot group `actions` weekly; `dependency-review.yml` reviews every pull request for vulnerable or disallowed-license additions |
| Container base images        | `deploy/docker/core.Dockerfile` pins `golang` and `distroless` by digest; Dependabot `docker` entry weekly |
| Protobuf toolchain           | Buf version pinned in `ci.yml`; generated code parity is a required check (`Protobuf contracts`) |
| Secrets in history           | `gitleaks` full-history scan is a required check (`scan`); `.gitleaks.toml` allowlists only generated code and non-secret fixtures |

Pull requests that bump pins are reviewed like any other change; a green
Dependabot PR is not auto-merged.

## Build

Release binaries are built by `.github/workflows/release.yml` on GitHub-hosted
`ubuntu-24.04` runners with:

- Go `1.26.6`, the same toolchain as the required `Go 1.26.6` check;
- `CGO_ENABLED=0`, `-trimpath`, `-buildvcs=true`, `-ldflags="-s -w"`;
- a clean checkout of the exact tagged commit (the workflow refuses a dirty
  tree).

`deploy/docker/core.Dockerfile` uses the same flags except `-buildvcs` (its
build context has no `.git`, so image binaries carry no VCS stamp and will not
match the release checksums). A rebuild from a clean git checkout of the same
commit with the same Go version and flags is expected to reproduce the release
binaries byte-for-byte; independent rebuilds that match `SHA256SUMS` are
welcome as review evidence.

## Outputs

Every release-qualified tag ships with a CycloneDX SBOM, `SHA256SUMS`, a
cosign keyless signature bundle, and a cosign provenance attestation bundle.
`docs/release-policy.md` lists the artifact set and the verification order.
The signing identity is the workflow itself; there is no long-lived key.

## Permissions

- `main` ruleset `21237783`: no bypass actors, eight required contexts, one
  approving review of the last push, linear history. See `GOVERNANCE.md`.
- Workflows default to `permissions: contents: read`. Only the `release` job
  in `release.yml` holds `contents: write` and `id-token: write`; `codeql.yml`
  holds `security-events: write` for its own uploads.
- No workflow reads a repository or organization secret. The only credentials
  are the ephemeral `GITHUB_TOKEN` and the OIDC token.

## Known gaps

- The provenance attestation is produced by `cosign attest-blob` from a
  predicate the workflow writes itself. Moving to
  `actions/attest-build-provenance` (GitHub-generated SLSA provenance) needs
  `attestations: write` on the release job, which is a permissions change to
  be made deliberately.
- The container image is not a release artifact and is not signed.
- `dependency-review.yml` is advisory until added to the ruleset.
- The two collaborator accounts are operated by one person; see the
  independence rule in `GOVERNANCE.md`.
