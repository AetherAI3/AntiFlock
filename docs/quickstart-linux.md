# Quickstart: antiflock-agent on a clean Linux host

This walks one Linux host (systemd, `amd64` or `arm64`) from nothing to a
running, enrolled observer, then through an upgrade, a rollback, and removal.
Everything the agent does in this release is read-only with respect to the
host network; see `docs/agent-lifecycle.md` for the boundary and
`docs/exit-codes.md` for exit codes.

You need: root on the host, a reachable AntiFlock Core URL, a deployment id,
and an operator-issued enrollment token (`POST /v1/enrollment/tokens`, see
`docs/api-contracts.md`). Replace the example values throughout.

## 1. Download and verify

Release artifacts and their verification procedure are defined in
`docs/release-policy.md`. Download the agent binary, `SHA256SUMS`, and the
two sigstore bundles for the tag, then verify **in this order**: signature,
provenance, checksum. A binary whose checksum is not in a verified
`SHA256SUMS` is not a release artifact.

```sh
tag=v0.2.0
arch=amd64   # or arm64
id="https://github.com/AetherAI3/AntiFlock/.github/workflows/release.yml@refs/tags/$tag"
iss=https://token.actions.githubusercontent.com

cosign verify-blob --bundle SHA256SUMS.sigstore.json \
  --certificate-identity "$id" --certificate-oidc-issuer "$iss" SHA256SUMS
cosign verify-blob-attestation --bundle SHA256SUMS.provenance.sigstore.json \
  --type slsaprovenance1 \
  --certificate-identity "$id" --certificate-oidc-issuer "$iss" SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
```

## 2. Install

Either install the package (deb/rpm built with `deploy/packaging/nfpm.yaml`
from the verified binary; package builds are not yet produced by the release
workflow), or install by hand:

```sh
install -m 0755 -o root -g root "antiflock-agent_${tag#v}_linux_${arch}" /usr/bin/antiflock-agent
install -m 0644 -o root -g root deploy/systemd/antiflock-agent.service /usr/lib/systemd/system/
groupadd --system antiflock
useradd --system --gid antiflock --home-dir /var/lib/antiflock --shell /usr/sbin/nologin antiflock
systemctl daemon-reload
antiflock-agent version
```

## 3. Initialise

```sh
antiflock-agent init \
  --node-id lab-node-1 --display-name "Lab node" \
  --deployment-id deploy-1 --core-url https://core.example.test:8787
chown -R antiflock:antiflock /var/lib/antiflock
```

`init` writes `/etc/antiflock/agent.yaml` (no secrets), creates
`/var/lib/antiflock` and `/var/lib/antiflock/queue` (`0700`), and generates
the node key (`0600`). It prints the key id, never the key. Re-running it
refuses to overwrite the config without `--force` and never replaces an
existing key. If Core uses a private CA, add `--ca-cert /etc/antiflock/core-ca.pem`.

## 4. Check the host

```sh
antiflock-agent doctor
antiflock-agent doctor --json | jq .result.missingRecoveryRequirements
```

Expect `PASS` for config, key, directories, and clock. `WARN` on `nft`/`ip`
only matters for future enforcement and is listed under "missing recovery
requirements"; observe mode needs none of it. Exit `3` means something must
be fixed before continuing (the reason code says what); `7` means warnings
only.

## 5. Enroll

Put the operator-issued token in a private file and submit:

```sh
install -m 0600 -o antiflock -g antiflock /dev/null /var/lib/antiflock/enroll.token
printf '%s' '<token>' > /var/lib/antiflock/enroll.token
sudo -u antiflock antiflock-agent enroll --config /etc/antiflock/agent.yaml \
  --enrollment-token-file /var/lib/antiflock/enroll.token
```

Exit `5` with `AF-ENROLL-PENDING` means an operator must approve the node in
Core. Re-run the same command after approval: exit `0` and
`/var/lib/antiflock/node.pem` is written. Then delete the token file.

## 6. Observe

One read-only, inspect-only pass (prints the observation, submits nothing):

```sh
sudo -u antiflock antiflock-agent observe --config /etc/antiflock/agent.yaml
```

One signed, durable submission cycle:

```sh
sudo -u antiflock antiflock-agent observe --config /etc/antiflock/agent.yaml --submit --once
```

Continuous operation under systemd:

```sh
systemctl enable --now antiflock-agent.service
systemctl status antiflock-agent.service
```

## 7. Status

```sh
antiflock-agent status
antiflock-agent status --json
```

`enrollment: ready` and a non-zero queue sequence confirm the loop works.
The driver table is `UNAVAILABLE` for every domain in this release; that is
the honest state, not an error.

## 8. Upgrade

Download and verify the new release exactly as in step 1. Write a local
manifest from the verified `SHA256SUMS` line (or ship one with the
artifacts), then check and apply:

```sh
new=antiflock-agent_0.3.0_linux_amd64
sum=$(grep " $new\$" SHA256SUMS | cut -d' ' -f1)
printf '{"document":"antiflock.release-manifest/v1","version":"0.3.0","artifacts":[{"name":"antiflock-agent","sha256":"%s"}]}\n' "$sum" > release.json

antiflock-agent update --check --manifest release.json        # exit 7 = update available
antiflock-agent update --from-file "$new" --manifest release.json
systemctl restart antiflock-agent.service
antiflock-agent version
```

`update` never downloads and refuses (exit `4`) if the file's checksum does
not match the manifest; the previous binary is kept as
`/usr/bin/antiflock-agent.previous`.

## 9. Roll back

```sh
antiflock-agent update --rollback
systemctl restart antiflock-agent.service
antiflock-agent version
```

## 10. Uninstall

```sh
antiflock-agent uninstall                 # dry run: lists what would be removed
antiflock-agent uninstall --yes --systemd # removes state, key, config; disables and removes the unit
rm /usr/bin/antiflock-agent /usr/bin/antiflock-agent.previous
```

`uninstall` refuses to remove anything outside the configured directories
and never touches firewall state. If a future release has created an
AntiFlock nftables table, its removal requires an explicit recovery plan;
`doctor` (as root) reports whether such a table exists.
