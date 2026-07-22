<!--
AntiFlock pull request. This repository is security- and privacy-sensitive.
A change is complete only when its behavior, evidence, and failure modes are
understandable. See CONTRIBUTING.md and docs/README.md.
-->

## Summary

<!-- The operator outcome, and the threat or failure mode you considered. -->

## Contracts & capabilities affected

<!-- Which docs/ contracts, protobuf schemas, or node capabilities does this touch? "None" is valid. -->

## Data handling

<!-- Data collected, transmitted, retained, or deleted by this change. "None" is valid. -->

## Tests & verification

<!-- Normal, failure, replay/idempotency, offline, and privacy-boundary coverage; manual steps run. -->

- [ ] `npm run verify` passes locally, or CI is green
- [ ] Added tests for failure, replay/idempotency, offline behavior, and privacy boundaries on the touched surface

## Compatibility & migration

<!-- Wire/protobuf compatibility and migrations. Protobuf fields are add-only once released; reserve, never renumber. -->

## Rollback / recovery

<!-- How this change rolls back or recovers on failure. -->

## Known limitations & evidence still unavailable

<!-- Be evidence-honest: state what this does NOT prove or protect. -->

## Checklist

- [ ] Enforcement stays deterministic — model output may explain but must not decide
- [ ] Evidence class, confidence, freshness, source, and false-positive context are preserved
- [ ] No real credentials, private identifiers, packet payloads, exact location, or unredacted media in fixtures or logs
- [ ] For security / privacy / evidence / community-safety / Scrambler design changes, an ADR is proposed or linked
- [ ] Exploitable vulnerabilities are reported privately (see SECURITY.md), not in this PR
