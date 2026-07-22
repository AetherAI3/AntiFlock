# AntiFlock frozen-reference audit artifact

## Outcome

- Product commit: `bab9126078bcd0307e879ed4807681b3ad7d7305`
- Product acceptance: **PASS**, `10/10` three times
- Strict LOOP-18 result: **FAIL-PROTOCOL-DEVIATION**
- Intended disposition: draft pull request to `main`; no automatic merge

## Locked reference boundary

- Nano v0.1-compatible parsing, deterministic evaluation, and proposal creation
  with caller-owned scheduler state and bounded resource budgets.
- Nano remains proposal-only: it performs no I/O and cannot mutate the host.
- Exact-scope Secure Action policy and one-time consent, durable execution-start
  consumption, evidence provenance, replay protection, and callback isolation.
- Owned-asset, digest-only public-surface fixture providers for Shodan-style,
  broker-registry, and paste-site evidence; all output is labeled simulation.
- Coarse, session-HMAC vehicle-appearance correlation with short rotation,
  aggregate-only output, and structural exclusion of images, plates, faces,
  VIN/OCR, embeddings, make/model, location, and free-form descriptors.
- Third-Eye informed-consent UI and persistent live/simulation provenance.

## Explicitly not shipped

- No live Shodan, data-broker, or paste-site scraping.
- No camera ingestion, computer vision, plate recognition, person tracking, or
  natural-language video analytics.
- No durable Nano program-install/evaluate API or local-context threat ledger.
- No autonomous host mutation, routing changes, honeypots, identity deception,
  synthetic profile deployment, location spoofing, or device-fingerprint spoofing.

## Verification evidence

- Exact acceptance harness values: `[10, 10, 10]`; total `10`; tolerance `0.01`.
- Focused Go packages passed, including Nano, footprint providers, Core server,
  storage, actions, config, and simulator.
- TypeScript SDK: 40 tests passed.
- Web: build, lint, 25 unit tests, and 3 rendered-route tests passed.
- Aether demo: build and 2 scenario tests passed.
- Live Core-to-SDK Compose test passed, including restart durability and replay
  conflict checks.
- Android: the full pinned Gradle test task passed inside every acceptance run.

The broader `npm run verify` process was stopped while still running when the
operator requested immediate publication. The three strict acceptance runs each
executed the complete ten-gate product harness and all returned successfully.
