# Adversarial weld audit

## Round 1 — Weld Auditor

- Apples-to-apples remeasurements: pass. All three final measurements used the
  literal command `node scripts/acceptance.mjs --strict` on commit
  `bab9126078bcd0307e879ed4807681b3ad7d7305`.
- Tolerance legitimacy: pass for final reproducibility only. Three values of 10
  have spread 0; the declared tolerance is 0.01.
- Single-suspect discipline: fail. The product commit contains Nano parsing and
  proposals, Secure Action hardening, public-surface fixtures, vehicle privacy
  references, dashboard consent, schema, storage, and documentation changes.
- Cherry-picking: pass. Every requested final run is recorded: `[10, 10, 10]`.
- Baseline comparability: fail. The historical baseline used one sample and a
  zero-width tolerance before this multi-capability build.

Round 1 rejects the weld. Product acceptance is not a substitute for LOOP-18's
single-variable causal guarantee.

## Round 2 — Hostile confirmation

The strongest counterargument is that each acceptance gate can be treated as an
independent ratchet tooth. That argument fails because the final remeasurement
observes all accumulated changes together, so no one diff is the sole suspect.
The original artifacts also show that the baseline sampling requirement was not
met. The immutable commit and three clean final runs establish repeatability and
product readiness for review, but they cannot retroactively create a compliant
baseline or isolated lever.

Final auditor verdict: **reject LOOP-18 weld; retain product commit for normal PR
review; report `FAIL-PROTOCOL-DEVIATION` with product result `PASS`.**
