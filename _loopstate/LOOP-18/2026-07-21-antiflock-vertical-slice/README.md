# AntiFlock vertical-slice LOOP-18 audit

> **Strict LOOP-18 verdict: FAIL-PROTOCOL-DEVIATION**
>
> **Frozen reference-product verdict: PASS — 10/10 gates in three runs**

The run produced a passing reference implementation, but it is not a valid
LOOP-18 weld. LOOP-18 permits exactly one declared variable and one isolated
change. This run built multiple capability slices and its original baseline used
one sample with a zero-width tolerance. Treating each slice as a separate tooth
did not cure that scope violation. The historical JSON checkpoints are preserved
unchanged as evidence of what actually happened.

The frozen product commit is
`bab9126078bcd0307e879ed4807681b3ad7d7305`. The exact reproducibility harness was:

```text
node scripts/acceptance.mjs --strict
```

It returned `10/10` at `2026-07-22T11:08:32.748Z`,
`2026-07-22T11:10:39.726Z`, and `2026-07-22T11:12:32.392Z`, for an observed
spread of `0` against a declared `0.01` tolerance.

See `protocol-deviation-and-rebaseline.json`, `adversarial-weld-audit.md`, and
`AUDIT-ARTIFACT.md`. A future LOOP-18 invocation must start clean and name one
metric, one lever, and one isolated diff before any product change.
