# AntiFlock vertical-slice ratchet

This run applies LOOP-18's monotonic verification discipline to a multi-capability
build by treating each independently testable capability slice as a separate tooth.
The fixed measurement harness is:

```text
node scripts/acceptance.mjs
```

The metric is `locked_vertical_slice_gates_passed`, higher is better, with ten
gates derived directly from the locked engineering objective. A strict release
verification uses `node scripts/acceptance.mjs --strict`.

LOOP-18 remains a single-variable tuning primitive. This run does not claim that
the entire architecture is one lever; every integrated capability is separately
reviewed and verified before the next is accepted.

