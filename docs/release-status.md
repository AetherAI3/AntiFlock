# Reference vertical-slice release status

Status date: 2026-07-22

The repository implements the locked, local, simulation-backed protected-action
vertical slice. This is an engineering completion boundary, not a claim of
production network protection or public-launch readiness.

## Implemented boundary

| Capability | Current state | Evidence boundary |
| --- | --- | --- |
| Identity and enrollment | Durable deployment/operator identity, one-time enrollment, node lifecycle, scoped credentials | Local Core and reference agents; platform keystore enrollment remains external work |
| Event and projection spine | Immutable idempotent events, SQLite projections, replay cursors, retention, signed hash-chained audit | Local relational store; no hosted replication claim |
| Decision plane | Deterministic posture, findings, policy compilation, signed expiring plans, secure-action gate | Decisions use available evidence and remain fail-closed on missing or stale inputs |
| Agent observation | Linux network/route/DNS collection plus read-only Tailscale and Headscale probes | Host observations are `DETECTED` unless an explicit verification method succeeds |
| Enforcement transaction | Validate, snapshot, apply, verify, commit or roll back; durable local transaction state | The executable agent does not enable production host mutation in this release |
| Secure Action SDK | Request binding, callback isolation, hold/block/allow, durable single-use grant consumption, mandatory execution-start audit, evidence-provenance enforcement | Reference TypeScript SDK and Aether demonstration only; simulation callbacks require an explicit per-call test opt-in |
| Android Guard | Pure Kotlin/JVM fail-closed state machine, platform ports, recording adapters, deterministic reference app | No APK, `VpnService`, real packet transport, or real-device validation |
| Third-Eye dashboard | Authenticated same-origin Core proxy, live projections/stream, all locked views and command boundaries | Private/local operator surface; Core credentials never enter browser JavaScript |
| Scrambler | Deterministic bounded simulation and explanation | Execution is disabled and no host/provider state is changed |
| Nano watchdog | Pinned Nano v0.1 Go conformance compiler/runtime, caller-owned schedule cursor, bounded finding projection, and immutable admitted Secure Action proposals | Proposal-only reference; Nano has no I/O or mutation capability and `antiflock-nano` actions require consent even under protected posture |
| Public surface | Verified-owned-asset provider contract plus deterministic Shodan-style, broker-registry, and paste-reference fixtures | Offline digest-only `REPORTED`/`SIMULATION` evidence; no live third-party scraping or raw public data retrieval |
| Vehicle appearance | Android coarse-feature, session-local HMAC correlation and aggregate-only output | In-memory reference only; no frames, faces, plates, VIN/OCR, embeddings, make/model, exact location, or cross-session tracking |
| Coffee-shop flow | Live Core + durable SQLite + simulator executes `HOLD` through verified recovery to `ALLOW` with five audit events | All network and recovery verification is explicitly labeled simulation |

## Verification contract

The sole release command is:

```powershell
npm run verify
```

It must pass from a clean checkout with locked dependencies and no undocumented
host tools. The final verified commit and evidence report are recorded in the
LOOP-18 run artifacts under `_loopstate/LOOP-18/`.

The strict acceptance harness has ten gates and reports
`reference_vertical_slice_gates_passed`. A release candidate requires `10 / 10`;
the presence of a file alone is not sufficient for runnable Core, web, SDK, and
coffee-shop gates. The SDK gate includes a live Core/SQLite restart test that
proves hold-to-allow re-evaluation, exactly-once callback execution, durable
lifecycle audit, idempotent replay, and changed-content conflict rejection.

## Explicitly not complete

The following are intentionally outside this reference-release boundary and
must not be inferred from a green verification run:

- production VPN or packet transport;
- a validated Android always-on/lockdown kill switch;
- unattended nftables or other privileged host mutation;
- real Tailscale, Headscale, WireGuard, DNS, captive-portal, or roaming tests;
- proof of interception, tracking, or active surveillance;
- imported or redistributed field-intelligence datasets;
- live Shodan, broker-registry, or paste-site retrieval;
- synthetic-profile publishing, location/device spoofing, or exposed honeypots;
- production Scrambler activation;
- public use of the `AntiFlock` working name;
- external penetration testing, privacy review, legal review, or release signing.

These are separate release gates because falsely claiming them would weaken the
project's safety and evidence contracts.
