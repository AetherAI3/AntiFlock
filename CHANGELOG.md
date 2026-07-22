# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project adopts
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) once a public release
is cut.

## [Unreleased]

### Changed
- Public name is now **AntiFl0ck** (chosen to avoid a documented naming collision).
  Internal identifiers migrate via `scripts/rebrand-antifl0ck.mjs`; see
  [docs/REBRAND.md](docs/REBRAND.md). The module path `github.com/DBarr3/AntiFlock`
  is preserved.

## [0.1.0] — reference vertical slice

The locked, local, simulation-backed protected-action vertical slice. This is an
engineering completion boundary, **not** production network protection or
public-launch readiness. See [docs/release-status.md](docs/release-status.md) for
the exact capability boundary and the gates that remain.

### Added

- **Core** — durable deployment/operator identity and one-time enrollment; an
  append-only, idempotent event spine with SQLite projections, replay cursors,
  retention, and a signed hash-chained audit; deterministic posture and
  findings; policy compilation; signed, expiring per-node plans; and the Secure
  Action gate.
- **Agent** — Linux network/route/DNS collection and read-only Tailscale and
  Headscale probes; the validate → snapshot → apply → verify → commit-or-roll-back
  enforcement transaction (production host mutation disabled in this release).
- **Third-Eye dashboard** — an authenticated same-origin Core proxy with live
  projections and event stream; Core credentials never enter browser JavaScript.
- **Secure Action SDK (TypeScript)** — request binding, callback isolation,
  hold/block/allow, durable single-use grants, and a live Core/SQLite restart
  acceptance test.
- **Android Guard reference** — a pure Kotlin/JVM fail-closed state machine with
  platform ports and recording adapters (no APK, `VpnService`, or packet
  transport).
- **Nano v0.1 watchdog** — an independent Go conformance runtime that is
  proposal-only and has no host capability.
- **Deterministic coffee-shop scenario** — `HOLD` through verified recovery to
  `ALLOW`, with a complete durable local audit trail.

### Security

- Fail-closed on missing or stale evidence; deterministic reason codes; an
  evidence class and calibrated confidence on every claim; a ten-gate strict
  acceptance harness enforced by `npm run verify`.

[Unreleased]: https://github.com/DBarr3/AntiFlock/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/DBarr3/AntiFlock/releases/tag/v0.1.0
