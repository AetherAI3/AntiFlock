# AntiFlock

> Internal working title. Do not publicly launch under the AntiFlock name until
> the documented namespace collision has been cleared or the project is renamed.

AntiFlock is an open-source, self-hosted personal private-security operating
layer. It joins an operator's enrolled devices into one explainable protection
domain, observes network and mesh state, evaluates deterministic policy, and can
hold sensitive application actions when the approved route is unavailable.

**See your exposure. Understand your environment. Control the path.**

The first release target is a locally auditable coffee-shop demonstration:

1. A simulated phone joins an untrusted network.
2. Its approved private route fails.
3. AntiFlock reports the exact failure and blocks protected egress.
4. An integrated Aether action is held.
5. The route returns and is verified.
6. The held action proceeds and the complete decision trail remains in SQLite.

AntiFlock does not claim that a broken tunnel or nearby reported monitoring
infrastructure proves active surveillance. Every finding carries an evidence
class, confidence, source, and precise explanation.

## Quick start

Requirements: Docker Desktop or Docker Engine with Compose, plus Node.js 24 or
newer for local verification helpers.

```bash
make dev
```

`make dev` starts Core, the deterministic simulator, and the Third-Eye web
dashboard. It does not require a Tailscale account, Headscale server, real VPN,
or surveillance dataset.

Useful commands:

```bash
make test       # all Go and JavaScript tests
make verify     # formatting, tests, builds, and locked acceptance gates
make lab        # coffee-shop failure and recovery scenario
make down       # stop the local stack
```

On Windows without `make`, use the equivalent npm commands:

```powershell
npm run dev
npm test
npm run verify
npm run lab
```

## Architecture

AntiFlock Core is the control, policy, and intelligence plane. It is not placed
in the packet data path. Existing Tailscale, Headscale, or WireGuard transports
move encrypted traffic; endpoint agents retain cached policy and enforce locally
during Core outages.

The repository is a modular monolith with explicit adapter boundaries:

- `core/` owns identity, events, projections, posture, findings, policy, plans,
  secure actions, field intelligence, footprint data, audit, and Scrambler plans.
- `agent/` owns endpoint collection, cached policy, enforcement, recovery, and
  the least-privileged helper contract.
- `adapters/` owns platform and provider integrations.
- `apps/web/` is the Third-Eye dashboard.
- `apps/android/` is the Android Guard reference client.
- `sdk/typescript/` is the AntiFlock Secure Action SDK.

Read [the architecture overview](docs/architecture.md) and
[threat model](docs/threat-model.md) before changing a security boundary.

## Status

This repository is under active construction toward the locked vertical slice.
It must not be represented as a production VPN, a validated mobile kill switch,
or proof of active surveillance until the corresponding platform verification
and external security review are complete.

## License and security

Licensed under Apache-2.0. Report vulnerabilities using [SECURITY.md](SECURITY.md),
not a public issue.
