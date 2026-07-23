<div align="center">

<img src="assets/antiflock-mark.svg" alt="AntiFl0ck" width="360" />

**Open-source, self-hosted digital counterintelligence.**

See your exposure. Understand your environment. Control the path.

[![CI](https://github.com/DBarr3/AntiFlock/actions/workflows/ci.yml/badge.svg)](https://github.com/DBarr3/AntiFlock/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-2dd4bf.svg)](LICENSE)
[![Go 1.26](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go&logoColor=white)](go.mod)
[![Node 24](https://img.shields.io/badge/Node-24-339933?logo=node.js&logoColor=white)](package.json)
[![GitHub stars](https://img.shields.io/github/stars/DBarr3/AntiFlock?style=social)](https://github.com/DBarr3/AntiFlock/stargazers)

**[Quick start](#quick-start)** · **[Integrations](#integration-map)** · **[OPEN work](#open--production-work)** · **[Docs](docs/README.md)** · **[Contribute](#contributing)**

<sub>⭐ Star it — that's how people find an open security project.</sub>

</div>

---

> Your accounts, devices, and networks leave a trail that moves together like a **flock**.
> AntiFl0ck helps you see that trail and stay in control of it.

**Where it stands:** the local, simulated demo works and is tested behind a 10-check release
gate. It is **not** yet a real VPN, a phone kill-switch, or proof that anyone is watching you.
Details in [release status](docs/release-status.md). The roadmap uses **OPEN** for work that is deliberately not connected or production-ready yet.

## Start here

Run the simulation first. It gives you a safe, local tour of the action gate, evidence labels, audit trail, and Third-Eye dashboard without a VPN account, provider key, or host-level network changes.

```powershell
npm run dev
npm run lab
```

Then use the dashboard at <http://127.0.0.1:4173> with the password in `.antiflock/dev.env`. Treat that file as a secret. The [operator runbook](docs/operator-runbook.md) has the full lifecycle and recovery steps.

## What it is

AntiFl0ck runs on your own machines. It watches your network and devices, checks them against
rules you set, and can **pause a sensitive app action** when your trusted route isn't
available — keeping a clear, signed record of every decision.

It brings a few things together in one place:

- **Private mesh** — adds identity, policy, and enforcement on top of Tailscale / Headscale /
  WireGuard. It never touches your actual traffic.
- **Third-Eye view** — a map of your devices, routes, and who *could* see your metadata.
- **Guard** — simple rules that decide whether your path is safe, and stop traffic if it isn't.
- **Secure-action gate** — apps ask before doing something sensitive; you allow, hold, or block.
- **Scrambler** *(simulation only for now)* — plans safe, reversible changes to your setup.

## What it is not

Being honest is the whole point. AntiFl0ck **won't**:

- claim someone is spying on you — a broken tunnel or a nearby camera isn't proof;
- act as a real VPN, an anonymity tool, or a phone kill-switch *(yet)*;
- track people, or turn a guess into an alarm;
- let an AI make the block-or-allow decision.

AntiFl0ck **will**:

- report only what it can actually see, with a confidence level;
- follow your rules and **fail safe** (stop) when it's unsure;
- explain every decision in plain terms;
- keep the full record on your machine.

## How it works

Core is the brain: it manages identity, reads events, checks policy, and explains results — but
it never sits in your traffic path. Each device keeps a local copy of the rules, so protection
keeps working even if Core goes offline.

```text
 device + provider adapters
            |
     send signed events
            v
   event log  ──►  live views (devices, paths, posture, activity)
            |
   policy check  ──►  signed, expiring plan per device
            |                    |
            └────────►  device enforcer
                              |
                     verify, or roll back
```

## Integration map

```text
Linux device ── read-only routes / DNS / interface state ──┐
Tailscale CLI ── `tailscale status --json` (read-only) ───┼──> signed events / Third-Eye
Headscale adapter ── read-only client (**OPEN:** no CLI/runner) ──────┘             │
                                                                            v
Nano source + typed finding ── deterministic proposal ──> Secure Action gate ──> consent + audit
```

The safe direction of travel is deliberately one-way: adapters observe, Nano proposes, and only the existing gate can authorize a bounded action. No adapter, Nano program, dashboard, or provider key can silently become a host-mutation capability.

### Tailscale status preview

On a Linux device with the official Tailscale client already installed and connected, the current agent can inspect local mesh state without changing it:

```bash
antiflock-agent --node-id YOUR_ENROLLED_NODE --mesh-provider tailscale --mesh-dry-run
antiflock-agent --node-id YOUR_ENROLLED_NODE --mesh-provider tailscale
```

It runs only `tailscale status --json`; it never invokes `up`, `down`, `set`, `serve`, or `funnel`. This currently prints a local observation document—it does **not** enroll the device, upload continuously, configure an exit node, or change traffic. See **OPEN** Tailscale ingestion below.

### BYOK today

The local demo generates its own development credentials. Current Tailscale and Headscale probes are read-only and do not need a provider API key. If you add a provider integration, keep credentials in a local secret file or platform keystore, scope them to read-only access, and never put them in YAML, browser code, Git, or issue text. Live provider execution is **OPEN**, not a hidden feature flag.

## The evidence rule

AntiFl0ck labels every claim with how sure it is, so a guess never reads like a fact:

- **DETECTED** — seen directly on your device.
- **VERIFIED** — confirmed by a second source.
- **REPORTED** — someone else reported it; unconfirmed.
- **INFERRED** — a rule worked it out from known facts.
- **SUSPECTED** — might be happening; not confirmed.
- **UNKNOWN** — not enough information to say.

So *"unknown Wi-Fi gateway detected"* never quietly becomes *"the network is hostile."*

## Try it — the coffee-shop demo

Fully simulated. No VPN account or real data required.

```bash
make dev    # start Core, the simulator, and the dashboard
make lab    # run the demo: hold a risky action, recover, then allow it
```

The demo joins a fake untrusted network, loses the safe route, **holds** a sensitive action,
verifies the route came back, then lets it through — leaving a full audit trail in SQLite.
Open <http://127.0.0.1:4173> (username `operator`, token from `.antiflock/dev.env`).

## Quick start

Needs **Docker** and **Node 24+**.

| Command | What it does |
|---|---|
| `make dev` | Start the local stack |
| `make lab` | Run the coffee-shop demo |
| `make verify` | Full release check — tests, builds, and the 10 gates |
| `make down` | Stop everything |

On Windows without `make`, use `npm run dev` / `lab` / `verify`. Full guide:
[operator runbook](docs/operator-runbook.md).

## What's built

The local, simulated slice is done and tested. The real-world pieces are separate, later
milestones — we don't claim them until they're proven.

**Working now:** identity + enrollment · event log with signed audit · deterministic policy,
findings, and signed plans · secure-action gate + TypeScript SDK · Linux network observation ·
Third-Eye dashboard · Android Guard reference · Nano watchdog evaluator/proposal boundary · the coffee-shop demo end-to-end.

## OPEN — production work

These are visible project work items, not implied capabilities. They are tracked in more detail in [OPEN decisions and release gates](docs/open-questions.md).

| Area | What exists now | OPEN before calling it production |
| --- | --- | --- |
| Tailscale / Headscale | Read-only status probes and model contracts | enrolled-agent delivery, identity association configuration, scheduled ingestion, real-network/roaming tests, and operator-visible failure handling |
| Third-Eye | authenticated local dashboard with live Core projections | a documented install path for real agents, topology provenance UX, and production deployment/review |
| Network traffic monitor | privacy-minimized route, DNS, and interface observations; no packets | opt-in flow-metadata collector with a documented schema, retention controls, process attribution limits, and real-network validation |
| Nano watchdog | deterministic parser/evaluator, bounded finding frame, and consent-gated proposals | versioned rule storage, a runner/scheduler, signed program admission, replay fixtures, and dashboard/audit presentation |
| BYOK providers | local Core credentials; read-only mesh probes; offline public-surface fixtures | provider-specific setup, secret storage/rotation, narrow scopes, revocation, audit, and integration tests |
| Enforcement | signed plans and rollback transaction model | reviewed privileged helper, real packet transport, kill-switch tests, and independent security/privacy review |

No **OPEN** item should be enabled by changing a boolean. Each needs its stated contracts, tests, and a security/privacy review before it can affect a real host or provider.

## Repo layout

```text
core/            the brain — identity, events, audit, policy, findings, gate, storage (Go)
agent/           runs on each device — collects state, enforces cached policy (Go)
adapters/        talks to Tailscale / Headscale, plus public-data fixtures
api/             protobuf contracts + generated code
apps/web/        Third-Eye dashboard — React on a Cloudflare Worker
apps/android/    Android Guard reference — Kotlin
sdk/typescript/  Secure Action SDK
cmd/             the four binaries: core, agent, sim, ctl
docs/            architecture, threat model, evidence model, OPEN roadmap, ADRs, release status
scripts/         dev + verify tooling (Node)
```

## Contributing

AntiFl0ck is built in public, and contributors shape the roadmap. Good first areas:
**observation** (network/device discovery), **intelligence** (exposure scoring, findings),
**security** (policy, signing, hardening), **experience** (dashboard, docs), and **research**.

Start with [CONTRIBUTING.md](CONTRIBUTING.md). Security or privacy changes begin with a short
design note (ADR); an AI may *explain* a decision but never *make* it. How decisions get made:
[GOVERNANCE.md](GOVERNANCE.md).

## Docs, security, and license

- **Start here:** [Vision](docs/vision.md) · [Architecture](docs/architecture.md) ·
  [Threat model](docs/threat-model.md) · [Evidence model](docs/evidence-model.md)
- **More:** [all docs](docs/README.md) · [release status](docs/release-status.md) ·
  [operator runbook](docs/operator-runbook.md)
- **Name:** *AntiFl0ck* is the public name — an earlier title clashed with another project, so
  internal names are being migrated.
- **License:** Apache-2.0. This is pre-release security software; don't rely on it alone for
  safety or anonymity. Report vulnerabilities privately via [SECURITY.md](SECURITY.md), not a
  public issue.

---

<div align="center">

**Evidence over alarm. Operator over platform.** If that resonates, a ⭐ helps others find it.

[![Star History Chart](https://api.star-history.com/svg?repos=DBarr3/AntiFlock&type=Date)](https://star-history.com/#DBarr3/AntiFlock&Date)

</div>
