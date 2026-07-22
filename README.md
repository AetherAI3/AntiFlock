<div align="center">

<img src="https://github.com/user-attachments/assets/84ab4fbb-9f44-43e4-b781-6279d7300a8a" alt="AntiFl0ck" width="360" />

**Open-source, self-hosted digital counterintelligence.**

See your exposure. Understand your environment. Control the path.

[![CI](https://github.com/DBarr3/AntiFlock/actions/workflows/ci.yml/badge.svg)](https://github.com/DBarr3/AntiFlock/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-2dd4bf.svg)](LICENSE)
[![Go 1.26](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go&logoColor=white)](go.mod)
[![Node 24](https://img.shields.io/badge/Node-24-339933?logo=node.js&logoColor=white)](package.json)
[![GitHub stars](https://img.shields.io/github/stars/DBarr3/AntiFlock?style=social)](https://github.com/DBarr3/AntiFlock/stargazers)

**[Quick start](#quick-start)** · **[What it is](#what-it-is)** · **[Demo](#try-it--the-coffee-shop-demo)** · **[Docs](docs/README.md)** · **[Contribute](#contributing)**

<sub>⭐ Star it — that's how people find an open security project.</sub>

</div>

---

> Your accounts, devices, and networks leave a trail that moves together like a **flock**.
> AntiFl0ck helps you see that trail and stay in control of it.

**Where it stands:** the local, simulated demo works and is tested behind a 10-check release
gate. It is **not** yet a real VPN, a phone kill-switch, or proof that anyone is watching you.
Details in [release status](docs/release-status.md).

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
Third-Eye dashboard · Android Guard reference · Nano watchdog · the coffee-shop demo end-to-end.

**Not here yet:** production VPN / packet transport · validated phone kill-switch · privileged
host changes · real Tailscale / DNS / roaming tests · any "proof of surveillance" · live OSINT ·
production Scrambler · external audit and release signing.

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
docs/            architecture, threat model, evidence model, ADRs, release status
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
