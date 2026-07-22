<div align="center">

<img src="assets/antiflock-logo.png" alt="AntiFl0ck" width="380" />

### Open-source, self-hosted digital counterintelligence.

**See your exposure. Understand your environment. Control the path.**

[![CI](https://github.com/DBarr3/AntiFlock/actions/workflows/ci.yml/badge.svg)](https://github.com/DBarr3/AntiFlock/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-2dd4bf.svg)](LICENSE)
[![Go 1.26](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go&logoColor=white)](go.mod)
[![Node 24](https://img.shields.io/badge/Node-24-339933?logo=node.js&logoColor=white)](package.json)
[![Status: reference slice](https://img.shields.io/badge/status-reference%20slice-6f42c1.svg)](docs/release-status.md)
[![GitHub stars](https://img.shields.io/github/stars/DBarr3/AntiFlock?style=social)](https://github.com/DBarr3/AntiFlock/stargazers)

**[Quick start](#quick-start)** · **[What it is](#what-antifl0ck-is)** · **[Demo](#the-coffee-shop-demo)** · **[Docs](docs/README.md)** · **[Roadmap](#roadmap)** · **[Contribute](#contributing-and-community)**

<sub>⭐ **Star AntiFl0ck** — stars are how other operators, researchers, and contributors find an open security project. It's the single biggest signal you can send.</sub>

</div>

---

> The internet builds an invisible environment around every person — accounts, devices,
> networks, identities, permissions, trackers, and data relationships that move together
> like a **flock**. Most people have no map of it.
>
> **AntiFl0ck is an open-source attempt to draw that map — and to give the operator control of the path.**

> **Status — honest by design.** The locked, local, simulation-backed *reference vertical
> slice* is implemented and verified behind a **ten-gate acceptance harness**. It is **not** a
> production VPN, a validated mobile kill switch, real host enforcement, or proof of active
> surveillance. Every capability below states its exact boundary. Full detail:
> [release status](docs/release-status.md).

## Table of contents

- [What AntiFl0ck is](#what-antifl0ck-is)
- [What it is not](#what-it-is-not)
- [How it works](#how-it-works)
- [Core concepts](#core-concepts)
- [Evidence discipline](#evidence-discipline)
- [The coffee-shop demo](#the-coffee-shop-demo)
- [Quick start](#quick-start)
- [Repository map](#repository-map)
- [Status](#status)
- [Roadmap](#roadmap)
- [Contributing and community](#contributing-and-community)
- [Documentation](#documentation)
- [Security](#security)
- [Naming, governance, and license](#naming-governance-and-license)

## What AntiFl0ck is

AntiFl0ck is a **self-hosted personal private-security operating layer**. It joins an
operator's enrolled devices into one explainable protection domain, observes network and
mesh state, evaluates **deterministic policy**, and can **hold sensitive application actions**
when the approved route is unavailable — while recording a complete, auditable evidence trail
on the operator's own machine.

It is the *human-facing control layer* over capabilities that usually live in separate tools:

| Capability | What it does | Evidence boundary |
|---|---|---|
| **Private mesh** | Adds identity, posture, policy, and enforcement above an existing encrypted transport (Tailscale / Headscale / WireGuard). | Control plane only — never in the packet path. |
| **Third-Eye view** | Relates your authorized identities, devices, paths, destinations, observers, and footprint from a third-person intelligence view. | Shows what *may observe* metadata — not proof anything *did*. |
| **Protection Guard** | Deterministically evaluates whether current facts meet policy and can fail **closed** locally. | Rules decide, not model-generated suspicion. |
| **Secure Action gate** | Lets integrated apps hold / allow / block / request scoped consent before a sensitive operation. | Proposals are gated + audited; nothing self-executes. |
| **Environmental intel** | Time-bounded *reported* infrastructure and conditions. | `REPORTED` provenance; it does not track people. |
| **Scrambler** | Plans and verifies controlled changes to approved observable network state. | Simulation-first; not an unbounded evasion engine. |

The system progresses monotonically: **Observe → Advise → Guard → Scramble.** An adapter must
reliably observe and explain a state before it may advise on it, and must produce a dry-run,
verification, recovery, and rollback contract before it may ever mutate it.

## What it is not

Credibility is a feature. AntiFl0ck **does not**:

- ❌ prove that a person or organization is monitoring you;
- ❌ identify attackers from network anomalies alone;
- ❌ act as a production VPN, anonymity system, or mobile kill switch *(yet — see [status](#status))*;
- ❌ track people, publish routines, or turn uncertainty into a sensational allegation;
- ❌ let model output make a blocking decision.

AntiFl0ck **does**:

- ✅ record observable security conditions with an evidence class and confidence;
- ✅ enforce user-defined, deterministic policy and **fail closed** on missing or stale facts;
- ✅ give explainable decisions with a reason code and false-positive context;
- ✅ preserve a signed, append-only evidence trail **under the operator's control**;
- ✅ reduce accidental exposure.

> The phrase *"someone is watching you"* is prohibited unless specific evidence supports an
> actual observation event and the wording has passed review. A public network, a failed
> tunnel, or a nearby camera is **not** that evidence.

## How it works

AntiFl0ck Core is the **control, policy, and intelligence plane — never the packet data
plane.** Existing mesh software moves encrypted traffic; Core manages identity, ingests
events, projects state, compiles policy, signs plans, serves the UI, and *explains* results.
Endpoint agents keep cached policy and enforce locally during Core outages.

```text
 Endpoint collectors and provider adapters
                  |
         authenticated event ingestion
                  v
    append-only event store  ──►  replayable projections
                  |                 ├─ asset & observer topology
                  |                 ├─ network state & paths
                  |                 ├─ posture & findings
                  |                 └─ activity stream
                  v
 deterministic policy compiler ──► signed, expiring per-node plans
                  |                          |
                  └──────────────►  endpoint enforcer
                                             |
                                    verify or roll back
```

Core outages **must not** disable established mesh traffic or endpoint protection: each agent
retains its device identity, last valid signed policy, current plan and rollback state,
offline expiry, and a deterministic local posture evaluator. Agents reject unsigned, expired,
replayed, mistargeted, or lower-revision plans, and never silently convert fail-closed to
fail-open. Read the [architecture overview](docs/architecture.md) and
[threat model](docs/threat-model.md) before changing a security boundary.

## Core concepts

| Term | Meaning |
|---|---|
| **Operator** | The principal who owns (or is delegated authority over) a deployment and its assets. You are in control; AntiFl0ck provides visibility and enforcement. |
| **Deployment** | One trust domain with stable identity, local authority, policy, and audit history. |
| **Node** | An enrolled device, gateway, server, or agent endpoint with its own key material. |
| **Finding** | A deterministic reason code + condition, consequence, evidence, confidence, response, and false-positive context. |
| **Posture / Protection state** | A point-in-time deterministic conclusion: `PROTECTED`, `DEGRADED`, `SUSPICIOUS`, `EXPOSED`, `UNKNOWN`, or `UNAVAILABLE`. |
| **Plan** | A signed, target-bound, expiring transaction with preconditions, actions, verification, and rollback. |
| **Bypass** | An explicit, narrow, expiring operator authorization — never a silent fail-open switch. |

## Evidence discipline

AntiFl0ck states only what its evidence supports. **Every** alert, finding, and claim carries
an evidence class, a calibrated confidence, freshness, source, and a false-positive note. The
UI shows **words before decimals**, and confidence never erases the evidence class.

| Class | Meaning |
|---|---|
| `DETECTED` | The local device or an authorized gateway directly observed it. |
| `VERIFIED` | Required corroboration confirmed it under a documented method (not permanent truth). |
| `REPORTED` | A public source or community contributor reported it; not independently established. |
| `INFERRED` | A deterministic rule derived it from named observable facts. |
| `SUSPECTED` | Evidence is consistent with a possible active event but is inconclusive. |
| `UNKNOWN` | Visibility is insufficient to classify the claim. |

This is the **reality filter**: an observation, its evidence, its confidence, and its
interpretation are kept separate — so *"unknown Wi-Fi gateway detected"* never silently
becomes *"the network is hostile."*

## The coffee-shop demo

The first release target is a locally auditable, **fully simulated** demonstration — no
Tailscale account, real VPN, or surveillance dataset required:

1. A simulated phone joins an untrusted network.
2. Its approved private route fails.
3. AntiFl0ck reports the exact failure and records **fail-closed** enforcement intent —
   *without mutating the host network*.
4. An integrated secure action is **held**.
5. The route returns and is **verified** (mesh, DNS, policy route, external egress).
6. The held action proceeds, and the complete decision trail remains in SQLite.

```bash
npm run lab   # runs the HOLD → verified recovery → ALLOW scenario, then exits
```

A successful run moves the action from `HOLD` to `ALLOW` **only after recovery evidence**,
emitting two context events, four verification events, and five lifecycle audit events —
every one labeled `simulation`.

## Quick start

**Requirements:** Docker Desktop / Engine with Compose, and Node.js 24+.

```bash
make dev        # start Core, the deterministic simulator, and the Third-Eye dashboard
```

Open <http://127.0.0.1:4173> and authenticate with the Basic username `operator` and the
dashboard token from `.antiflock/dev.env` (keep it private — the browser never receives a Core
API credential). The full safe-use and recovery procedure is the
[operator runbook](docs/operator-runbook.md).

| Command | What it does |
|---|---|
| `make dev` | Start the local stack (Core + simulator + dashboard). |
| `make lab` | Run the coffee-shop failure-and-recovery scenario. |
| `make test` | All Go and JavaScript tests. |
| `make verify` | The locked release gate: formatting, tests, builds, and the ten acceptance gates. |
| `make down` | Stop the local stack. |

> On Windows without `make`, use the `npm run …` equivalents (`dev`, `test`, `verify`, `lab`).

## Repository map

A modular monolith with explicit adapter boundaries — [browse the contracts first](docs/README.md).

```text
core/            Control, policy & intelligence plane (Go)
  ├─ identity/ enrollment/ events/ audit/     durable identity, event spine, signed audit
  ├─ posture/ findings/ policy/ actions/      deterministic decision plane + Secure Action gate
  ├─ storage/ retention/ server/              SQLite projections, retention, API server
  ├─ nano/                                    Nano v0.1 watchdog conformance runtime (proposal-only)
  ├─ footprint/ scrambler/                    exposure view + simulation-first Scrambler
agent/           Endpoint collection, cached policy, enforcement, recovery (Go)
adapters/        mesh (Tailscale/Headscale probes) + publicsurface fixtures
api/             Protobuf contracts (antiflock.v1) + generated code
apps/web/        Third-Eye dashboard — React 19 / Next on a Cloudflare Worker
apps/android/    Android Guard reference — pure Kotlin/JVM fail-closed state machine
apps/aether-demo/  Reference Secure Action SDK integration (terminal demo)
sdk/typescript/  Secure Action SDK (@antifl0ck secure action)
cmd/             Binaries: core, agent, sim, ctl
deploy/  configs/  scripts/                   Docker, config profiles, Node dev/verify harness
docs/            Architecture, threat model, evidence model, ADRs, release status
tests/           Cross-cutting end-to-end acceptance (coffee-shop)
```

## Status

The **reference vertical slice** is implemented and verified. This is an engineering
completion boundary, not production network protection.

| Implemented (behind the 10-gate harness) | Deliberately gated (separate release) |
|---|---|
| Identity & one-time enrollment; scoped credentials | Production VPN / packet transport |
| Event spine + SQLite projections + signed hash-chained audit | Validated Android always-on / kill switch |
| Deterministic posture, findings, policy, signed expiring plans | Unattended privileged host mutation |
| Secure Action gate + TypeScript SDK (live restart-tested) | Real Tailscale / Headscale / WireGuard / DNS / roaming tests |
| Agent observation (Linux net/route/DNS) + read-only mesh probes | Proof of interception, tracking, or surveillance |
| Enforcement transaction (validate→snapshot→apply→verify→commit/rollback) | Imported field-intelligence datasets; live OSINT retrieval |
| Third-Eye dashboard (authenticated same-origin Core proxy) | Production Scrambler execution |
| Android Guard reference (Kotlin/JVM state machine, no APK) | External pentest, privacy/legal review, release signing |
| Nano v0.1 watchdog (proposal-only, no host capability) | |
| Coffee-shop `HOLD → recovery → ALLOW` end-to-end | |

Nothing above may be inferred from a green run beyond its stated boundary — the
[release status](docs/release-status.md) and [open decisions](docs/open-questions.md) keep the
line honest.

## Roadmap

Capability grows monotonically and conservatively; a state must be **observed and explained**
before it is advised, and carry **dry-run + verification + rollback** before it mutates.

- **Phase 1 — Observable layer** *(done)* — event spine, deterministic policy, SQLite evidence, simulated environments.
- **Phase 2 — Trusted action control** *(next)* — real platform integration, stronger identity verification, encrypted evidence storage.
- **Phase 3 — Distributed domains** *(later)* — multi-device trust, delegated policy, organizational deployments.

Detailed gates live in [open-questions.md](docs/open-questions.md). We intentionally avoid
promising "AI threat detection" or "surveillance mapping" — those create credibility problems
a security project cannot afford.

## Contributing and community

**AntiFl0ck is built in public.** Security tools should be inspectable, privacy systems should
not require blind trust, detection logic should be explainable, and operators should own their
evidence. Contributors shape the roadmap.

Good places to start:

| Area | Examples |
|---|---|
| 🛰 **Observation** | network discovery, device inventory, mesh probes |
| 🧠 **Intelligence** | exposure scoring, findings, visualization |
| 🔐 **Security** | policy engine, signing, hardening, threat models |
| 🎨 **Experience** | Third-Eye dashboard, UX, accessibility, docs |
| 🧪 **Research** | privacy experiments, evidence methodology, adversarial review |

This repository is security- and privacy-sensitive: read [CONTRIBUTING.md](CONTRIBUTING.md) and
the [contract docs](docs/README.md) first. Changes to security, privacy, evidence, community
safety, or Scrambler design start with an **ADR**. Model output may *explain* but must never
*decide*. See [GOVERNANCE.md](GOVERNANCE.md) for how decisions are made.

## Documentation

| Document | Contents |
|---|---|
| [Vision](docs/vision.md) · [Architecture](docs/architecture.md) | What it is and how it's shaped |
| [Threat model](docs/threat-model.md) · [Evidence model](docs/evidence-model.md) | Adversaries, controls, and the evidence contract |
| [Protection states](docs/protection-states.md) · [Alert catalog](docs/alert-catalog.md) | Deterministic states and honest wording |
| [Privacy invariants](docs/privacy-invariants.md) · [Data retention](docs/data-retention.md) | What stays local, and for how long |
| [Nano watchdog](docs/nano-watchdog.md) · [Scrambler safety](docs/scrambler-safety-model.md) | Proposal-only rules and constrained mutation |
| [ADRs](docs/adr/README.md) · [Release status](docs/release-status.md) · [Operator runbook](docs/operator-runbook.md) | Decisions, the honest capability line, and safe operation |

## Naming, governance, and license

**AntiFl0ck** is the project's public name. An earlier working title collided with an existing
project in an overlapping area; the codebase is migrating internal identifiers to match. No
trademark claim or implication of affiliation is made, and truthful evidence semantics are
never subscription-dependent. Governance is documented in [GOVERNANCE.md](GOVERNANCE.md).

Licensed under **Apache-2.0** ([LICENSE](LICENSE)). This is pre-release security software — do
not rely on it as a sole control for life safety, emergency communication, legal compliance,
or anonymity. Report vulnerabilities privately per [SECURITY.md](SECURITY.md), **not** a public
issue.

---

<div align="center">

**If AntiFl0ck's approach resonates — evidence over alarm, operator over platform — a ⭐ helps others find it.**

[![Star History Chart](https://api.star-history.com/svg?repos=DBarr3/AntiFlock&type=Date)](https://star-history.com/#DBarr3/AntiFlock&Date)

<sub>See your exposure. Understand your environment. Control the path.</sub>

</div>
