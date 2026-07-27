# AntiFl0ck Launch — Distribution Kit

Companion to [launch-report.md](launch-report.md). Every piece preserves the same
boundaries: independent project, pre-alpha, simulation works today, no anonymity
claims, no interference with third-party infrastructure, AI never makes the
enforcement decision.

---

## 300-word condensed article

**Surveillance has a network. The defensive side should have one too.**

A camera reads a plate. A phone joins a network. An account signs in from a new city. Individually ordinary; correlated together, they describe movement, habits, and relationships. The debate around Flock Safety and large-scale license-plate-reader networks made a broader problem visible: systems that collect and correlate observations are advancing faster than the tools ordinary people have for understanding their own exposure.

Defensive tools remain fragments. A VPN carries traffic but can't tell your applications when the trusted path disappeared. A firewall blocks packets but doesn't understand intent. Dashboards show one device, not how your devices, routes, and providers relate. And almost nothing pauses before a sensitive action to check whether your trusted conditions still hold.

AntiFl0ck is an independent, open-source experiment in building that missing layer: self-hosted software that maps your exposure, verifies your route, and gates sensitive actions under deterministic, operator-defined policy — with every decision recorded in a signed local audit log.

The working demo is a fully simulated coffee-shop scenario: a laptop joins an untrusted network, the trusted route is gone, an application requests a sensitive upload. The action is held with a recorded reason. When the route returns and is verified, the action is allowed. Five signed audit events, replayable on your machine today.

Every finding carries an evidence label — detected, verified, reported, inferred, suspected, or unknown — so a guess never quietly becomes an accusation. An AI may explain a finding; it never makes the allow-or-block decision.

AntiFl0ck is pre-alpha and honest about it. Production enforcement, mobile support, and independent review are open engineering work. It's Apache-2.0, built in public, and looking for observers, visualizers, policy builders, researchers, and hardening engineers.

Evidence over alarm. Operator over platform.

→ github.com/AetherAI3/AntiFlock

---

## 100-word project summary

AntiFl0ck is an independent, open-source counter-surveillance project for the networks you control. It maps device and network exposure, labels every finding by evidence status (detected through unknown), evaluates deterministic operator-defined policy, and holds sensitive actions when a trusted route disappears — recording every decision in a signed local audit log. The pre-alpha ships a fully simulated coffee-shop scenario, a policy engine, a secure-action gate with TypeScript SDK, read-only Tailscale/Headscale probes, and the Third-Eye dashboard. Production enforcement remains open engineering work. Apache-2.0, built in public. A guess never quietly becomes an accusation. Evidence over alarm; operator over platform.

---

## GitHub release introduction (one paragraph)

This pre-alpha release delivers AntiFl0ck's first working slice: the end-to-end simulated coffee-shop scenario in which a sensitive action is held when the trusted route disappears, verified on recovery, allowed, and recorded as five signed events in the hash-chained local audit log. It includes the deterministic policy engine, signed expiring device plans, the secure-action gate and TypeScript SDK, endpoint enrollment with mTLS identity, Linux route observation, read-only Tailscale/Headscale probes, the Third-Eye dashboard, and a proposal-only Nano watchdog boundary — all behind a ten-gate `make verify` release check. It is not yet a production enforcement system; the boundaries are documented in [release status](../release-status.md).

---

## Five social post hooks

1. Surveillance has become networked. Defensive privacy tools are still fragmented. AntiFl0ck is an open-source experiment in building the other side.

2. A VPN can carry your traffic. It can't always tell your applications that the trusted path just disappeared. AntiFl0ck holds sensitive actions until the route is verified again — and signs the audit trail.

3. Security software should distinguish what it detected from what it merely suspects. AntiFl0ck labels every finding: DETECTED, VERIFIED, REPORTED, INFERRED, SUSPECTED, UNKNOWN. A guess never quietly becomes an accusation.

4. What would counter-surveillance infrastructure look like if the operator — not the platform — controlled the evidence, the policy, and the final decision? We're building one answer in public. Pre-alpha, Apache-2.0.

5. Tiny deterministic watchdogs — like unit scripts in a strategy game. They watch declared signals, propose a bounded move, and can't act on their own. The operator owns the gate. That's the automation model behind AntiFl0ck + Nano.

---

## Hacker News title

Show HN: AntiFl0ck – open-source tool that holds sensitive actions when your trusted route disappears

*(Alternate: AntiFl0ck: An open-source defensive layer for networked surveillance)*

---

## Reddit title (r/privacy, r/selfhosted, r/opensource)

I'm building an open-source, self-hosted tool that maps your network exposure and holds sensitive actions until your trusted route is verified — pre-alpha, demo works today, looking for contributors

---

## LinkedIn founder post

The Flock Safety debate made something clear to me that goes way beyond one company: surveillance now operates as a network — cameras, devices, accounts, and providers whose observations can be correlated into a picture nobody consented to. The defensive side? Still a junk drawer of disconnected tools.

So I started building the missing layer in public.

AntiFl0ck is an independent open-source project: self-hosted software that maps your exposure, verifies your trusted routes, and gates sensitive actions under deterministic policy you define — with every decision signed into a local audit log you own.

The demo works today: a laptop joins coffee-shop Wi-Fi, the trusted route is gone, an app requests a sensitive upload. The action is held with a recorded reason, the route recovery is verified, the action is allowed — five signed audit events, replayable on your machine.

Two principles I refuse to compromise on:

→ A guess never quietly becomes an accusation. Every finding is labeled by evidence status — detected, verified, reported, inferred, suspected, unknown.
→ AI can explain a finding. It never makes the allow-or-block decision. The operator owns the gate.

It's pre-alpha and honest about it — production enforcement, mobile support, and independent review are open engineering work, and that's exactly where contributors can have the most impact.

Apache-2.0. Built in public. If you're a privacy engineer, systems developer, or security researcher, the repo is open: github.com/AetherAI3/AntiFlock

Evidence over alarm. Operator over platform.

---

## Newsletter / media pitch

**Subject: An open-source answer to networked surveillance — launched pre-alpha, on purpose**

Hi [name],

The Flock Safety controversy surfaced a structural problem your readers already feel: surveillance systems correlate observations across cameras, devices, and accounts, while defensive tools remain fragmented single-purpose products. AntiFl0ck is a new independent open-source project taking a run at the missing layer — self-hosted software that maps exposure, verifies trusted routes, and holds sensitive actions under deterministic operator policy, with a signed local audit trail.

What makes it a story rather than a repo announcement: it launched pre-alpha deliberately, with a working end-to-end simulation, a six-level evidence taxonomy ("a guess never quietly becomes an accusation"), a hard rule that AI explains but never enforces, and its unfinished engineering listed as the invitation. It's Apache-2.0 and recruiting contributors across five lanes.

Happy to share the full launch report, the threat model, or a walkthrough of the demo.

[signature]
