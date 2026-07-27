# Surveillance Has a Network. The Defensive Side Should Have One Too.

*Introducing AntiFl0ck, an open-source experiment in mapping digital exposure, verifying trusted routes, and gating sensitive actions.*

<!-- HERO IMAGE: assets/brand/antifl0ck-lockup-hero.png — transparent eagle over subtle topology field. Tagline: SEE THE PATH. -->

> AntiFl0ck is an independent open-source project initiated by Brandon Barrante and developed in public with contributors. It is not affiliated with or endorsed by Flock Safety, and it does not interfere with third-party surveillance infrastructure.

## The asymmetry

A camera reads a plate. A phone joins a network. A laptop's traffic changes routes. An account signs in from a new city. Each event, on its own, is unremarkable. Connected together, they describe movement, habits, identity, and relationships — a picture no single observer ever asked permission to assemble.

This is the quiet shift of the last decade: surveillance stopped being a collection of individual sensors and became a network. Observations made by different cameras, devices, providers, and platforms can be correlated across time and space, and the correlation is where the power lives. The public debate around Flock Safety and large-scale automatic license-plate-reader networks made this visible to people who had never thought about it before. Cities discovered that plate reads from thousands of cameras could be queried like a database. The specific company matters less than what the controversy exposed: systems for collecting and correlating observations are advancing faster than the tools ordinary people have for understanding their own exposure.

Meanwhile, the defensive side looks nothing like a network. It looks like a junk drawer. A VPN here, a firewall there, a privacy toggle buried in an account settings page, a dashboard that shows one device and nothing about how that device relates to anything else. Surveillance operates as coordinated infrastructure. Defense operates as fragments.

AntiFl0ck is an open-source experiment in building the other side of that asymmetry — not a weapon pointed at anyone's cameras, but a defensive layer for the networks you already control.

## The defensive tooling gap

The fragments we do have are individually useful and collectively blind.

A VPN can carry your traffic, but it cannot tell your applications whether the trusted path is actually available right now, and it rarely explains what the rest of your exposure looks like around it. A firewall can block packets, but it does not understand what your application was trying to do or why. A device dashboard shows local state — this interface, this address — but not how your phone, laptop, mesh peers, and providers relate to each other. Alerting products go the other direction and over-conclude: they announce threats without distinguishing what they directly observed from what they merely inferred.

And almost nothing sits at the moment that matters most: the instant before a sensitive action. Applications sync files, push commits, upload photos, and send messages without ever pausing to ask whether the conditions the operator considers safe still hold. The trusted tunnel dropped two minutes ago? The upload proceeds anyway, over whatever network happens to be underneath.

So the question AntiFl0ck explores is simple to state: could devices, routes, policies, and sensitive actions be connected into one operator-controlled evidence system — where the software checks your conditions before acting, tells you exactly what it knows and how it knows it, and writes down every decision it makes?

## What AntiFl0ck is

AntiFl0ck is open-source, self-hosted counter-surveillance software for the networks you control. Its job fits in three verbs: **map your exposure, verify your route, gate sensitive actions.**

It is built from four capabilities:

**See.** Map your devices, network routes, mesh peers, interfaces, and the metadata an outside observer could plausibly collect about them. Not a threat feed — an inventory of your own footprint.

**Understand.** Label every finding by its evidence status. Something directly observed is not the same as something reported by a third party, and neither is the same as an inference. AntiFl0ck keeps those categories separate on purpose.

**Decide.** Apply deterministic, operator-defined policy. You write the conditions under which a sensitive action may proceed. The system evaluates them the same way every time. No model guesses whether a situation "feels" risky.

**Prove.** Record every decision — what was allowed, what was held, and why — in a signed, hash-chained audit log that lives on your machine, not a vendor's cloud.

The design center is the operator. Not a platform that decides for you, not an AI that acts on your behalf, not a subscription service holding your telemetry. Your devices, your rules, your evidence, your log.

## The coffee-shop scenario

The clearest way to understand AntiFl0ck is to watch the scenario it can already run end-to-end, fully simulated, on your machine.

<!-- ANIMATED DEMO: assets/demo/coffee-shop.svg — place directly under this paragraph.
     State strip: TRUSTED → ROUTE LOST → ACTION HELD → ROUTE VERIFIED → ACTION ALLOWED -->

A laptop joins a coffee-shop Wi-Fi network. The network is not hostile — it is simply unknown, and the operator's expected trusted route through their mesh is unavailable. A few moments later, an application asks permission to perform a sensitive action: an upload it would normally fire without a second thought.

AntiFl0ck's policy engine evaluates the operator's conditions. The trusted route is down, so the action is **held** — not silently dropped, not permitted with a shrug, but held, with a recorded, plain-language reason. When the trusted route comes back, the system does not just take the tunnel's word for it; it verifies the route is genuinely working. Only then is the action **allowed**. Every step — the hold, the reason, the verification, the release — lands in the signed local audit log, five events you can read back and check.

This matters because of what it is *not*. AntiFl0ck does not ask an AI to guess whether an action feels dangerous. It checks conditions the operator declared in advance and produces a bounded, explainable result. The same inputs produce the same decision every time, and the log shows exactly why.

The simulation, the policy engine, and the dashboard behind this scenario work today. Clone the repository, run `make dev` and `make lab`, and walk through it yourself — no VPN account, no real data, no cloud dependency.

## Evidence before alarm

The security industry has an incentive problem: alarm sells. AntiFl0ck's most deliberate design decision pushes the other way.

Every finding in the system carries one of six evidence labels: `DETECTED`, `VERIFIED`, `REPORTED`, `INFERRED`, `SUSPECTED`, or `UNKNOWN`.

<!-- EVIDENCE GRAPHIC: assets/brand/evidence-scale.svg -->

The rule those labels enforce: **a guess never quietly becomes an accusation.**

An unfamiliar gateway is not proof of hostility — it is an unfamiliar gateway. A broken tunnel is not proof of surveillance — it is a broken tunnel. A third-party report does not get promoted to a verified observation just because it sounds alarming. And an AI-generated explanation of a finding is never allowed to masquerade as an enforcement decision.

This is unglamorous, and it is the point. A defensive tool that inflates its own certainty trains its operator to either panic or ignore it. A tool that says "I detected this, I verified that, I merely suspect the other" earns the right to be trusted when it does hold an action.

## What exists today

AntiFl0ck is **pre-alpha**, and this report will not pretend otherwise. Here is the honest inventory.

Working now, in the repository, behind a ten-gate release verification (`make verify`):

- The coffee-shop simulation end-to-end, producing five signed audit events
- Signed, hash-chained event and audit storage
- A deterministic policy engine with findings and signed, expiring device plans
- A secure-action gate with a TypeScript SDK for applications
- Endpoint enrollment and mTLS device identity
- Linux route and interface observation, with opt-in socket-table flow metadata (no packets, no payloads)
- Read-only live mesh probes for Tailscale and Headscale
- The Third-Eye dashboard
- A proposal-only Nano watchdog boundary with audited program admission

What it is **not** yet: a production VPN, an anonymity service, a phone kill-switch, or a complete host-enforcement system. Production packet-path enforcement, Android enforcement beyond the reference state machine, provider lifecycle automation, and independent security review are open engineering work — genuinely open, in the sense that they are where contributors can have the most impact.

That contrast is not a weakness of the launch. It is the launch. You can run what exists, read what does not, and see exactly where the line sits.

## The architecture in one page

The shape of the system is simple enough to hold in your head.

<!-- ARCHITECTURE DIAGRAM: observations → signed events → Core → policy → operator authorization → local agent → audit -->

Adapters and device agents **observe** — routes, interfaces, mesh state, provider metadata. Their observations are signed and sent to **Core**, the brain of the system: identity, events, policy evaluation, and the audit record. Core never sits in your packet path; it is a decision layer, not a traffic middlebox. Devices keep a cached copy of policy, so protection does not evaporate if Core goes offline.

When something should change on a host, the change is issued as a signed, expiring plan — and proposed changes do not automatically become host mutations. The operator remains the authorization boundary. Findings can be explained in plain language, but explanation and enforcement are separate lanes by construction.

Enrollment mechanics, certificate handling, and queue internals are documented in the repository for those who want them. The load-bearing idea fits in one sentence: observations flow up signed, decisions flow down signed, and a human owns the gate in between.

## Deterministic watchdogs: small agents that cannot go rogue

One piece of AntiFl0ck deserves its own spotlight, because it is a separate open-source project with a life beyond this one: **[Nano](https://github.com/DBarr3/Nano)**.

Nano is a tiny, deterministic rule language. A Nano "agent" is not an autonomous AI process — it is closer to a unit script in a strategy game: a few readable lines that watch declared signals and propose a bounded move. Legible, predictable, replayable. The complexity comes from composing many small rules, and the player — the operator — never loses command.

A watchdog for the coffee-shop scenario is almost embarrassingly short:

```nano
strategy TrustedRouteWatchdog {
  every 1m {
    if TRUSTED_ROUTE < 1 {
      pause()
      observe()
    }
  }
}
```

The host measures the route and supplies `TRUSTED_ROUTE`. Nano evaluates the threshold and returns proposed intents with an ordered execution log. It cannot fetch data, call an API, or touch the network. In AntiFl0ck, watchdog programs pass through audited admission and are **proposal-only**: the policy engine and operator gate decide what actually happens.

Once you see the pattern, the ideas multiply. A watchdog that proposes a hold when authentication failures spike within a window. One that flags a release carrying unsigned artifacts. One that notices a signing key aging past your rotation policy, or a new mesh peer nobody enrolled, and proposes an alert the operator has pre-authorized to fire immediately. Rules like *"pause deployment while critical findings exceed zero and approvals are below two"* stop being paragraphs in a compliance document and become five lines of versioned, replayable source — where the rule's evaluation, its proposal, and the host's final decision are preserved as three separate, auditable facts.

Nano ships today as a v0.1.0 reference implementation with trading-flavored examples; the watchdog and compliance directions are where it is heading, and they need contributors too. If deterministic, host-governed automation is your kind of problem, that repository is worth a star of its own.

## Why it is open source

Defensive privacy infrastructure has one non-negotiable property: you must be able to check it.

A closed counter-surveillance product asks you to trade one opaque observer for another. AntiFl0ck's claims — what is signed, what is stored locally, what the policy engine does, where AI can and cannot act — are only worth anything because they are inspectable, reproducible, and forkable. The threat model is public. The release gates are public. If a claim in this report is wrong, the code is right there to prove it.

Openness is also a hedge against the failure mode where a single platform ends up controlling the defensive layer, which would simply recreate the original problem with friendlier branding.

AntiFl0ck is released under **Apache-2.0**. The code can be studied, modified, integrated, and redistributed under the license terms. The AntiFl0ck name and eagle mark remain project marks, so unofficial forks cannot imply endorsement.

## What the public can build

The project is deliberately structured so that you do not need to understand the whole system to contribute to one lane of it.

**Observers.** Collectors and adapters — macOS, Windows, Android, routers, providers. Every new observation source widens what the map can show.

**Visualizers.** Topology maps, exposure timelines, route-state views, audit interfaces. The Third-Eye dashboard is a beginning, not a conclusion.

**Policy builders.** Deterministic rules, Nano watchdogs, and secure-action integrations that bring real applications to the gate.

**Researchers.** Metadata models, ALPR research, surveillance-system analysis, threat modeling. The evidence taxonomy needs adversarial minds.

**Hardening engineers.** Signing, storage, privilege separation, rollback, fuzzing, deployment review. Pre-alpha is exactly when this scrutiny is cheapest.

## An open question, placed in public

AntiFl0ck is not presented as a completed answer. It is a working first slice of a larger question: what should the defensive side of networked surveillance look like when the operator — not the platform — controls the evidence, the policy, and the final decision?

Run the simulation. Inspect the threat model. Challenge the assumptions. Open an issue. Build an adapter. Improve the dashboard. Review the signing model. Or simply star the repository so the people capable of building the next part can find it.

- **[View the repository](https://github.com/AetherAI3/AntiFlock)**
- **[Run the demo](https://github.com/AetherAI3/AntiFlock#run-the-demo)**
- **[Explore good first issues](https://github.com/AetherAI3/AntiFlock/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22)**
- **[Read the threat model](https://github.com/AetherAI3/AntiFlock/blob/main/docs/threat-model.md)**
- **[Explore Nano](https://github.com/DBarr3/Nano)**

**Evidence over alarm. Operator over platform.**
