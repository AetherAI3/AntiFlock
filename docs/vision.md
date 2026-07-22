# Vision

## Canonical definition

AntiFlock is an open-source personal private-security operating layer. It
creates a protected mesh across an operator's authorized devices and agents,
shows network activity and the operator's verified digital footprint from a
third-person intelligence view, evaluates protection conditions, presents
nearby *reported* monitoring infrastructure, and gives the operator control
over whether sensitive traffic may leave a device.

The promise is:

> See your exposure. Understand your environment. Control the path.

It is not only a VPN, a surveillance map, an OSINT dashboard, a home-network
monitor, a security score, or a Scrambler interface. It is the human-facing
control layer that connects those capabilities while preserving their
different evidence boundaries.

## Product capabilities

1. **Private Mesh** uses an established encrypted transport such as Tailscale,
   Headscale, or WireGuard. AntiFlock adds identity, posture, policy,
   observation, enforcement, and explanation above that transport.
2. **Third-Eye View** relates operator-authorized identities, devices, paths,
   destinations, observers, footprint assets, findings, and field reports.
3. **Protection Guard** deterministically evaluates whether current facts meet
   the selected policy and can enforce a fail-closed path locally.
4. **Environmental Intelligence** displays time-bounded public or community
   reports about infrastructure and conditions. It does not track people.
5. **Secure Action Gate** lets integrated applications hold, allow, block, or
   request scoped consent before a sensitive operation.
6. **Scrambler** plans and verifies controlled changes to approved observable
   network state. It is not an unbounded evasion engine.

## Operator questions

The product should answer, with evidence and uncertainty visible:

- Which authorized devices, applications, agents, accounts, domains, and
  networks are in my security domain?
- How are they connected, and which route is active?
- Which organizations or infrastructure can potentially receive metadata?
- Which public monitoring systems have been reported nearby, and how fresh is
  each report?
- Does the current path satisfy policy?
- What was held, blocked, allowed, bypassed, rerouted, or rolled back, and why?
- What evidence supports each statement?

## Trust commitments

- AntiFlock MUST NOT claim certainty the evidence does not support.
- A broken secure route and nearby monitoring infrastructure are separate
  facts. Neither proves active interception.
- Deterministic rules, not model-generated suspicion, make blocking decisions.
- Core evidence labels and warnings do not vary by subscription tier.
- Paid services may improve infrastructure, automation, retention, and
  remediation, but may not unlock a more truthful security state.
- Only operator-owned or explicitly authorized private identifiers may enter
  the Footprint Graph.
- Standard telemetry is metadata only; packet payload collection is off and
  out of scope by default.

## Capability progression

The system progresses monotonically through **Observe**, **Advise**, **Guard**,
and **Scramble**. An adapter must reliably observe and explain a state before
it may advise about it, and must produce a dry-run, verification, recovery,
and rollback contract before it may mutate it.
