# AntiFlock contract set

These documents define the safety, privacy, evidence, and interoperability
contracts for the AntiFlock working title. Implementations may add capability,
but they may not weaken these contracts without an accepted architecture
decision and an explicit security and privacy review.

Start with:

- [Vision](vision.md)
- [Architecture](architecture.md)
- [Threat model](threat-model.md)
- [Evidence model](evidence-model.md)
- [Privacy invariants](privacy-invariants.md)
- [Protection states](protection-states.md)
- [Initial alert catalog](alert-catalog.md)
- [Terminology](terminology.md)
- [Data retention](data-retention.md)
- [Community intelligence policy](community-intelligence-policy.md)
- [Scrambler safety model](scrambler-safety-model.md)
- [API contracts](api-contracts.md)
- [Event contracts](event-contracts.md)
- [Signing contracts](signing-contracts.md)
- [**OPEN** decisions, unconnected features, and release gates](open-questions.md)
- [Reference vertical-slice release status](release-status.md)
- [Local operator runbook](operator-runbook.md)
- [Nano watchdog boundary and runner roadmap](nano-watchdog.md)
- [Continuous agent and Nano watchdog loop](agent-watchdog-loop.md)
- [Architecture decisions](adr/README.md)

Normative words such as **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are
used in their ordinary requirements sense. A protobuf comment and its
corresponding contract document are both normative. If they conflict, choose
the more privacy-preserving and fail-safe behavior and open an ADR to resolve
the ambiguity.

## Public-name hold

`AntiFlock` is an internal working title. An existing project uses that name
in an overlapping area. No public launch, namespace claim, trademark claim,
or implication of affiliation is authorized until the name is cleared,
permission or partnership is established, or a distinct public name is
selected. This is a documented collision, not a legal conclusion.
