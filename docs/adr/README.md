# Architecture decision records

Accepted decisions:

- [0001: Core is control plane, not data plane](0001-control-plane-not-data-plane.md)
- [0002: Start as a modular monolith with relational projections](0002-modular-monolith-relational-projections.md)
- [0003: Deterministic evidence-honest enforcement](0003-deterministic-evidence-honest-enforcement.md)
- [0004: AntiFlock identity is independent of mesh providers](0004-provider-independent-identity.md)
- [0005: Local-first privacy and metadata minimization](0005-local-first-privacy.md)
- [0006: Guard and Scrambler share one mutation transaction](0006-one-mutation-transaction.md)

ADRs are append-only. A superseded decision remains in history and links to
its replacement. Contract, security, privacy, or public-safety changes require
review from the corresponding maintainers before acceptance.
