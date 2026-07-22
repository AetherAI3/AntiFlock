# ADR 0006: Guard and Scrambler share one mutation transaction

- Status: Accepted
- Date: 2026-07-21

## Context

Moving-target changes can disrupt connectivity and would be unsafe through a
separate privileged control path.

## Decision

All endpoint mutations use capability matching, dry-run planning, targeted
signed plans, local preconditions, captured rollback, bounded application,
endpoint-local verification, and audit. Scrambler adds candidate generation and
transition lifecycle but no extra authority.

## Consequences

Scrambler begins in simulation and enables dimensions only after their Guard
transaction is proven. Failed or indeterminate verification rolls back; a
rollback failure enters safe recovery and stops further transitions.
