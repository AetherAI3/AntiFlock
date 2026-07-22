# ADR 0002: Start as a modular monolith with relational projections

- Status: Accepted
- Date: 2026-07-21

## Context

The product needs clean domains but does not yet benefit from distributed
coordination, a graph database, or independent service scaling.

## Decision

Begin with one Core process, one agent per endpoint, one web UI, and a local
relational database. Store immutable events and project entities,
relationships, network state, posture, and findings into relational tables.
Domain interfaces do not import platform or provider implementations.

## Consequences

Development and self-hosting remain understandable while boundaries can later
be extracted. Projection replay is required. Cross-module calls must respect
domain ownership even though they share a process. A graph database or service
split requires measured need and a new ADR.
