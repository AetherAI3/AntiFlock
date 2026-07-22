# ADR 0004: AntiFlock identity is independent of mesh providers

- Status: Accepted
- Date: 2026-07-21

## Context

Deployments may switch among Tailscale, Headscale, WireGuard, or later
transports. A provider account or node ID cannot be the sole identity for
policy, history, or authorization.

## Decision

Each deployment owns an AntiFlock authority and each endpoint generates its own
key material. Provider identities are revocable associations on a stable node.
Enrollment is short-lived, single-use, proof-of-possession based, and audited.

## Consequences

Provider migration preserves policy and history, at the cost of operating a
local credential lifecycle and recovery process. Private keys never transit
Core during enrollment.
