# ADR 0003: Deterministic, evidence-honest enforcement

- Status: Accepted
- Date: 2026-07-21

## Context

Security products can cause harm by overstating uncertainty or allowing opaque
model output to block traffic. Nearby infrastructure, path failure, and active
interception are different claims.

## Decision

Only deterministic, versioned rules using named facts may produce posture,
findings, or enforcement. Every alert has a reason code, evidence requirements,
confidence rule, factual wording, response, and false-positive explanation.
AI may summarize but does not decide blocking or upgrade evidence.

## Consequences

Rules are testable and user claims remain defensible. Some sophisticated
correlation will initially remain advisory. Commercial tiers use identical
evidence labels and core warnings.
