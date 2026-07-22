# ADR 0001: Core is the control plane, not the data plane

- Status: Accepted
- Date: 2026-07-21

## Context

AntiFlock needs identity, policy, state correlation, and explanation across
devices. Established mesh transports already provide encrypted packet movement
and peer connectivity. Routing all traffic through Core would add a bottleneck
and make controller availability a packet-path dependency.

## Decision

Core manages identity, enrollment, ingestion, projections, posture, findings,
policy compilation, signed plans, intelligence, and UI APIs. Endpoint mesh or
VPN software carries packets. Agents retain cached valid policy and local
enforcement during Core outages.

## Consequences

Core can fail without breaking established transport. Endpoint logic and plan
signing become security boundaries and require offline expiry, replay defense,
and recovery. AntiFlock integrates providers through supported adapters rather
than reimplementing cryptography or NAT traversal.
