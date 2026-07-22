# ADR 0005: Local-first privacy and metadata minimization

- Status: Accepted
- Date: 2026-07-21

## Context

Network metadata, location, footprint assets, and community reports can create
the same surveillance risk the product is intended to reduce.

## Decision

Self-hosted operation is complete without hosted telemetry. Standard
collection excludes payloads. Exact nearby matching happens locally against
signed regional packs. Footprint assets require ownership or authorization.
Data is collected and retained by declared purpose and class.

## Consequences

Some global correlation and convenience are reduced. Hosted features require
per-class opt-in, encryption, retention controls, and privacy review; they do
not become a prerequisite for honest posture.
