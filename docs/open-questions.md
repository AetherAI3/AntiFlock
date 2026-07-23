# OPEN — decisions, unconnected features, and release gates

**OPEN** means an item is intentionally not production-ready, not wired into a continuous operator workflow, or still needs a decision. It is not an invitation to bypass a safety check. The current safe default remains in force until the stated gate is completed.

## OPEN — integration work

| Capability | Current safe boundary | OPEN completion criteria |
| --- | --- | --- |
| Tailscale and Headscale | The enrolled Linux agent runs only `tailscale status --json` or Headscale `GET /api/v1/node`, then sends explicitly associated peer/path metadata through its signed durable queue. Neither mutates a mesh. | Show stale/failed probes in Third-Eye and validate real exit-node, DNS, captive-portal, partition, and roaming recovery. |
| Third-Eye | Authenticated local dashboard renders Core projections; browser JavaScript never receives Core credentials. Setup cards describe enrollment, metadata-only flow, read-only mesh probes, and the opt-in Nano scheduler. | Live setup/status polling, evidence-provenance/freshness UX, deployment/TLS model, accessibility, threat-model, and production review. |
| Network traffic monitor | The Linux agent has opt-in `/proc/net` socket-table endpoint metadata. It captures no packets, payloads, byte counters, direction, timing, or process identity. | Retention controls, process-attribution limits, non-Linux collectors, real-network tests, and independent privacy review. |
| Nano watchdog | Signed immutable admission, SQLite cursor, Core-owned bounded finding projection, and an explicit Core-configured program allowlist/interval are wired. Nano emits only expiring consent-gated proposals. | Program disable/version lifecycle, replay corpus, durable proposal/audit views, and dedicated authoring UX. |
| BYOK providers | Headscale uses a locally stored read-only private key file plus explicit provider-to-node associations; the agent rereads it every collection cycle for restart-free rotation. Tailscale uses local CLI status and needs no provider credential. Browser code never receives either. | Credential revocation, platform-keystore references, outbound egress controls, durable audit records, provider failure tests, and live integration coverage. |
| Privileged enforcement | Plans and rollback semantics are modeled; executable host mutation is disabled. | Separate least-privilege helper, operator-visible dry run, recovery path, real-host validation, independent security review, and platform-specific signing/release. |

## OPEN — release and governance decisions

| Decision | Current safe default | Required before |
| --- | --- | --- |
| Public product and protocol name | `AntiFlock` remains an internal working title; no affiliation or legal clearance is claimed. | Public launch, domain/namespace promotion, or trademark use. |
| Public repository controls | Repository is private at this audit; workflow and community-health files are present. | Public opening: enable private vulnerability reporting, name the security contact, confirm branch protections and GitHub billing, then rerun CI. |
| Repository and generated-language namespaces | Protobuf package is the internal `antiflock.v1`; language-specific package options are intentionally absent. | Publishing generated SDKs. |
| License and copyright attribution | Apache License 2.0 is included as the permissive open-source default. | First public distribution; project owner and counsel should ratify. |
| Staffed private security and conduct contacts | Use repository-host private reporting and a non-conflicted maintainer. No response-time promise is made. | Accepting public users or contributions. |
| Platform credential storage and CA profile | Private keys stay local; Ed25519 and P-256 signature identifiers are modeled. | Implementing enrollment and release signing. |
| Retention and legal-jurisdiction profile | Conservative local defaults in `data-retention.md`; hosted upload is off. | Hosted service, new jurisdiction, or payload/location feature. |
| Dataset license and regional publication rules | Every source carries provenance/license and packs fail on missing or incompatible metadata. | Importing or redistributing each dataset. |
| Verification independence and reporter reputation | Duplicate/copied/correlated sources do not count as independent; no reputation score is trusted yet. | Promoting reports to verified states at scale. |
| Experimental detection claims | General cellular-interceptor/RF classification remains out of scope. | Any user-facing detector or enforcement rule in those domains. |
| Scrambler state dimensions | Simulation first; lower-risk approved exit, DNS, relay, route, and service dimensions only. | Enabling overlay identity, aggressive rotation, or adaptive execution. |
