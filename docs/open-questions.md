# OPEN — decisions, unconnected features, and release gates

**OPEN** means an item is intentionally not production-ready, not wired into a continuous operator workflow, or still needs a decision. It is not an invitation to bypass a safety check. The current safe default remains in force until the stated gate is completed.

## OPEN — integration work

| Capability | Current safe boundary | OPEN completion criteria |
| --- | --- | --- |
| Tailscale and Headscale | The Tailscale CLI probe returns local mesh status; a separate Headscale adapter exists but has no agent CLI or scheduler wiring. Neither enrolls, alters a mesh, or continuously uploads observations. | Configure canonical provider-to-node associations; deliver signed agent events; schedule bounded collection; show stale/failed probes; validate real exit-node, DNS, captive-portal, and roaming recovery. |
| Third-Eye | Authenticated local dashboard renders Core projections; browser JavaScript never receives Core credentials. | Document a real-agent installation flow; surface evidence provenance and data freshness; define deployment/TLS model; complete accessibility, threat-model, and production review. |
| Network traffic monitor | Collectors deliberately exclude packets, sockets, process payloads, and continuous flow capture. | Define opt-in flow-metadata schema and retention; prove no payload collection; document process-attribution limits; add Linux collector and real-network tests; review privacy impact. |
| Nano watchdog | Nano source can only evaluate host-provided numeric signals and emit immutable, consent-gated proposals. There is no runner. | Add signed/versioned rule admission, persistent schedule cursor, bounded runner, replay corpus, proposal/audit views, and explicit per-binding operator consent. |
| BYOK providers | Local Core uses local credentials; mesh probes are read-only and public-surface providers are offline fixtures. | One provider at a time: least-privilege scopes, keystore/file-secret handling, rotation/revocation, egress allowlist, audit trail, failure tests, and no browser credential exposure. |
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
