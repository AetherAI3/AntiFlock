# Open decisions and release gates

These items do not weaken the v1 safety contracts. They must be resolved before
the named milestone.

| Decision | Current safe default | Required before |
| --- | --- | --- |
| Public product and protocol name | `AntiFlock` remains an internal working title; no affiliation or legal clearance is claimed. | Public launch, domain/namespace promotion, or trademark use. |
| Repository and generated-language namespaces | Protobuf package is the internal `antiflock.v1`; language-specific package options are intentionally absent. | Publishing generated SDKs. |
| License and copyright attribution | Apache License 2.0 is included as the permissive open-source default. | First public distribution; project owner and counsel should ratify. |
| Staffed private security and conduct contacts | Use repository-host private reporting and a non-conflicted maintainer. No response-time promise is made. | Accepting public users or contributions. |
| Platform credential storage and CA profile | Private keys stay local; Ed25519 and P-256 signature identifiers are modeled. | Implementing enrollment and release signing. |
| Retention and legal-jurisdiction profile | Conservative local defaults in `data-retention.md`; hosted upload is off. | Hosted service, new jurisdiction, or payload/location feature. |
| Dataset license and regional publication rules | Every source carries provenance/license and packs fail on missing or incompatible metadata. | Importing or redistributing each dataset. |
| Verification independence and reporter reputation | Duplicate/copied/correlated sources do not count as independent; no reputation score is trusted yet. | Promoting reports to verified states at scale. |
| Experimental detection claims | General cellular-interceptor/RF classification remains out of scope. | Any user-facing detector or enforcement rule in those domains. |
| Scrambler state dimensions | Simulation first; lower-risk approved exit, DNS, relay, route, and service dimensions only. | Enabling overlay identity, aggressive rotation, or adaptive execution. |
