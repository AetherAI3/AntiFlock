# Governance

AntiFlock is governed as safety-sensitive open-source infrastructure. The
current name is an internal working title and is not cleared for public launch;
governance under this file does not claim a trademark or affiliation with any
existing project.

## Roles

- **Contributors** propose code, documentation, research, reports, and review.
- **Maintainers** merge changes, cut releases, and steward one or more domains.
- **Security and privacy maintainers** review identity, authorization,
  privileged execution, evidence, data collection, retention, community abuse,
  and Scrambler changes.
- **Project lead** resolves decisions that remain blocked after documented
  alternatives and objections. Until named in the repository, this role is
  held by the repository owner and may not be inferred from commit access.

Repository permissions are not permission to override safety contracts.

## Decisions

Routine, reversible changes use normal review. Architecture, wire-compatibility,
privacy, security, evidence semantics, community-safety, naming, and governance
changes require an ADR or equivalent design record with consequences and
explicit domain-maintainer approval. Maintainers seek rough consensus, record
material objections, and favor the narrower, privacy-preserving, reversible
choice when evidence is incomplete.

No maintainer may unilaterally:

- weaken the prohibition on tracking or targeting people;
- permit equipment interference, harassment, or automatic evasion routes;
- put model output into the blocking path;
- upload exact continuous location or collect payloads by default;
- make truthful evidence semantics subscription-dependent;
- bypass signed plans, verification, or rollback for Scrambler; or
- publicly launch under the working name without documented clearance.

## Changes and releases

All changes are reviewed through branches. A release requires passing tests,
schema compatibility review, dependency and artifact provenance, known-risk
notes, and security/privacy sign-off proportional to the touched surface.
Critical findings block release unless the project lead and security
maintainers document an explicit, time-bounded exception that does not put
users or third parties at unreasonable risk.

Generated contracts derive from the checked-in protobuf sources. Published
field or enum numbers are never reused. Security corrections remain visible in
history; confidential exploit detail may be embargoed until coordinated
disclosure.

## Community intelligence moderation

Moderation follows `docs/community-intelligence-policy.md`. Reports are judged
by evidence, public-interest value, privacy, freshness, and safety rather than
commercial tier or viewpoint. Appeals and corrections are documented. Access
to non-public reporter information is least-privilege and audited.

## Conflicts and conduct

Maintainers disclose material employment, financial, vendor, dataset, or
personal conflicts and recuse when impartial review is doubtful. Conduct is
governed by `CODE_OF_CONDUCT.md`. Retaliation for good-faith security, privacy,
or safety concerns is prohibited.

## Amendments

Governance amendments require a public proposal, review period once a public
community exists, approval by a majority of active maintainers including one
security/privacy maintainer, and a recorded decision. Before that body exists,
the repository owner may bootstrap roles but may not weaken the locked safety
boundaries above.
