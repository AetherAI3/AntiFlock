# Privacy invariants

These invariants are release gates, not preferences.

1. **Operator scope.** Private identifiers and Footprint Graph assets require
   ownership verification or explicit, revocable authorization. AntiFlock is
   not a general-purpose people-search or dossier system.
2. **Infrastructure, not people.** Community intelligence does not accept
   individual identities, real-time person or officer locations, private
   routines, or harassment-oriented content.
3. **Location stays local by default.** Exact continuous location is not
   uploaded for nearby matching. Signed regional packs are matched on-device.
   A deliberate report submits only the minimum useful precision.
4. **No payloads by default.** Standard observation records connection and
   system metadata, never packet or message bodies. Any future payload capture
   is separately opt-in, visibly active, narrowly scoped, short-lived, and
   threat-model reviewed.
5. **Minimize before collection.** A field is not collected merely because an
   API exposes it. Each collected field has a purpose, sensitivity, retention
   class, and deletion path.
6. **Keys stay at their origin.** Endpoint, recovery, and signing private keys
   never leave their protected origin in plaintext. Enrollment transmits only
   public material and proof of possession.
7. **Local-first operation.** A self-hosted deployment does not require an
   Aether account or hosted telemetry. Hosted synchronization is optional,
   explicit, encrypted, and separable by data class.
8. **No hidden monetization.** AntiFlock does not sell, broker, or use operator
   telemetry, location, footprint, or community reports for advertising.
9. **Purpose-bound access.** Components and plugins receive only the data and
   operations declared by a capability grant. Privileged collection and
   mutation are isolated and auditable.
10. **Evidence survives explanation.** AI summaries never replace raw evidence
    or provenance and never make blocking decisions.
11. **Export, correction, deletion.** Operators can inspect and export their
    local data, correct labels, revoke connector authorization, and delete data
    subject only to explicitly disclosed security/audit preservation windows.
12. **Privacy is tier-independent.** A paid tier may add infrastructure and
    longer operator-chosen history; it may not weaken these invariants or make
    honest evidence labels a premium feature.

Telemetry or analytics that cannot satisfy these invariants MUST remain off.
Changes require a privacy review, data-flow update, migration/deletion plan,
and explicit release note.
