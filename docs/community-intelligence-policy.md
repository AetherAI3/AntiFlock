# Community intelligence policy

## Purpose

Community intelligence reports publicly visible infrastructure and hazardous
conditions for situational awareness. It does not track people, infer guilt,
identify targets, or establish that reported equipment caused a network event.

## Allowed report subjects

- Fixed public ALPR or public surveillance-camera installations or clusters.
- Publicly documented camera registries, monitoring deployments, public safety
  sensors, or gunshot-detection systems.
- Public Wi-Fi access points and hazards, including suspected impersonation,
  when the technical basis and uncertainty are recorded.
- Persistent passive technical signatures attributable to infrastructure,
  with privacy-reduced precision.
- Network outage or interference areas.
- Corrections, disputes, removed equipment, or an incorrect marker.

A submission may contain the minimum useful geometry, category, observation
time, public-equipment photograph with metadata removed, orientation,
manufacturer when visible, public-record citation, passive signature, source
license, reporter confidence, and evidence references.

A persistent wireless signature must be stationary infrastructure evidence. A
tag, phone, vehicle, or other signal moving with a person is not reportable.

## Prohibited content and use

The service MUST reject or remove:

- individual people, faces, license plates, personal identifiers, private
  routines, or real-time locations of officers or private persons;
- private residential cameras absent a documented, reviewed public-interest
  exception;
- instructions or operational details intended to damage, disable, spoof,
  interfere with, trespass against, or evade monitoring equipment or lawful
  controls;
- targeting, harassment, threats, doxxing, or owner contact campaigns;
- unsupported accusations, claims of interception inferred only from proximity,
  or content presented with a stronger evidence class than its provenance;
- precise sensitive facilities or locations where publication creates a
  credible safety risk; and
- automatically generated evasion routes.

## Location and reporter privacy

Nearby matching uses signed regional packs on the device. Exact continuous
device location is not uploaded. Reports reduce precision to what the category
needs, remove image metadata and personal details, and warn submitters that a
public photograph may reveal identity or routine. Public records expose a
pseudonymous reporter reference at most; abuse controls keep separately
protected identifiers only when necessary and for a bounded period.

## Lifecycle

Reports progress through `UNREVIEWED`, `COMMUNITY_CORROBORATED`,
`DOCUMENT_SUPPORTED`, `TECHNICAL_SIGNATURE_OBSERVED`, `MAINTAINER_VERIFIED`,
`STALE`, `DISPUTED`, and `REMOVED`. These are moderation/verification states,
not evidence classes. Each report retains its source-level evidence class.

Category and source policy define expiry. A stale report is never rendered as
current. Corroboration requires independent provenance, not duplicate imports
or copied posts. Disputes are visible, corrections are append-only, and
removal tombstones prevent immediate re-import without retaining unnecessary
personal data.

## Wording

Approved nearby wording separates facts:

> Two community-verified ALPR installations are reported within the current
> area. This does not indicate active interception of your phone or network
> traffic.

Moderators enforce this policy independently of commercial tier, viewpoint,
or whether a report is convenient to AntiFlock or Aether.
