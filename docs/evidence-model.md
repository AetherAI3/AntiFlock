# Evidence model

## First rule

AntiFlock states only what its evidence supports. Evidence class, confidence,
freshness, and location precision are independent dimensions. A high-confidence
community report is still `REPORTED`; a directly measured but noisy condition
is still `DETECTED` with lower confidence.

## Evidence classes

| Class | Meaning | Permitted assertion pattern |
| --- | --- | --- |
| `DETECTED` | The local device or an authorized gateway directly observed the condition. | "The default gateway changed at 10:42." |
| `VERIFIED` | Required corroboration or a trusted reviewer confirmed the claim under a documented method. | "This record was verified from two independent sources." |
| `REPORTED` | A public source or community contributor reported the claim; AntiFlock has not independently established it. | "An ALPR installation is reported in this area." |
| `INFERRED` | A deterministic rule derived the claim from named observable facts. | "Traffic is inferred to bypass the approved route." |
| `SUSPECTED` | Evidence is consistent with a possible active security event but is inconclusive. | "Interception is suspected but not confirmed." |
| `UNKNOWN` | Visibility or evidence is insufficient to classify the claim. | "AntiFlock cannot verify the complete path." |

`VERIFIED` is not permanent truth. It records that a verification policy was
satisfied at a time. Expired evidence cannot remain presented as current.

## Required claim fields

Every alert, finding, field marker, footprint relationship, or intelligence
claim MUST carry or resolve to:

- a stable claim/finding ID and deterministic reason code;
- evidence class and a confidence value from 0 through 1;
- observed or reported time and received time;
- last-verification time when verification occurred;
- expiry or an explicit retention/refresh rule;
- source type and source reference, with license where applicable;
- evidence type and integrity reference where available;
- location precision and sensitivity where location is relevant;
- an evidence-grounded explanation;
- recommended response;
- a false-positive or alternative-explanation note; and
- all supporting evidence references, including contradictory or disputed
  evidence material to the decision.

Confidence MUST be calibrated within a rule or source family, never treated as
a universal probability. User interfaces MUST show words before decimals and
MUST NOT use confidence to erase the evidence class.

## Alert contract

Before an alert template can ship, it defines:

1. **Reason code**: stable, searchable, and versioned.
2. **Evidence requirements**: facts, freshness, capabilities, and exclusions.
3. **Confidence rule**: deterministic computation and threshold.
4. **User wording**: factual condition, consequence, and uncertainty.
5. **Recommended response**: reversible and scoped where possible.
6. **False-positive explanation**: plausible benign or incomplete causes.

The phrase "someone is watching you" is prohibited unless evidence supports a
specific actual observation or interception event and the wording has passed a
security and legal review. A public network, failed tunnel, nearby camera, or
reported ALPR is not that evidence.

Approved examples:

- **Protection interrupted.** Your approved secure route is unavailable on an
  untrusted network. Protected traffic has been paused.
- **Potential interception indicators.** AntiFlock detected behavior
  consistent with gateway impersonation or traffic interception. Active
  interception is suspected but not confirmed.
- **Reported monitoring infrastructure nearby.** Two recently verified reports
  are located within the current area. This does not indicate interception of
  your device or traffic.
- **Visibility unknown.** AntiFlock cannot verify the complete path between
  this device and the destination.

## Corrections and aggregation

Evidence is append-only at the event boundary. Corrections reference the
superseded claim or event; they do not rewrite history. Aggregators preserve
source-level classifications and provenance. Multiple reports may satisfy a
documented verification policy, but duplication, copied sources, shared
ownership, and correlated sensors do not count as independent corroboration.

When evidence conflicts, AntiFlock lowers confidence, exposes the dispute, and
uses `UNKNOWN` or `SUSPECTED` as appropriate. It does not select the most
dramatic source.
