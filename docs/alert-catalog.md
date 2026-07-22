# Initial alert and reason-code catalog

This catalog satisfies the Phase 0 alert gate. A rule may use a lower
confidence than shown when capability quality, freshness, or contradictory
evidence requires it. It may not use a higher evidence class merely because a
finding is severe.

`high` below means a rule-family confidence at or above `0.90` from fresh,
direct, full-support telemetry. `moderate` means `0.60-0.89`, normally because
attribution is partial or corroboration is incomplete. Values are calibration
starting points, not universal probabilities.

## Route, mesh, and DNS

| Reason | Trigger and evidence requirement | Class / confidence | Required user wording | Recommended response | False-positive or alternate explanation |
| --- | --- | --- | --- | --- | --- |
| `AF-MESH-001` | Policy requires mesh; a fresh full-support node probe directly observes the required mesh disconnected. | `DETECTED`, high. Stale/missing probe becomes `UNKNOWN`, not this alert. | **Private mesh disconnected.** This device is not connected to the private mesh required by policy. | Restore mesh; hold or block protected egress according to policy; offer only a scoped bypass. | Provider status can lag or a device may be between interfaces; verify locally before alleging a provider outage or attack. |
| `AF-PATH-001` | Policy requires an approved exit; endpoint route and external-exit checks establish it is inactive. | `DETECTED`, high when both checks agree; otherwise `UNKNOWN` or moderate. | **Protection interrupted.** Your approved secure route is unavailable. Protected traffic has been paused where policy requires it. | Reconnect, select an approved exit, then verify route, DNS, and external identity before release. | A probe destination may be unavailable while the tunnel itself works; use multiple scoped checks. |
| `AF-PATH-002` | A fresh route/flow observation directly shows protected egress on an interface outside the approved tunnel. | `DETECTED`, high for exact route; moderate when process attribution is partial. | **Traffic leaving outside the mesh.** This traffic is using a path that policy does not approve. | Block affected egress, inspect route ownership, restore and verify the tunnel. | Split-tunnel or recovery traffic may be explicitly allowed; evaluate the effective policy before alerting. |
| `AF-DNS-001` | Current resolver differs from the approved resolver under a policy that requires it. | `DETECTED`, high for direct configuration; state depends on policy criticality. | **DNS policy mismatch.** This device is not using an approved resolver. | Restore the approved DNS profile and verify the query path. | Captive portals and OS transition states may temporarily replace DNS without proving manipulation. |
| `AF-DNS-002` | Required DNS-path verification cannot be completed with fresh supported telemetry. | `UNKNOWN`; confidence expresses confidence in the visibility gap, not in an attack. | **DNS visibility unknown.** AntiFlock cannot verify that DNS is using the approved path. | Retry verification or remain held/blocked according to the explicit fail mode. | A blocked probe or unsupported platform may cause the gap; do not say DNS was hijacked. |

## Network, node, service, and certificate

| Reason | Trigger and evidence requirement | Class / confidence | Required user wording | Recommended response | False-positive or alternate explanation |
| --- | --- | --- | --- | --- | --- |
| `AF-NET-001` | A fresh direct observation differs from the last verified gateway for the same network context. | `DETECTED`, high for the change; `SUSPECTED` only with separate interception indicators. | **Default gateway changed.** The current network path differs from the last verified path. Active interception is not confirmed. | Re-verify network identity, route, certificate, and DNS; isolate only if policy requires it. | DHCP renewal, roaming, failover, or network maintenance commonly changes a gateway. |
| `AF-NET-002` | Wi-Fi security is directly observed as open. | `DETECTED`, high; posture impact follows policy. | **Open wireless network.** This network does not provide link-layer authentication. | Require the approved mesh/exit or avoid sensitive activity. | An open link does not prove malicious ownership or active interception. |
| `AF-NODE-001` | Provider and AntiFlock identity state show a mesh node without authorization for this deployment. | `DETECTED` or `VERIFIED`, high only after identity mapping is fresh. | **Unrecognized mesh node.** A node not authorized by current policy appears in the mesh. | Suspend peer access, verify provider association, and revoke if unauthorized. | A newly enrolled or renamed node may be awaiting identity synchronization. |
| `AF-NODE-002` | Node telemetry exceeds its rule-specific freshness window. | `UNKNOWN`, high confidence in staleness. | **Device visibility stale.** AntiFlock has not received current telemetry from this node. | Check device and Core connectivity; rely on the node's cached policy within its validity. | Sleeping, powered-off, or intermittently connected devices are not necessarily compromised. |
| `AF-SVC-001` | A direct socket observation finds a listening service absent from the approved baseline. | `DETECTED`, high for the socket; process attribution may be moderate. | **New listening service detected.** A service not present in the approved baseline is accepting connections. | Identify the service and exposure scope; approve, restrict, or stop it. | Software updates and local development tools commonly open legitimate listeners. |
| `AF-CERT-001` | A fresh trust-store digest differs from the approved baseline and the change is not an authorized update. | `DETECTED`, high for the change; `SUSPECTED` only with corroborating behavior. | **Trusted certificate store changed.** The device trust set differs from its approved baseline. | Inspect added/removed authorities and restore policy if unauthorized. | OS, browser, enterprise-management, and security-tool updates may legitimately change roots. |

## Intelligence

| Reason | Trigger and evidence requirement | Class / confidence | Required user wording | Recommended response | False-positive or alternate explanation |
| --- | --- | --- | --- | --- | --- |
| `AF-INTEL-001` | A destination indicator matches a non-expired intelligence record. The finding preserves the record's evidence class and source. | Inherits `REPORTED`, `VERIFIED`, or other source class; never promoted by the match itself. | **Destination matches an intelligence record.** State the source, class, freshness, and what was matched; do not call it malicious unless the evidence supports that exact claim. | Inspect provenance and policy; block only when a deterministic policy explicitly covers that record class. | Shared hosting, reassigned IPs, wildcard domains, copied feeds, and stale records can produce unrelated matches. |

## Nearby field context

Nearby reports are context cards, not `AF-PATH-*` or interception findings:

> **Reported monitoring infrastructure nearby.** Two community-verified ALPR
> installations are reported within the current area. This does not indicate
> active interception of your phone or network traffic.

No proximity rule may change a network finding to `SUSPICIOUS` or `EXPOSED`
without independent technical evidence of the network condition.
