# Terminology

| Term | Contract meaning |
| --- | --- |
| **AntiFlock** | Internal working title for the personal private-security operating layer; not a cleared public product name. |
| **Operator** | The principal who owns or is explicitly delegated authority over a deployment and its assets. |
| **Deployment** | One trust domain with stable AntiFlock identity, local authority, policy, and audit history. |
| **Node** | An enrolled device, gateway, server, router, or agent endpoint with its own key material. |
| **Agent** | The endpoint process that observes state, evaluates cached policy, exchanges events/plans, and requests privileged operations. |
| **Core** | The control, intelligence, and policy plane. Core is not the packet data plane. |
| **Mesh** | An established encrypted transport and identity network used to connect authorized nodes. |
| **Provider identity** | A Tailscale, Headscale, WireGuard, or other provider association; never the sole AntiFlock node identity. |
| **Capability** | A versioned claim that a node can observe, enforce, or verify a particular operation, including support quality and limits. |
| **Observation** | A collected fact about a device, network, path, service, or flow. Standard observations exclude payload content. |
| **Event** | An immutable, authenticated envelope recording a fact or transition for replay. |
| **Evidence** | A provenance-bearing reference that supports or disputes a claim. See the evidence classes in `evidence-model.md`. |
| **Finding** | A deterministic reason code plus condition, consequence, evidence, confidence, response, and false-positive context. |
| **Posture** | A point-in-time deterministic evaluation of observed facts against one policy. |
| **Protection state** | `PROTECTED`, `DEGRADED`, `SUSPICIOUS`, `EXPOSED`, `UNKNOWN`, or `UNAVAILABLE`. |
| **Policy** | Operator intent and constraints, independent of a platform implementation. |
| **Plan** | A signed, target-bound, expiring transaction with preconditions, actions, verification, and rollback. |
| **Protected action** | An application operation evaluated before sensitive data or a restricted destination is accessed. |
| **Bypass** | Explicit, narrow, expiring operator authorization. It is not a silent fail-open switch. |
| **Asset Graph** | Entities controlled, owned, or verified by the operator and their relationships. |
| **Observer Graph** | Services or infrastructure that interacts with or may receive metadata from authorized assets. `May observe` does not mean `did intercept`. |
| **Footprint Graph** | The operator-authorized digital asset and public-exposure view; not a people-search graph. |
| **Field report** | A time-bounded claim about infrastructure or a condition, with provenance, precision, evidence, and moderation state. |
| **Regional intelligence pack** | A signed, expiring dataset downloaded for local nearby matching. |
| **Scrambler** | A constrained planner/executor for controlled changes to approved observable network state with verification and rollback. |
| **Detected / Verified / Reported / Inferred / Suspected / Unknown** | Evidence classes; none is a subscription tier or UI severity. |
| **Confidence** | Calibrated support within a rule/source family, expressed from 0 to 1; not a substitute for evidence class. |
