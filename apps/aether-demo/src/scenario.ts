import {
  scopeForRequest,
  type ActionAuditEvent,
  type AgentTransport,
  type AuthorizeOnceRequest,
  type EvaluationContext,
  type AllowOnceDecision,
  type ProtectionSnapshot,
  type SecureActionDecision,
  type SecureActionRequest,
  type WaitForProtectionRequest,
  type WaitForProtectionResult,
} from "@aether/antiflock-secure-action";

export const PROTECTION_NOTIFICATION = {
  title: "Protection interrupted",
  body: "Your approved secure route is unavailable on an untrusted network. Protected traffic has been paused.",
} as const;

const exposedSnapshot: ProtectionSnapshot = {
  state: "EXPOSED",
  observedAt: "2026-07-21T13:00:00.000Z",
  validUntil: "2026-07-21T13:05:00.000Z",
  policyRevision: 7,
  networkTrust: "UNTRUSTED",
  meshConnected: false,
  approvedExitActive: false,
  dnsProtected: null,
  reasonCodes: ["AF-MESH-001", "AF-PATH-001", "AF-DNS-002"],
  evidenceProvenance: "SIMULATION",
};

const restoredSnapshot: ProtectionSnapshot = {
  state: "PROTECTED",
  observedAt: "2026-07-21T13:00:03.000Z",
  validUntil: "2026-07-21T13:05:00.000Z",
  policyRevision: 7,
  networkTrust: "UNTRUSTED",
  meshConnected: true,
  approvedExitActive: true,
  dnsProtected: true,
  reasonCodes: [],
  evidenceProvenance: "SIMULATION",
};

export interface CoffeeShopTransportOptions {
  readonly restorationDelayMs?: number;
  readonly onRestorationStarted?: () => void;
  readonly onRestored?: () => void;
}

/**
 * Deterministic local-agent simulator for the vertical-slice demonstration.
 * It models control decisions only; it does not create a VPN or move packets.
 */
export class CoffeeShopAgentTransport implements AgentTransport {
  readonly audits: ActionAuditEvent[] = [];
  readonly evaluationContexts: EvaluationContext[] = [];
  #protected = false;
  readonly #restorationDelayMs: number;
  readonly #onRestorationStarted: (() => void) | undefined;
  readonly #onRestored: (() => void) | undefined;

  constructor(options: CoffeeShopTransportOptions = {}) {
    this.#restorationDelayMs = options.restorationDelayMs ?? 250;
    this.#onRestorationStarted = options.onRestorationStarted;
    this.#onRestored = options.onRestored;
  }

  async evaluate(
    request: SecureActionRequest,
    context: EvaluationContext,
  ): Promise<SecureActionDecision> {
    this.evaluationContexts.push(context);
    if (!this.#protected) {
      return {
        decision: "HOLD",
        actionId: request.id,
        protection: exposedSnapshot,
        reasonCodes: ["AF-PATH-001", "AF-DNS-002"],
        hold: {
          releaseWhen: "PROTECTION_RESTORED",
          expiresAt: "2026-07-21T13:05:00.000Z",
        },
        audit: {
          traceId: request.operationId,
          decisionId: "demo-decision-hold",
          policyRevision: 7,
          evaluatedAt: exposedSnapshot.observedAt,
          agentId: request.nodeId,
          evidenceClass: "DETECTED",
        },
      };
    }
    return {
      decision: "ALLOW",
      actionId: request.id,
      protection: restoredSnapshot,
      reasonCodes: [],
      audit: {
        traceId: request.operationId,
        decisionId: "demo-decision-allow",
        policyRevision: 7,
        evaluatedAt: restoredSnapshot.observedAt,
        agentId: request.nodeId,
        evidenceClass: "VERIFIED",
      },
    };
  }

  async waitForProtection(
    request: WaitForProtectionRequest,
  ): Promise<WaitForProtectionResult> {
    this.#onRestorationStarted?.();
    await abortableDelay(this.#restorationDelayMs, request.signal);
    if (Date.parse(request.deadline) <= Date.parse(restoredSnapshot.observedAt)) {
      return { restored: false, snapshot: exposedSnapshot };
    }
    this.#protected = true;
    this.#onRestored?.();
    return { restored: true, snapshot: restoredSnapshot };
  }

  async authorizeOnce(request: AuthorizeOnceRequest): Promise<AllowOnceDecision> {
    return {
      decision: "ALLOW_ONCE",
      actionId: request.actionId,
      protection: exposedSnapshot,
      reasonCodes: ["USER_AUTHORIZED_ONCE"],
      audit: {
        traceId: request.request.operationId,
        decisionId: "demo-decision-allow-once",
        policyRevision: 7,
        evaluatedAt: exposedSnapshot.observedAt,
        agentId: request.request.nodeId,
        evidenceClass: "DETECTED",
      },
      authorization: {
        grantId: "demo-one-time-grant",
        token: "demo-opaque-token-not-for-production",
        scope: scopeForRequest(request.request),
        issuedAt: exposedSnapshot.observedAt,
        expiresAt: request.expiresAt,
        remainingUses: 1,
      },
    };
  }

  async appendAudit(event: ActionAuditEvent): Promise<void> {
    this.audits.push(event);
  }
}

function abortableDelay(milliseconds: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(signal.reason);
      return;
    }
    const timer = setTimeout(resolve, milliseconds);
    signal?.addEventListener(
      "abort",
      () => {
        clearTimeout(timer);
        reject(signal.reason);
      },
      { once: true },
    );
  });
}
