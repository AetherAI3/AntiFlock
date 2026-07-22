import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  AuditAppendError,
  FetchLoopbackTransport,
  OneTimeAuthorizationError,
  SecureActionClient,
  parseCanonicalDecisionResponse,
  parseDecision,
  scopeForRequest,
  toCanonicalAuthorizeRequest,
  toCanonicalEvaluateRequest,
  type ActionAuditEvent,
  type AgentTransport,
  type AllowOnceDecision,
  type AuthorizeOnceRequest,
  type EvaluationContext,
  type OneTimeAuthorization,
  type ProtectionSnapshot,
  type SecureActionDecision,
  type SecureActionRequest,
  type WaitForProtectionRequest,
  type WaitForProtectionResult,
} from "../src/index.js";

const NOW = "2026-07-21T12:00:00.000Z";
const LATER = "2026-07-21T12:05:00.000Z";

const exposed: ProtectionSnapshot = {
  state: "EXPOSED",
  observedAt: NOW,
  networkTrust: "UNTRUSTED",
  meshConnected: false,
  approvedExitActive: false,
  dnsProtected: false,
  reasonCodes: ["AF-PATH-001", "AF-DNS-002"],
};

const protectedSnapshot: ProtectionSnapshot = {
  state: "PROTECTED",
  observedAt: "2026-07-21T12:00:10.000Z",
  networkTrust: "UNTRUSTED",
  meshConnected: true,
  approvedExitActive: true,
  dnsProtected: true,
  reasonCodes: [],
};

const request: SecureActionRequest = {
  id: "request-1",
  applicationId: "aether-demo",
  nodeId: "phone-1",
  actionType: "message.send",
  destinations: ["messages.aether.example"],
  dataClass: "message-body",
  sensitivity: "CONFIDENTIAL",
  deadline: LATER,
  operationId: "operation-1",
};

function audit(decisionId: string) {
  return {
    traceId: "trace-1",
    decisionId,
    policyRevision: 42,
    evaluatedAt: NOW,
    agentId: "local-agent-1",
    evidenceClass: "DETECTED" as const,
  };
}

function allow(actionId = "action-1"): SecureActionDecision {
  return {
    decision: "ALLOW",
    actionId,
    protection: protectedSnapshot,
    reasonCodes: [],
    audit: audit(`decision-${actionId}`),
  };
}

function hold(actionId = "action-1"): SecureActionDecision {
  return {
    decision: "HOLD",
    actionId,
    protection: exposed,
    reasonCodes: ["AF-PATH-001"],
    audit: audit(`decision-${actionId}`),
    hold: { releaseWhen: "PROTECTION_RESTORED", expiresAt: LATER },
  };
}

function grant(grantId = "grant-1"): OneTimeAuthorization {
  return {
    grantId,
    token: `opaque-${grantId}`,
    scope: scopeForRequest(request),
    issuedAt: NOW,
    expiresAt: LATER,
    remainingUses: 1,
  };
}

class ScriptedTransport implements AgentTransport {
  readonly contexts: EvaluationContext[] = [];
  readonly waits: WaitForProtectionRequest[] = [];
  readonly authorizeRequests: AuthorizeOnceRequest[] = [];
  readonly audits: ActionAuditEvent[] = [];
  failAuditLifecycle?: string;

  constructor(
    readonly decisions: SecureActionDecision[],
    readonly waitResults: WaitForProtectionResult[] = [],
    readonly authorizedDecisions: AllowOnceDecision[] = [],
  ) {}

  async evaluate(
    _request: SecureActionRequest,
    context: EvaluationContext,
  ): Promise<SecureActionDecision> {
    this.contexts.push(context);
    const next = this.decisions.shift();
    assert.ok(next, "test transport ran out of decisions");
    return next;
  }

  async waitForProtection(requestValue: WaitForProtectionRequest) {
    this.waits.push(requestValue);
    const next = this.waitResults.shift();
    assert.ok(next, "test transport ran out of wait results");
    return next;
  }

  async authorizeOnce(requestValue: AuthorizeOnceRequest) {
    this.authorizeRequests.push(requestValue);
    const next = this.authorizedDecisions.shift();
    assert.ok(next, "test transport ran out of authorized decisions");
    return next;
  }

  async appendAudit(event: ActionAuditEvent) {
    if (event.lifecycle === this.failAuditLifecycle) {
      throw new Error("audit unavailable");
    }
    this.audits.push(event);
  }
}

function client(transport: AgentTransport) {
  let id = 0;
  return new SecureActionClient(transport, {
    now: () => new Date(NOW),
    idFactory: () => `event-${++id}`,
  });
}

describe("SecureActionClient", () => {
  it("executes an ALLOW decision and records the lifecycle", async () => {
    const transport = new ScriptedTransport([allow()]);
    let executions = 0;
    const outcome = await client(transport).execute(request, () => {
      executions += 1;
      return "sent";
    });

    assert.equal(outcome.status, "executed");
    assert.equal(outcome.status === "executed" && outcome.value, "sent");
    assert.equal(executions, 1);
    assert.deepEqual(
      transport.audits.map((event) => event.lifecycle),
      [
        "SDK_DECISION_RECEIVED",
        "SDK_ACTION_EXECUTION_STARTED",
        "SDK_ACTION_EXECUTION_SUCCEEDED",
      ],
    );
  });

  it("holds, waits for verified restoration, re-evaluates, and then releases", async () => {
    const transport = new ScriptedTransport(
      [hold("held-action"), allow("released-action")],
      [{ restored: true, snapshot: protectedSnapshot }],
    );
    const decisions: string[] = [];
    const outcome = await client(transport).execute(request, () => "sent", {
      onDecision: (decision) => {
        decisions.push(decision.decision);
      },
    });

    assert.equal(outcome.status, "executed");
    assert.equal(outcome.status === "executed" && outcome.attempts, 1);
    assert.deepEqual(decisions, ["HOLD", "ALLOW"]);
    assert.equal(transport.waits.length, 1);
    assert.equal(transport.contexts[1]?.priorActionId, "held-action");
    assert.deepEqual(
      transport.audits.map((event) => event.lifecycle),
      [
        "SDK_DECISION_RECEIVED",
        "SDK_HOLD_WAIT_STARTED",
        "SDK_PROTECTION_RESTORED",
        "SDK_DECISION_RECEIVED",
        "SDK_ACTION_EXECUTION_STARTED",
        "SDK_ACTION_EXECUTION_SUCCEEDED",
      ],
    );
  });

  it("does not release when the restored snapshot is not protected", async () => {
    const transport = new ScriptedTransport([hold()], [
      { restored: true, snapshot: { ...protectedSnapshot, state: "DEGRADED" } },
    ]);
    let executed = false;
    const outcome = await client(transport).execute(request, () => {
      executed = true;
    });

    assert.equal(outcome.status, "expired");
    assert.equal(executed, false);
    assert.ok(
      outcome.status === "expired" &&
        outcome.reasonCodes.includes("SDK_RESTORED_STATE_NOT_PROTECTED"),
    );
  });

  it("returns an expired outcome when protection restoration times out", async () => {
    const transport = new ScriptedTransport([hold()], [
      { restored: false, snapshot: exposed },
    ]);
    const outcome = await client(transport).execute(request, () => "not-run");

    assert.equal(outcome.status, "expired");
    assert.ok(
      outcome.status === "expired" &&
        outcome.reasonCodes.includes("SDK_PROTECTION_RESTORE_TIMEOUT"),
    );
  });

  it("returns HOLD without waiting when automatic retry is disabled", async () => {
    const transport = new ScriptedTransport([hold()]);
    const outcome = await client(transport).execute(request, () => "not-run", {
      retryOnProtectionRestored: false,
    });

    assert.equal(outcome.status, "held");
    assert.equal(transport.waits.length, 0);
  });

  it("fails closed on BLOCK", async () => {
    const transport = new ScriptedTransport([
      {
        decision: "BLOCK",
        actionId: "blocked-action",
        protection: exposed,
        reasonCodes: ["AF-PATH-002"],
        audit: audit("decision-block"),
      },
    ]);
    let executed = false;
    const outcome = await client(transport).execute(request, () => {
      executed = true;
    });

    assert.equal(outcome.status, "blocked");
    assert.equal(executed, false);
  });

  it("requires an explicit consent provider and converts consent into ALLOW_ONCE", async () => {
    const authorization = grant();
    const consentDecision: SecureActionDecision = {
      decision: "REQUIRE_CONSENT",
      actionId: "consent-action",
      protection: exposed,
      reasonCodes: ["AF-PATH-001"],
      audit: audit("decision-consent"),
      consent: {
        prompt: "Send once outside the protected route?",
        expiresAt: LATER,
        scope: scopeForRequest(request),
      },
    };
    const onceDecision: AllowOnceDecision = {
      decision: "ALLOW_ONCE",
      actionId: "once-action",
      protection: exposed,
      reasonCodes: ["USER_AUTHORIZED_ONCE"],
      audit: audit("decision-once"),
      authorization,
    };
    const transport = new ScriptedTransport([consentDecision], [], [onceDecision]);
    const outcome = await client(transport).execute(request, () => "sent-once", {
      consentProvider: async () => ({ confirmed: true }),
    });

    assert.equal(outcome.status, "executed");
    assert.equal(outcome.status === "executed" && outcome.decision, "ALLOW_ONCE");
    assert.equal(transport.authorizeRequests.length, 1);
    assert.equal(transport.contexts.length, 1);
    assert.equal(transport.authorizeRequests[0]?.expiresAt, LATER);
  });

  it("returns consent-required without prompting implicitly", async () => {
    const consentDecision: SecureActionDecision = {
      decision: "REQUIRE_CONSENT",
      actionId: "consent-action",
      protection: exposed,
      reasonCodes: ["AF-PATH-001"],
      audit: audit("decision-consent"),
      consent: {
        prompt: "Send once outside the protected route?",
        expiresAt: LATER,
        scope: scopeForRequest(request),
      },
    };
    const transport = new ScriptedTransport([consentDecision]);

    const outcome = await client(transport).execute(request, () => "not-run");

    assert.equal(outcome.status, "consent_required");
    assert.equal(transport.authorizeRequests.length, 0);
  });

  it("records explicit consent decline and keeps the action closed", async () => {
    const consentDecision: SecureActionDecision = {
      decision: "REQUIRE_CONSENT",
      actionId: "consent-action",
      protection: exposed,
      reasonCodes: ["AF-PATH-001"],
      audit: audit("decision-consent"),
      consent: {
        prompt: "Send once outside the protected route?",
        expiresAt: LATER,
        scope: scopeForRequest(request),
      },
    };
    const transport = new ScriptedTransport([consentDecision]);
    const outcome = await client(transport).execute(request, () => "not-run", {
      consentProvider: async () => ({ confirmed: false, reason: "user-cancelled" }),
    });

    assert.equal(outcome.status, "consent_required");
    assert.equal(transport.audits.at(-1)?.lifecycle, "SDK_CONSENT_DECLINED");
  });

  it("prevents reuse of the same one-time grant", async () => {
    const authorization = grant("reused-grant");
    const once = (): SecureActionDecision => ({
      decision: "ALLOW_ONCE",
      actionId: "once-action",
      protection: exposed,
      reasonCodes: ["USER_AUTHORIZED_ONCE"],
      audit: audit("decision-once"),
      authorization,
    });
    const transport = new ScriptedTransport([once(), once()]);
    const sdk = client(transport);
    await sdk.execute(request, () => "first");

    await assert.rejects(() => sdk.execute(request, () => "second"), OneTimeAuthorizationError);
  });

  it("rejects a one-time grant for a broader or different scope", async () => {
    const wrongGrant: OneTimeAuthorization = {
      ...grant(),
      scope: { ...scopeForRequest(request), destinations: ["evil.example"] },
    };
    const transport = new ScriptedTransport([
      {
        decision: "ALLOW_ONCE",
        actionId: "once-action",
        protection: exposed,
        reasonCodes: ["USER_AUTHORIZED_ONCE"],
        audit: audit("decision-once"),
        authorization: wrongGrant,
      },
    ]);

    await assert.rejects(
      () => client(transport).execute(request, () => "should-not-run"),
      OneTimeAuthorizationError,
    );
  });

  it("fails closed before execution when required audit storage is unavailable", async () => {
    const transport = new ScriptedTransport([allow()]);
    transport.failAuditLifecycle = "SDK_DECISION_RECEIVED";
    let executed = false;

    await assert.rejects(
      () =>
        client(transport).execute(request, () => {
          executed = true;
        }),
      (error: unknown) =>
        error instanceof AuditAppendError && error.actionMayHaveExecuted === false,
    );
    assert.equal(executed, false);
  });

  it("reports completion-audit failure without mislabeling a successful action as failed", async () => {
    const transport = new ScriptedTransport([allow()]);
    transport.failAuditLifecycle = "SDK_ACTION_EXECUTION_SUCCEEDED";
    let executed = false;

    await assert.rejects(
      () =>
        client(transport).execute(request, () => {
          executed = true;
          return "sent";
        }),
      (error: unknown) =>
        error instanceof AuditAppendError && error.actionMayHaveExecuted === true,
    );
    assert.equal(executed, true);
    assert.deepEqual(
      transport.audits.map((event) => event.lifecycle),
      ["SDK_DECISION_RECEIVED", "SDK_ACTION_EXECUTION_STARTED"],
    );
  });

  it("records execution failure and preserves the operation error", async () => {
    const transport = new ScriptedTransport([allow()]);
    const operationError = new TypeError("send failed");

    await assert.rejects(
      () => client(transport).execute(request, () => Promise.reject(operationError)),
      operationError,
    );
    assert.equal(transport.audits.at(-1)?.lifecycle, "SDK_ACTION_EXECUTION_FAILED");
    assert.deepEqual(transport.audits.at(-1)?.details, { errorType: "TypeError" });
  });
});

describe("agent response validation", () => {
  it("rejects a HOLD response without the required release condition", () => {
    assert.throws(
      () =>
        parseDecision({
          decision: "HOLD",
          actionId: "action",
          protection: exposed,
          reasonCodes: [],
          audit: audit("decision"),
          hold: { releaseWhen: "TIMER", expiresAt: LATER },
        }),
      /PROTECTION_RESTORED/,
    );
  });

  it("validates every rich native decision variant at the transport boundary", () => {
    const authorization = grant("validated-grant");
    const fixtures: SecureActionDecision[] = [
      allow(),
      hold(),
      {
        decision: "BLOCK",
        actionId: "blocked-action",
        protection: exposed,
        reasonCodes: ["AF-PATH-002"],
        audit: audit("decision-block"),
      },
      {
        decision: "REQUIRE_CONSENT",
        actionId: "consent-action",
        protection: exposed,
        reasonCodes: ["AF-PATH-001"],
        audit: audit("decision-consent"),
        consent: {
          prompt: "Authorize once?",
          expiresAt: LATER,
          scope: scopeForRequest(request),
        },
      },
      {
        decision: "ALLOW_ONCE",
        actionId: "once-action",
        protection: exposed,
        reasonCodes: ["USER_AUTHORIZED_ONCE"],
        audit: audit("decision-once"),
        authorization,
      },
    ];

    assert.deepEqual(
      fixtures.map((fixture) => parseDecision(fixture).decision),
      ["ALLOW", "HOLD", "BLOCK", "REQUIRE_CONSENT", "ALLOW_ONCE"],
    );
  });

  it("refuses remote HTTP agent endpoints unless explicitly enabled", () => {
    assert.throws(
      () =>
        new FetchLoopbackTransport({
          baseUrl: "https://agent.example",
          bearerToken: "test-token",
        }),
      /Refusing non-loopback/,
    );
  });

  it("requires authentication for loopback transport by default", () => {
    assert.throws(() => new FetchLoopbackTransport(), /bearer token is required/);
    assert.doesNotThrow(
      () => new FetchLoopbackTransport({ allowUnauthenticated: true }),
    );
  });

  it("maps the canonical ActionGateService JSON projection without inventing certainty", () => {
    assert.deepEqual(toCanonicalEvaluateRequest(request), {
      action: {
        id: "request-1",
        applicationId: "aether-demo",
        nodeId: "phone-1",
        actionType: "message.send",
        destinations: ["messages.aether.example"],
        dataClass: "message-body",
        sensitivity: "SENSITIVITY_OPERATOR_PRIVATE",
        deadline: LATER,
        operationId: "operation-1",
      },
    });

    const decision = parseCanonicalDecisionResponse(
      {
        decision: {
          actionId: "canonical-action-1",
          decision: "SECURE_ACTION_DECISION_TYPE_HOLD",
          status: "SECURE_ACTION_STATUS_HELD",
          protection: {
            id: "snapshot-1",
            nodeId: "phone-1",
            policyRevision: "9",
            state: "PROTECTION_STATE_EXPOSED",
            evaluatedAt: NOW,
            reasons: [{ reasonCode: "AF-PATH-001" }],
          },
          reasonCodes: ["AF-PATH-001"],
          expiresAt: LATER,
          userMessage: "Protection interrupted",
        },
      },
      request,
    );

    assert.equal(decision.decision, "HOLD");
    assert.equal(decision.protection.networkTrust, "UNKNOWN");
    assert.equal(decision.audit.traceId, "snapshot-1");
    assert.equal(decision.audit.policyRevision, 9);
    assert.equal(decision.audit.evidenceClass, "UNKNOWN");
  });

  it("maps canonical one-time authorization to the exact request scope", () => {
    const authorizeBody = toCanonicalAuthorizeRequest({
      actionId: "canonical-action-1",
      request,
      scope: scopeForRequest(request),
      expiresAt: LATER,
      consent: { confirmed: true, confirmedAt: NOW, method: "USER_EXPLICIT" },
    });
    assert.deepEqual(authorizeBody, {
      actionId: "canonical-action-1",
      operationId: "operation-1",
      authorizedDestinations: ["messages.aether.example"],
      expiresAt: LATER,
      consentReasonCode: "USER_EXPLICIT",
    });

    const decision = parseCanonicalDecisionResponse(
      {
        decision: {
          actionId: "canonical-action-1",
          decision: "SECURE_ACTION_DECISION_TYPE_ALLOW_ONCE",
          protection: {
            id: "snapshot-1",
            nodeId: "phone-1",
            policyRevision: 9,
            state: "PROTECTION_STATE_EXPOSED",
            evaluatedAt: NOW,
            reasons: [{ reasonCode: "AF-PATH-001" }],
          },
          reasonCodes: ["USER_AUTHORIZED_ONCE"],
          authorization: "opaque-token",
          expiresAt: LATER,
        },
      },
      request,
    );

    assert.equal(decision.decision, "ALLOW_ONCE");
    assert.deepEqual(
      decision.decision === "ALLOW_ONCE" && decision.authorization.scope,
      scopeForRequest(request),
    );
  });

  it("sends canonical evaluate JSON through the authenticated loopback adapter", async () => {
    let capturedBody: unknown;
    let capturedAuthorization: string | null = null;
    const transport = new FetchLoopbackTransport({
      bearerToken: "local-test-token",
      fetch: async (_input, init) => {
        capturedBody = JSON.parse(String(init?.body));
        capturedAuthorization = new Headers(init?.headers).get("authorization");
        return new Response(
          JSON.stringify({
            decision: {
              actionId: "canonical-action-1",
              decision: "SECURE_ACTION_DECISION_TYPE_ALLOW",
              protection: {
                id: "snapshot-1",
                nodeId: "phone-1",
                policyRevision: "9",
                state: "PROTECTION_STATE_PROTECTED",
                evaluatedAt: NOW,
                reasons: [],
              },
              reasonCodes: [],
            },
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      },
    });

    const decision = await transport.evaluate(request, { attempt: 0 });

    assert.deepEqual(capturedBody, toCanonicalEvaluateRequest(request));
    assert.equal(capturedAuthorization, "Bearer local-test-token");
    assert.equal(decision.decision, "ALLOW");
  });

  it("maps canonical wait and authorize responses and appends idempotent audit events", async () => {
    const paths: string[] = [];
    const transport = new FetchLoopbackTransport({
      bearerToken: "local-test-token",
      fetch: async (input) => {
        const path = new URL(String(input)).pathname;
        paths.push(path);
        if (path.endsWith("/wait")) {
          return new Response(
            JSON.stringify({
              restored: true,
              snapshot: {
                id: "snapshot-2",
                nodeId: "phone-1",
                policyRevision: "9",
                state: "PROTECTION_STATE_PROTECTED",
                evaluatedAt: NOW,
                reasons: [],
              },
            }),
            { status: 200, headers: { "content-type": "application/json" } },
          );
        }
        if (path.endsWith("/authorize")) {
          return new Response(
            JSON.stringify({
              decision: {
                actionId: "canonical-action-1",
                decision: "SECURE_ACTION_DECISION_TYPE_ALLOW_ONCE",
                protection: {
                  id: "snapshot-1",
                  nodeId: "phone-1",
                  policyRevision: "9",
                  state: "PROTECTION_STATE_EXPOSED",
                  evaluatedAt: NOW,
                  reasons: [{ reasonCode: "AF-PATH-001" }],
                },
                reasonCodes: ["USER_AUTHORIZED_ONCE"],
                authorization: "opaque-token",
                expiresAt: LATER,
              },
            }),
            { status: 200, headers: { "content-type": "application/json" } },
          );
        }
        return new Response(null, { status: 204 });
      },
    });

    const waited = await transport.waitForProtection({
      actionId: "canonical-action-1",
      afterObservedAt: NOW,
      deadline: LATER,
    });
    const authorized = await transport.authorizeOnce({
      actionId: "canonical-action-1",
      request,
      scope: scopeForRequest(request),
      expiresAt: LATER,
      consent: { confirmed: true, confirmedAt: NOW, method: "USER_EXPLICIT" },
    });
    await transport.appendAudit({
      eventId: "event-1",
      lifecycle: "SDK_DECISION_RECEIVED",
      occurredAt: NOW,
      actionId: "canonical-action-1",
      requestId: request.id,
      decision: "ALLOW_ONCE",
      traceId: "trace-1",
      policyRevision: 9,
      reasonCodes: [],
    });

    assert.equal(waited.snapshot.state, "PROTECTED");
    assert.equal(authorized.decision, "ALLOW_ONCE");
    assert.deepEqual(paths, [
      "/v1/actions/canonical-action-1/wait",
      "/v1/actions/canonical-action-1/authorize",
      "/v1/actions/canonical-action-1/audit",
    ]);
  });
});
