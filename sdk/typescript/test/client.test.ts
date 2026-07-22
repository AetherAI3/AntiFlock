import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  AuditAppendError,
  FetchLoopbackTransport,
  InvalidAgentResponseError,
  OneTimeAuthorizationError,
  SecureActionAbortedError,
  SecureActionClient,
  SimulationExecutionDeniedError,
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
const SDK_TOKEN = "sdk-test-token-with-more-than-thirty-two-bytes";
const OPERATOR_TOKEN = "operator-test-token-with-more-than-thirty-two-bytes";

const exposed: ProtectionSnapshot = {
  state: "EXPOSED",
  observedAt: NOW,
  validUntil: LATER,
  policyRevision: 42,
  networkTrust: "UNTRUSTED",
  meshConnected: false,
  approvedExitActive: false,
  dnsProtected: false,
  reasonCodes: ["AF-PATH-001", "AF-DNS-002"],
  evidenceProvenance: "LIVE",
};

const protectedSnapshot: ProtectionSnapshot = {
  state: "PROTECTED",
  observedAt: "2026-07-21T12:00:10.000Z",
  validUntil: "2026-07-21T12:04:00.000Z",
  policyRevision: 42,
  networkTrust: "UNTRUSTED",
  meshConnected: true,
  approvedExitActive: true,
  dnsProtected: true,
  reasonCodes: [],
  evidenceProvenance: "LIVE",
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
    traceId: request.operationId,
    decisionId,
    policyRevision: 42,
    evaluatedAt: NOW,
    agentId: request.nodeId,
    evidenceClass: "DETECTED" as const,
  };
}

function allow(actionId = request.id): SecureActionDecision {
  return {
    decision: "ALLOW",
    actionId,
    protection: protectedSnapshot,
    reasonCodes: [],
    audit: audit(`decision-${actionId}`),
  };
}

function hold(actionId = request.id): SecureActionDecision {
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
      [hold(), allow()],
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
    assert.equal(transport.contexts[1]?.priorActionId, request.id);
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
        actionId: request.id,
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

  it("does not let an onDecision observer rewrite BLOCK into ALLOW", async () => {
    const transport = new ScriptedTransport([{
      decision: "BLOCK",
      actionId: request.id,
      protection: exposed,
      reasonCodes: ["AF-PATH-002"],
      audit: audit("decision-block"),
    }]);
    let executed = false;
    const outcome = await client(transport).execute(request, () => {
      executed = true;
    }, {
      onDecision: (observed) => {
        try {
          (observed as { decision: string }).decision = "ALLOW";
        } catch {
          // The observer receives a detached, frozen value in strict modules.
        }
      },
    });

    assert.equal(outcome.status, "blocked");
    assert.equal(executed, false);
  });

  it("rejects a decision bound to a different secure action request", async () => {
    const transport = new ScriptedTransport([allow("different-request")]);
    let executed = false;

    await assert.rejects(
      () => client(transport).execute(request, () => { executed = true; }),
      InvalidAgentResponseError,
    );
    assert.equal(executed, false);
    assert.equal(transport.audits.length, 0);
  });

  it("rejects plain ALLOW unless the returned posture is protected", async () => {
    const transport = new ScriptedTransport([{
      ...allow(),
      protection: exposed,
    }]);
    let executed = false;

    await assert.rejects(
      () => client(transport).execute(request, () => { executed = true; }),
      InvalidAgentResponseError,
    );
    assert.equal(executed, false);
  });

  it("requires an explicit consent provider and converts consent into ALLOW_ONCE", async () => {
    const authorization = grant();
    const consentDecision: SecureActionDecision = {
      decision: "REQUIRE_CONSENT",
      actionId: request.id,
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
      actionId: request.id,
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

  it("isolates consent and operation callbacks from the bound action scope", async () => {
    const consentDecision: SecureActionDecision = {
      decision: "REQUIRE_CONSENT",
      actionId: request.id,
      protection: exposed,
      reasonCodes: ["AF-PATH-001"],
      audit: audit("decision-consent-isolation"),
      consent: {
        prompt: "Authorize this exact scope?",
        expiresAt: LATER,
        scope: scopeForRequest(request),
      },
    };
    const onceDecision: AllowOnceDecision = {
      decision: "ALLOW_ONCE",
      actionId: request.id,
      protection: exposed,
      reasonCodes: ["USER_AUTHORIZED_ONCE"],
      audit: audit("decision-once-isolation"),
      authorization: grant("isolated-grant"),
    };
    const transport = new ScriptedTransport([consentDecision], [], [onceDecision]);
    let callbackScope: ReturnType<typeof scopeForRequest> | undefined;
    const attemptMutation = (mutate: () => void): void => {
      try {
        mutate();
      } catch {
        // Runtime freezing is expected to reject mutation in strict modules.
      }
    };

    const outcome = await client(transport).execute(request, (context) => {
      attemptMutation(() => {
        (context.request as { dataClass: string }).dataClass = "credentials";
      });
      attemptMutation(() => {
        (context.decision as { actionId: string }).actionId = "crossed-action";
      });
      callbackScope = scopeForRequest(context.request);
      return "isolated";
    }, {
      consentProvider: async (context) => {
        attemptMutation(() => {
          (context.request as { actionType: string }).actionType = "secret.delete";
        });
        attemptMutation(() => {
          (context.decision.consent.scope as { sensitivity: "RESTRICTED" }).sensitivity = "RESTRICTED";
        });
        return { confirmed: true };
      },
    });

    assert.equal(outcome.status, "executed");
    assert.deepEqual(callbackScope, scopeForRequest(request));
    assert.deepEqual(transport.authorizeRequests[0]?.scope, scopeForRequest(request));
    assert.equal(transport.audits.at(-1)?.actionId, request.id);
    assert.equal(transport.audits.at(-1)?.lifecycle, "SDK_ACTION_EXECUTION_SUCCEEDED");
  });

  it("returns consent-required without prompting implicitly", async () => {
    const consentDecision: SecureActionDecision = {
      decision: "REQUIRE_CONSENT",
      actionId: request.id,
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
      actionId: request.id,
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
      actionId: request.id,
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

  it("requires server-side start consumption for ALLOW_ONCE even in best-effort audit mode", async () => {
    const authorization = grant("server-consume-required");
    const transport = new ScriptedTransport([{
      decision: "ALLOW_ONCE",
      actionId: request.id,
      protection: exposed,
      reasonCodes: ["USER_AUTHORIZED_ONCE"],
      audit: audit("decision-once"),
      authorization,
    }]);
    transport.failAuditLifecycle = "SDK_ACTION_EXECUTION_STARTED";
    const sdk = new SecureActionClient(transport, {
      auditMode: "best-effort",
      now: () => new Date(NOW),
      idFactory: () => "event-once-consume",
    });
    let executed = false;

    await assert.rejects(
      () => sdk.execute(request, () => { executed = true; }),
      (error: unknown) => error instanceof AuditAppendError && error.actionMayHaveExecuted === false,
    );
    assert.equal(executed, false);
  });

  it("rechecks one-time expiry after the server-side consume await", async () => {
    let currentTime = NOW;
    const authorization = {
      ...grant("expires-during-consume"),
      expiresAt: "2026-07-21T12:01:00.000Z",
    };
    const transport = new ScriptedTransport([{
      decision: "ALLOW_ONCE",
      actionId: request.id,
      protection: exposed,
      reasonCodes: ["USER_AUTHORIZED_ONCE"],
      audit: audit("decision-once"),
      authorization,
    }]);
    const appendAudit = transport.appendAudit.bind(transport);
    transport.appendAudit = async (event) => {
      await appendAudit(event);
      if (event.lifecycle === "SDK_ACTION_EXECUTION_STARTED") currentTime = "2026-07-21T12:02:00.000Z";
    };
    const sdk = new SecureActionClient(transport, {
      now: () => new Date(currentTime),
      idFactory: () => "event-expiry-recheck",
    });
    let executed = false;

    await assert.rejects(
      () => sdk.execute(request, () => { executed = true; }),
      OneTimeAuthorizationError,
    );
    assert.equal(executed, false);
  });

  it("rechecks the request deadline after the execution-start audit await", async () => {
    let currentTime = NOW;
    const transport = new ScriptedTransport([allow()]);
    const appendAudit = transport.appendAudit.bind(transport);
    transport.appendAudit = async (event) => {
      await appendAudit(event);
      if (event.lifecycle === "SDK_ACTION_EXECUTION_STARTED") currentTime = "2026-07-21T12:06:00.000Z";
    };
    const sdk = new SecureActionClient(transport, {
      now: () => new Date(currentTime),
      idFactory: () => "event-deadline-recheck",
    });
    let executed = false;

    await assert.rejects(
      () => sdk.execute(request, () => { executed = true; }),
      SecureActionAbortedError,
    );
    assert.equal(executed, false);
  });

  it("releases only the local one-time reservation when execution-start storage fails", async () => {
    const authorization = grant("retry-after-start-failure");
    const once = (): SecureActionDecision => ({
      decision: "ALLOW_ONCE",
      actionId: request.id,
      protection: exposed,
      reasonCodes: ["USER_AUTHORIZED_ONCE"],
      audit: audit("decision-once-retry"),
      authorization,
    });
    const transport = new ScriptedTransport([once(), once()]);
    const appendAudit = transport.appendAudit.bind(transport);
    let starts = 0;
    transport.appendAudit = async (event) => {
      if (event.lifecycle === "SDK_ACTION_EXECUTION_STARTED" && starts++ === 0) {
        throw new Error("ambiguous start transport failure");
      }
      await appendAudit(event);
    };
    const sdk = client(transport);

    await assert.rejects(
      () => sdk.execute(request, () => "must-not-run"),
      (error: unknown) => error instanceof AuditAppendError && error.actionMayHaveExecuted === false,
    );
    const retried = await sdk.execute(request, () => "retried");

    assert.equal(retried.status, "executed");
    assert.equal(retried.status === "executed" && retried.value, "retried");
    assert.equal(transport.contexts.length, 2);
  });

  it("requires the server execution-start recheck for ALLOW even in best-effort audit mode", async () => {
    const transport = new ScriptedTransport([allow()]);
    transport.failAuditLifecycle = "SDK_ACTION_EXECUTION_STARTED";
    const sdk = new SecureActionClient(transport, {
      auditMode: "best-effort",
      now: () => new Date(NOW),
      idFactory: () => "event-allow-start-required",
    });
    let executed = false;

    await assert.rejects(
      () => sdk.execute(request, () => { executed = true; }),
      (error: unknown) => error instanceof AuditAppendError && error.actionMayHaveExecuted === false,
    );
    assert.equal(executed, false);
  });

  it("requires explicit opt-in before a simulation verdict can invoke the callback", async () => {
    const simulated = allow();
    if (simulated.decision !== "ALLOW") throw new Error("test decision must allow");
    const simulationDecision: SecureActionDecision = {
      ...simulated,
      protection: { ...simulated.protection, evidenceProvenance: "SIMULATION" },
    };
    let defaultExecutions = 0;
    await assert.rejects(
      () => client(new ScriptedTransport([simulationDecision])).execute(request, () => { defaultExecutions += 1; }),
      SimulationExecutionDeniedError,
    );
    assert.equal(defaultExecutions, 0);

    let optedInExecutions = 0;
    const outcome = await client(new ScriptedTransport([simulationDecision])).execute(
      request,
      () => { optedInExecutions += 1; return "simulated"; },
      { allowSimulationExecution: true },
    );
    assert.equal(outcome.status, "executed");
    assert.equal(optedInExecutions, 1);
  });

  it("does not consume a simulated one-time grant before execution opt-in", async () => {
    const authorization = grant("simulation-opt-in-retry");
    const simulatedOnce = (): SecureActionDecision => ({
      decision: "ALLOW_ONCE",
      actionId: request.id,
      protection: { ...protectedSnapshot, evidenceProvenance: "SIMULATION" },
      reasonCodes: ["USER_AUTHORIZED_ONCE"],
      audit: audit("decision-simulated-once"),
      authorization,
    });
    const transport = new ScriptedTransport([simulatedOnce(), simulatedOnce()]);
    const sdk = client(transport);

    await assert.rejects(
      () => sdk.execute(request, () => "must-not-run"),
      SimulationExecutionDeniedError,
    );
    const retried = await sdk.execute(request, () => "simulated", {
      allowSimulationExecution: true,
    });

    assert.equal(retried.status, "executed");
  });

  it("does not invoke onDecision when required audit latency expires ALLOW evidence", async () => {
    let currentTime = NOW;
    const transport = new ScriptedTransport([allow()]);
    const appendAudit = transport.appendAudit.bind(transport);
    transport.appendAudit = async (event) => {
      await appendAudit(event);
      if (event.lifecycle === "SDK_DECISION_RECEIVED") {
        currentTime = "2026-07-21T12:04:00.000Z";
      }
    };
    const sdk = new SecureActionClient(transport, {
      now: () => new Date(currentTime),
      idFactory: () => "event-decision-audit-expiry",
    });
    let observed = false;
    let executed = false;

    await assert.rejects(
      () => sdk.execute(request, () => { executed = true; }, {
        onDecision: () => { observed = true; },
      }),
      /protection evidence has expired/,
    );
    assert.equal(observed, false);
    assert.equal(executed, false);
  });

  it("rechecks ALLOW evidence immediately after asynchronous onDecision work", async () => {
    let currentTime = NOW;
    const transport = new ScriptedTransport([allow()]);
    const sdk = new SecureActionClient(transport, {
      now: () => new Date(currentTime),
      idFactory: () => "event-observer-expiry",
    });
    let executed = false;

    await assert.rejects(
      () => sdk.execute(request, () => { executed = true; }, {
        onDecision: async () => {
          await Promise.resolve();
          currentTime = "2026-07-21T12:04:00.000Z";
        },
      }),
      /protection evidence has expired/,
    );
    assert.equal(executed, false);
  });

  it("rechecks ALLOW evidence after the server execution-start boundary", async () => {
    let currentTime = NOW;
    const transport = new ScriptedTransport([allow()]);
    const appendAudit = transport.appendAudit.bind(transport);
    transport.appendAudit = async (event) => {
      await appendAudit(event);
      if (event.lifecycle === "SDK_ACTION_EXECUTION_STARTED") {
        currentTime = "2026-07-21T12:04:00.000Z";
      }
    };
    const sdk = new SecureActionClient(transport, {
      now: () => new Date(currentTime),
      idFactory: () => "event-start-evidence-expiry",
    });
    let executed = false;

    await assert.rejects(
      () => sdk.execute(request, () => { executed = true; }),
      /protection evidence has expired/,
    );
    assert.equal(executed, false);
  });

  it("rechecks abort state after a transport ignores cancellation", async () => {
    const controller = new AbortController();
    const transport = new ScriptedTransport([allow()]);
    const appendAudit = transport.appendAudit.bind(transport);
    transport.appendAudit = async (event) => {
      await appendAudit(event);
      if (event.lifecycle === "SDK_ACTION_EXECUTION_STARTED") controller.abort();
    };
    let executed = false;

    await assert.rejects(
      () => client(transport).execute(request, () => { executed = true; }, { signal: controller.signal }),
      SecureActionAbortedError,
    );
    assert.equal(executed, false);
  });

  it("rejects a one-time grant for a broader or different scope", async () => {
    const wrongGrant: OneTimeAuthorization = {
      ...grant(),
      scope: { ...scopeForRequest(request), destinations: ["evil.example"] },
    };
    const transport = new ScriptedTransport([
      {
        decision: "ALLOW_ONCE",
        actionId: request.id,
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

    for (const scope of [
      { ...scopeForRequest(request), dataClass: "credentials" },
      { ...scopeForRequest(request), sensitivity: "RESTRICTED" as const },
    ]) {
      const crossed = new ScriptedTransport([{
        decision: "ALLOW_ONCE",
        actionId: request.id,
        protection: exposed,
        reasonCodes: ["USER_AUTHORIZED_ONCE"],
        audit: audit("decision-once-crossed"),
        authorization: { ...grant("crossed-scope"), scope },
      }]);
      await assert.rejects(
        () => client(crossed).execute(request, () => "should-not-run"),
        OneTimeAuthorizationError,
      );
    }
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
  it("requires validUntil and policyRevision in every protection snapshot", () => {
    const missingValidUntil = {
      ...allow(),
      protection: (({ validUntil: _omitted, ...snapshot }) => snapshot)(protectedSnapshot),
    };
    assert.throws(() => parseDecision(missingValidUntil), /protection.validUntil/);

    const missingPolicyRevision = {
      ...allow(),
      protection: (({ policyRevision: _omitted, ...snapshot }) => snapshot)(protectedSnapshot),
    };
    assert.throws(() => parseDecision(missingPolicyRevision), /protection.policyRevision/);
  });

  it("rejects a decision whose audit and protection policy revisions differ", async () => {
    const transport = new ScriptedTransport([{
      ...allow(),
      audit: { ...audit("revision-mismatch"), policyRevision: 41 },
    }]);
    await assert.rejects(
      () => client(transport).execute(request, () => "not-run"),
      /policy revision does not match/,
    );
  });

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
          bearerToken: SDK_TOKEN,
        }),
      /Refusing non-loopback/,
    );
  });

  it("requires authentication for loopback transport by default", () => {
    assert.throws(() => new FetchLoopbackTransport(), /bearer token of at least 32 bytes is required/);
    assert.throws(() => new FetchLoopbackTransport({ bearerToken: "short" }), /at least 32 bytes/);
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
            evidenceProvenance: "EVIDENCE_PROVENANCE_LIVE",
            policyRevision: "9",
            state: "PROTECTION_STATE_EXPOSED",
            evaluatedAt: NOW,
            validUntil: LATER,
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
    assert.equal(decision.audit.traceId, request.operationId);
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
            evidenceProvenance: "EVIDENCE_PROVENANCE_LIVE",
            policyRevision: 9,
            state: "PROTECTION_STATE_EXPOSED",
            evaluatedAt: NOW,
            validUntil: LATER,
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
      bearerToken: SDK_TOKEN,
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
                evidenceProvenance: "EVIDENCE_PROVENANCE_LIVE",
                policyRevision: "9",
                state: "PROTECTION_STATE_PROTECTED",
                evaluatedAt: NOW,
                validUntil: LATER,
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
    assert.equal(capturedAuthorization, `Bearer ${SDK_TOKEN}`);
    assert.equal(decision.decision, "ALLOW");
  });

  it("maps canonical wait and authorize responses and appends idempotent audit events", async () => {
    const paths: string[] = [];
    const authorizations: Array<string | null> = [];
    const transport = new FetchLoopbackTransport({
      bearerToken: SDK_TOKEN,
      authorizationBearerToken: OPERATOR_TOKEN,
      fetch: async (input, init) => {
        const path = new URL(String(input)).pathname;
        paths.push(path);
        authorizations.push(new Headers(init?.headers).get("authorization"));
        if (path.endsWith("/wait")) {
          return new Response(
            JSON.stringify({
              restored: true,
              snapshot: {
                id: "snapshot-2",
                nodeId: "phone-1",
                evidenceProvenance: "EVIDENCE_PROVENANCE_LIVE",
                policyRevision: "9",
                state: "PROTECTION_STATE_PROTECTED",
                evaluatedAt: NOW,
                validUntil: LATER,
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
                  evidenceProvenance: "EVIDENCE_PROVENANCE_LIVE",
                  policyRevision: "9",
                  state: "PROTECTION_STATE_EXPOSED",
                  evaluatedAt: NOW,
                  validUntil: LATER,
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
    assert.deepEqual(authorizations, [`Bearer ${SDK_TOKEN}`, `Bearer ${OPERATOR_TOKEN}`, `Bearer ${SDK_TOKEN}`]);
  });

  it("fails closed before authorize fetch when no separate operator credential is configured", async () => {
    let contacted = false;
    const transport = new FetchLoopbackTransport({
      bearerToken: SDK_TOKEN,
      fetch: async () => { contacted = true; return Response.json({}); },
    });
    await assert.rejects(() => transport.authorizeOnce({
      actionId: "canonical-action-1",
      request,
      scope: scopeForRequest(request),
      expiresAt: LATER,
      consent: { confirmed: true, confirmedAt: NOW, method: "USER_EXPLICIT" },
    }), /separate operator credential/);
    assert.equal(contacted, false);
  });
});
