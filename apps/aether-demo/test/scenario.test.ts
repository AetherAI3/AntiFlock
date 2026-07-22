import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { SecureActionClient } from "@aether/antiflock-secure-action";
import { CoffeeShopAgentTransport, PROTECTION_NOTIFICATION } from "../src/scenario.js";

describe("coffee-shop secure action scenario", () => {
  it("holds a message and releases it only after protection is restored", async () => {
    const transport = new CoffeeShopAgentTransport({ restorationDelayMs: 0 });
    const client = new SecureActionClient(transport, {
      now: () => new Date("2026-07-21T13:00:01.000Z"),
      idFactory: (() => {
        let id = 0;
        return () => `event-${++id}`;
      })(),
    });
    const decisions: string[] = [];
    let sent = false;

    const result = await client.execute(
      {
        id: "demo-message-001",
        applicationId: "aether-messages-demo",
        nodeId: "demo-phone",
        actionType: "message.send",
        destinations: ["messages.aether.example"],
        dataClass: "message-body",
        sensitivity: "CONFIDENTIAL",
        deadline: "2026-07-21T13:05:00.000Z",
        operationId: "demo-message-send-001",
      },
      () => {
        sent = true;
        return "sent";
      },
      {
        onDecision: (decision) => {
          decisions.push(decision.decision);
        },
      },
    );

    assert.equal(result.status, "executed");
    assert.equal(sent, true);
    assert.deepEqual(decisions, ["HOLD", "ALLOW"]);
    assert.equal(transport.evaluationContexts[1]?.priorActionId, "demo-held-message");
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

  it("uses the locked, uncertainty-aware protection copy", () => {
    assert.equal(PROTECTION_NOTIFICATION.title, "Protection interrupted");
    assert.equal(
      PROTECTION_NOTIFICATION.body,
      "Your approved secure route is unavailable on an untrusted network. Protected traffic has been paused.",
    );
    assert.doesNotMatch(PROTECTION_NOTIFICATION.body, /watching|intercepting/i);
  });
});
