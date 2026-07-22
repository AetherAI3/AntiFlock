import { SecureActionClient, type SecureActionDecision } from "@aether/antiflock-secure-action";
import { CoffeeShopAgentTransport, PROTECTION_NOTIFICATION } from "./scenario.js";

const line = (message = "") => process.stdout.write(`${message}\n`);

line("AntiFlock / Aether Secure Action demonstration (simulation)");
line("No VPN or packet transport is created by this demo.");
line();
line("[network] Joined coffee-shop Wi-Fi (untrusted)");
line("[path] Approved private route unavailable; DNS path unverified");
line("[app] User pressed Send for a confidential message");

const transport = new CoffeeShopAgentTransport({
  onRestorationStarted: () => line("[guard] Restore Shield requested; validating route..."),
  onRestored: () => line("[guard] Mesh, trusted exit, and protected DNS verified"),
});
const client = new SecureActionClient(transport, {
  // The scenario uses fixed evidence timestamps so its audit output is repeatable.
  now: () => new Date("2026-07-21T13:00:01.000Z"),
  idFactory: (() => {
    let sequence = 0;
    return () => `demo-event-${++sequence}`;
  })(),
});

function renderDecision(decision: SecureActionDecision): void {
  if (decision.decision === "HOLD") {
    line();
    line(PROTECTION_NOTIFICATION.title);
    line(PROTECTION_NOTIFICATION.body);
    line("Public network: untrusted");
    line("Private mesh: disconnected");
    line("DNS path: unverified");
    line("Active interception: not confirmed");
    line();
    line("[app] Amber shield shown; message remains pending");
  } else if (decision.decision === "ALLOW") {
    line("[gate] Protection re-evaluated: ALLOW");
  }
}

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
    metadata: { scenario: "coffee-shop" },
  },
  async () => {
    line("[app] Message sent through the verified protected path");
    return { messageId: "demo-message-001", delivered: true };
  },
  { allowSimulationExecution: true, onDecision: renderDecision },
);

line();
line(`[result] ${result.status}`);
line(`[audit] ${transport.audits.length} local lifecycle events`);
for (const event of transport.audits) {
  line(`  ${event.eventId} ${event.lifecycle} decision=${event.decision}`);
}

if (result.status !== "executed") {
  process.exitCode = 1;
}
