import assert from "node:assert/strict";
import test from "node:test";
import { createDemoData } from "../src/test-fixtures/demo";
import { dataForScenario, protectionStateForStage, scenarioState } from "../src/state/scenario";

test("coffee-shop failure is fail-closed and evidence-honest", () => {
  const joined = dataForScenario("joining", createDemoData("PROTECTED"));
  const verifying = dataForScenario("verifying", joined);
  const exposed = dataForScenario("exposed", verifying);

  assert.equal(protectionStateForStage("joining"), "VERIFYING");
  assert.equal(exposed.posture.state, "EXPOSED");
  assert.equal(exposed.posture.reasonCode, "AF-PATH-001");
  assert.equal(exposed.actions[0].decision, "HOLD");
  assert.equal(exposed.paths[0].segments.find((segment) => segment.id === "dest")?.state, "blocked");
  assert.match(exposed.findings[0].falsePositiveNote, /does not by itself indicate interception/i);
  assert.equal(exposed.findings[0].evidence.find((item) => item.label === "Interception status")?.evidenceClass, "Unknown");
});

test("verified recovery releases the held action", () => {
  const exposed = createDemoData("EXPOSED");
  const restoring = dataForScenario("restoring", exposed);
  const recovered = dataForScenario("recovered", restoring);

  assert.equal(restoring.posture.state, "VERIFYING");
  assert.equal(recovered.posture.state, "PROTECTED");
  assert.equal(recovered.actions[0].decision, "ALLOW");
  assert.equal(recovered.findings[0].status, "resolved");
  assert.equal(recovered.events[0].kind, "action.allowed");
  assert.equal(scenarioState("recovered").step, 7);
});

test("send-once bypass is narrow, expiring, and does not claim protection", () => {
  const bypassed = dataForScenario("bypassed", createDemoData("EXPOSED"));

  assert.equal(bypassed.posture.state, "EXPOSED");
  assert.equal(bypassed.actions[0].decision, "ALLOW_ONCE");
  assert.deepEqual(bypassed.actions[0].reasonCodes, ["USER-SCOPED-BYPASS", "AF-PATH-001"]);
  assert.ok(bypassed.actions[0].expiresAt);
  assert.match(bypassed.events[0].summary, /only Aether Code → api.github.com for this action/i);
});
