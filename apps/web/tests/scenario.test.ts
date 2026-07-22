import assert from "node:assert/strict";
import test from "node:test";
import { createUnknownLiveData } from "../src/api/client";
import { createDemoData } from "../src/test-fixtures/demo";
import { dataForScenario, liveScenarioState, protectionStateForStage, scenarioState } from "../src/state/scenario";

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

test("live data never labels an initial protected projection as a recovery", () => {
  const protectedData = createDemoData("PROTECTED");

  assert.equal(liveScenarioState(null, protectedData).stage, "protected");
  assert.equal(liveScenarioState(null, createUnknownLiveData()).label, "Awaiting current Core evidence");
});

test("live recovery requires the same held action to become allowed", () => {
  const held = createDemoData("EXPOSED");
  const allowed = createDemoData("PROTECTED");
  assert.equal(liveScenarioState(held, allowed).stage, "recovered");

  allowed.actions[0] = { ...allowed.actions[0], id: "different-action" };
  assert.equal(liveScenarioState(held, allowed).stage, "protected");
});

test("send-once bypass is narrow, expiring, and does not claim protection", () => {
  const bypassed = dataForScenario("bypassed", createDemoData("EXPOSED"));

  assert.equal(bypassed.posture.state, "EXPOSED");
  assert.equal(bypassed.actions[0].decision, "ALLOW_ONCE");
  assert.deepEqual(bypassed.actions[0].reasonCodes, ["USER-SCOPED-BYPASS", "AF-PATH-001"]);
  assert.ok(bypassed.actions[0].expiresAt);
  assert.match(bypassed.events[0].summary, /only Aether Code → api.github.com for this action/i);
});
