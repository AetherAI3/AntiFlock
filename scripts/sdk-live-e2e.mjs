#!/usr/bin/env node

import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer } from "node:net";
import { join, relative, sep } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { pathToFileURL } from "node:url";
import { ensureDevelopmentEnvironment } from "./dev-environment.mjs";
import { commandExists, npmCommand, root, run } from "./tooling.mjs";

const baseCompose = "docker-compose.yml";
const liveOverride = "deploy/compose/sdk-live.override.yml";
const sdkBuild = "sdk/typescript/dist/src/index.js";
const lifecycleSequence = Object.freeze([
  "SDK_DECISION_RECEIVED",
  "SDK_HOLD_WAIT_STARTED",
  "SDK_PROTECTION_RESTORED",
  "SDK_DECISION_RECEIVED",
  "SDK_ACTION_EXECUTION_STARTED",
  "SDK_ACTION_EXECUTION_SUCCEEDED",
]);
let liveComposeEnvironment;

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function parseEnvironment(contents) {
  const values = new Map();
  for (const rawLine of contents.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (line === "" || line.startsWith("#")) continue;
    const separator = line.indexOf("=");
    if (separator <= 0) throw new Error("Private development environment is malformed.");
    values.set(line.slice(0, separator), line.slice(separator + 1));
  }
  return values;
}

function mustValue(values, key) {
  const value = values.get(key);
  invariant(value && !/[\r\n]/.test(value), `Private development environment is missing ${key}.`);
  return value;
}

function command(label, executable, args, options = {}) {
  const result = run(executable, args, {
    capture: options.capture ?? false,
    timeout: options.timeout ?? 1_800_000,
    env: options.env,
  });
  if (result.status !== 0) {
    throw new Error(`${label} failed${result.status === null ? " before starting" : ` with exit code ${result.status}`}.`);
  }
  return result;
}

function composeArguments(environmentPath, override, args) {
  const environmentArgument = relative(root, environmentPath).split(sep).join("/");
  return [
    "compose",
    "--env-file",
    environmentArgument,
    "-f",
    baseCompose,
    ...(override ? ["-f", liveOverride] : []),
    ...(override ? ["--profile", "sdk-live"] : []),
    ...args,
  ];
}

function compose(environmentPath, override, label, args, options = {}) {
  return command(
    label,
    "docker",
    composeArguments(environmentPath, override, args),
    {
      ...options,
      env: {
        ...(override ? liveComposeEnvironment : {}),
        ...options.env,
      },
    },
  );
}

function serviceRunning(environmentPath, service) {
  const result = compose(
    environmentPath,
    false,
    `Inspect ${service} state`,
    ["ps", "--status", "running", "--services", service],
    { capture: true, timeout: 30_000 },
  );
  return result.stdout.trim().split(/\r?\n/).includes(service);
}

async function selectLoopbackPort() {
  const server = createServer();
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  invariant(address && typeof address === "object", "Could not select a temporary loopback port.");
  return address.port;
}

function verifyTemporaryLoopbackBinding(environmentPath, port) {
  const identity = compose(
    environmentPath,
    true,
    "Locate temporary SDK loopback bridge",
    ["ps", "-q", "sdk-loopback"],
    { capture: true, timeout: 30_000 },
  );
  const containerId = identity.stdout.trim();
  invariant(containerId !== "", "Temporary SDK loopback bridge could not be inspected.");
  const inspection = command(
    "Inspect temporary Core loopback binding",
    "docker",
    ["inspect", "--format", "{{json .HostConfig.PortBindings}}", containerId],
    { capture: true, timeout: 30_000 },
  );
  const bindings = JSON.parse(inspection.stdout);
  const coreBindings = bindings?.["18787/tcp"];
  invariant(
    Array.isArray(coreBindings) && coreBindings.length === 1 &&
      coreBindings[0].HostIp === "127.0.0.1" && coreBindings[0].HostPort === String(port),
    "Compose did not publish the Core bridge exclusively on the selected loopback port.",
  );
}

async function waitFor(label, probe, timeoutMs = 60_000) {
  const deadline = Date.now() + timeoutMs;
  let lastError;
  while (Date.now() < deadline) {
    try {
      if (await probe()) return;
    } catch (error) {
      lastError = error;
    }
    await delay(250);
  }
  throw new Error(`${label} did not become ready in ${timeoutMs}ms.`, {
    cause: lastError,
  });
}

async function requestJSON(origin, path, token, options = {}) {
  const response = await fetch(new URL(path, origin), {
    method: options.method ?? "GET",
    headers: {
      accept: "application/json",
      ...(options.body === undefined ? {} : { "content-type": "application/json" }),
      ...(token === undefined ? {} : { authorization: `Bearer ${token}` }),
    },
    ...(options.body === undefined ? {} : { body: JSON.stringify(options.body) }),
    signal: AbortSignal.timeout(options.timeoutMs ?? 15_000),
  });
  let body;
  if (response.status !== 204) {
    body = await response.json().catch(() => undefined);
  }
  return { status: response.status, body };
}

async function waitForCore(origin) {
  await waitFor("Core", async () => {
    const response = await requestJSON(origin, "readyz", undefined, { timeoutMs: 2_000 });
    return response.status === 200 && response.body?.status === "ready";
  });
}

async function waitForNode(origin, operatorToken, nodeId) {
  await waitFor("simulator enrollment", async () => {
    const response = await requestJSON(origin, "v1/nodes", operatorToken);
    return response.status === 200 && response.body?.nodes?.some((node) => node.id === nodeId);
  });
}

async function waitForPosture(origin, operatorToken, state) {
  await waitFor(`posture ${state}`, async () => {
    const response = await requestJSON(origin, "v1/posture", operatorToken);
    return response.status === 200 && response.body?.state === state;
  });
}

function exposedPosture(nodeId) {
  const observedAt = new Date();
  return {
    nodeId,
    state: "EXPOSED",
    observedAt: observedAt.toISOString(),
    validUntil: new Date(observedAt.getTime() + 90_000).toISOString(),
    networkTrust: "UNTRUSTED",
    meshConnected: false,
    approvedExitActive: false,
    dnsProtected: false,
    routeProtected: false,
    reasonCodes: ["AF-SDK-LIVE-E2E-EXPOSED"],
    policyRevision: 7,
  };
}

async function verifyNormalCoreHasNoPublishedPort(environmentPath) {
  const identity = compose(
    environmentPath,
    false,
    "Locate restored Core container",
    ["ps", "-q", "core"],
    { capture: true, timeout: 30_000 },
  );
  const containerId = identity.stdout.trim();
  invariant(containerId !== "", "Restored Core container could not be inspected.");
  const inspection = command(
    "Inspect restored Core port bindings",
    "docker",
    ["inspect", "--format", "{{json .HostConfig.PortBindings}}", containerId],
    { capture: true, timeout: 30_000 },
  );
  const bindings = JSON.parse(inspection.stdout);
  invariant(
    bindings && Object.keys(bindings).length === 0,
    "Core remained published after the live SDK acceptance cleanup.",
  );
}

async function main() {
  invariant(commandExists("docker"), "Docker is required for the live SDK acceptance.");
  invariant(commandExists(npmCommand()), "npm is required for the live SDK acceptance.");

  const environment = ensureDevelopmentEnvironment(root);
  const values = parseEnvironment(readFileSync(environment.environmentPath, "utf8"));
  const operatorToken = mustValue(values, "ANTIFLOCK_OPERATOR_TOKEN");
  const sdkToken = mustValue(values, "ANTIFLOCK_SDK_TOKEN");
  const agentToken = mustValue(values, "ANTIFLOCK_AGENT_TOKEN");
  const applicationId = mustValue(values, "ANTIFLOCK_SDK_APPLICATION_ID");
  const nodeId = mustValue(values, "ANTIFLOCK_AGENT_NODE_ID");
  invariant(applicationId === "aether-code", "The live SDK acceptance requires the explicit aether-code demo application policy.");

  const coreWasRunning = serviceRunning(environment.environmentPath, "core");
  const simulatorWasRunning = serviceRunning(environment.environmentPath, "simulator");
  const livePort = await selectLoopbackPort();
  liveComposeEnvironment = { ANTIFLOCK_SDK_E2E_PORT: String(livePort) };
  let overrideApplied = false;
  let origin;
  let completed = false;
  let result;
  let primaryError;
  let cleanupError;

  try {
    command(
      "Build TypeScript Secure Action SDK",
      npmCommand(),
      ["run", "build", "--prefix", "sdk/typescript"],
      { timeout: 300_000 },
    );
    const sdk = await import(pathToFileURL(join(root, sdkBuild)).href + `?live=${Date.now()}`);

    overrideApplied = true;
    compose(
      environment.environmentPath,
      true,
      "Start isolated Core, signed simulator, and temporary loopback bridge",
      ["up", "-d", "--build", "core", "simulator", "sdk-loopback"],
    );
    verifyTemporaryLoopbackBinding(environment.environmentPath, livePort);
    origin = `http://127.0.0.1:${livePort}/`;
    await waitForCore(origin);
    await waitForNode(origin, operatorToken, nodeId);

    compose(
      environment.environmentPath,
      true,
      "Pause continuous simulator before the fail-closed transition",
      ["stop", "simulator"],
      { timeout: 120_000 },
    );
    const exposed = await requestJSON(origin, "v1/posture/report", agentToken, {
      method: "POST",
      body: exposedPosture(nodeId),
    });
    invariant(exposed.status === 202 && exposed.body?.accepted === true, "Core rejected the deterministic EXPOSED posture.");
    await waitForPosture(origin, operatorToken, "EXPOSED");

    const fetchTransport = new sdk.FetchLoopbackTransport({
      baseUrl: origin,
      bearerToken: sdkToken,
      clientId: "antiflock-sdk-live-e2e",
      requestTimeoutMs: 15_000,
    });
    const persistedEvents = [];
    const recordingTransport = {
      evaluate: (...args) => fetchTransport.evaluate(...args),
      waitForProtection: (...args) => fetchTransport.waitForProtection(...args),
      authorizeOnce: (...args) => fetchTransport.authorizeOnce(...args),
      appendAudit: async (event, signal) => {
        await fetchTransport.appendAudit(event, signal);
        persistedEvents.push(structuredClone(event));
      },
    };

    const nonce = `${Date.now().toString(36)}-${randomUUID().slice(0, 8)}`;
    let nextAudit = 0;
    let operationCallbackCount = 0;
    let startPersistedBeforeCallback = false;
    let recoveryStarted = false;
    const decisions = [];
    const client = new sdk.SecureActionClient(recordingTransport, {
      defaultDeadlineMs: 120_000,
      idFactory: () => `sdk-live-${nonce}-audit-${String(++nextAudit).padStart(2, "0")}`,
    });
    const request = {
      id: `sdk-live-${nonce}-action`,
      applicationId,
      nodeId,
      actionType: "git.push",
      destinations: ["github.com"],
      dataClass: "repository-source",
      sensitivity: "CONFIDENTIAL",
      deadline: new Date(Date.now() + 120_000).toISOString(),
      operationId: `sdk-live-${nonce}-operation`,
      metadata: { simulation: true, harness: "typescript-live-e2e" },
    };

    const outcome = await client.execute(
      request,
      async () => {
        const startEvent = persistedEvents.find(
          (event) => event.lifecycle === "SDK_ACTION_EXECUTION_STARTED",
        );
        invariant(startEvent, "SDK invoked the callback before persisting execution start.");
        let replayStatus;
        try {
          await fetchTransport.appendAudit(startEvent);
        } catch (error) {
          if (error instanceof sdk.AgentTransportError) replayStatus = error.status;
          else throw error;
        }
        invariant(replayStatus === 409, "Execution-start replay was not rejected before callback execution.");
        startPersistedBeforeCallback = true;
        operationCallbackCount += 1;
        return "executed-once";
      },
      {
        retryOnProtectionRestored: true,
        maxProtectionRestorations: 1,
        allowSimulationExecution: true,
        onDecision: async (decision, attempt) => {
          invariant(
            decision.protection.evidenceProvenance === "SIMULATION",
            `Core returned ${decision.protection.evidenceProvenance} provenance for simulator evidence.`,
          );
          decisions.push({
            decision: decision.decision,
            attempt,
            evidenceProvenance: decision.protection.evidenceProvenance,
          });
          if (decision.decision === "HOLD" && !recoveryStarted) {
            recoveryStarted = true;
            compose(
              environment.environmentPath,
              true,
              "Resume signed simulator to provide verified recovery evidence",
              ["up", "-d", "simulator"],
              { timeout: 120_000 },
            );
          }
        },
      },
    );

    invariant(outcome.status === "executed", `SDK returned ${outcome.status} instead of executed.`);
    invariant(outcome.value === "executed-once", "SDK returned an unexpected operation value.");
    invariant(outcome.decision === "ALLOW" && outcome.attempts === 1, "SDK did not re-evaluate HOLD into ALLOW exactly once.");
    invariant(operationCallbackCount === 1, `Operation callback ran ${operationCallbackCount} times instead of exactly once.`);
    invariant(startPersistedBeforeCallback, "Callback crossed without a durably acknowledged execution start.");
    invariant(
      JSON.stringify(decisions) === JSON.stringify([
        { decision: "HOLD", attempt: 0, evidenceProvenance: "SIMULATION" },
        { decision: "ALLOW", attempt: 1, evidenceProvenance: "SIMULATION" },
      ]),
      `SDK decision path was ${JSON.stringify(decisions)} instead of HOLD then ALLOW.`,
    );
    invariant(
      JSON.stringify(persistedEvents.map((event) => event.lifecycle)) === JSON.stringify(lifecycleSequence),
      `SDK lifecycle path was ${JSON.stringify(persistedEvents.map((event) => event.lifecycle))}.`,
    );
    invariant(new Set(persistedEvents.map((event) => event.eventId)).size === persistedEvents.length, "SDK reused a lifecycle event ID.");
    invariant(persistedEvents.every((event) => event.policyRevision > 0), "SDK emitted an unversioned lifecycle event.");

    compose(
      environment.environmentPath,
      true,
      "Pause simulator before the Core durability restart",
      ["stop", "simulator"],
      { timeout: 120_000 },
    );
    compose(
      environment.environmentPath,
      true,
      "Restart Core to cross a durable process boundary",
      ["restart", "core"],
      { timeout: 120_000 },
    );
    await waitForCore(origin);
    compose(
      environment.environmentPath,
      true,
      "Restore fresh protected posture for lifecycle persistence probes",
      ["up", "-d", "simulator"],
      { timeout: 120_000 },
    );
    await waitForPosture(origin, operatorToken, "PROTECTED");

    const actions = await requestJSON(origin, "v1/actions?limit=200", operatorToken);
    const durableAction = actions.body?.actions?.find((action) => action.actionId === request.id);
    invariant(actions.status === 200 && durableAction?.decision === "ALLOW", "Core did not retain the released secure action across restart.");

    const changedReplayStatuses = [];
    for (const event of persistedEvents) {
      const conflictEvent = {
        ...event,
        details: { ...(event.details ?? {}), conflictProbe: "different-payload" },
      };
      let conflictStatus;
      try {
        await fetchTransport.appendAudit(conflictEvent);
      } catch (error) {
        if (error instanceof sdk.AgentTransportError) conflictStatus = error.status;
        else throw error;
      }
      invariant(conflictStatus === 409, `Core returned ${String(conflictStatus)} instead of 409 for a changed event-id replay.`);
      changedReplayStatuses.push(conflictStatus);
    }
    const idempotentEvents = persistedEvents.filter(
      (event) => event.lifecycle !== "SDK_ACTION_EXECUTION_STARTED",
    );
    for (const event of idempotentEvents) {
      await fetchTransport.appendAudit(event);
    }
    const startEvent = persistedEvents.find(
      (event) => event.lifecycle === "SDK_ACTION_EXECUTION_STARTED",
    );
    invariant(startEvent, "Persisted lifecycle omitted execution start.");
    let executionStartReplayStatus;
    try {
      await fetchTransport.appendAudit(startEvent);
    } catch (error) {
      if (error instanceof sdk.AgentTransportError) executionStartReplayStatus = error.status;
      else throw error;
    }
    invariant(executionStartReplayStatus === 409, "Core did not reject an execution-start replay after restart.");

    result = {
      schemaVersion: "antiflock.sdk-live-e2e/v1",
      simulation: true,
      transport: "FetchLoopbackTransport",
      initialDecision: decisions[0].decision,
      finalDecision: decisions[1].decision,
      evidenceProvenance: "SIMULATION",
      reevaluationCount: 1,
      operationCallbackCount,
      lifecycleEventCount: persistedEvents.length,
      lifecycleSequence: persistedEvents.map((event) => event.lifecycle),
      coreRestartVerified: true,
      durableActionDecision: durableAction.decision,
      idempotentReplayCount: idempotentEvents.length,
      executionStartReplayStatus,
      changedReplayCount: changedReplayStatuses.length,
      changedReplayStatus: changedReplayStatuses.every((status) => status === 409) ? 409 : undefined,
      temporaryCoreExposure: "loopback-ephemeral-removed",
      verified: true,
    };
    completed = true;
  } catch (error) {
    primaryError = error;
  } finally {
    if (overrideApplied) {
      try {
        compose(environment.environmentPath, true, "Remove temporary SDK loopback bridge", ["rm", "-f", "-s", "sdk-loopback"], { timeout: 120_000 });
        compose(environment.environmentPath, true, "Stop simulator before restoring the normal stack", ["stop", "simulator"], { timeout: 120_000 });
        compose(
          environment.environmentPath,
          false,
          "Restore normal Core service",
          ["up", "-d", "--no-deps", "core"],
          { timeout: 300_000 },
        );
        await verifyNormalCoreHasNoPublishedPort(environment.environmentPath);
        if (coreWasRunning) {
          compose(
            environment.environmentPath,
            false,
            "Refresh normal simulator posture",
            ["up", "-d", "simulator"],
            { timeout: 120_000 },
          );
          if (!simulatorWasRunning) {
            await delay(2_000);
            compose(
              environment.environmentPath,
              false,
              "Restore stopped simulator state",
              ["stop", "simulator"],
              { timeout: 120_000 },
            );
          }
        } else {
          compose(
            environment.environmentPath,
            false,
            "Restore stopped Core state",
            ["stop", "core"],
            { timeout: 120_000 },
          );
        }
      } catch (error) {
        completed = false;
        cleanupError = error;
      }
    }
  }

  if (primaryError) throw primaryError;
  if (cleanupError) {
    throw new Error("Live SDK acceptance could not restore the normal private stack.", { cause: cleanupError });
  }
  invariant(completed && result?.verified === true, "Live SDK acceptance did not complete.");
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
}

main().catch((error) => {
  process.stderr.write(`Live SDK acceptance failed: ${error.message}\n`);
  process.exitCode = 1;
});
