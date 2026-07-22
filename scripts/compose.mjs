#!/usr/bin/env node

import { relative, sep } from "node:path";
import { ensureDevelopmentEnvironment } from "./dev-environment.mjs";
import { commandExists, root, run, runStep } from "./tooling.mjs";

const commands = Object.freeze({
  dev: ["up", "--build"],
  down: ["down", "--remove-orphans"],
  lab: ["--profile", "lab", "run", "--rm", "--build", "lab"],
  build: ["build"],
  clean: ["down", "--remove-orphans", "--volumes"],
});

const action = process.argv[2];
if (!commands[action] || process.argv.length !== 3) {
  process.stderr.write("Usage: node scripts/compose.mjs <dev|down|lab|build|clean>\n");
  process.exit(2);
}

try {
  const environment = ensureDevelopmentEnvironment(root);
  const status = environment.created ? "Created" : environment.updated ? "Updated" : "Reusing";
  process.stdout.write(`${status} private development environment at .antiflock/dev.env.\n`);

  if (!commandExists("docker")) throw new Error("Docker is required to run the local AntiFlock stack.");
  const environmentArgument = relative(root, environment.environmentPath).split(sep).join("/");
  const compose = ["compose", "--env-file", environmentArgument];
  let simulatorWasRunning = false;
  if (action === "lab") {
    const status = run("docker", [...compose, "ps", "--status", "running", "--services", "simulator"], {
      capture: true,
      timeout: 30_000,
    });
    simulatorWasRunning = status.status === 0 && status.stdout.trim().split(/\r?\n/).includes("simulator");
    if (simulatorWasRunning && !runStep("Pause the continuous simulator", "docker", [...compose, "stop", "simulator"], { timeout: 120_000 })) {
      process.exit(1);
    }
  }

  let passed;
  try {
    passed = runStep(
      `Docker Compose ${action}`,
      "docker",
      [...compose, ...commands[action]],
      { timeout: 1_800_000 },
    );
  } finally {
    if (simulatorWasRunning) {
      passed = runStep("Resume the continuous simulator", "docker", [...compose, "start", "simulator"], { timeout: 120_000 }) && passed;
    }
  }
  if (!passed) process.exitCode = 1;
} catch (error) {
  process.stderr.write(`Local stack command failed: ${error.message}\n`);
  process.exitCode = 1;
}
